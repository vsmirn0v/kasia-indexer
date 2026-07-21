use crate::api::to_rpc_address;
use crate::context::IndexerContext;
use anyhow::Context;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use indexer_db::messages::group_invite::{
    GroupInviteByTagPartition, INVITE_TAG_LEN, TxIdToGroupInvitePartition,
};
use indexer_db::processing::tx_id_to_acceptance::TxIDToAcceptancePartition;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio::task::spawn_blocking;
use utoipa::{IntoParams, ToSchema};

#[derive(Clone)]
pub struct GroupInviteApi {
    tx_keyspace: fjall::TxKeyspace,
    group_invite_by_tag_partition: GroupInviteByTagPartition,
    tx_id_to_acceptance_partition: TxIDToAcceptancePartition,
    tx_id_to_group_invite_partition: TxIdToGroupInvitePartition,
    context: IndexerContext,
}

impl GroupInviteApi {
    pub fn new(
        tx_keyspace: fjall::TxKeyspace,
        group_invite_by_tag_partition: GroupInviteByTagPartition,
        tx_id_to_acceptance_partition: TxIDToAcceptancePartition,
        tx_id_to_group_invite_partition: TxIdToGroupInvitePartition,
        context: IndexerContext,
    ) -> Self {
        Self {
            tx_keyspace,
            group_invite_by_tag_partition,
            tx_id_to_acceptance_partition,
            tx_id_to_group_invite_partition,
            context,
        }
    }

    pub fn router() -> Router<Self> {
        Router::new().route("/by-tag", get(get_group_invites_by_tag))
    }
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct GroupInvitePaginationParams {
    pub limit: Option<usize>,
    pub block_time: Option<u64>,
    pub invite_tag: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GroupInviteResponse {
    pub tx_id: String,
    pub sender: Option<String>,
    pub invite_tag: String,
    pub block_time: u64,
    pub accepting_block: Option<String>,
    pub accepting_daa_score: Option<u64>,
    pub message_payload: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
}

#[utoipa::path(
    get,
    path = "/group-invites/by-tag",
    params(GroupInvitePaginationParams),
    responses(
        (status = 200, description = "Get group invites by invite tag", body = [GroupInviteResponse]),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn get_group_invites_by_tag(
    State(state): State<GroupInviteApi>,
    Query(params): Query<GroupInvitePaginationParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(10).min(50);
    let cursor = params.block_time.unwrap_or(0);

    if params.invite_tag.len() != INVITE_TAG_LEN * 2 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!(
                    "invite_tag hex length must be exactly {} characters",
                    INVITE_TAG_LEN * 2
                ),
            }),
        ));
    }

    let mut invite_tag = [0u8; INVITE_TAG_LEN];
    if let Err(e) = faster_hex::hex_decode(params.invite_tag.as_bytes(), &mut invite_tag) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid invite_tag hex: {e}"),
            }),
        ));
    }

    let result = spawn_blocking(move || {
        let rtx = state.tx_keyspace.read_tx();
        let mut seen_tx_ids = HashSet::with_capacity(limit);

        state
            .group_invite_by_tag_partition
            .iter_by_tag_from_block_time_rtx(&rtx, &invite_tag, cursor)
            .process_results(|iter| {
                iter.filter(|(key, _sender)| seen_tx_ids.insert(key.tx_id))
                    .take(limit)
                    .map(|(key, sender_payload)| {
                        let block_time = key.block_time.get();
                        let sender = to_rpc_address(&sender_payload, state.context.network_type)
                            .context("Sender address conversion error")?
                            .map(|addr| addr.to_string());

                        let acceptance = state
                            .tx_id_to_acceptance_partition
                            .acceptance_by_tx_id_rtx(&rtx, &key.tx_id)?;

                        let (accepting_block, accepting_daa_score) =
                            if let Some(acceptance) = acceptance {
                                (
                                    Some(faster_hex::hex_string(
                                        &acceptance.header.accepting_block_hash,
                                    )),
                                    Some(acceptance.header.accepting_daa.into()),
                                )
                            } else {
                                (None, None)
                            };

                        let sealed_hex = state
                            .tx_id_to_group_invite_partition
                            .get_rtx(&rtx, &key.tx_id)?
                            .context("Missing group invite payload")?;
                        let message_payload = faster_hex::hex_string(sealed_hex.as_ref());

                        Ok(GroupInviteResponse {
                            tx_id: faster_hex::hex_string(&key.tx_id),
                            sender,
                            invite_tag: params.invite_tag.clone(),
                            block_time,
                            accepting_block,
                            accepting_daa_score,
                            message_payload,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .flatten()
    })
    .await;

    match result {
        Ok(Ok(messages)) => Ok(Json(messages)),
        Ok(Err(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )),
        Err(join_err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Task error: {join_err}"),
            }),
        )),
    }
}
