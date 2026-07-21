use crate::{AddressPayload, SharedImmutable};
use anyhow::Result;
use fjall::{PartitionCreateOptions, ReadTransaction, WriteTransaction};
use std::fmt::Debug;
use zerocopy::big_endian::U64;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

pub const INVITE_TAG_LEN: usize = 16;

/// invite_tag (16) + block_time (8) + block_hash (32) + version (1) + tx_id (32)
/// Note: a device holding an invite link computes `invite_tag` locally and looks up any
/// beacons published under it; the indexer never learns the group's real identity.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Immutable, KnownLayout, IntoBytes, FromBytes, Unaligned,
)]
pub struct GroupInviteKeyByTag {
    pub invite_tag: [u8; INVITE_TAG_LEN],
    pub block_time: U64,
    pub block_hash: [u8; 32],
    pub version: u8,
    pub tx_id: [u8; 32],
}

#[derive(Clone)]
pub struct GroupInviteByTagPartition(fjall::TxPartition);

impl GroupInviteByTagPartition {
    pub fn new(keyspace: &fjall::TxKeyspace) -> Result<Self> {
        Ok(Self(keyspace.open_partition(
            "group_invite_by_tag",
            PartitionCreateOptions::default(),
        )?))
    }

    pub fn len(&self) -> Result<usize> {
        Ok(self.0.inner().len()?)
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.0.inner().is_empty()?)
    }

    pub fn approximate_len(&self) -> usize {
        self.0.approximate_len()
    }

    pub fn insert_wtx(
        &self,
        wtx: &mut WriteTransaction,
        key: &GroupInviteKeyByTag,
        sender: Option<AddressPayload>,
    ) -> Result<()> {
        let sender = sender.unwrap_or_default();
        wtx.update_fetch(&self.0, key.as_bytes(), |old| match old {
            None => Some(sender.as_bytes().into()),
            Some(old) => {
                let old_sender = AddressPayload::try_ref_from_bytes(old.as_bytes()).unwrap();
                if old_sender != &AddressPayload::default() {
                    Some(old.clone())
                } else {
                    Some(sender.as_bytes().into())
                }
            }
        })?;
        Ok(())
    }

    pub fn iter_by_tag_from_block_time_rtx(
        &self,
        rtx: &ReadTransaction,
        invite_tag: &[u8; INVITE_TAG_LEN],
        block_time: u64,
    ) -> impl DoubleEndedIterator<
        Item = Result<(
            SharedImmutable<GroupInviteKeyByTag>,
            SharedImmutable<AddressPayload>,
        )>,
    > + '_ {
        const PREFIX_LEN: usize = INVITE_TAG_LEN + 8;
        let mut range_start = [0u8; PREFIX_LEN];
        range_start[..INVITE_TAG_LEN].copy_from_slice(invite_tag);
        range_start[INVITE_TAG_LEN..].copy_from_slice(&block_time.to_be_bytes());

        let mut range_end = [0xFFu8; PREFIX_LEN];
        range_end[..INVITE_TAG_LEN].copy_from_slice(invite_tag);

        rtx.range(&self.0, range_start..=range_end).map(|item| {
            let (key_bytes, value_bytes) = item?;
            Ok((
                SharedImmutable::new(key_bytes),
                SharedImmutable::new(value_bytes),
            ))
        })
    }
}

#[derive(Clone)]
pub struct TxIdToGroupInvitePartition(fjall::TxPartition);

impl TxIdToGroupInvitePartition {
    pub fn new(keyspace: &fjall::TxKeyspace) -> Result<Self> {
        Ok(Self(keyspace.open_partition(
            "tx-id-to-group-invite",
            PartitionCreateOptions::default(),
        )?))
    }

    pub fn len(&self) -> Result<usize> {
        Ok(self.0.inner().len()?)
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.0.inner().is_empty()?)
    }

    pub fn approximate_len(&self) -> usize {
        self.0.approximate_len()
    }

    pub fn insert_wtx(&self, wtx: &mut WriteTransaction, tx_id: &[u8; 32], sealed_hex: &[u8]) {
        wtx.insert(&self.0, tx_id, sealed_hex);
    }

    pub fn get_rtx(
        &self,
        rtx: &ReadTransaction,
        tx_id: &[u8; 32],
    ) -> Result<Option<SharedImmutable<[u8]>>> {
        rtx.get(&self.0, tx_id)
            .map(|bts| bts.map(SharedImmutable::new))
            .map_err(anyhow::Error::from)
    }
}
