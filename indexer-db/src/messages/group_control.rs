use crate::{AddressPayload, SharedImmutable};
use anyhow::Result;
use fjall::{PartitionCreateOptions, ReadTransaction, WriteTransaction};
use std::fmt::Debug;
use zerocopy::big_endian::U64;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// sender (34) + block_time (8) + block_hash (32) + version (1) + tx_id (32)
/// Note: sender can be zeros (when not resolved yet)
/// GroupControlV1 is ECIES-encrypted to one specific recipient (same "sender self-stashes,
/// only the intended recipient can decrypt" shape as ContextualMessageV1); the indexer has
/// no way to learn the recipient on-chain, so it is indexed by sender only, like
/// ContextualMessageV1/SelfStashV1.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Immutable, KnownLayout, IntoBytes, FromBytes, Unaligned,
)]
pub struct GroupControlKeyBySender {
    pub sender: AddressPayload,
    pub block_time: U64,
    pub block_hash: [u8; 32],
    pub version: u8,
    pub tx_id: [u8; 32],
}

#[derive(Clone)]
pub struct GroupControlBySenderPartition(fjall::TxPartition);

impl GroupControlBySenderPartition {
    pub fn new(keyspace: &fjall::TxKeyspace) -> Result<Self> {
        Ok(Self(keyspace.open_partition(
            "group_control_by_sender",
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

    pub fn insert_wtx(&self, wtx: &mut WriteTransaction, key: &GroupControlKeyBySender) {
        wtx.insert(&self.0, key.as_bytes(), []);
    }

    pub fn get_by_sender_from_block_time(
        &self,
        rtx: &ReadTransaction,
        sender: &AddressPayload,
        from_block_time: u64,
    ) -> impl DoubleEndedIterator<Item = Result<SharedImmutable<GroupControlKeyBySender>>> + '_
    {
        // Create range start: sender (34 bytes) + block_time (8 bytes)
        let mut range_start = [0u8; 42]; // 34 + 8
        range_start[..34].copy_from_slice(sender.as_bytes());
        range_start[34..42].copy_from_slice(&from_block_time.to_be_bytes());

        // Create range end: sender (34 bytes) + max block_time (8 bytes)
        let mut range_end = [0xFFu8; 42]; // 34 + 8
        range_end[..34].copy_from_slice(sender.as_bytes());

        rtx.range(&self.0, range_start..=range_end).map(|item| {
            item.map(|(key, _value)| SharedImmutable::new(key))
                .map_err(anyhow::Error::from)
        })
    }
}

#[derive(Clone)]
pub struct TxIdToGroupControlPartition(fjall::TxPartition);

impl TxIdToGroupControlPartition {
    pub fn new(keyspace: &fjall::TxKeyspace) -> Result<Self> {
        Ok(Self(keyspace.open_partition(
            "tx-id-to-group-control",
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
