use indexer_db::AddressPayload;

#[derive(Debug, Clone, Copy)]
pub enum PushEventKind {
    Contextual,
    Payment,
    Handshake,
    SelfStash,
    /// A `gcomm` group message. Unlike every other kind, there's no on-chain recipient address
    /// to key push matching off - each member sends under their own per-sender blinded group id
    /// (see GroupCipher's protocol notes), so this is matched against `blinded_group_id` /
    /// `WatchedGroupIdPartition` instead of `watched_address` / `WatchedAddressPartition`.
    GroupMessage,
    /// A `gctl` admin control message (add/remove member, epoch rotation) - matched by sender
    /// address exactly like `SelfStash`/`Contextual`. When the sender (admin) isn't yet
    /// registered as watched by anyone (a brand-new member has no reason to be watching an
    /// admin they've never interacted with before), the push registry fans this out to every
    /// registered device instead of silently dropping it - each device attempts its own ECIES
    /// decrypt and only the real target succeeds.
    GroupControl,
}

#[derive(Debug, Clone)]
pub struct PushEvent {
    pub kind: PushEventKind,
    pub watched_address: AddressPayload,
    pub sender: AddressPayload,
    pub receiver: AddressPayload,
    pub alias: Option<String>,
    pub tx_id: [u8; 32],
    pub amount: Option<u64>,
    pub payload: Option<String>,
    pub timestamp: u64,
    pub daa_score: u64,
    /// Only set for `GroupMessage` events - the sender's per-member blinded group id.
    pub blinded_group_id: Option<[u8; 32]>,
}

pub fn parse_self_stash_alias(raw: &[u8]) -> Option<String> {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    if end == 0 {
        return None;
    }
    let alias = std::str::from_utf8(&raw[..end]).ok()?.trim();
    if alias.is_empty() {
        return None;
    }
    Some(alias.to_owned())
}

#[cfg(test)]
mod tests {
    use super::parse_self_stash_alias;

    #[test]
    fn parses_plain_alias() {
        assert_eq!(
            parse_self_stash_alias(b"alias123"),
            Some("alias123".to_string())
        );
    }

    #[test]
    fn parses_zero_padded_alias() {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(b"alias123");
        assert_eq!(parse_self_stash_alias(&bytes), Some("alias123".to_string()));
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(
            parse_self_stash_alias(b"  alias123  "),
            Some("alias123".to_string())
        );
    }

    #[test]
    fn rejects_empty_alias() {
        assert_eq!(parse_self_stash_alias(b""), None);
        assert_eq!(parse_self_stash_alias(b"   "), None);
        assert_eq!(parse_self_stash_alias(&[0u8; 8]), None);
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert_eq!(parse_self_stash_alias(&[0xFF, 0xFE]), None);
    }
}
