use deserializer::parse_sealed_operation;

pub mod deserializer;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Payment {
    pub r#type: String,
    pub amount: u64,
    pub message: String,
    pub timestamp: String,
    pub version: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Handshake {
    pub alias: String,
    pub timestamp: String,
    pub conversation_id: String,
    pub version: u32,
    pub recipient_address: String,
    pub send_to_recipient: bool,
    pub is_response: Option<bool>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Message {
    pub content: String,
}

#[derive(Debug, PartialEq, Eq, Clone)]
/**
 * ContextualMessage is a message that is sent only once handshake is done.
 */
pub struct ContextualMessage {
    pub alias: String,
    pub content: String,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SealedHandshake {
    pub alias: String,
    pub timestamp: String,
    pub conversation_id: String,
    pub version: u32,
    pub recipient_address: String,
    pub send_to_recipient: bool,
    pub is_response: Option<bool>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SealedMessage {
    pub alias: String,
    pub sealed_hex: String,
}

#[derive(Debug, PartialEq, Eq, Clone)]
/**
 * SealedContextualMessage is a message that is sent only once handshake is done.
 */
pub struct SealedContextualMessageV1<'a> {
    pub alias: &'a [u8],
    pub sealed_hex: &'a [u8],
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SealedPaymentV1<'a> {
    pub sealed_hex: &'a [u8],
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SealedHandshakeV2<'a> {
    pub sealed_hex: &'a [u8],
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct SealedMessageOrSealedHandshakeVNone<'a> {
    pub sealed_hex: &'a [u8],
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct SealedSelfStashV1<'a> {
    pub key: Option<&'a [u8]>,
    pub sealed_hex: &'a [u8],
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct SealedGroupMessageV1<'a> {
    pub blinded_group_id: &'a [u8],
    pub epoch: &'a [u8],
    pub sender_id: &'a [u8],
    pub sender_pub: &'a [u8],
    pub msg_id: &'a [u8],
    pub ciphertext: &'a [u8],
    pub signature: &'a [u8],
    /// The full `blinded_group_id:epoch:sender_id:sender_pub:msg_id:ciphertext:signature`
    /// span, kept verbatim for storage/retrieval purposes.
    pub sealed_hex: &'a [u8],
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct SealedGroupInviteV1<'a> {
    pub invite_tag: &'a [u8],
    pub encrypted_payload: &'a [u8],
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct SealedGroupControlV1<'a> {
    pub sealed_hex: &'a [u8],
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SealedOperation<'a> {
    /**
     * "ciph_msg:{{SealedMessage_as_json_string_as_hex}}"
     */
    SealedMessageOrSealedHandshakeVNone(SealedMessageOrSealedHandshakeVNone<'a>),
    /**
     * "ciph_msg:1:comm:{alias_as_string}:{{SealedContextualMessage_as_hex}}"
     */
    ContextualMessageV1(SealedContextualMessageV1<'a>),
    /**
     * "ciph_msg:1:payment:{{SealedPayment_as_json_string_as_hex}}"
     */
    PaymentV1(SealedPaymentV1<'a>),
    /**
     * "ciph_msg:1:self_stash:{{SealedSelfStash_as_json_string_as_hex}}"
     */
    SelfStashV1(SealedSelfStashV1<'a>),

    // V2
    /**
     * "ciph_msg:1:handshake:{{SealedHandshake_as_hex}}"
     */
    SealedHandshakeV2(SealedHandshakeV2<'a>),

    // Group chat
    /**
     * "ciph_msg:1:gcomm:{blinded_group_id}:{epoch}:{sender_id}:{sender_pub}:{msg_id}:{ciphertext}:{signature}"
     */
    GroupMessageV1(SealedGroupMessageV1<'a>),
    /**
     * "ciph_msg:1:ginv:{invite_tag}:{encrypted_payload}"
     */
    GroupInviteV1(SealedGroupInviteV1<'a>),
    /**
     * "ciph_msg:1:gctl:{hex_encrypted_bytes}"
     */
    GroupControlV1(SealedGroupControlV1<'a>),
}

impl<'a> SealedOperation<'a> {
    pub fn from_payload(payload: &'a [u8]) -> Option<SealedOperation<'a>> {
        parse_sealed_operation(payload)
    }

    pub fn op_type_name(&self) -> &'static str {
        match self {
            SealedOperation::SealedMessageOrSealedHandshakeVNone(_) => "HandshakeVNone",
            SealedOperation::ContextualMessageV1(_) => "ContextualMessageV1",
            SealedOperation::PaymentV1(_) => "PaymentV1",
            SealedOperation::SelfStashV1(_) => "SelfStashV1",
            SealedOperation::SealedHandshakeV2(_) => "HandshakeV2",
            SealedOperation::GroupMessageV1(_) => "GroupMessageV1",
            SealedOperation::GroupInviteV1(_) => "GroupInviteV1",
            SealedOperation::GroupControlV1(_) => "GroupControlV1",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_sealed_payment() {
        let payload = b"ciph_msg:1:payment:abc123";
        let result = parse_sealed_operation(payload);
        assert_eq!(
            result,
            Some(SealedOperation::PaymentV1(SealedPaymentV1 {
                sealed_hex: b"abc123",
            }))
        );
    }

    #[test]
    fn test_deserialize_sealed_contextual_message() {
        let payload = b"ciph_msg:1:comm:alias123:abc123";
        let result = parse_sealed_operation(payload);
        assert_eq!(
            result,
            Some(SealedOperation::ContextualMessageV1(
                SealedContextualMessageV1 {
                    alias: b"alias123",
                    sealed_hex: b"abc123",
                }
            ))
        );
    }

    #[test]
    fn test_deserialize_sealed_message_or_sealed_handshake() {
        let payload = b"ciph_msg:abc123";
        let result = parse_sealed_operation(payload);
        assert_eq!(
            result,
            Some(SealedOperation::SealedMessageOrSealedHandshakeVNone(
                SealedMessageOrSealedHandshakeVNone {
                    sealed_hex: b"abc123",
                }
            ))
        );
    }

    #[test]
    fn test_deserialize_sealed_self_stash_with_key() {
        let payload = b"ciph_msg:1:self_stash:key:abc123";
        let result = parse_sealed_operation(payload);
        assert_eq!(
            result,
            Some(SealedOperation::SelfStashV1(SealedSelfStashV1 {
                key: Some(b"key"),
                sealed_hex: b"abc123",
            }))
        );
    }

    #[test]
    fn test_deserialize_sealed_self_stash_without_key() {
        let payload = b"ciph_msg:1:self_stash:abc123";
        let result = parse_sealed_operation(payload);
        assert_eq!(
            result,
            Some(SealedOperation::SelfStashV1(SealedSelfStashV1 {
                key: None,
                sealed_hex: b"abc123",
            }))
        )
    }

    #[test]
    fn test_deserialize_sealed_handshake_v2() {
        let payload = b"ciph_msg:1:handshake:abc123";
        let result = parse_sealed_operation(payload);
        assert_eq!(
            result,
            Some(SealedOperation::SealedHandshakeV2(SealedHandshakeV2 {
                sealed_hex: b"abc123",
            }))
        );
    }

    #[test]
    fn test_deserialize_invalid_payload() {
        let payload = b"invalid_payload";
        let result = parse_sealed_operation(payload);
        assert_eq!(result, None);
    }

    #[test]
    fn test_deserialize_sealed_group_message() {
        let payload = b"ciph_msg:1:gcomm:aabb:42:ccdd:eeff:0011:2233:4455";
        let result = parse_sealed_operation(payload);
        assert_eq!(
            result,
            Some(SealedOperation::GroupMessageV1(SealedGroupMessageV1 {
                blinded_group_id: b"aabb",
                epoch: b"42",
                sender_id: b"ccdd",
                sender_pub: b"eeff",
                msg_id: b"0011",
                ciphertext: b"2233",
                signature: b"4455",
                sealed_hex: b"aabb:42:ccdd:eeff:0011:2233:4455",
            }))
        );
    }

    #[test]
    fn test_deserialize_sealed_group_message_missing_fields() {
        let payload = b"ciph_msg:1:gcomm:aabb:42:ccdd";
        let result = parse_sealed_operation(payload);
        assert_eq!(result, None);
    }

    #[test]
    fn test_deserialize_sealed_group_invite() {
        let payload = b"ciph_msg:1:ginv:aabb:ccddeeff";
        let result = parse_sealed_operation(payload);
        assert_eq!(
            result,
            Some(SealedOperation::GroupInviteV1(SealedGroupInviteV1 {
                invite_tag: b"aabb",
                encrypted_payload: b"ccddeeff",
            }))
        );
    }

    #[test]
    fn test_deserialize_sealed_group_control() {
        let payload = b"ciph_msg:1:gctl:abc123";
        let result = parse_sealed_operation(payload);
        assert_eq!(
            result,
            Some(SealedOperation::GroupControlV1(SealedGroupControlV1 {
                sealed_hex: b"abc123",
            }))
        );
    }
}
