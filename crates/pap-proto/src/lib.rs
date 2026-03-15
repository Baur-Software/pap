pub mod envelope;
pub mod error;
pub mod message;

pub use envelope::Envelope;
pub use error::ProtoError;
pub use message::ProtocolMessage;

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use pap_core::session::CapabilityToken;
    use rand::rngs::OsRng;

    #[test]
    fn message_serialization_roundtrip() {
        let messages = vec![
            ProtocolMessage::TokenAccepted {
                session_id: "sess-1".into(),
                receiver_session_did: "did:key:zReceiver".into(),
            },
            ProtocolMessage::TokenRejected {
                reason: "invalid scope".into(),
            },
            ProtocolMessage::SessionDidExchange {
                initiator_session_did: "did:key:zInitiator".into(),
            },
            ProtocolMessage::SessionDidAck,
            ProtocolMessage::DisclosureOffer {
                disclosures: vec![serde_json::json!({"key": "schema:name", "value": "Alice"})],
            },
            ProtocolMessage::DisclosureAccepted,
            ProtocolMessage::ExecutionResult {
                result: serde_json::json!({"@type": "Flight", "status": "confirmed"}),
            },
            ProtocolMessage::SessionClose {
                session_id: "sess-1".into(),
            },
            ProtocolMessage::SessionClosed,
            ProtocolMessage::Error {
                code: "E001".into(),
                message: "something went wrong".into(),
            },
        ];

        for msg in messages {
            let json = serde_json::to_string(&msg).unwrap();
            let restored: ProtocolMessage = serde_json::from_str(&json).unwrap();
            assert_eq!(msg.message_type(), restored.message_type());
        }
    }

    #[test]
    fn envelope_unsigned_roundtrip() {
        let env = Envelope::new(
            "session-42",
            "did:key:zSender",
            "did:key:zRecipient",
            0,
            ProtocolMessage::SessionDidAck,
        );

        let bytes = env.to_bytes().unwrap();
        let restored = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(env.session_id, restored.session_id);
        assert_eq!(env.sender, restored.sender);
        assert_eq!(env.sequence, restored.sequence);
        assert!(restored.signature.is_none());
    }

    #[test]
    fn envelope_sign_verify() {
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();

        let mut env = Envelope::new(
            "session-42",
            "did:key:zSender",
            "did:key:zRecipient",
            1,
            ProtocolMessage::DisclosureAccepted,
        );

        env.sign(&key);
        assert!(env.signature.is_some());
        env.verify(&vk).unwrap();
    }

    #[test]
    fn envelope_wrong_key_fails() {
        let key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);

        let mut env = Envelope::new(
            "session-42",
            "did:key:zSender",
            "did:key:zRecipient",
            2,
            ProtocolMessage::SessionClosed,
        );

        env.sign(&key);
        let result = env.verify(&wrong_key.verifying_key());
        assert!(result.is_err());
    }

    #[test]
    fn envelope_tampered_payload_fails() {
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();

        let mut env = Envelope::new(
            "session-42",
            "did:key:zSender",
            "did:key:zRecipient",
            3,
            ProtocolMessage::ExecutionResult {
                result: serde_json::json!({"price": 100}),
            },
        );

        env.sign(&key);

        // Tamper with the payload
        env.payload = ProtocolMessage::ExecutionResult {
            result: serde_json::json!({"price": 999}),
        };

        let result = env.verify(&vk);
        assert!(result.is_err());
    }

    #[test]
    fn envelope_sequence_preserved() {
        for seq in [0, 1, 42, u64::MAX] {
            let env = Envelope::new("s", "a", "b", seq, ProtocolMessage::SessionClosed);
            let bytes = env.to_bytes().unwrap();
            let restored = Envelope::from_bytes(&bytes).unwrap();
            assert_eq!(restored.sequence, seq);
        }
    }

    #[test]
    fn message_type_names() {
        assert_eq!(
            ProtocolMessage::TokenPresentation {
                token: dummy_token()
            }
            .message_type(),
            "TokenPresentation"
        );
        assert_eq!(
            ProtocolMessage::SessionDidAck.message_type(),
            "SessionDidAck"
        );
        assert_eq!(
            ProtocolMessage::SessionClosed.message_type(),
            "SessionClosed"
        );
    }

    fn dummy_token() -> CapabilityToken {
        use chrono::{Duration, Utc};
        CapabilityToken::mint(
            "did:key:zTarget".into(),
            "schema:SearchAction".into(),
            "did:key:zIssuer".into(),
            Utc::now() + Duration::hours(1),
        )
    }
}
