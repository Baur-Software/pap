pub mod client;
pub mod endpoint;
pub mod error;
pub mod group_handler;
pub mod handler;
pub mod ohttp;
pub mod ohttp_client;
pub mod remote;
pub mod server;
pub mod ws_client;
pub mod ws_remote;
pub mod ws_server;

pub(crate) mod ws_common;

pub use client::AgentClient;
pub use endpoint::EndpointRegistry;
pub use error::TransportError;
pub use group_handler::GroupChatRoom;
pub use handler::AgentHandler;
pub use ohttp::{
    OhttpConfig, OhttpDecryptor, OhttpEncryptor, OhttpServerDecryptor, OhttpServerEncryptor,
};
pub use ohttp_client::OhttpClient;
pub use remote::RemoteAgentHandler;
pub use server::AgentServer;
pub use ws_client::WsAgentClient;
pub use ws_remote::WsRemoteAgentHandler;
pub use ws_server::WsAgentServer;

#[cfg(test)]
mod tests {
    use super::*;
    use pap_proto::ProtocolMessage;

    #[test]
    fn endpoint_registry_register_and_resolve() {
        let mut registry = EndpointRegistry::new();
        registry.register("did:key:zABC", "http://127.0.0.1:8080");
        registry.register("did:key:zDEF", "http://127.0.0.1:8081");

        assert_eq!(
            registry.resolve("did:key:zABC"),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(
            registry.resolve("did:key:zDEF"),
            Some("http://127.0.0.1:8081")
        );
        assert_eq!(registry.resolve("did:key:zMissing"), None);
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn protocol_message_json_type_tag() {
        // Verify the serde tag shows up correctly for HTTP transport
        let msg = ProtocolMessage::TokenAccepted {
            session_id: "s1".into(),
            receiver_session_did: "did:key:z123".into(),
            attestation: None,
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "TokenAccepted");
    }

    #[test]
    fn client_construction() {
        // Just verify it doesn't panic
        let _client = AgentClient::new("http://127.0.0.1:9000");
        let _client = AgentClient::new("http://127.0.0.1:9000/");
    }
}
