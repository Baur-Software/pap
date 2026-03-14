pub mod error;
pub mod peer;
pub mod registry;
pub mod server;
pub mod sync;

pub use error::FederationError;
pub use peer::RegistryPeer;
pub use registry::FederatedRegistry;
pub use server::FederationServer;
pub use sync::{FederationClient, FederationMessage};

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use pap_marketplace::AgentAdvertisement;
    use rand::rngs::OsRng;

    fn make_signed_ad(name: &str, action: &str) -> AgentAdvertisement {
        let key = SigningKey::generate(&mut OsRng);
        let did = pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
            .unwrap()
            .did();

        let mut ad = AgentAdvertisement::new(
            name,
            "TestCorp",
            &did,
            vec![action.into()],
            vec![],
            vec![],
            vec!["schema:SearchResult".into()],
        );
        ad.sign(&key);
        ad
    }

    #[test]
    fn federated_registry_register_and_query() {
        let mut registry = FederatedRegistry::new();

        let ad = make_signed_ad("Search Agent", "schema:SearchAction");
        registry.register_local(ad).unwrap();

        let results = registry.query_local("schema:SearchAction");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Search Agent");
    }

    #[test]
    fn federated_registry_dedup() {
        let mut registry = FederatedRegistry::new();

        let ad = make_signed_ad("Search Agent", "schema:SearchAction");
        let ad_clone = ad.clone();

        registry.register_local(ad).unwrap();
        // Same ad again should be rejected as duplicate
        let result = registry.register_local(ad_clone);
        assert!(result.is_err());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn merge_remote_dedup() {
        let mut registry = FederatedRegistry::new();

        let ad1 = make_signed_ad("Agent A", "schema:SearchAction");
        let ad2 = make_signed_ad("Agent B", "schema:SearchAction");
        let ad1_clone = ad1.clone();

        registry.register_local(ad1).unwrap();

        // Merge: ad1_clone is a dup, ad2 is new
        let merged = registry.merge_remote(vec![ad1_clone, ad2]);
        assert_eq!(merged, 1);
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn merge_remote_rejects_unsigned() {
        let mut registry = FederatedRegistry::new();

        let unsigned = AgentAdvertisement::new(
            "Unsigned Agent",
            "Corp",
            "did:key:zunsigned",
            vec!["schema:SearchAction".into()],
            vec![],
            vec![],
            vec![],
        );

        let merged = registry.merge_remote(vec![unsigned]);
        assert_eq!(merged, 0);
        assert!(registry.is_empty());
    }

    #[test]
    fn peer_management() {
        let mut registry = FederatedRegistry::new();
        assert!(registry.peers().is_empty());

        registry.add_peer(RegistryPeer::new("did:key:zPeer1", "http://peer1:8080"));
        registry.add_peer(RegistryPeer::new("did:key:zPeer2", "http://peer2:8080"));
        assert_eq!(registry.peers().len(), 2);
    }

    #[test]
    fn query_satisfiable_through_federation() {
        let mut registry = FederatedRegistry::new();

        let open_ad = make_signed_ad("Open Agent", "schema:SearchAction");

        let key = SigningKey::generate(&mut OsRng);
        let did = pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
            .unwrap()
            .did();
        let mut restricted_ad = AgentAdvertisement::new(
            "Restricted Agent",
            "Corp",
            &did,
            vec!["schema:SearchAction".into()],
            vec![],
            vec!["schema:Person.name".into()],
            vec!["schema:SearchResult".into()],
        );
        restricted_ad.sign(&key);

        registry.register_local(open_ad).unwrap();
        registry.register_local(restricted_ad).unwrap();

        // Zero-disclosure query should only find the open agent
        let results = registry.query_local_satisfiable("schema:SearchAction", &[]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Open Agent");

        // With name available, both match
        let results = registry.query_local_satisfiable(
            "schema:SearchAction",
            &["schema:Person.name".into()],
        );
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn federation_message_serialization() {
        let ad = make_signed_ad("Test", "schema:SearchAction");

        let messages = vec![
            FederationMessage::QueryByAction {
                action: "schema:SearchAction".into(),
            },
            FederationMessage::QueryResponse {
                advertisements: vec![ad.clone()],
            },
            FederationMessage::Announce {
                advertisement: Box::new(ad),
            },
            FederationMessage::AnnounceAck {
                hash: "abc123".into(),
                accepted: true,
            },
            FederationMessage::PeerList,
            FederationMessage::PeerListResponse {
                peers: vec![RegistryPeer::new("did:key:z1", "http://example.com")],
            },
        ];

        for msg in messages {
            let json = serde_json::to_string(&msg).unwrap();
            let _restored: FederationMessage = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn peer_serialization_roundtrip() {
        let mut peer = RegistryPeer::new("did:key:zPeer", "http://localhost:8080");
        peer.last_sync = Some(chrono::Utc::now());

        let json = serde_json::to_string(&peer).unwrap();
        let restored: RegistryPeer = serde_json::from_str(&json).unwrap();
        assert_eq!(peer.did, restored.did);
        assert_eq!(peer.endpoint, restored.endpoint);
    }
}
