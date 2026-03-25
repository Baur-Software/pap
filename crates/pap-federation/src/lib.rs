pub mod error;
pub mod notary;
pub mod peer;
pub mod registry;
pub mod resolve;
pub mod sync;

#[cfg(feature = "native")]
pub mod server;
#[cfg(feature = "native")]
pub mod tls;

#[cfg(feature = "wasm")]
pub mod web_client;

pub use error::FederationError;
pub use notary::NotarySet;
pub use peer::{NodeIdentityResponse, RegistryPeer};
pub use registry::FederatedRegistry;
pub use resolve::{PapTransport, PapUrl};
pub use sync::FederationMessage;

#[cfg(feature = "native")]
pub use server::FederationServer;
#[cfg(feature = "native")]
pub use sync::FederationClient;
#[cfg(feature = "native")]
pub use tls::{
    build_pinned_client, build_pinned_tls_config, build_tofu_client, cert_fingerprint,
    generate_node_identity, NodeTlsIdentity,
};

#[cfg(feature = "wasm")]
pub use web_client::FetchFederationClient;

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
        let results =
            registry.query_local_satisfiable("schema:SearchAction", &["schema:Person.name".into()]);
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

    // --- Registry: remove_by_hash ---

    #[test]
    fn remove_by_hash_returns_true_when_found() {
        let mut registry = FederatedRegistry::new();
        let ad = make_signed_ad("Agent", "schema:SearchAction");
        let hash = ad.hash();
        registry.register_local(ad).unwrap();
        assert_eq!(registry.len(), 1);

        assert!(registry.remove_by_hash(&hash));
        assert_eq!(registry.len(), 0);
        assert!(registry.is_empty());
    }

    #[test]
    fn remove_by_hash_returns_false_when_not_found() {
        let mut registry = FederatedRegistry::new();
        assert!(!registry.remove_by_hash("nonexistent_hash"));
    }

    #[test]
    fn remove_by_hash_allows_re_registration() {
        let mut registry = FederatedRegistry::new();
        let ad = make_signed_ad("Agent", "schema:SearchAction");
        let ad_clone = ad.clone();
        let hash = ad.hash();

        registry.register_local(ad).unwrap();
        registry.remove_by_hash(&hash);

        // Should be able to register the same ad again after removal
        assert!(registry.register_local(ad_clone).is_ok());
        assert_eq!(registry.len(), 1);
    }

    // --- Registry: remove_peer ---

    #[test]
    fn remove_peer_by_did() {
        let mut registry = FederatedRegistry::new();
        registry.add_peer(RegistryPeer::new("did:key:zPeer1", "http://peer1:8080"));
        registry.add_peer(RegistryPeer::new("did:key:zPeer2", "http://peer2:8080"));
        assert_eq!(registry.peers().len(), 2);

        assert!(registry.remove_peer("did:key:zPeer1"));
        assert_eq!(registry.peers().len(), 1);
        assert_eq!(registry.peers()[0].did, "did:key:zPeer2");
    }

    #[test]
    fn remove_peer_returns_false_when_not_found() {
        let mut registry = FederatedRegistry::new();
        registry.add_peer(RegistryPeer::new("did:key:zPeer1", "http://peer1:8080"));
        assert!(!registry.remove_peer("did:key:zNonexistent"));
        assert_eq!(registry.peers().len(), 1);
    }

    // --- Registry: all_advertisements ---

    #[test]
    fn all_advertisements_returns_complete_list() {
        let mut registry = FederatedRegistry::new();
        let ad1 = make_signed_ad("Agent A", "schema:SearchAction");
        let ad2 = make_signed_ad("Agent B", "schema:BookAction");

        registry.register_local(ad1).unwrap();
        registry.register_local(ad2).unwrap();

        let all = registry.all_advertisements();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn all_advertisements_empty_registry() {
        let registry = FederatedRegistry::new();
        assert!(registry.all_advertisements().is_empty());
    }

    // --- Registry: verify_advertisement ---

    #[test]
    fn verify_advertisement_valid_signature() {
        let registry = FederatedRegistry::new();
        let ad = make_signed_ad("Agent", "schema:SearchAction");
        assert!(registry.verify_advertisement(&ad));
    }

    #[test]
    fn verify_advertisement_unsigned() {
        let registry = FederatedRegistry::new();
        let ad = AgentAdvertisement::new(
            "Agent",
            "Corp",
            "did:key:zunsigned",
            vec!["schema:SearchAction".into()],
            vec![],
            vec![],
            vec![],
        );
        assert!(!registry.verify_advertisement(&ad));
    }

    #[test]
    fn verify_advertisement_wrong_did() {
        let registry = FederatedRegistry::new();
        // Sign with one key, but set signed_by to a different DID
        let key = SigningKey::generate(&mut OsRng);
        let other_key = SigningKey::generate(&mut OsRng);
        let other_did = pap_did::PrincipalKeypair::from_bytes(&other_key.to_bytes())
            .unwrap()
            .did();

        let mut ad = AgentAdvertisement::new(
            "Agent",
            "Corp",
            &other_did,
            vec!["schema:SearchAction".into()],
            vec![],
            vec![],
            vec![],
        );
        ad.sign(&key); // sign with wrong key
        assert!(!registry.verify_advertisement(&ad));
    }

    // --- Registry: Default ---

    #[test]
    fn federated_registry_default() {
        let registry = FederatedRegistry::default();
        assert!(registry.is_empty());
        assert!(registry.peers().is_empty());
    }

    // --- Registry: query returns empty for unknown action ---

    #[test]
    fn query_local_no_matches() {
        let mut registry = FederatedRegistry::new();
        let ad = make_signed_ad("Agent", "schema:SearchAction");
        registry.register_local(ad).unwrap();

        let results = registry.query_local("schema:BookAction");
        assert!(results.is_empty());
    }

    // --- FederationMessage: revocation variants serialization ---

    #[test]
    fn revocation_message_serialization() {
        use pap_core::recovery::RevocationProof;

        let proof = RevocationProof {
            old_principal_did: "did:key:zOld".into(),
            new_principal_did: "did:key:zNew".into(),
            recovery_proof_hash: "hash123".into(),
            revoked_at: chrono::Utc::now(),
            signature: None,
        };

        let msg = FederationMessage::RevocationBroadcast {
            revocation: Box::new(proof),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let restored: FederationMessage = serde_json::from_str(&json).unwrap();
        match restored {
            FederationMessage::RevocationBroadcast { revocation } => {
                assert_eq!(revocation.old_principal_did, "did:key:zOld");
            }
            _ => panic!("wrong variant"),
        }

        let ack = FederationMessage::RevocationAck {
            old_principal_did: "did:key:zOld".into(),
            accepted: true,
        };
        let json = serde_json::to_string(&ack).unwrap();
        let restored: FederationMessage = serde_json::from_str(&json).unwrap();
        match restored {
            FederationMessage::RevocationAck {
                old_principal_did,
                accepted,
            } => {
                assert_eq!(old_principal_did, "did:key:zOld");
                assert!(accepted);
            }
            _ => panic!("wrong variant"),
        }
    }

    // --- FederationClient: with_client constructor ---

    #[cfg(feature = "native")]
    #[test]
    fn federation_client_with_client() {
        let client = reqwest::Client::new();
        let _fc = FederationClient::with_client(client);
    }

    #[cfg(feature = "native")]
    #[test]
    fn federation_client_default() {
        let _fc = FederationClient::default();
    }

    #[cfg(feature = "native")]
    #[test]
    fn federation_client_pinned_rejects_empty_fingerprints() {
        let peers = vec![RegistryPeer::new("did:key:z1", "http://p:8080")];
        // Peers have no fingerprints
        let result = FederationClient::pinned(&peers);
        assert!(result.is_err());
    }
}
