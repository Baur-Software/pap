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
pub use peer::{
    DomainVerification, NodeIdentityResponse, OperationalHistory, PeerStatus, PeerTrustSignals,
    PeerVouch, RegistryPeer,
};
pub use registry::{FederatedRegistry, PeerRegistrationPolicy};
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
    use pap_test_utils::{did_from_key, make_keypair};
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
        ad.sign(&key).unwrap();
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
        restricted_ad.sign(&key).unwrap();

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
                cursor: None,
                page_size: 100,
            },
            FederationMessage::QueryResponse {
                advertisements: vec![ad.clone()],
                next_cursor: None,
                has_more: false,
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
        ad.sign(&key).unwrap(); // sign with wrong key
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
            algorithm: pap_did::SignatureAlgorithm::default(),
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

    // =========================================================================
    // Vouch-based peer registration tests
    // =========================================================================

    /// Create a registry pre-populated with `count` established active peers.
    /// Returns (registry, vec of (key, did) pairs for the seeded peers).
    fn registry_with_established_peers(
        count: usize,
        age_days: i64,
    ) -> (FederatedRegistry, Vec<(SigningKey, String)>) {
        let mut registry = FederatedRegistry::new();
        let now = chrono::Utc::now();
        let registered_at = (now - chrono::Duration::days(age_days)).to_rfc3339();

        let mut peers = Vec::new();
        for i in 0..count {
            let key = make_keypair();
            let did = did_from_key(&key);
            let mut peer = RegistryPeer::new(&did, format!("https://peer{i}.example.com"));
            peer.status = PeerStatus::Active;
            peer.registered_at = Some(registered_at.clone());
            registry.add_peer(peer);
            peers.push((key, did));
        }
        (registry, peers)
    }

    /// Create `count` vouches for `vouchee_did` from the given established peers.
    fn make_vouches(
        peers: &[(SigningKey, String)],
        vouchee_did: &str,
        count: usize,
    ) -> Vec<PeerVouch> {
        peers
            .iter()
            .take(count)
            .map(|(key, did)| {
                PeerVouch::sign(
                    did,
                    vouchee_did,
                    "2026-03-15T12:00:00Z",
                    "direct-interaction",
                    key,
                )
            })
            .collect()
    }

    #[test]
    fn register_peer_with_vouches_success() {
        let (mut registry, established) = registry_with_established_peers(3, 100);
        let new_key = make_keypair();
        let new_did = did_from_key(&new_key);
        let new_peer = RegistryPeer::new(&new_did, "https://new.example.com");

        let vouches = make_vouches(&established, &new_did, 3);
        let now = chrono::Utc::now();

        let result = registry.register_peer_with_vouches(new_peer, vouches, now);
        assert!(result.is_ok());

        // New peer should be added as probationary
        assert_eq!(registry.peers().len(), 4);
        let registered = registry.peers().iter().find(|p| p.did == new_did).unwrap();
        assert_eq!(registered.status, PeerStatus::Probationary);
        assert!(registered.registered_at.is_some());
        assert!(registered.is_probationary());
    }

    #[test]
    fn register_peer_rejects_insufficient_vouches() {
        let (mut registry, established) = registry_with_established_peers(3, 100);
        let new_key = make_keypair();
        let new_did = did_from_key(&new_key);
        let new_peer = RegistryPeer::new(&new_did, "https://new.example.com");

        // Only 2 vouches, but policy requires 3
        let vouches = make_vouches(&established, &new_did, 2);
        let now = chrono::Utc::now();

        let result = registry.register_peer_with_vouches(new_peer, vouches, now);
        assert!(result.is_err());
        match result.unwrap_err() {
            FederationError::InsufficientVouches { needed, got } => {
                assert_eq!(needed, 3);
                assert_eq!(got, 2);
            }
            other => panic!("expected InsufficientVouches, got: {other}"),
        }
    }

    #[test]
    fn register_peer_rejects_zero_vouches() {
        let (mut registry, _) = registry_with_established_peers(3, 100);
        let new_key = make_keypair();
        let new_did = did_from_key(&new_key);
        let new_peer = RegistryPeer::new(&new_did, "https://new.example.com");
        let now = chrono::Utc::now();

        let result = registry.register_peer_with_vouches(new_peer, vec![], now);
        assert!(result.is_err());
        match result.unwrap_err() {
            FederationError::InsufficientVouches { needed: 3, got: 0 } => {}
            other => panic!("expected InsufficientVouches, got: {other}"),
        }
    }

    #[test]
    fn register_peer_rejects_invalid_vouch_signature() {
        let (mut registry, established) = registry_with_established_peers(3, 100);
        let new_key = make_keypair();
        let new_did = did_from_key(&new_key);
        let new_peer = RegistryPeer::new(&new_did, "https://new.example.com");

        let mut vouches = make_vouches(&established, &new_did, 3);
        // Tamper with the first vouch's signature
        vouches[0].justification = "tampered".into();

        let now = chrono::Utc::now();
        let result = registry.register_peer_with_vouches(new_peer, vouches, now);
        assert!(result.is_err());
        match result.unwrap_err() {
            FederationError::InvalidVouch(_) => {}
            other => panic!("expected InvalidVouch, got: {other}"),
        }
    }

    #[test]
    fn register_peer_rejects_voucher_not_in_peer_list() {
        let (mut registry, _) = registry_with_established_peers(2, 100);
        let new_key = make_keypair();
        let new_did = did_from_key(&new_key);
        let new_peer = RegistryPeer::new(&new_did, "https://new.example.com");

        // Create vouch from a key that is NOT in the registry
        let outsider_key = make_keypair();
        let outsider_did = did_from_key(&outsider_key);
        let outsider_vouch = PeerVouch::sign(
            &outsider_did,
            &new_did,
            "2026-03-15T12:00:00Z",
            "direct-interaction",
            &outsider_key,
        );

        // 2 valid vouches + 1 outsider
        let mut vouches: Vec<PeerVouch> = registry
            .peers()
            .iter()
            .take(2)
            .map(|_| outsider_vouch.clone())
            .collect();
        vouches.clear();

        // Actually use the outsider vouch as the first of 3
        let established_key1 = make_keypair();
        let established_did1 = did_from_key(&established_key1);
        // The outsider's DID won't be found in registry
        vouches.push(outsider_vouch);
        vouches.push(PeerVouch::sign(
            &established_did1,
            &new_did,
            "2026-03-15T12:00:00Z",
            "direct-interaction",
            &established_key1,
        ));
        vouches.push(PeerVouch::sign(
            &established_did1,
            &new_did,
            "2026-03-15T12:00:00Z",
            "direct-interaction-2",
            &established_key1,
        ));

        let now = chrono::Utc::now();
        let result = registry.register_peer_with_vouches(new_peer, vouches, now);
        assert!(result.is_err());
        match result.unwrap_err() {
            FederationError::VoucherNotFound(did) => {
                assert_eq!(did, outsider_did);
            }
            other => panic!("expected VoucherNotFound, got: {other}"),
        }
    }

    #[test]
    fn register_peer_rejects_voucher_too_young() {
        // Peers are only 30 days old, but policy requires 90 days
        let (mut registry, established) = registry_with_established_peers(3, 30);
        let new_key = make_keypair();
        let new_did = did_from_key(&new_key);
        let new_peer = RegistryPeer::new(&new_did, "https://new.example.com");

        let vouches = make_vouches(&established, &new_did, 3);
        let now = chrono::Utc::now();

        let result = registry.register_peer_with_vouches(new_peer, vouches, now);
        assert!(result.is_err());
        match result.unwrap_err() {
            FederationError::VoucherTooYoung {
                age_days, min_days, ..
            } => {
                assert_eq!(age_days, 30);
                assert_eq!(min_days, 90);
            }
            other => panic!("expected VoucherTooYoung, got: {other}"),
        }
    }

    #[test]
    fn register_peer_rejects_probationary_voucher() {
        let (mut registry, established) = registry_with_established_peers(2, 100);
        let new_key = make_keypair();
        let new_did = did_from_key(&new_key);

        // Add a probationary peer
        let probationary_key = make_keypair();
        let probationary_did = did_from_key(&probationary_key);
        let mut probationary_peer =
            RegistryPeer::new(&probationary_did, "https://probationary.example.com");
        probationary_peer.status = PeerStatus::Probationary;
        probationary_peer.registered_at =
            Some((chrono::Utc::now() - chrono::Duration::days(100)).to_rfc3339());
        registry.add_peer(probationary_peer);

        // Create vouches: 2 from established + 1 from probationary
        let mut vouches = make_vouches(&established, &new_did, 2);
        vouches.push(PeerVouch::sign(
            &probationary_did,
            &new_did,
            "2026-03-15T12:00:00Z",
            "direct-interaction",
            &probationary_key,
        ));

        let new_peer = RegistryPeer::new(&new_did, "https://new.example.com");
        let now = chrono::Utc::now();

        let result = registry.register_peer_with_vouches(new_peer, vouches, now);
        assert!(result.is_err());
        match result.unwrap_err() {
            FederationError::PeerProbationary(did) => {
                assert_eq!(did, probationary_did);
            }
            other => panic!("expected PeerProbationary, got: {other}"),
        }
    }

    #[test]
    fn register_peer_custom_policy() {
        // Create a lenient policy: only 1 vouch, 0 min age
        let policy = PeerRegistrationPolicy {
            min_vouches: 1,
            vouch_budget_per_year: 10,
            min_age_to_vouch_days: 0,
            probation_days: 30,
            require_diverse_paths: false,
            path_diversity_hops: 3,
            max_shared_ancestor_vouchers: 2,
        };
        let mut registry = FederatedRegistry::with_policy(policy);

        // Add one established peer
        let voucher_key = make_keypair();
        let voucher_did = did_from_key(&voucher_key);
        let mut voucher_peer = RegistryPeer::new(&voucher_did, "https://voucher.example.com");
        voucher_peer.status = PeerStatus::Active;
        voucher_peer.registered_at = Some(chrono::Utc::now().to_rfc3339());
        registry.add_peer(voucher_peer);

        // Register with just 1 vouch
        let new_key = make_keypair();
        let new_did = did_from_key(&new_key);
        let new_peer = RegistryPeer::new(&new_did, "https://new.example.com");
        let vouches = vec![PeerVouch::sign(
            &voucher_did,
            &new_did,
            "2026-03-15T12:00:00Z",
            "direct-interaction",
            &voucher_key,
        )];

        let now = chrono::Utc::now();
        let result = registry.register_peer_with_vouches(new_peer, vouches, now);
        assert!(result.is_ok());
        assert_eq!(registry.peers().len(), 2);
    }

    #[test]
    fn add_peer_bypasses_vouch_requirements() {
        // Existing add_peer method should still work without vouches (backward compat)
        let mut registry = FederatedRegistry::new();
        let peer = RegistryPeer::new("did:key:zBootstrap", "https://bootstrap.example.com");
        registry.add_peer(peer);
        assert_eq!(registry.peers().len(), 1);
        // Peer added via add_peer defaults to Active status
        assert_eq!(registry.peers()[0].status, PeerStatus::Active);
    }

    #[test]
    fn peer_registration_policy_default_values() {
        let policy = PeerRegistrationPolicy::default();
        assert_eq!(policy.min_vouches, 3);
        assert_eq!(policy.vouch_budget_per_year, 3);
        assert_eq!(policy.min_age_to_vouch_days, 90);
        assert_eq!(policy.probation_days, 60);
        assert!(policy.require_diverse_paths);
        assert_eq!(policy.path_diversity_hops, 3);
        assert_eq!(policy.max_shared_ancestor_vouchers, 2);
    }

    #[test]
    fn peer_registration_policy_serialization_roundtrip() {
        let policy = PeerRegistrationPolicy {
            min_vouches: 5,
            vouch_budget_per_year: 2,
            min_age_to_vouch_days: 180,
            probation_days: 90,
            require_diverse_paths: false,
            path_diversity_hops: 5,
            max_shared_ancestor_vouchers: 3,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let restored: PeerRegistrationPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.min_vouches, 5);
        assert_eq!(restored.vouch_budget_per_year, 2);
        assert_eq!(restored.min_age_to_vouch_days, 180);
        assert_eq!(restored.probation_days, 90);
        assert!(!restored.require_diverse_paths);
    }

    #[test]
    fn peer_age_uses_registered_at_over_last_sync() {
        // When both registered_at and last_sync exist, registered_at should be used
        let (mut registry, established) = registry_with_established_peers(3, 100);
        let new_key = make_keypair();
        let new_did = did_from_key(&new_key);

        let vouches = make_vouches(&established, &new_did, 3);

        // Set registered_at to 100 days ago but last_sync to yesterday
        // Age should be 100 based on registered_at
        let now = chrono::Utc::now();
        let result = registry.register_peer_with_vouches(
            RegistryPeer::new(&new_did, "https://new.example.com"),
            vouches,
            now,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn register_peer_with_vouches_does_not_modify_existing_peers() {
        let (mut registry, established) = registry_with_established_peers(3, 100);
        let initial_peer_count = registry.peers().len();

        let new_key = make_keypair();
        let new_did = did_from_key(&new_key);
        let new_peer = RegistryPeer::new(&new_did, "https://new.example.com");
        let vouches = make_vouches(&established, &new_did, 3);
        let now = chrono::Utc::now();

        registry
            .register_peer_with_vouches(new_peer, vouches, now)
            .unwrap();

        // Verify existing peers are unchanged
        for i in 0..initial_peer_count {
            assert_eq!(registry.peers()[i].status, PeerStatus::Active);
        }
        // New peer is last and probationary
        assert_eq!(
            registry.peers()[initial_peer_count].status,
            PeerStatus::Probationary
        );
    }

    #[test]
    fn error_display_messages() {
        // Verify the error messages are human-readable
        let err = FederationError::InsufficientVouches { needed: 3, got: 1 };
        assert!(err.to_string().contains("3"));
        assert!(err.to_string().contains("1"));

        let err = FederationError::VoucherTooYoung {
            did: "did:key:z1".into(),
            age_days: 30,
            min_days: 90,
        };
        assert!(err.to_string().contains("30"));
        assert!(err.to_string().contains("90"));

        let err = FederationError::InvalidVouch("bad sig".into());
        assert!(err.to_string().contains("bad sig"));

        let err = FederationError::VoucherNotFound("did:key:z1".into());
        assert!(err.to_string().contains("did:key:z1"));

        let err = FederationError::PeerProbationary("did:key:z1".into());
        assert!(err.to_string().contains("probationary"));
    }

    // =========================================================================
    // Pagination tests
    // =========================================================================

    #[test]
    fn paginated_query_exact_page_size() {
        let mut registry = FederatedRegistry::new();
        for i in 0..3 {
            let ad = make_signed_ad(&format!("Agent {i}"), "schema:SearchAction");
            registry.register_local(ad).unwrap();
        }

        let (ads, next_cursor, has_more) =
            registry.query_local_paginated("schema:SearchAction", None, 3);
        assert_eq!(ads.len(), 3);
        assert!(!has_more);
        assert!(next_cursor.is_none());
    }

    #[test]
    fn paginated_query_multiple_pages() {
        let mut registry = FederatedRegistry::new();
        for i in 0..5 {
            let ad = make_signed_ad(&format!("Agent {i}"), "schema:SearchAction");
            registry.register_local(ad).unwrap();
        }

        // First page
        let (page1, cursor1, has_more1) =
            registry.query_local_paginated("schema:SearchAction", None, 2);
        assert_eq!(page1.len(), 2);
        assert!(has_more1);
        assert!(cursor1.is_some());

        // Second page
        let (page2, cursor2, has_more2) =
            registry.query_local_paginated("schema:SearchAction", cursor1.as_deref(), 2);
        assert_eq!(page2.len(), 2);
        assert!(has_more2);
        assert!(cursor2.is_some());

        // Third page (last)
        let (page3, cursor3, has_more3) =
            registry.query_local_paginated("schema:SearchAction", cursor2.as_deref(), 2);
        assert_eq!(page3.len(), 1);
        assert!(!has_more3);
        assert!(cursor3.is_none());
    }

    #[test]
    fn paginated_query_cursor_resumes_correctly() {
        let mut registry = FederatedRegistry::new();
        for i in 0..4 {
            let ad = make_signed_ad(&format!("Agent {i}"), "schema:SearchAction");
            registry.register_local(ad).unwrap();
        }

        // Get first page
        let (page1, cursor1, _) = registry.query_local_paginated("schema:SearchAction", None, 2);
        assert_eq!(page1.len(), 2);

        // Get second page with cursor
        let (page2, _, _) =
            registry.query_local_paginated("schema:SearchAction", cursor1.as_deref(), 2);
        assert_eq!(page2.len(), 2);

        // Verify no overlap: page1 DIDs and page2 DIDs should be disjoint
        let page1_dids: Vec<&str> = page1.iter().map(|a| a.signed_by.as_str()).collect();
        let page2_dids: Vec<&str> = page2.iter().map(|a| a.signed_by.as_str()).collect();
        for did in &page1_dids {
            assert!(
                !page2_dids.contains(did),
                "overlap detected: {did} in both pages"
            );
        }

        // Verify ordering: all page1 DIDs < all page2 DIDs
        for d1 in &page1_dids {
            for d2 in &page2_dids {
                assert!(d1 < d2, "expected {d1} < {d2}");
            }
        }
    }

    #[test]
    fn paginated_query_empty_result() {
        let registry = FederatedRegistry::new();
        let (ads, next_cursor, has_more) =
            registry.query_local_paginated("schema:SearchAction", None, 10);
        assert!(ads.is_empty());
        assert!(!has_more);
        assert!(next_cursor.is_none());
    }

    #[test]
    fn paginated_query_no_cursor_returns_first_page() {
        let mut registry = FederatedRegistry::new();
        for i in 0..5 {
            let ad = make_signed_ad(&format!("Agent {i}"), "schema:SearchAction");
            registry.register_local(ad).unwrap();
        }

        // Without cursor, should get the first 2 (sorted by DID)
        let (page, _, has_more) = registry.query_local_paginated("schema:SearchAction", None, 2);
        assert_eq!(page.len(), 2);
        assert!(has_more);

        // Verify these are the lexicographically smallest DIDs
        let all_dids: Vec<String> = {
            let mut ads: Vec<&AgentAdvertisement> = registry.query_local("schema:SearchAction");
            ads.sort_by(|a, b| a.signed_by.cmp(&b.signed_by));
            ads.iter().map(|a| a.signed_by.clone()).collect()
        };
        assert_eq!(page[0].signed_by, all_dids[0]);
        assert_eq!(page[1].signed_by, all_dids[1]);
    }

    #[test]
    fn paginated_query_serialization_roundtrip() {
        let ad = make_signed_ad("Test", "schema:SearchAction");

        // QueryByAction with pagination fields
        let msg = FederationMessage::QueryByAction {
            action: "schema:SearchAction".into(),
            cursor: Some("did:key:zCursor".into()),
            page_size: 50,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let restored: FederationMessage = serde_json::from_str(&json).unwrap();
        match restored {
            FederationMessage::QueryByAction {
                action,
                cursor,
                page_size,
            } => {
                assert_eq!(action, "schema:SearchAction");
                assert_eq!(cursor, Some("did:key:zCursor".into()));
                assert_eq!(page_size, 50);
            }
            _ => panic!("wrong variant"),
        }

        // QueryResponse with pagination fields
        let msg = FederationMessage::QueryResponse {
            advertisements: vec![ad],
            next_cursor: Some("did:key:zNext".into()),
            has_more: true,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let restored: FederationMessage = serde_json::from_str(&json).unwrap();
        match restored {
            FederationMessage::QueryResponse {
                advertisements,
                next_cursor,
                has_more,
            } => {
                assert_eq!(advertisements.len(), 1);
                assert_eq!(next_cursor, Some("did:key:zNext".into()));
                assert!(has_more);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn paginated_query_backward_compat_deserialize() {
        // Old-format QueryByAction (no cursor/page_size) should deserialize
        let json = r#"{"type":"QueryByAction","action":"schema:SearchAction"}"#;
        let msg: FederationMessage = serde_json::from_str(json).unwrap();
        match msg {
            FederationMessage::QueryByAction {
                action,
                cursor,
                page_size,
            } => {
                assert_eq!(action, "schema:SearchAction");
                assert!(cursor.is_none());
                assert_eq!(page_size, 100); // default
            }
            _ => panic!("wrong variant"),
        }

        // Old-format QueryResponse (no next_cursor/has_more) should deserialize
        let json = r#"{"type":"QueryResponse","advertisements":[]}"#;
        let msg: FederationMessage = serde_json::from_str(json).unwrap();
        match msg {
            FederationMessage::QueryResponse {
                advertisements,
                next_cursor,
                has_more,
            } => {
                assert!(advertisements.is_empty());
                assert!(next_cursor.is_none());
                assert!(!has_more); // default
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── Version-aware query tests ───────────────────────────────────────────

    fn make_versioned_ad(name: &str, version: &str, key: &SigningKey) -> AgentAdvertisement {
        let did = pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
            .unwrap()
            .did();
        let mut ad = AgentAdvertisement::new(
            name,
            "TestCorp",
            &did,
            vec!["schema:SearchAction".into()],
            vec![],
            vec![],
            vec!["schema:SearchResult".into()],
        )
        .with_version(version);
        ad.sign(key).unwrap();
        ad
    }

    #[test]
    fn query_local_versioned_filters_correctly() {
        let mut registry = FederatedRegistry::new();
        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);
        registry
            .register_local(make_versioned_ad("Agent v1", "1.0.0", &key_a))
            .unwrap();
        registry
            .register_local(make_versioned_ad("Agent v2", "2.0.0", &key_b))
            .unwrap();

        let results = registry.query_local_versioned("schema:SearchAction", "1.0.0");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Agent v1");

        let results = registry.query_local_versioned("schema:SearchAction", "9.9.9");
        assert!(results.is_empty());
    }

    #[test]
    fn query_local_latest_returns_highest() {
        let mut registry = FederatedRegistry::new();
        // Same provider key → same DID
        let key = SigningKey::generate(&mut OsRng);
        registry
            .register_local(make_versioned_ad("Agent v1", "0.1.0", &key))
            .unwrap();
        registry
            .register_local(make_versioned_ad("Agent v2", "0.2.0", &key))
            .unwrap();

        let results = registry.query_local_latest("schema:SearchAction");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].version, "0.2.0");
    }

    // =========================================================================
    // require_diverse_paths tests
    // =========================================================================

    /// Coordinated cluster attack: all three vouchers share a single intermediate
    /// ancestor (admin). Registration must be rejected with NonDiversePaths.
    ///
    /// Graph:  genesis --vouches--> admin --vouches--> peer_a, peer_b, peer_c
    ///         peer_a, peer_b, peer_c --vouch--> candidate
    #[test]
    fn coordinated_cluster_rejected() {
        let policy = registry::PeerRegistrationPolicy {
            min_vouches: 1,
            vouch_budget_per_year: 10,
            min_age_to_vouch_days: 0,
            probation_days: 60,
            require_diverse_paths: true,
            path_diversity_hops: 3,
            max_shared_ancestor_vouchers: 2,
        };
        let mut registry = FederatedRegistry::with_policy(policy);

        let now = chrono::Utc::now();

        // Genesis peer: added directly (trust root, no vouchers needed).
        let genesis_key = make_keypair();
        let genesis_did = did_from_key(&genesis_key);
        let mut genesis_peer =
            RegistryPeer::new(&genesis_did, "https://genesis.example.com");
        genesis_peer.status = PeerStatus::Active;
        genesis_peer.registered_at =
            Some((now - chrono::Duration::days(200)).to_rfc3339());
        registry.add_peer(genesis_peer);

        // Admin peer: registered via genesis vouch, then promoted to Active.
        let admin_key = make_keypair();
        let admin_did = did_from_key(&admin_key);
        let admin_peer = RegistryPeer::new(&admin_did, "https://admin.example.com");
        let admin_vouch = vec![PeerVouch::sign(
            &genesis_did,
            &admin_did,
            "2026-01-01T00:00:00Z",
            "bootstrap",
            &genesis_key,
        )];
        registry
            .register_peer_with_vouches(admin_peer, admin_vouch, now)
            .unwrap();
        registry.promote_peer_to_active(&admin_did);

        // Leaf peers peer_a, peer_b, peer_c: each vouched only by admin.
        let mut leaf_peers: Vec<(ed25519_dalek::SigningKey, String)> = Vec::new();
        for i in 0..3usize {
            let leaf_key = make_keypair();
            let leaf_did = did_from_key(&leaf_key);
            let leaf_peer =
                RegistryPeer::new(&leaf_did, format!("https://leaf{i}.example.com"));
            let vouch = vec![PeerVouch::sign(
                &admin_did,
                &leaf_did,
                "2026-02-01T00:00:00Z",
                "direct",
                &admin_key,
            )];
            registry
                .register_peer_with_vouches(leaf_peer, vouch, now)
                .unwrap();
            registry.promote_peer_to_active(&leaf_did);
            leaf_peers.push((leaf_key, leaf_did));
        }

        // Candidate: vouched by all three leaves (which all trace through admin).
        let cand_key = make_keypair();
        let cand_did = did_from_key(&cand_key);
        let cand_peer = RegistryPeer::new(&cand_did, "https://candidate.example.com");
        let vouches: Vec<PeerVouch> = leaf_peers
            .iter()
            .map(|(k, d)| {
                PeerVouch::sign(d, &cand_did, "2026-03-01T00:00:00Z", "direct", k)
            })
            .collect();

        let result = registry.register_peer_with_vouches(cand_peer, vouches, now);
        assert!(result.is_err(), "expected rejection of coordinated cluster");
        match result.unwrap_err() {
            FederationError::NonDiversePaths {
                common_ancestor,
                voucher_count,
            } => {
                assert_eq!(
                    common_ancestor, admin_did,
                    "shared ancestor should be the admin node"
                );
                assert!(
                    voucher_count >= 2,
                    "at least 2 vouchers must share the common ancestor"
                );
            }
            other => panic!("expected NonDiversePaths, got: {other}"),
        }
    }

    /// Diverse graph: each voucher traces to a distinct genesis peer.
    /// Registration must succeed.
    ///
    /// Graph:  genesis_0 --> leaf_0 \
    ///         genesis_1 --> leaf_1  >-- candidate
    ///         genesis_2 --> leaf_2 /
    #[test]
    fn diverse_paths_accepted() {
        let policy = registry::PeerRegistrationPolicy {
            min_vouches: 1,
            vouch_budget_per_year: 10,
            min_age_to_vouch_days: 0,
            probation_days: 60,
            require_diverse_paths: true,
            path_diversity_hops: 3,
            max_shared_ancestor_vouchers: 2,
        };
        let mut registry = FederatedRegistry::with_policy(policy);

        let now = chrono::Utc::now();

        // Three independent genesis → leaf chains.
        let mut leaf_peers: Vec<(ed25519_dalek::SigningKey, String)> = Vec::new();
        for i in 0..3usize {
            let genesis_key = make_keypair();
            let genesis_did = did_from_key(&genesis_key);
            let mut genesis_peer =
                RegistryPeer::new(&genesis_did, format!("https://genesis{i}.example.com"));
            genesis_peer.status = PeerStatus::Active;
            genesis_peer.registered_at =
                Some((now - chrono::Duration::days(200)).to_rfc3339());
            registry.add_peer(genesis_peer);

            let leaf_key = make_keypair();
            let leaf_did = did_from_key(&leaf_key);
            let leaf_peer =
                RegistryPeer::new(&leaf_did, format!("https://leaf{i}.example.com"));
            let vouch = vec![PeerVouch::sign(
                &genesis_did,
                &leaf_did,
                "2026-01-01T00:00:00Z",
                "bootstrap",
                &genesis_key,
            )];
            registry
                .register_peer_with_vouches(leaf_peer, vouch, now)
                .unwrap();
            registry.promote_peer_to_active(&leaf_did);
            leaf_peers.push((leaf_key, leaf_did));
        }

        // Candidate vouched by all three independent leaves.
        let cand_key = make_keypair();
        let cand_did = did_from_key(&cand_key);
        let cand_peer = RegistryPeer::new(&cand_did, "https://candidate.example.com");
        let vouches: Vec<PeerVouch> = leaf_peers
            .iter()
            .map(|(k, d)| {
                PeerVouch::sign(d, &cand_did, "2026-03-01T00:00:00Z", "direct", k)
            })
            .collect();

        let result = registry.register_peer_with_vouches(cand_peer, vouches, now);
        assert!(
            result.is_ok(),
            "expected diverse-path registration to succeed, got: {:?}",
            result.unwrap_err()
        );
        let registered = registry
            .peers()
            .iter()
            .find(|p| p.did == cand_did)
            .expect("candidate not found in registry");
        assert_eq!(registered.status, PeerStatus::Probationary);
    }
}
