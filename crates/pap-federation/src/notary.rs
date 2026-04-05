//! NotarySet registry for M-of-N social recovery.
//!
//! Stores recovery mandates and tracks revoked principal DIDs.
//! Queryable by principal DID to find the recovery mandate for a given
//! principal. Processes revocation proofs to mark old DIDs as revoked.

use std::collections::{HashMap, HashSet};

use pap_core::recovery::{RecoveryMandate, RevocationProof};
use pap_did::verify_key_from_did;

use crate::error::FederationError;

/// A federated registry of recovery mandates and DID revocations.
///
/// Each federation node maintains a NotarySet to:
/// 1. Store recovery mandates registered by principals
/// 2. Track which principal DIDs have been revoked via recovery
/// 3. Answer queries about a principal's recovery mandate
pub struct NotarySet {
    /// Recovery mandates indexed by principal DID
    mandates: HashMap<String, RecoveryMandate>,
    /// Set of revoked principal DIDs
    revoked_dids: HashSet<String>,
}

impl NotarySet {
    pub fn new() -> Self {
        Self {
            mandates: HashMap::new(),
            revoked_dids: HashSet::new(),
        }
    }

    /// Register a recovery mandate.
    ///
    /// The mandate must be signed by the principal. Only one recovery
    /// mandate per principal DID is allowed; a new one replaces the old.
    pub fn register(&mut self, mandate: RecoveryMandate) -> Result<(), FederationError> {
        // Verify the mandate is signed by the principal
        let verifying_key = verify_key_from_did(&mandate.principal_did)
            .map_err(|e| FederationError::NotaryError(format!("invalid principal DID: {e}")))?;
        mandate
            .verify(&verifying_key)
            .map_err(|e| FederationError::NotaryError(format!("invalid mandate signature: {e}")))?;

        // Don't allow registration for revoked DIDs
        if self.revoked_dids.contains(&mandate.principal_did) {
            return Err(FederationError::NotaryError(
                "principal DID has been revoked".into(),
            ));
        }

        self.mandates.insert(mandate.principal_did.clone(), mandate);
        Ok(())
    }

    /// Query the recovery mandate for a principal DID.
    pub fn query(&self, principal_did: &str) -> Option<&RecoveryMandate> {
        self.mandates.get(principal_did)
    }

    /// Check if a principal DID has been revoked.
    pub fn is_revoked(&self, did: &str) -> bool {
        self.revoked_dids.contains(did)
    }

    /// Process a revocation proof, marking the old DID as revoked.
    ///
    /// Verifies the revocation proof is signed by the new principal before
    /// accepting. Returns the old DID that was revoked.
    pub fn process_revocation(
        &mut self,
        proof: &RevocationProof,
    ) -> Result<String, FederationError> {
        // Verify the revocation proof is signed by the new principal
        let new_key = verify_key_from_did(&proof.new_principal_did).map_err(|e| {
            FederationError::RevocationError(format!("invalid new principal DID: {e}"))
        })?;
        proof.verify(&new_key).map_err(|e| {
            FederationError::RevocationError(format!("invalid revocation signature: {e}"))
        })?;

        // Mark old DID as revoked
        self.revoked_dids.insert(proof.old_principal_did.clone());

        // Remove the old recovery mandate (no longer needed)
        self.mandates.remove(&proof.old_principal_did);

        Ok(proof.old_principal_did.clone())
    }

    /// All registered recovery mandates.
    pub fn all_mandates(&self) -> Vec<&RecoveryMandate> {
        self.mandates.values().collect()
    }

    /// All revoked DIDs.
    pub fn revoked_dids(&self) -> &HashSet<String> {
        &self.revoked_dids
    }

    pub fn mandate_count(&self) -> usize {
        self.mandates.len()
    }

    pub fn revocation_count(&self) -> usize {
        self.revoked_dids.len()
    }
}

impl Default for NotarySet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn did_from_key(key: &SigningKey) -> String {
        pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
            .unwrap()
            .did()
    }

    fn make_signed_mandate(key: &SigningKey) -> RecoveryMandate {
        let did = did_from_key(key);
        let notary_key = make_keypair();
        let notary_did = did_from_key(&notary_key);

        let mut mandate = RecoveryMandate::new(did, 1, vec![notary_did]).unwrap();
        mandate.sign(key);
        mandate
    }

    #[test]
    fn register_and_query_mandate() {
        let mut notary_set = NotarySet::new();
        let key = make_keypair();
        let did = did_from_key(&key);
        let mandate = make_signed_mandate(&key);

        notary_set.register(mandate).unwrap();
        assert_eq!(notary_set.mandate_count(), 1);

        let queried = notary_set.query(&did);
        assert!(queried.is_some());
        assert_eq!(queried.unwrap().principal_did, did);
    }

    #[test]
    fn query_nonexistent_returns_none() {
        let notary_set = NotarySet::new();
        assert!(notary_set.query("did:key:zNonexistent").is_none());
    }

    #[test]
    fn register_rejects_unsigned_mandate() {
        let mut notary_set = NotarySet::new();
        let key = make_keypair();
        let did = did_from_key(&key);
        let notary_key = make_keypair();
        let notary_did = did_from_key(&notary_key);

        // Create without signing
        let mandate = RecoveryMandate::new(did, 1, vec![notary_did]).unwrap();
        let result = notary_set.register(mandate);
        assert!(result.is_err());
        assert_eq!(notary_set.mandate_count(), 0);
    }

    #[test]
    fn register_replaces_existing_mandate() {
        let mut notary_set = NotarySet::new();
        let key = make_keypair();

        let mandate1 = make_signed_mandate(&key);
        let mandate2 = make_signed_mandate(&key);

        notary_set.register(mandate1).unwrap();
        notary_set.register(mandate2).unwrap();

        // Should still be 1 — second replaced first
        assert_eq!(notary_set.mandate_count(), 1);
    }

    #[test]
    fn register_rejects_revoked_did() {
        let mut notary_set = NotarySet::new();

        // Manually revoke a DID
        let key = make_keypair();
        let did = did_from_key(&key);
        notary_set.revoked_dids.insert(did.clone());

        let mandate = make_signed_mandate(&key);
        let result = notary_set.register(mandate);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("revoked"));
    }

    #[test]
    fn process_revocation_marks_old_did_revoked() {
        let mut notary_set = NotarySet::new();
        let old_key = make_keypair();
        let old_did = did_from_key(&old_key);
        let new_key = make_keypair();
        let new_did = did_from_key(&new_key);

        // Register a mandate for the old DID
        let mandate = make_signed_mandate(&old_key);
        notary_set.register(mandate).unwrap();
        assert_eq!(notary_set.mandate_count(), 1);
        assert!(!notary_set.is_revoked(&old_did));

        // Create and sign a revocation proof
        let mut proof = RevocationProof {
            old_principal_did: old_did.clone(),
            new_principal_did: new_did,
            recovery_proof_hash: "test_hash".into(),
            revoked_at: chrono::Utc::now(),
            algorithm: pap_did::SignatureAlgorithm::default(),
            signature: None,
        };
        proof.sign(&new_key);

        let revoked_did = notary_set.process_revocation(&proof).unwrap();
        assert_eq!(revoked_did, old_did);
        assert!(notary_set.is_revoked(&old_did));
        // Old mandate should be removed
        assert_eq!(notary_set.mandate_count(), 0);
        assert!(notary_set.query(&old_did).is_none());
        assert_eq!(notary_set.revocation_count(), 1);
    }

    #[test]
    fn process_revocation_rejects_unsigned_proof() {
        let mut notary_set = NotarySet::new();
        let new_key = make_keypair();
        let new_did = did_from_key(&new_key);

        let proof = RevocationProof {
            old_principal_did: "did:key:zOld".into(),
            new_principal_did: new_did,
            recovery_proof_hash: "hash".into(),
            revoked_at: chrono::Utc::now(),
            algorithm: pap_did::SignatureAlgorithm::default(),
            signature: None,
        };

        let result = notary_set.process_revocation(&proof);
        assert!(result.is_err());
    }

    #[test]
    fn process_revocation_rejects_wrong_signer() {
        let mut notary_set = NotarySet::new();
        let new_key = make_keypair();
        let new_did = did_from_key(&new_key);
        let wrong_key = make_keypair();

        let mut proof = RevocationProof {
            old_principal_did: "did:key:zOld".into(),
            new_principal_did: new_did,
            recovery_proof_hash: "hash".into(),
            revoked_at: chrono::Utc::now(),
            algorithm: pap_did::SignatureAlgorithm::default(),
            signature: None,
        };
        proof.sign(&wrong_key); // sign with wrong key

        let result = notary_set.process_revocation(&proof);
        assert!(result.is_err());
    }

    #[test]
    fn all_mandates_and_revoked_dids() {
        let mut notary_set = NotarySet::new();
        let key1 = make_keypair();
        let key2 = make_keypair();

        notary_set.register(make_signed_mandate(&key1)).unwrap();
        notary_set.register(make_signed_mandate(&key2)).unwrap();

        assert_eq!(notary_set.all_mandates().len(), 2);
        assert!(notary_set.revoked_dids().is_empty());
    }

    #[test]
    fn default_notary_set_is_empty() {
        let ns = NotarySet::default();
        assert_eq!(ns.mandate_count(), 0);
        assert_eq!(ns.revocation_count(), 0);
    }
}
