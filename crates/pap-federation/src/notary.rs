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
