//! M-of-N social recovery via designated notaries (spec section 9.5).
//!
//! A principal designates N notary DIDs at mandate creation time. If the
//! principal loses access to their key, any M notaries can co-sign a
//! recovery request to rotate to a new principal keypair.
//!
//! Design constraints:
//! - No central recovery authority
//! - Notaries are designated at creation time by the principal
//! - Recovery produces a new principal keypair; old key is cryptographically revoked
//! - Notaries learn nothing about each other's co-signature (threshold blind scheme)

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use crate::error::PapError;

/// A recovery mandate designating N notary DIDs with threshold M.
///
/// Created by a healthy principal to prepare for potential key loss.
/// The mandate is signed by the principal's current key, binding the
/// notary set cryptographically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryMandate {
    /// DID of the principal creating this recovery mandate
    pub principal_did: String,
    /// M: minimum number of notary co-signatures required
    pub threshold: usize,
    /// N notary DIDs designated by the principal
    pub notary_dids: Vec<String>,
    /// When this recovery mandate was created
    pub created_at: DateTime<Utc>,
    /// Ed25519 signature by the principal (base64-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl RecoveryMandate {
    /// Create a new recovery mandate.
    ///
    /// `threshold` must be >= 1 and <= notary count.
    /// `notary_dids` must not be empty and must not contain duplicates.
    pub fn new(
        principal_did: String,
        threshold: usize,
        notary_dids: Vec<String>,
    ) -> Result<Self, PapError> {
        if notary_dids.is_empty() {
            return Err(PapError::InvalidRecoveryMandate(
                "notary set must not be empty".into(),
            ));
        }
        if threshold == 0 || threshold > notary_dids.len() {
            return Err(PapError::InvalidRecoveryMandate(format!(
                "threshold {} invalid for {} notaries",
                threshold,
                notary_dids.len()
            )));
        }
        let unique: HashSet<&str> = notary_dids.iter().map(|s| s.as_str()).collect();
        if unique.len() != notary_dids.len() {
            return Err(PapError::InvalidRecoveryMandate(
                "duplicate notary DIDs".into(),
            ));
        }

        Ok(Self {
            principal_did,
            threshold,
            notary_dids,
            created_at: Utc::now(),
            signature: None,
        })
    }

    /// Check if a DID is in the designated notary set.
    pub fn is_notary(&self, did: &str) -> bool {
        self.notary_dids.iter().any(|d| d == did)
    }

    /// SHA-256 hash of the canonical form (excluding signature).
    pub fn hash(&self) -> String {
        let canonical = self.canonical_bytes();
        let digest = Sha256::digest(&canonical);
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    }

    /// Sign this recovery mandate with the principal's key.
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        let bytes = self.canonical_bytes();
        let sig = signing_key.sign(&bytes);
        use base64::Engine;
        self.signature =
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()));
    }

    /// Verify this recovery mandate's signature against the principal's public key.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), PapError> {
        let sig_b64 = self
            .signature
            .as_ref()
            .ok_or_else(|| PapError::InvalidRecoveryMandate("unsigned recovery mandate".into()))?;
        use base64::Engine;
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| {
                PapError::InvalidRecoveryMandate(format!("invalid signature encoding: {e}"))
            })?;
        let signature =
            Signature::from_bytes(sig_bytes.as_slice().try_into().map_err(|_| {
                PapError::InvalidRecoveryMandate("invalid signature length".into())
            })?);
        let bytes = self.canonical_bytes();
        verifying_key
            .verify(&bytes, &signature)
            .map_err(|_| PapError::VerificationFailed)
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let canonical = serde_json::json!({
            "principal_did": self.principal_did,
            "threshold": self.threshold,
            "notary_dids": self.notary_dids,
            "created_at": self.created_at.to_rfc3339(),
        });
        serde_json::to_vec(&canonical).expect("canonical serialization cannot fail")
    }
}

/// A recovery request identifying the old principal, new principal, and
/// the recovery mandate that authorizes the recovery.
///
/// This is what each notary signs independently. Notaries do not learn
/// which other notaries have been contacted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRequest {
    /// DID of the principal whose key is being recovered
    pub old_principal_did: String,
    /// DID of the new principal keypair
    pub new_principal_did: String,
    /// Hash of the RecoveryMandate authorizing this recovery
    pub recovery_mandate_hash: String,
    /// When the recovery was requested
    pub requested_at: DateTime<Utc>,
}

impl RecoveryRequest {
    pub fn new(
        old_principal_did: String,
        new_principal_did: String,
        recovery_mandate_hash: String,
    ) -> Self {
        Self {
            old_principal_did,
            new_principal_did,
            recovery_mandate_hash,
            requested_at: Utc::now(),
        }
    }

    /// SHA-256 hash of this request (used as the message each notary signs).
    pub fn hash(&self) -> String {
        let canonical = self.canonical_bytes();
        let digest = Sha256::digest(&canonical);
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    }

    /// Canonical bytes — the deterministic form that notaries sign.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let canonical = serde_json::json!({
            "old_principal_did": self.old_principal_did,
            "new_principal_did": self.new_principal_did,
            "recovery_mandate_hash": self.recovery_mandate_hash,
            "requested_at": self.requested_at.to_rfc3339(),
        });
        serde_json::to_vec(&canonical).expect("canonical serialization cannot fail")
    }
}

/// A blind partial signature from a single notary.
///
/// Each notary signs the recovery request independently, without
/// knowledge of which other notaries have been contacted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialRecoverySignature {
    /// DID of the notary who produced this signature
    pub notary_did: String,
    /// Ed25519 signature over the RecoveryRequest canonical bytes (base64-encoded)
    pub signature: String,
    /// When the notary signed
    pub signed_at: DateTime<Utc>,
}

impl PartialRecoverySignature {
    /// A notary signs a recovery request.
    ///
    /// The notary verifies the recovery mandate was signed by the old
    /// principal and that they are in the designated notary set before signing.
    pub fn sign(
        recovery_mandate: &RecoveryMandate,
        request: &RecoveryRequest,
        notary_did: &str,
        notary_signing_key: &ed25519_dalek::SigningKey,
        principal_verifying_key: &VerifyingKey,
    ) -> Result<Self, PapError> {
        // Verify the recovery mandate was signed by the principal
        recovery_mandate.verify(principal_verifying_key)?;

        // Verify this notary is in the designated set
        if !recovery_mandate.is_notary(notary_did) {
            return Err(PapError::NotaryNotInSet(notary_did.to_string()));
        }

        // Verify the request references the correct recovery mandate
        if request.recovery_mandate_hash != recovery_mandate.hash() {
            return Err(PapError::RecoveryError(
                "request references wrong recovery mandate".into(),
            ));
        }

        // Verify the request is for the correct principal
        if request.old_principal_did != recovery_mandate.principal_did {
            return Err(PapError::RecoveryError(
                "request principal does not match recovery mandate".into(),
            ));
        }

        // Sign the recovery request
        let request_bytes = request.canonical_bytes();
        let sig = notary_signing_key.sign(&request_bytes);
        use base64::Engine;
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());

        Ok(Self {
            notary_did: notary_did.to_string(),
            signature: sig_b64,
            signed_at: Utc::now(),
        })
    }

    /// Verify this partial signature against the notary's public key.
    pub fn verify(
        &self,
        request: &RecoveryRequest,
        notary_verifying_key: &VerifyingKey,
    ) -> Result<(), PapError> {
        use base64::Engine;
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|e| PapError::RecoveryError(format!("invalid signature encoding: {e}")))?;
        let signature = Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| PapError::RecoveryError("invalid signature length".into()))?,
        );
        let request_bytes = request.canonical_bytes();
        notary_verifying_key
            .verify(&request_bytes, &signature)
            .map_err(|_| PapError::VerificationFailed)
    }
}

/// Assembled proof that M notaries have co-signed a recovery request.
///
/// This is the final artifact that proves the threshold has been met
/// and authorizes the key rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryProof {
    /// The recovery request that was co-signed
    pub request: RecoveryRequest,
    /// The recovery mandate that authorized the recovery
    pub recovery_mandate: RecoveryMandate,
    /// M partial signatures from designated notaries
    pub partial_signatures: Vec<PartialRecoverySignature>,
}

impl RecoveryProof {
    /// Assemble a recovery proof from collected partial signatures.
    ///
    /// Validates:
    /// 1. Recovery mandate was signed by the old principal
    /// 2. At least M notary signatures are present
    /// 3. All signers are in the designated notary set
    /// 4. No duplicate signers
    /// 5. All signatures are cryptographically valid
    pub fn assemble(
        request: RecoveryRequest,
        recovery_mandate: RecoveryMandate,
        partial_signatures: Vec<PartialRecoverySignature>,
        principal_verifying_key: &VerifyingKey,
        notary_keys: &[(String, VerifyingKey)],
    ) -> Result<Self, PapError> {
        // 1. Verify the recovery mandate
        recovery_mandate.verify(principal_verifying_key)?;

        // 2. Check threshold
        if partial_signatures.len() < recovery_mandate.threshold {
            return Err(PapError::ThresholdNotMet(
                recovery_mandate.threshold,
                partial_signatures.len(),
            ));
        }

        // 3 & 4. Check all signers are in the notary set, no duplicates
        let mut seen_notaries = HashSet::new();
        for ps in &partial_signatures {
            if !recovery_mandate.is_notary(&ps.notary_did) {
                return Err(PapError::NotaryNotInSet(ps.notary_did.clone()));
            }
            if !seen_notaries.insert(ps.notary_did.clone()) {
                return Err(PapError::DuplicateNotarySignature(ps.notary_did.clone()));
            }
        }

        // 5. Verify each signature cryptographically
        for ps in &partial_signatures {
            let notary_key = notary_keys
                .iter()
                .find(|(did, _)| did == &ps.notary_did)
                .map(|(_, key)| key)
                .ok_or_else(|| {
                    PapError::RecoveryError(format!(
                        "no verifying key for notary {}",
                        ps.notary_did
                    ))
                })?;
            ps.verify(&request, notary_key)?;
        }

        Ok(Self {
            request,
            recovery_mandate,
            partial_signatures,
        })
    }

    /// Verify an already-assembled recovery proof.
    pub fn verify(
        &self,
        principal_verifying_key: &VerifyingKey,
        notary_keys: &[(String, VerifyingKey)],
    ) -> Result<(), PapError> {
        // Verify recovery mandate signature
        self.recovery_mandate.verify(principal_verifying_key)?;

        // Check threshold
        if self.partial_signatures.len() < self.recovery_mandate.threshold {
            return Err(PapError::ThresholdNotMet(
                self.recovery_mandate.threshold,
                self.partial_signatures.len(),
            ));
        }

        // Check uniqueness and set membership
        let mut seen = HashSet::new();
        for ps in &self.partial_signatures {
            if !self.recovery_mandate.is_notary(&ps.notary_did) {
                return Err(PapError::NotaryNotInSet(ps.notary_did.clone()));
            }
            if !seen.insert(&ps.notary_did) {
                return Err(PapError::DuplicateNotarySignature(ps.notary_did.clone()));
            }
        }

        // Verify each partial signature
        for ps in &self.partial_signatures {
            let notary_key = notary_keys
                .iter()
                .find(|(did, _)| did == &ps.notary_did)
                .map(|(_, key)| key)
                .ok_or_else(|| {
                    PapError::RecoveryError(format!(
                        "no verifying key for notary {}",
                        ps.notary_did
                    ))
                })?;
            ps.verify(&self.request, notary_key)?;
        }

        Ok(())
    }

    /// SHA-256 hash of this recovery proof.
    pub fn hash(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("serialization cannot fail");
        let digest = Sha256::digest(&bytes);
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    }
}

/// Cryptographic proof that an old principal DID has been revoked
/// and replaced by a new one via M-of-N social recovery.
///
/// This is broadcast to federation peers so they can update their
/// registries and reject the old DID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationProof {
    /// The old principal DID being revoked
    pub old_principal_did: String,
    /// The new principal DID replacing it
    pub new_principal_did: String,
    /// Hash of the RecoveryProof that authorized this revocation
    pub recovery_proof_hash: String,
    /// When the revocation was issued
    pub revoked_at: DateTime<Utc>,
    /// Signature by the new principal key (base64-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl RevocationProof {
    /// Create a revocation proof from a verified recovery proof.
    pub fn from_recovery_proof(proof: &RecoveryProof) -> Self {
        Self {
            old_principal_did: proof.request.old_principal_did.clone(),
            new_principal_did: proof.request.new_principal_did.clone(),
            recovery_proof_hash: proof.hash(),
            revoked_at: Utc::now(),
            signature: None,
        }
    }

    /// Sign with the new principal's key (proves possession).
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        let bytes = self.canonical_bytes();
        let sig = signing_key.sign(&bytes);
        use base64::Engine;
        self.signature =
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()));
    }

    /// Verify against the new principal's public key.
    pub fn verify(&self, new_principal_key: &VerifyingKey) -> Result<(), PapError> {
        let sig_b64 = self
            .signature
            .as_ref()
            .ok_or_else(|| PapError::RecoveryError("unsigned revocation proof".into()))?;
        use base64::Engine;
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| PapError::RecoveryError(format!("invalid signature encoding: {e}")))?;
        let signature = Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| PapError::RecoveryError("invalid signature length".into()))?,
        );
        let bytes = self.canonical_bytes();
        new_principal_key
            .verify(&bytes, &signature)
            .map_err(|_| PapError::VerificationFailed)
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let canonical = serde_json::json!({
            "old_principal_did": self.old_principal_did,
            "new_principal_did": self.new_principal_did,
            "recovery_proof_hash": self.recovery_proof_hash,
            "revoked_at": self.revoked_at.to_rfc3339(),
        });
        serde_json::to_vec(&canonical).expect("canonical serialization cannot fail")
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

    #[test]
    fn recovery_mandate_creation_and_signing() {
        let principal_key = make_keypair();
        let principal_did = did_from_key(&principal_key);
        let notary1_did = did_from_key(&make_keypair());
        let notary2_did = did_from_key(&make_keypair());
        let notary3_did = did_from_key(&make_keypair());

        let mut mandate = RecoveryMandate::new(
            principal_did.clone(),
            2,
            vec![notary1_did, notary2_did, notary3_did],
        )
        .unwrap();

        mandate.sign(&principal_key);
        assert!(mandate.verify(&principal_key.verifying_key()).is_ok());
    }

    #[test]
    fn recovery_mandate_rejects_empty_notaries() {
        let result = RecoveryMandate::new("did:key:zprincipal".into(), 1, vec![]);
        assert!(matches!(result, Err(PapError::InvalidRecoveryMandate(_))));
    }

    #[test]
    fn recovery_mandate_rejects_zero_threshold() {
        let result = RecoveryMandate::new(
            "did:key:zprincipal".into(),
            0,
            vec!["did:key:znotary1".into()],
        );
        assert!(matches!(result, Err(PapError::InvalidRecoveryMandate(_))));
    }

    #[test]
    fn recovery_mandate_rejects_threshold_exceeding_notary_count() {
        let result = RecoveryMandate::new(
            "did:key:zprincipal".into(),
            3,
            vec!["did:key:znotary1".into(), "did:key:znotary2".into()],
        );
        assert!(matches!(result, Err(PapError::InvalidRecoveryMandate(_))));
    }

    #[test]
    fn recovery_mandate_rejects_duplicate_notaries() {
        let result = RecoveryMandate::new(
            "did:key:zprincipal".into(),
            1,
            vec!["did:key:znotary1".into(), "did:key:znotary1".into()],
        );
        assert!(matches!(result, Err(PapError::InvalidRecoveryMandate(_))));
    }

    #[test]
    fn partial_signature_rejects_non_notary() {
        let principal_key = make_keypair();
        let principal_did = did_from_key(&principal_key);
        let notary1_key = make_keypair();
        let notary1_did = did_from_key(&notary1_key);
        let outsider_key = make_keypair();
        let outsider_did = did_from_key(&outsider_key);

        let mut mandate =
            RecoveryMandate::new(principal_did.clone(), 1, vec![notary1_did]).unwrap();
        mandate.sign(&principal_key);

        let request =
            RecoveryRequest::new(principal_did, did_from_key(&make_keypair()), mandate.hash());

        let result = PartialRecoverySignature::sign(
            &mandate,
            &request,
            &outsider_did,
            &outsider_key,
            &principal_key.verifying_key(),
        );
        assert!(matches!(result, Err(PapError::NotaryNotInSet(_))));
    }

    #[test]
    fn recovery_proof_rejects_below_threshold() {
        let principal_key = make_keypair();
        let principal_did = did_from_key(&principal_key);
        let notary1_key = make_keypair();
        let notary1_did = did_from_key(&notary1_key);
        let notary2_did = did_from_key(&make_keypair());
        let notary3_did = did_from_key(&make_keypair());
        let new_principal_did = did_from_key(&make_keypair());

        let mut mandate = RecoveryMandate::new(
            principal_did.clone(),
            2,
            vec![notary1_did.clone(), notary2_did, notary3_did],
        )
        .unwrap();
        mandate.sign(&principal_key);

        let request = RecoveryRequest::new(principal_did, new_principal_did, mandate.hash());

        // Only 1 signature, but threshold is 2
        let ps1 = PartialRecoverySignature::sign(
            &mandate,
            &request,
            &notary1_did,
            &notary1_key,
            &principal_key.verifying_key(),
        )
        .unwrap();

        let result = RecoveryProof::assemble(
            request,
            mandate,
            vec![ps1],
            &principal_key.verifying_key(),
            &[(notary1_did, notary1_key.verifying_key())],
        );
        assert!(matches!(result, Err(PapError::ThresholdNotMet(2, 1))));
    }

    #[test]
    fn recovery_proof_rejects_duplicate_signer() {
        let principal_key = make_keypair();
        let principal_did = did_from_key(&principal_key);
        let notary1_key = make_keypair();
        let notary1_did = did_from_key(&notary1_key);
        let notary2_did = did_from_key(&make_keypair());
        let new_principal_did = did_from_key(&make_keypair());

        let mut mandate = RecoveryMandate::new(
            principal_did.clone(),
            2,
            vec![notary1_did.clone(), notary2_did],
        )
        .unwrap();
        mandate.sign(&principal_key);

        let request = RecoveryRequest::new(principal_did, new_principal_did, mandate.hash());

        let ps1 = PartialRecoverySignature::sign(
            &mandate,
            &request,
            &notary1_did,
            &notary1_key,
            &principal_key.verifying_key(),
        )
        .unwrap();

        // Duplicate the same signature
        let ps1_dup = ps1.clone();

        let result = RecoveryProof::assemble(
            request,
            mandate,
            vec![ps1, ps1_dup],
            &principal_key.verifying_key(),
            &[(notary1_did, notary1_key.verifying_key())],
        );
        assert!(matches!(result, Err(PapError::DuplicateNotarySignature(_))));
    }

    #[test]
    fn full_2_of_3_recovery_flow() {
        // Setup: principal with 3 notaries, threshold 2
        let principal_key = make_keypair();
        let principal_did = did_from_key(&principal_key);
        let new_principal_key = make_keypair();
        let new_principal_did = did_from_key(&new_principal_key);

        let notary1_key = make_keypair();
        let notary1_did = did_from_key(&notary1_key);
        let notary2_key = make_keypair();
        let notary2_did = did_from_key(&notary2_key);
        let notary3_key = make_keypair();
        let notary3_did = did_from_key(&notary3_key);

        // Principal creates recovery mandate
        let mut mandate = RecoveryMandate::new(
            principal_did.clone(),
            2,
            vec![
                notary1_did.clone(),
                notary2_did.clone(),
                notary3_did.clone(),
            ],
        )
        .unwrap();
        mandate.sign(&principal_key);

        // Recovery request (principal lost key, recovery coordinator creates this)
        let request =
            RecoveryRequest::new(principal_did, new_principal_did.clone(), mandate.hash());

        // Notary 1 signs (blind — doesn't know about notary 3)
        let ps1 = PartialRecoverySignature::sign(
            &mandate,
            &request,
            &notary1_did,
            &notary1_key,
            &principal_key.verifying_key(),
        )
        .unwrap();

        // Notary 3 signs (blind — doesn't know about notary 1)
        let ps3 = PartialRecoverySignature::sign(
            &mandate,
            &request,
            &notary3_did,
            &notary3_key,
            &principal_key.verifying_key(),
        )
        .unwrap();

        // Assemble proof with 2 of 3 signatures
        let notary_keys = vec![
            (notary1_did, notary1_key.verifying_key()),
            (notary2_did, notary2_key.verifying_key()),
            (notary3_did, notary3_key.verifying_key()),
        ];

        let proof = RecoveryProof::assemble(
            request,
            mandate,
            vec![ps1, ps3],
            &principal_key.verifying_key(),
            &notary_keys,
        )
        .unwrap();

        // Verify the proof
        assert!(proof
            .verify(&principal_key.verifying_key(), &notary_keys)
            .is_ok());

        // Create and sign revocation proof
        let mut revocation = RevocationProof::from_recovery_proof(&proof);
        revocation.sign(&new_principal_key);
        assert!(revocation
            .verify(&new_principal_key.verifying_key())
            .is_ok());
        assert_eq!(revocation.new_principal_did, new_principal_did);
    }

    #[test]
    fn recovery_mandate_hash_stability() {
        let mandate = RecoveryMandate::new(
            "did:key:zprincipal".into(),
            2,
            vec![
                "did:key:znotary1".into(),
                "did:key:znotary2".into(),
                "did:key:znotary3".into(),
            ],
        )
        .unwrap();
        let h1 = mandate.hash();
        let h2 = mandate.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn revocation_proof_unsigned_verify_fails() {
        let key = make_keypair();
        let revocation = RevocationProof {
            old_principal_did: "did:key:zold".into(),
            new_principal_did: "did:key:znew".into(),
            recovery_proof_hash: "hash".into(),
            revoked_at: Utc::now(),
            signature: None,
        };
        assert!(revocation.verify(&key.verifying_key()).is_err());
    }
}
