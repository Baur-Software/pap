//! M-of-N social recovery via designated notaries (spec section 13.5).
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
use pap_did::SignatureAlgorithm;
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
    /// Signature algorithm used. Defaults to Ed25519 for backward compatibility.
    #[serde(default)]
    pub algorithm: SignatureAlgorithm,
    /// Signature by the principal (base64-encoded)
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
            algorithm: SignatureAlgorithm::default(),
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
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) -> Result<(), PapError> {
        if self.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(PapError::UnsupportedAlgorithm(format!(
                "{:?}",
                self.algorithm
            )));
        }
        let bytes = self.canonical_bytes();
        let sig = signing_key.sign(&bytes);
        use base64::Engine;
        self.signature =
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()));
        Ok(())
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
    /// Signature over the RecoveryRequest canonical bytes (base64-encoded)
    pub signature: String,
    /// When the notary signed
    pub signed_at: DateTime<Utc>,
    /// Signature algorithm used. Defaults to Ed25519 for backward compatibility.
    #[serde(default)]
    pub algorithm: SignatureAlgorithm,
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
            algorithm: recovery_mandate.algorithm,
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
    /// Signature algorithm used. Defaults to Ed25519 for backward compatibility.
    #[serde(default)]
    pub algorithm: SignatureAlgorithm,
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
            algorithm: proof.recovery_mandate.algorithm,
            signature: None,
        }
    }

    /// Sign with the new principal's key (proves possession).
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) -> Result<(), PapError> {
        if self.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(PapError::UnsupportedAlgorithm(format!(
                "{:?}",
                self.algorithm
            )));
        }
        let bytes = self.canonical_bytes();
        let sig = signing_key.sign(&bytes);
        use base64::Engine;
        self.signature =
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()));
        Ok(())
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
    use pap_test_utils::{did_from_key, make_keypair};

    /// Parameterized recovery mandate sign/verify test body.
    fn recovery_sign_verify_for_algorithm(algorithm: SignatureAlgorithm) {
        assert_eq!(algorithm, SignatureAlgorithm::Ed25519);
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
        assert_eq!(mandate.algorithm, algorithm);

        mandate.sign(&principal_key).unwrap();
        assert!(mandate.verify(&principal_key.verifying_key()).is_ok());
    }

    #[test]
    fn recovery_mandate_creation_and_signing() {
        recovery_sign_verify_for_algorithm(SignatureAlgorithm::Ed25519);
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
        mandate.sign(&principal_key).unwrap();

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
        mandate.sign(&principal_key).unwrap();

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
        mandate.sign(&principal_key).unwrap();

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
        mandate.sign(&principal_key).unwrap();

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
        revocation.sign(&new_principal_key).unwrap();
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
            algorithm: SignatureAlgorithm::default(),
            signature: None,
        };
        assert!(revocation.verify(&key.verifying_key()).is_err());
    }

    // ── RecoveryMandate::is_notary ────────────────────────────────────────────

    #[test]
    fn is_notary_returns_true_for_designated_did() {
        let mandate = RecoveryMandate::new(
            "did:key:zprincipal".into(),
            1,
            vec!["did:key:znotary1".into(), "did:key:znotary2".into()],
        )
        .unwrap();
        assert!(mandate.is_notary("did:key:znotary1"));
        assert!(mandate.is_notary("did:key:znotary2"));
    }

    #[test]
    fn is_notary_returns_false_for_unknown_did() {
        let mandate = RecoveryMandate::new(
            "did:key:zprincipal".into(),
            1,
            vec!["did:key:znotary1".into()],
        )
        .unwrap();
        assert!(!mandate.is_notary("did:key:znotary2"));
        assert!(!mandate.is_notary(""));
        // is_notary is case-sensitive — partial matches must not succeed
        assert!(!mandate.is_notary("did:key:znotary"));
    }

    // ── RecoveryMandate::verify edge cases ────────────────────────────────────

    #[test]
    fn recovery_mandate_verify_with_wrong_key_fails() {
        let principal_key = make_keypair();
        let wrong_key = make_keypair();
        let principal_did = did_from_key(&principal_key);

        let mut mandate =
            RecoveryMandate::new(principal_did, 1, vec!["did:key:znotary1".into()]).unwrap();
        mandate.sign(&principal_key).unwrap();

        // Verify against a *different* key — must fail
        assert!(mandate.verify(&wrong_key.verifying_key()).is_err());
    }

    #[test]
    fn recovery_mandate_verify_with_tampered_signature_fails() {
        let principal_key = make_keypair();
        let principal_did = did_from_key(&principal_key);

        let mut mandate =
            RecoveryMandate::new(principal_did, 1, vec!["did:key:znotary1".into()]).unwrap();
        mandate.sign(&principal_key).unwrap();

        // Flip a byte in the middle of the base64-encoded signature
        if let Some(ref mut sig) = mandate.signature {
            let mut bytes = sig.clone().into_bytes();
            let mid = bytes.len() / 2;
            bytes[mid] ^= 0x01;
            *sig = String::from_utf8_lossy(&bytes).into_owned();
        }

        assert!(mandate.verify(&principal_key.verifying_key()).is_err());
    }

    #[test]
    fn recovery_mandate_verify_unsigned_fails() {
        let key = make_keypair();
        let mandate =
            RecoveryMandate::new(did_from_key(&key), 1, vec!["did:key:znotary1".into()]).unwrap();
        // No call to .sign() — signature field is None
        assert!(mandate.verify(&key.verifying_key()).is_err());
    }

    // ── RecoveryMandate::hash ─────────────────────────────────────────────────

    #[test]
    fn recovery_mandate_hash_changes_when_principal_changes() {
        let notaries = vec!["did:key:znotary1".into()];
        let m1 = RecoveryMandate::new("did:key:zprincipal_a".into(), 1, notaries.clone()).unwrap();
        let m2 = RecoveryMandate::new("did:key:zprincipal_b".into(), 1, notaries).unwrap();
        assert_ne!(m1.hash(), m2.hash());
    }

    #[test]
    fn recovery_mandate_hash_changes_when_threshold_changes() {
        let notaries = vec!["did:key:zn1".into(), "did:key:zn2".into()];
        let m1 = RecoveryMandate::new("did:key:zprincipal".into(), 1, notaries.clone()).unwrap();
        let m2 = RecoveryMandate::new("did:key:zprincipal".into(), 2, notaries).unwrap();
        // Different thresholds → different canonical bytes → different hashes
        assert_ne!(m1.hash(), m2.hash());
    }

    #[test]
    fn recovery_mandate_sign_twice_overwrites_signature() {
        let key = make_keypair();
        let mut mandate =
            RecoveryMandate::new(did_from_key(&key), 1, vec!["did:key:znotary1".into()]).unwrap();

        mandate.sign(&key).unwrap();
        let sig1 = mandate.signature.clone().unwrap();
        mandate.sign(&key).unwrap();
        let sig2 = mandate.signature.clone().unwrap();

        // Ed25519 is deterministic — same key + same data → same signature
        assert_eq!(sig1, sig2);
        // And the mandate must still verify cleanly after the second sign
        assert!(mandate.verify(&key.verifying_key()).is_ok());
    }

    // ── RecoveryMandate::new — threshold edge cases ───────────────────────────

    #[test]
    fn one_of_one_threshold_is_valid() {
        let result = RecoveryMandate::new(
            "did:key:zprincipal".into(),
            1,
            vec!["did:key:znotary1".into()],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn n_of_n_threshold_all_notaries_required() {
        let result = RecoveryMandate::new(
            "did:key:zprincipal".into(),
            3,
            vec![
                "did:key:zn1".into(),
                "did:key:zn2".into(),
                "did:key:zn3".into(),
            ],
        );
        assert!(result.is_ok());
        let mandate = result.unwrap();
        assert_eq!(mandate.threshold, mandate.notary_dids.len());
    }

    // ── RecoveryRequest ───────────────────────────────────────────────────────

    #[test]
    fn recovery_request_hash_is_deterministic() {
        let req = RecoveryRequest::new(
            "did:key:zold".into(),
            "did:key:znew".into(),
            "mandate-hash-abc".into(),
        );
        assert_eq!(req.hash(), req.hash());
    }

    #[test]
    fn recovery_request_hash_differs_for_different_content() {
        let req1 = RecoveryRequest::new(
            "did:key:zold_a".into(),
            "did:key:znew".into(),
            "mandate-hash".into(),
        );
        let req2 = RecoveryRequest::new(
            "did:key:zold_b".into(),
            "did:key:znew".into(),
            "mandate-hash".into(),
        );
        assert_ne!(req1.hash(), req2.hash());
    }

    #[test]
    fn recovery_request_fields_are_stored_correctly() {
        let req = RecoveryRequest::new(
            "did:key:zold".into(),
            "did:key:znew".into(),
            "mandate-hash-xyz".into(),
        );
        assert_eq!(req.old_principal_did, "did:key:zold");
        assert_eq!(req.new_principal_did, "did:key:znew");
        assert_eq!(req.recovery_mandate_hash, "mandate-hash-xyz");
    }

    // ── RecoveryRequest serde ─────────────────────────────────────────────────

    #[test]
    fn recovery_request_roundtrip_json() {
        let req = RecoveryRequest::new(
            "did:key:zold".into(),
            "did:key:znew".into(),
            "mandate-hash-abc".into(),
        );
        let json = serde_json::to_string(&req).unwrap();
        let back: RecoveryRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.old_principal_did, req.old_principal_did);
        assert_eq!(back.new_principal_did, req.new_principal_did);
        assert_eq!(back.recovery_mandate_hash, req.recovery_mandate_hash);
        // Timestamp must survive the round-trip
        assert_eq!(back.requested_at.timestamp(), req.requested_at.timestamp());
    }

    // ── RecoveryMandate serde ─────────────────────────────────────────────────

    #[test]
    fn recovery_mandate_roundtrip_json_unsigned() {
        let mandate = RecoveryMandate::new(
            "did:key:zprincipal".into(),
            1,
            vec!["did:key:znotary1".into()],
        )
        .unwrap();
        let json = serde_json::to_string(&mandate).unwrap();
        // unsigned mandates must NOT emit a "signature" field
        assert!(
            !json.contains("\"signature\""),
            "unsigned mandate must omit signature field, got: {json}"
        );
        let back: RecoveryMandate = serde_json::from_str(&json).unwrap();
        assert!(back.signature.is_none());
        assert_eq!(back.threshold, 1);
    }

    #[test]
    fn recovery_mandate_roundtrip_json_signed() {
        let key = make_keypair();
        let mut mandate =
            RecoveryMandate::new(did_from_key(&key), 1, vec!["did:key:znotary1".into()]).unwrap();
        mandate.sign(&key).unwrap();

        let json = serde_json::to_string(&mandate).unwrap();
        let back: RecoveryMandate = serde_json::from_str(&json).unwrap();
        assert!(back.signature.is_some());
        // Signature must still verify after round-trip
        assert!(back.verify(&key.verifying_key()).is_ok());
    }

    // ── PartialRecoverySignature edge cases ───────────────────────────────────

    #[test]
    fn partial_signature_rejects_wrong_mandate_hash_in_request() {
        let principal_key = make_keypair();
        let principal_did = did_from_key(&principal_key);
        let notary_key = make_keypair();
        let notary_did = did_from_key(&notary_key);

        let mut mandate =
            RecoveryMandate::new(principal_did.clone(), 1, vec![notary_did.clone()]).unwrap();
        mandate.sign(&principal_key).unwrap();

        // Request references a *different* (wrong) mandate hash
        let request = RecoveryRequest::new(
            principal_did,
            did_from_key(&make_keypair()),
            "wrong-mandate-hash".into(),
        );

        let result = PartialRecoverySignature::sign(
            &mandate,
            &request,
            &notary_did,
            &notary_key,
            &principal_key.verifying_key(),
        );
        assert!(
            matches!(result, Err(PapError::RecoveryError(ref s)) if s.contains("wrong recovery mandate")),
            "expected wrong-mandate-hash error, got: {result:?}"
        );
    }

    #[test]
    fn partial_signature_rejects_mismatched_principal_in_request() {
        let principal_key = make_keypair();
        let principal_did = did_from_key(&principal_key);
        let notary_key = make_keypair();
        let notary_did = did_from_key(&notary_key);

        let mut mandate =
            RecoveryMandate::new(principal_did.clone(), 1, vec![notary_did.clone()]).unwrap();
        mandate.sign(&principal_key).unwrap();

        // Request claims a *different* old_principal_did
        let request = RecoveryRequest::new(
            "did:key:zdifferent_principal".into(), // wrong
            did_from_key(&make_keypair()),
            mandate.hash(),
        );

        let result = PartialRecoverySignature::sign(
            &mandate,
            &request,
            &notary_did,
            &notary_key,
            &principal_key.verifying_key(),
        );
        assert!(
            matches!(result, Err(PapError::RecoveryError(ref s)) if s.contains("principal does not match")),
            "expected principal-mismatch error, got: {result:?}"
        );
    }

    #[test]
    fn partial_signature_verify_with_wrong_notary_key_fails() {
        let principal_key = make_keypair();
        let principal_did = did_from_key(&principal_key);
        let notary_key = make_keypair();
        let notary_did = did_from_key(&notary_key);
        let wrong_key = make_keypair();

        let mut mandate =
            RecoveryMandate::new(principal_did.clone(), 1, vec![notary_did.clone()]).unwrap();
        mandate.sign(&principal_key).unwrap();

        let request =
            RecoveryRequest::new(principal_did, did_from_key(&make_keypair()), mandate.hash());

        let ps = PartialRecoverySignature::sign(
            &mandate,
            &request,
            &notary_did,
            &notary_key,
            &principal_key.verifying_key(),
        )
        .unwrap();

        // Verify against the *wrong* key — must fail
        let result = ps.verify(&request, &wrong_key.verifying_key());
        assert!(
            matches!(result, Err(PapError::VerificationFailed)),
            "expected VerificationFailed, got: {result:?}"
        );
    }

    // ── RecoveryProof::verify (standalone, after assemble) ───────────────────

    #[test]
    fn recovery_proof_verify_standalone() {
        let principal_key = make_keypair();
        let principal_did = did_from_key(&principal_key);
        let notary1_key = make_keypair();
        let notary1_did = did_from_key(&notary1_key);
        let notary2_key = make_keypair();
        let notary2_did = did_from_key(&notary2_key);

        let mut mandate = RecoveryMandate::new(
            principal_did.clone(),
            2,
            vec![notary1_did.clone(), notary2_did.clone()],
        )
        .unwrap();
        mandate.sign(&principal_key).unwrap();

        let request =
            RecoveryRequest::new(principal_did, did_from_key(&make_keypair()), mandate.hash());

        let ps1 = PartialRecoverySignature::sign(
            &mandate,
            &request,
            &notary1_did,
            &notary1_key,
            &principal_key.verifying_key(),
        )
        .unwrap();
        let ps2 = PartialRecoverySignature::sign(
            &mandate,
            &request,
            &notary2_did,
            &notary2_key,
            &principal_key.verifying_key(),
        )
        .unwrap();

        let notary_keys = vec![
            (notary1_did, notary1_key.verifying_key()),
            (notary2_did, notary2_key.verifying_key()),
        ];

        let proof = RecoveryProof::assemble(
            request,
            mandate,
            vec![ps1, ps2],
            &principal_key.verifying_key(),
            &notary_keys,
        )
        .unwrap();

        // The standalone verify must also pass (separate call from assemble)
        assert!(
            proof
                .verify(&principal_key.verifying_key(), &notary_keys)
                .is_ok(),
            "standalone verify must pass for a correctly assembled proof"
        );
    }

    #[test]
    fn recovery_proof_hash_is_deterministic() {
        let principal_key = make_keypair();
        let principal_did = did_from_key(&principal_key);
        let notary_key = make_keypair();
        let notary_did = did_from_key(&notary_key);

        let mut mandate =
            RecoveryMandate::new(principal_did.clone(), 1, vec![notary_did.clone()]).unwrap();
        mandate.sign(&principal_key).unwrap();

        let request =
            RecoveryRequest::new(principal_did, did_from_key(&make_keypair()), mandate.hash());

        let ps = PartialRecoverySignature::sign(
            &mandate,
            &request,
            &notary_did,
            &notary_key,
            &principal_key.verifying_key(),
        )
        .unwrap();

        let proof = RecoveryProof::assemble(
            request,
            mandate,
            vec![ps],
            &principal_key.verifying_key(),
            &[(notary_did, notary_key.verifying_key())],
        )
        .unwrap();

        // Hash must be stable across a serde round-trip (tests real determinism,
        // not just two calls on the same in-memory struct).
        let json = serde_json::to_string(&proof).unwrap();
        let proof2: RecoveryProof = serde_json::from_str(&json).unwrap();
        assert_eq!(
            proof.hash(),
            proof2.hash(),
            "hash must be identical after a JSON round-trip"
        );
        // Also verify calling hash() twice on the same instance is consistent.
        assert_eq!(proof.hash(), proof.hash());
    }

    #[test]
    fn recovery_proof_assemble_rejects_outsider_signer() {
        let principal_key = make_keypair();
        let principal_did = did_from_key(&principal_key);
        let notary_key = make_keypair();
        let notary_did = did_from_key(&notary_key);
        let outsider_key = make_keypair();
        let outsider_did = did_from_key(&outsider_key);

        let mut mandate =
            RecoveryMandate::new(principal_did.clone(), 1, vec![notary_did.clone()]).unwrap();
        mandate.sign(&principal_key).unwrap();

        let request =
            RecoveryRequest::new(principal_did, did_from_key(&make_keypair()), mandate.hash());

        // Build a PartialRecoverySignature manually for an outsider —
        // can't go through PartialRecoverySignature::sign (it rejects outsiders),
        // so we construct it directly.
        let outsider_sig_bytes = outsider_key.sign(&request.canonical_bytes());
        use base64::Engine;
        let outsider_ps = PartialRecoverySignature {
            notary_did: outsider_did.clone(),
            signature: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(outsider_sig_bytes.to_bytes()),
            signed_at: Utc::now(),
            algorithm: SignatureAlgorithm::default(),
        };

        let result = RecoveryProof::assemble(
            request,
            mandate,
            vec![outsider_ps],
            &principal_key.verifying_key(),
            &[(outsider_did, outsider_key.verifying_key())],
        );
        assert!(
            matches!(result, Err(PapError::NotaryNotInSet(_))),
            "expected NotaryNotInSet for outsider signer, got: {result:?}"
        );
    }

    #[test]
    fn recovery_proof_assemble_rejects_missing_notary_key() {
        let principal_key = make_keypair();
        let principal_did = did_from_key(&principal_key);
        let notary_key = make_keypair();
        let notary_did = did_from_key(&notary_key);

        let mut mandate =
            RecoveryMandate::new(principal_did.clone(), 1, vec![notary_did.clone()]).unwrap();
        mandate.sign(&principal_key).unwrap();

        let request =
            RecoveryRequest::new(principal_did, did_from_key(&make_keypair()), mandate.hash());

        let ps = PartialRecoverySignature::sign(
            &mandate,
            &request,
            &notary_did,
            &notary_key,
            &principal_key.verifying_key(),
        )
        .unwrap();

        // Pass an empty notary_keys slice — the key for the signer is absent
        let result = RecoveryProof::assemble(
            request,
            mandate,
            vec![ps],
            &principal_key.verifying_key(),
            &[], // no keys provided
        );
        assert!(
            matches!(result, Err(PapError::RecoveryError(ref s)) if s.contains("no verifying key")),
            "expected missing-key error, got: {result:?}"
        );
    }

    // ── RevocationProof serde ─────────────────────────────────────────────────

    #[test]
    fn revocation_proof_roundtrip_json() {
        let new_key = make_keypair();
        let mut proof = RevocationProof {
            old_principal_did: "did:key:zold".into(),
            new_principal_did: did_from_key(&new_key),
            recovery_proof_hash: "hash-xyz".into(),
            revoked_at: Utc::now(),
            algorithm: SignatureAlgorithm::default(),
            signature: None,
        };
        proof.sign(&new_key).unwrap();

        let json = serde_json::to_string(&proof).unwrap();
        let back: RevocationProof = serde_json::from_str(&json).unwrap();
        assert!(back.signature.is_some());
        assert!(back.verify(&new_key.verifying_key()).is_ok());
        assert_eq!(back.old_principal_did, "did:key:zold");
    }

    #[test]
    fn revocation_proof_verify_with_tampered_signature_fails() {
        let new_key = make_keypair();
        let mut proof = RevocationProof {
            old_principal_did: "did:key:zold".into(),
            new_principal_did: did_from_key(&new_key),
            recovery_proof_hash: "hash-xyz".into(),
            revoked_at: Utc::now(),
            algorithm: SignatureAlgorithm::default(),
            signature: None,
        };
        proof.sign(&new_key).unwrap();

        // Flip a byte in the signature
        if let Some(ref mut sig) = proof.signature {
            let mut bytes = sig.clone().into_bytes();
            bytes[10] ^= 0xFF;
            *sig = String::from_utf8_lossy(&bytes).into_owned();
        }

        assert!(proof.verify(&new_key.verifying_key()).is_err());
    }

    #[test]
    fn revocation_proof_from_recovery_proof_carries_correct_dids() {
        // Build a minimal 1-of-1 proof to derive a RevocationProof from
        let principal_key = make_keypair();
        let principal_did = did_from_key(&principal_key);
        let new_principal_key = make_keypair();
        let new_principal_did = did_from_key(&new_principal_key);
        let notary_key = make_keypair();
        let notary_did = did_from_key(&notary_key);

        let mut mandate =
            RecoveryMandate::new(principal_did.clone(), 1, vec![notary_did.clone()]).unwrap();
        mandate.sign(&principal_key).unwrap();

        let request = RecoveryRequest::new(
            principal_did.clone(),
            new_principal_did.clone(),
            mandate.hash(),
        );

        let ps = PartialRecoverySignature::sign(
            &mandate,
            &request,
            &notary_did,
            &notary_key,
            &principal_key.verifying_key(),
        )
        .unwrap();

        let proof = RecoveryProof::assemble(
            request,
            mandate,
            vec![ps],
            &principal_key.verifying_key(),
            &[(notary_did, notary_key.verifying_key())],
        )
        .unwrap();

        let revocation = RevocationProof::from_recovery_proof(&proof);
        assert_eq!(revocation.old_principal_did, principal_did);
        assert_eq!(revocation.new_principal_did, new_principal_did);
        assert_eq!(revocation.recovery_proof_hash, proof.hash());
        // Unsigned initially
        assert!(revocation.signature.is_none());
    }
}
