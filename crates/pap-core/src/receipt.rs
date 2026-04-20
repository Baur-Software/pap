use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use pap_did::SignatureAlgorithm;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::PapError;
use crate::mandate::Mandate;
use crate::session::Session;

// ─── Bilateral Session Attestation ──────────────────────────────────

/// Outcome of a session as attested by one party.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionOutcome {
    /// Both parties agree the action completed successfully
    Fulfilled,
    /// The action was partially completed
    Partial,
    /// The action failed
    Failed,
    /// One party disputes the other's characterization of the session
    Disputed,
}

impl SessionOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionOutcome::Fulfilled => "fulfilled",
            SessionOutcome::Partial => "partial",
            SessionOutcome::Failed => "failed",
            SessionOutcome::Disputed => "disputed",
        }
    }
}

impl std::fmt::Display for SessionOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A session attestation from one party, stating their view of the
/// session outcome. Both parties should attest for bilateral verification
/// — unilateral attestation enables selective reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAttestation {
    /// Ephemeral session ID this attestation refers to
    pub session_id: String,
    /// Ephemeral session DID of the attesting party
    pub attester_did: String,
    /// The attester's assessment of the session outcome
    pub outcome: SessionOutcome,
    /// Schema.org action type that was performed
    pub action_type: String,
    /// When this attestation was created
    pub timestamp: DateTime<Utc>,
    /// Signature algorithm used. Defaults to Ed25519 for backward compatibility.
    #[serde(default)]
    pub algorithm: SignatureAlgorithm,
    /// Signature over the canonical bytes (base64url-no-pad)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl SessionAttestation {
    /// Create a new unsigned attestation.
    pub fn new(
        session_id: impl Into<String>,
        attester_did: impl Into<String>,
        outcome: SessionOutcome,
        action_type: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            attester_did: attester_did.into(),
            outcome,
            action_type: action_type.into(),
            timestamp: Utc::now(),
            algorithm: SignatureAlgorithm::default(),
            signature: None,
        }
    }

    /// Sign this attestation with the attester's session key.
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

    /// Verify this attestation's signature.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), PapError> {
        let sig_b64 = self
            .signature
            .as_ref()
            .ok_or_else(|| PapError::AttestationError("unsigned attestation".into()))?;
        use base64::Engine;
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| PapError::AttestationError(format!("invalid signature encoding: {e}")))?;
        let signature = Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| PapError::AttestationError("invalid signature length".into()))?,
        );
        let bytes = self.canonical_bytes();
        verifying_key
            .verify_strict(&bytes, &signature)
            .map_err(|_| PapError::VerificationFailed)
    }

    /// Canonical bytes for signing (excludes signature field).
    fn canonical_bytes(&self) -> Vec<u8> {
        let canonical = serde_json::json!({
            "session_id": self.session_id,
            "attester_did": self.attester_did,
            "outcome": self.outcome,
            "action_type": self.action_type,
            "timestamp": self.timestamp.to_rfc3339(),
        });
        serde_json::to_vec(&canonical).expect("canonical serialization cannot fail")
    }
}

/// Attestation status of a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    /// No attestations present
    Unattested,
    /// Only one party has attested
    UnilaterallyAttested,
    /// Both parties have attested
    BilaterallyAttested,
}

impl AttestationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttestationStatus::Unattested => "unattested",
            AttestationStatus::UnilaterallyAttested => "unilaterally_attested",
            AttestationStatus::BilaterallyAttested => "bilaterally_attested",
        }
    }
}

impl std::fmt::Display for AttestationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── Per-Action Reputation Segmentation ─────────────────────────────

/// Reputation data for a single action type. Zero-disclosure search
/// reputation does not transfer to flight-booking reputation.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReputationSegment {
    /// Schema.org action type for this segment
    pub action_type: String,
    /// Total number of receipts recorded for this action type
    pub total_receipts: u64,
    /// Number of receipts with bilateral attestation
    pub bilateral_attestations: u64,
    /// Number of unique counterparty ephemeral DIDs seen
    pub unique_counterparties: u64,
    /// Internal set for tracking unique counterparties (not serialized)
    #[serde(skip)]
    counterparty_set: std::collections::HashSet<String>,
}

impl ReputationSegment {
    /// Create a new empty reputation segment for the given action type.
    pub fn new(action_type: impl Into<String>) -> Self {
        Self {
            action_type: action_type.into(),
            total_receipts: 0,
            bilateral_attestations: 0,
            unique_counterparties: 0,
            counterparty_set: std::collections::HashSet::new(),
        }
    }
}

/// A reputation profile segmented by action type. Prevents reputation
/// earned in zero-disclosure contexts (e.g. search) from inflating
/// reputation in high-trust contexts (e.g. flight booking, payments).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReputationProfile {
    /// Map from Schema.org action type to reputation segment
    pub segments: HashMap<String, ReputationSegment>,
}

impl ReputationProfile {
    /// Create an empty reputation profile.
    pub fn new() -> Self {
        Self {
            segments: HashMap::new(),
        }
    }

    /// Record a transaction receipt into the appropriate reputation segment.
    /// The receipt's action type determines which segment it goes into.
    /// If the receipt has bilateral attestation, the bilateral count is
    /// incremented. Counterparty uniqueness is tracked by ephemeral DID.
    pub fn record_receipt(&mut self, receipt: &TransactionReceipt) {
        let segment = self
            .segments
            .entry(receipt.action.clone())
            .or_insert_with(|| ReputationSegment::new(&receipt.action));

        segment.total_receipts += 1;

        if receipt.attestation_status() == AttestationStatus::BilaterallyAttested {
            segment.bilateral_attestations += 1;
        }

        // Track unique counterparties — both initiator and receiver are
        // ephemeral session DIDs, so we count both for diversity.
        if segment
            .counterparty_set
            .insert(receipt.receiving_agent_did.clone())
        {
            segment.unique_counterparties += 1;
        }
        if segment
            .counterparty_set
            .insert(receipt.initiating_agent_did.clone())
        {
            segment.unique_counterparties += 1;
        }
    }

    /// Look up a specific action type's reputation segment.
    pub fn segment(&self, action_type: &str) -> Option<&ReputationSegment> {
        self.segments.get(action_type)
    }

    /// Total receipts across all segments.
    pub fn total_receipts(&self) -> u64 {
        self.segments.values().map(|s| s.total_receipts).sum()
    }

    /// Number of distinct action types with reputation data.
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }
}

/// A transaction receipt co-signed by both session parties.
/// Contains property references only — never values.
/// Auditable by both principals. Not stored by any platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    /// Ephemeral session ID (not linked to principal)
    pub session_id: String,
    /// Schema.org action reference
    pub action: String,
    /// Ephemeral session DID of the initiating agent
    pub initiating_agent_did: String,
    /// Ephemeral session DID of the receiving agent
    pub receiving_agent_did: String,
    /// Property references disclosed by the initiator (refs only, no values)
    pub disclosed_by_initiator: Vec<String>,
    /// Property references / operator statement from receiver
    pub disclosed_by_receiver: Vec<String>,
    /// Description of what was executed
    pub executed: String,
    /// Description of what was returned
    pub returned: String,
    /// Payment proof commitment hash (if the action involved payment).
    /// Contains only the commitment reference — never amounts or destinations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_proof_commitment: Option<String>,
    /// SHA-256 hash of the actual Phase 3 disclosure payload.
    /// Included in canonical bytes so the co-signature proves the
    /// disclosed_by_* property refs match the actual disclosure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disclosure_hash: Option<String>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Co-signatures from both session DIDs (base64-encoded)
    pub signatures: Vec<String>,
    /// Bilateral session attestations from each party (spec hardening).
    /// A receipt with attestations from both parties is `BilaterallyAttested`;
    /// with only one party it is `UnilaterallyAttested`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<SessionAttestation>,
}

impl TransactionReceipt {
    /// Build a receipt from a completed session.
    pub fn from_session(
        session: &Session,
        disclosed_by_initiator: Vec<String>,
        disclosed_by_receiver: Vec<String>,
        executed: String,
        returned: String,
    ) -> Result<Self, PapError> {
        let initiator_did = session
            .initiator_session_did
            .as_ref()
            .ok_or_else(|| PapError::ReceiptError("no initiator session DID".into()))?;
        let receiver_did = session
            .receiver_session_did
            .as_ref()
            .ok_or_else(|| PapError::ReceiptError("no receiver session DID".into()))?;

        Ok(Self {
            session_id: session.id.clone(),
            action: session.action.clone(),
            initiating_agent_did: initiator_did.clone(),
            receiving_agent_did: receiver_did.clone(),
            disclosed_by_initiator,
            disclosed_by_receiver,
            executed,
            returned,
            payment_proof_commitment: None,
            disclosure_hash: None,
            timestamp: Utc::now(),
            signatures: vec![],
            attestations: vec![],
        })
    }

    /// Attach the payment proof commitment from a mandate.
    /// Copies only the commitment hash — no amounts or payment details.
    pub fn with_payment_proof(mut self, mandate: &Mandate) -> Self {
        self.payment_proof_commitment = mandate
            .payment_proof
            .as_ref()
            .map(|p| p.commitment().to_string());
        self
    }

    /// Commit a SHA-256 hash of the actual Phase 3 disclosure values into
    /// the receipt. Call this before co-signing so the signatures cover
    /// the disclosure hash and bind the property refs to the real payload.
    pub fn with_disclosure_hash(mut self, disclosures: &[serde_json::Value]) -> Self {
        use sha2::{Digest, Sha256};
        let canonical = serde_json::to_vec(disclosures).unwrap_or_default();
        let hash = Sha256::digest(&canonical);
        use base64::Engine;
        self.disclosure_hash = Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash));
        self
    }

    /// Verify the disclosure hash matches the provided Phase 3 disclosures.
    /// Call this on receipt of a co-signed receipt to verify integrity.
    /// Receipts without a committed hash (legacy) pass without error.
    pub fn verify_disclosure_hash(
        &self,
        disclosures: &[serde_json::Value],
    ) -> Result<(), PapError> {
        match &self.disclosure_hash {
            None => Ok(()), // No hash committed — legacy receipt, skip check
            Some(expected) => {
                use sha2::{Digest, Sha256};
                let canonical = serde_json::to_vec(disclosures).unwrap_or_default();
                let hash = Sha256::digest(&canonical);
                use base64::Engine;
                let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
                if computed == *expected {
                    Ok(())
                } else {
                    Err(PapError::ReceiptError(
                        "disclosure hash mismatch: receipt property refs do not match Phase 3 disclosures".into(),
                    ))
                }
            }
        }
    }

    /// Validate that the receipt's payment proof commitment is consistent
    /// with the mandate. If the action is `schema:PayAction`, the mandate
    /// MUST have a payment proof and the receipt MUST carry the commitment.
    pub fn validate_payment_commitment(&self, mandate: &Mandate) -> Result<(), PapError> {
        let is_pay_action = self.action == "schema:PayAction";

        if is_pay_action {
            // Mandate must have a proof
            let proof = mandate
                .payment_proof
                .as_ref()
                .ok_or(PapError::MissingPaymentProof)?;

            // Receipt must carry the commitment
            let receipt_commitment = self.payment_proof_commitment.as_ref().ok_or_else(|| {
                PapError::ReceiptError(
                    "receipt missing payment proof commitment for PayAction".into(),
                )
            })?;

            // Commitment must match the mandate's proof
            if receipt_commitment != proof.commitment() {
                return Err(PapError::PaymentProofError(
                    "receipt commitment does not match mandate proof".into(),
                ));
            }
        }

        Ok(())
    }

    /// Canonical bytes for signing (excludes signatures).
    fn canonical_bytes(&self) -> Vec<u8> {
        let canonical = serde_json::json!({
            "session_id": self.session_id,
            "action": self.action,
            "initiating_agent_did": self.initiating_agent_did,
            "receiving_agent_did": self.receiving_agent_did,
            "disclosed_by_initiator": self.disclosed_by_initiator,
            "disclosed_by_receiver": self.disclosed_by_receiver,
            "executed": self.executed,
            "returned": self.returned,
            "payment_proof_commitment": self.payment_proof_commitment,
            "disclosure_hash": self.disclosure_hash,
            "timestamp": self.timestamp.to_rfc3339(),
        });
        serde_json::to_vec(&canonical).expect("canonical serialization cannot fail")
    }

    /// Co-sign the receipt with a session key.
    pub fn co_sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        let bytes = self.canonical_bytes();
        let sig = signing_key.sign(&bytes);
        use base64::Engine;
        self.signatures
            .push(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()));
    }

    /// Verify a specific signature on the receipt.
    pub fn verify_signature(
        &self,
        index: usize,
        verifying_key: &VerifyingKey,
    ) -> Result<(), PapError> {
        let sig_b64 = self
            .signatures
            .get(index)
            .ok_or_else(|| PapError::ReceiptError(format!("no signature at index {index}")))?;
        use base64::Engine;
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| PapError::ReceiptError(format!("invalid signature encoding: {e}")))?;
        let signature = Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| PapError::ReceiptError("invalid signature length".into()))?,
        );
        let bytes = self.canonical_bytes();
        verifying_key
            .verify_strict(&bytes, &signature)
            .map_err(|_| PapError::VerificationFailed)
    }

    /// Verify both co-signatures.
    pub fn verify_both(
        &self,
        initiator_key: &VerifyingKey,
        receiver_key: &VerifyingKey,
    ) -> Result<(), PapError> {
        if self.signatures.len() != 2 {
            return Err(PapError::ReceiptError(format!(
                "expected 2 signatures, found {}",
                self.signatures.len()
            )));
        }
        self.verify_signature(0, initiator_key)?;
        self.verify_signature(1, receiver_key)?;
        Ok(())
    }

    /// Return the Schema.org action type for this receipt.
    pub fn action_type(&self) -> &str {
        &self.action
    }

    /// Add a session attestation from one party.
    /// Both the initiating and receiving agents should attest to the
    /// session outcome for bilateral verification.
    pub fn add_attestation(&mut self, attestation: SessionAttestation) -> Result<(), PapError> {
        // Validate that the attestation refers to this receipt's session
        if attestation.session_id != self.session_id {
            return Err(PapError::AttestationError(format!(
                "attestation session_id {} does not match receipt session_id {}",
                attestation.session_id, self.session_id
            )));
        }

        // Validate that the attester is one of the session parties
        if attestation.attester_did != self.initiating_agent_did
            && attestation.attester_did != self.receiving_agent_did
        {
            return Err(PapError::AttestationError(format!(
                "attester {} is not a party to session {}",
                attestation.attester_did, self.session_id
            )));
        }

        // Prevent duplicate attestation from the same party
        if self
            .attestations
            .iter()
            .any(|a| a.attester_did == attestation.attester_did)
        {
            return Err(PapError::AttestationError(format!(
                "duplicate attestation from {}",
                attestation.attester_did
            )));
        }

        self.attestations.push(attestation);
        Ok(())
    }

    /// Determine the attestation status of this receipt.
    pub fn attestation_status(&self) -> AttestationStatus {
        let has_initiator = self
            .attestations
            .iter()
            .any(|a| a.attester_did == self.initiating_agent_did);
        let has_receiver = self
            .attestations
            .iter()
            .any(|a| a.attester_did == self.receiving_agent_did);

        match (has_initiator, has_receiver) {
            (true, true) => AttestationStatus::BilaterallyAttested,
            (true, false) | (false, true) => AttestationStatus::UnilaterallyAttested,
            (false, false) => AttestationStatus::Unattested,
        }
    }

    /// Verify all attestation signatures on this receipt.
    /// Takes a mapping from DID to verifying key.
    pub fn verify_attestations(
        &self,
        keys: &HashMap<String, VerifyingKey>,
    ) -> Result<(), PapError> {
        for attestation in &self.attestations {
            let key = keys.get(&attestation.attester_did).ok_or_else(|| {
                PapError::AttestationError(format!(
                    "no verifying key for attester {}",
                    attestation.attester_did
                ))
            })?;
            attestation.verify(key)?;
        }
        Ok(())
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("receipt serialization cannot fail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{CapabilityToken, Session};
    use chrono::Duration;
    use pap_test_utils::{did_from_key, make_keypair};

    fn make_executed_session() -> Session {
        let issuer_key = make_keypair();
        let issuer_did = did_from_key(&issuer_key);
        let target_did = "did:key:ztarget".to_string();

        let mut token = CapabilityToken::mint(
            target_did.clone(),
            "schema:SearchAction".into(),
            issuer_did,
            Utc::now() + Duration::hours(1),
        );
        token.sign(&issuer_key).unwrap();

        let mut session =
            Session::initiate(&token, &target_did, &issuer_key.verifying_key()).unwrap();
        session
            .open("did:key:zinit_sess".into(), "did:key:zrecv_sess".into())
            .unwrap();
        session.execute().unwrap();
        session
    }

    #[test]
    fn receipt_from_session_and_cosign() {
        let session = make_executed_session();
        let init_session_key = make_keypair();
        let recv_session_key = make_keypair();

        let mut receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec!["operator:search_executed".into()],
            "schema:SearchAction executed".into(),
            "schema:SearchResult returned".into(),
        )
        .unwrap();

        receipt.co_sign(&init_session_key);
        receipt.co_sign(&recv_session_key);

        assert_eq!(receipt.signatures.len(), 2);
        assert!(receipt
            .verify_both(
                &init_session_key.verifying_key(),
                &recv_session_key.verifying_key()
            )
            .is_ok());
    }

    #[test]
    fn receipt_zero_disclosure() {
        let session = make_executed_session();
        let receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec!["operator:search_executed".into()],
            "schema:SearchAction executed".into(),
            "schema:SearchResult returned".into(),
        )
        .unwrap();

        assert!(receipt.disclosed_by_initiator.is_empty());
    }

    #[test]
    fn receipt_json_roundtrip() {
        let session = make_executed_session();
        let init_key = make_keypair();
        let recv_key = make_keypair();

        let mut receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec!["operator:search_executed".into()],
            "schema:SearchAction executed".into(),
            "schema:SearchResult returned".into(),
        )
        .unwrap();
        receipt.co_sign(&init_key);
        receipt.co_sign(&recv_key);

        let json = receipt.to_json();
        let receipt2: TransactionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt.session_id, receipt2.session_id);
        assert_eq!(receipt.signatures.len(), receipt2.signatures.len());
    }

    #[test]
    fn wrong_key_verify_fails() {
        let session = make_executed_session();
        let init_key = make_keypair();
        let recv_key = make_keypair();
        let wrong_key = make_keypair();

        let mut receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap();
        receipt.co_sign(&init_key);
        receipt.co_sign(&recv_key);

        assert!(receipt
            .verify_both(&wrong_key.verifying_key(), &recv_key.verifying_key())
            .is_err());
    }

    // ─── SessionAttestation Tests ───────────────────────────────────

    /// Parameterized attestation sign/verify test body.
    fn attestation_sign_verify_for_algorithm(algorithm: SignatureAlgorithm) {
        assert_eq!(algorithm, SignatureAlgorithm::Ed25519);
        let key = make_keypair();
        let did = did_from_key(&key);

        let mut att = SessionAttestation::new(
            "session-123",
            &did,
            SessionOutcome::Fulfilled,
            "schema:SearchAction",
        );
        assert_eq!(att.algorithm, algorithm);

        att.sign(&key).unwrap();
        assert!(att.signature.is_some());
        assert!(att.verify(&key.verifying_key()).is_ok());
    }

    #[test]
    fn attestation_sign_and_verify() {
        attestation_sign_verify_for_algorithm(SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn attestation_verify_wrong_key_fails() {
        let key = make_keypair();
        let wrong_key = make_keypair();
        let did = did_from_key(&key);

        let mut att = SessionAttestation::new(
            "session-123",
            &did,
            SessionOutcome::Fulfilled,
            "schema:SearchAction",
        );
        att.sign(&key).unwrap();

        assert!(att.verify(&wrong_key.verifying_key()).is_err());
    }

    #[test]
    fn attestation_unsigned_verify_fails() {
        let key = make_keypair();
        let att = SessionAttestation::new(
            "session-123",
            "did:key:ztest",
            SessionOutcome::Fulfilled,
            "schema:SearchAction",
        );

        assert!(matches!(
            att.verify(&key.verifying_key()),
            Err(PapError::AttestationError(_))
        ));
    }

    #[test]
    fn attestation_serialization_roundtrip() {
        let mut att = SessionAttestation::new(
            "session-456",
            "did:key:zattester",
            SessionOutcome::Partial,
            "schema:ReserveAction",
        );
        let key = make_keypair();
        att.sign(&key).unwrap();

        let json = serde_json::to_string(&att).unwrap();
        let att2: SessionAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(att.session_id, att2.session_id);
        assert_eq!(att.attester_did, att2.attester_did);
        assert_eq!(att.outcome, att2.outcome);
        assert_eq!(att.action_type, att2.action_type);
        assert_eq!(att.signature, att2.signature);
    }

    #[test]
    fn session_outcome_display() {
        assert_eq!(SessionOutcome::Fulfilled.as_str(), "fulfilled");
        assert_eq!(SessionOutcome::Partial.as_str(), "partial");
        assert_eq!(SessionOutcome::Failed.as_str(), "failed");
        assert_eq!(SessionOutcome::Disputed.as_str(), "disputed");
    }

    // ─── Bilateral Attestation on Receipts Tests ────────────────────

    #[test]
    fn receipt_attestation_status_unattested() {
        let session = make_executed_session();
        let receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap();

        assert_eq!(receipt.attestation_status(), AttestationStatus::Unattested);
    }

    #[test]
    fn receipt_unilateral_attestation() {
        let session = make_executed_session();
        let init_key = make_keypair();

        let mut receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap();

        let mut att = SessionAttestation::new(
            &receipt.session_id,
            &receipt.initiating_agent_did,
            SessionOutcome::Fulfilled,
            "schema:SearchAction",
        );
        att.sign(&init_key).unwrap();

        receipt.add_attestation(att).unwrap();
        assert_eq!(
            receipt.attestation_status(),
            AttestationStatus::UnilaterallyAttested
        );
    }

    #[test]
    fn receipt_bilateral_attestation() {
        let session = make_executed_session();
        let init_key = make_keypair();
        let recv_key = make_keypair();

        let mut receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap();

        let mut init_att = SessionAttestation::new(
            &receipt.session_id,
            &receipt.initiating_agent_did,
            SessionOutcome::Fulfilled,
            "schema:SearchAction",
        );
        init_att.sign(&init_key).unwrap();

        let mut recv_att = SessionAttestation::new(
            &receipt.session_id,
            &receipt.receiving_agent_did,
            SessionOutcome::Fulfilled,
            "schema:SearchAction",
        );
        recv_att.sign(&recv_key).unwrap();

        receipt.add_attestation(init_att).unwrap();
        receipt.add_attestation(recv_att).unwrap();
        assert_eq!(
            receipt.attestation_status(),
            AttestationStatus::BilaterallyAttested
        );
    }

    #[test]
    fn receipt_attestation_wrong_session_rejected() {
        let session = make_executed_session();
        let mut receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap();

        let att = SessionAttestation::new(
            "wrong-session-id",
            &receipt.initiating_agent_did,
            SessionOutcome::Fulfilled,
            "schema:SearchAction",
        );

        assert!(matches!(
            receipt.add_attestation(att),
            Err(PapError::AttestationError(_))
        ));
    }

    #[test]
    fn receipt_attestation_non_party_rejected() {
        let session = make_executed_session();
        let mut receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap();

        let att = SessionAttestation::new(
            &receipt.session_id,
            "did:key:zoutsider",
            SessionOutcome::Fulfilled,
            "schema:SearchAction",
        );

        assert!(matches!(
            receipt.add_attestation(att),
            Err(PapError::AttestationError(_))
        ));
    }

    #[test]
    fn receipt_attestation_duplicate_rejected() {
        let session = make_executed_session();
        let init_key = make_keypair();

        let mut receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap();

        let mut att1 = SessionAttestation::new(
            &receipt.session_id,
            &receipt.initiating_agent_did,
            SessionOutcome::Fulfilled,
            "schema:SearchAction",
        );
        att1.sign(&init_key).unwrap();

        let mut att2 = SessionAttestation::new(
            &receipt.session_id,
            &receipt.initiating_agent_did,
            SessionOutcome::Disputed,
            "schema:SearchAction",
        );
        att2.sign(&init_key).unwrap();

        receipt.add_attestation(att1).unwrap();
        assert!(matches!(
            receipt.add_attestation(att2),
            Err(PapError::AttestationError(_))
        ));
    }

    #[test]
    fn receipt_verify_attestation_signatures() {
        let session = make_executed_session();
        let init_key = make_keypair();
        let recv_key = make_keypair();

        let mut receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap();

        let mut init_att = SessionAttestation::new(
            &receipt.session_id,
            &receipt.initiating_agent_did,
            SessionOutcome::Fulfilled,
            "schema:SearchAction",
        );
        init_att.sign(&init_key).unwrap();

        let mut recv_att = SessionAttestation::new(
            &receipt.session_id,
            &receipt.receiving_agent_did,
            SessionOutcome::Fulfilled,
            "schema:SearchAction",
        );
        recv_att.sign(&recv_key).unwrap();

        receipt.add_attestation(init_att).unwrap();
        receipt.add_attestation(recv_att).unwrap();

        let mut keys = HashMap::new();
        keys.insert(
            receipt.initiating_agent_did.clone(),
            init_key.verifying_key(),
        );
        keys.insert(
            receipt.receiving_agent_did.clone(),
            recv_key.verifying_key(),
        );

        assert!(receipt.verify_attestations(&keys).is_ok());
    }

    #[test]
    fn receipt_verify_attestations_wrong_key_fails() {
        let session = make_executed_session();
        let init_key = make_keypair();
        let wrong_key = make_keypair();

        let mut receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap();

        let mut att = SessionAttestation::new(
            &receipt.session_id,
            &receipt.initiating_agent_did,
            SessionOutcome::Fulfilled,
            "schema:SearchAction",
        );
        att.sign(&init_key).unwrap();

        receipt.add_attestation(att).unwrap();

        let mut keys = HashMap::new();
        keys.insert(
            receipt.initiating_agent_did.clone(),
            wrong_key.verifying_key(),
        );

        assert!(receipt.verify_attestations(&keys).is_err());
    }

    #[test]
    fn receipt_action_type_accessor() {
        let session = make_executed_session();
        let receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap();

        assert_eq!(receipt.action_type(), "schema:SearchAction");
    }

    #[test]
    fn receipt_attestation_status_display() {
        assert_eq!(AttestationStatus::Unattested.as_str(), "unattested");
        assert_eq!(
            AttestationStatus::UnilaterallyAttested.as_str(),
            "unilaterally_attested"
        );
        assert_eq!(
            AttestationStatus::BilaterallyAttested.as_str(),
            "bilaterally_attested"
        );
    }

    #[test]
    fn receipt_with_attestations_json_roundtrip() {
        let session = make_executed_session();
        let init_key = make_keypair();

        let mut receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap();

        let mut att = SessionAttestation::new(
            &receipt.session_id,
            &receipt.initiating_agent_did,
            SessionOutcome::Fulfilled,
            "schema:SearchAction",
        );
        att.sign(&init_key).unwrap();
        receipt.add_attestation(att).unwrap();

        let json = receipt.to_json();
        let receipt2: TransactionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt.attestations.len(), receipt2.attestations.len());
        assert_eq!(
            receipt.attestations[0].attester_did,
            receipt2.attestations[0].attester_did
        );
    }

    // ─── Reputation Profile Tests ───────────────────────────────────

    #[test]
    fn reputation_profile_empty() {
        let profile = ReputationProfile::new();
        assert_eq!(profile.total_receipts(), 0);
        assert_eq!(profile.segment_count(), 0);
        assert!(profile.segment("schema:SearchAction").is_none());
    }

    #[test]
    fn reputation_profile_record_single_receipt() {
        let session = make_executed_session();
        let receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap();

        let mut profile = ReputationProfile::new();
        profile.record_receipt(&receipt);

        assert_eq!(profile.total_receipts(), 1);
        assert_eq!(profile.segment_count(), 1);

        let seg = profile.segment("schema:SearchAction").unwrap();
        assert_eq!(seg.total_receipts, 1);
        assert_eq!(seg.bilateral_attestations, 0);
        assert_eq!(seg.unique_counterparties, 2); // both initiator and receiver
    }

    #[test]
    fn reputation_profile_segments_by_action() {
        let issuer_key = make_keypair();
        let issuer_did = did_from_key(&issuer_key);

        // Create a SearchAction session
        let target_did = "did:key:ztarget".to_string();
        let mut search_token = CapabilityToken::mint(
            target_did.clone(),
            "schema:SearchAction".into(),
            issuer_did.clone(),
            Utc::now() + Duration::hours(1),
        );
        search_token.sign(&issuer_key).unwrap();
        let mut search_session =
            Session::initiate(&search_token, &target_did, &issuer_key.verifying_key()).unwrap();
        search_session
            .open("did:key:zinit1".into(), "did:key:zrecv1".into())
            .unwrap();
        search_session.execute().unwrap();

        let search_receipt = TransactionReceipt::from_session(
            &search_session,
            vec![],
            vec![],
            "search".into(),
            "results".into(),
        )
        .unwrap();

        // Create a ReserveAction session
        let mut reserve_token = CapabilityToken::mint(
            target_did.clone(),
            "schema:ReserveAction".into(),
            issuer_did,
            Utc::now() + Duration::hours(1),
        );
        reserve_token.sign(&issuer_key).unwrap();
        let mut reserve_session =
            Session::initiate(&reserve_token, &target_did, &issuer_key.verifying_key()).unwrap();
        reserve_session
            .open("did:key:zinit2".into(), "did:key:zrecv2".into())
            .unwrap();
        reserve_session.execute().unwrap();

        let reserve_receipt = TransactionReceipt::from_session(
            &reserve_session,
            vec!["schema:Person.schema:name".into()],
            vec![],
            "reserve".into(),
            "confirmation".into(),
        )
        .unwrap();

        let mut profile = ReputationProfile::new();
        profile.record_receipt(&search_receipt);
        profile.record_receipt(&reserve_receipt);

        assert_eq!(profile.total_receipts(), 2);
        assert_eq!(profile.segment_count(), 2);

        let search_seg = profile.segment("schema:SearchAction").unwrap();
        assert_eq!(search_seg.total_receipts, 1);

        let reserve_seg = profile.segment("schema:ReserveAction").unwrap();
        assert_eq!(reserve_seg.total_receipts, 1);

        // Search reputation does not leak into reserve reputation
        assert!(profile.segment("schema:PayAction").is_none());
    }

    #[test]
    fn reputation_profile_counts_bilateral_attestations() {
        let session = make_executed_session();
        let init_key = make_keypair();
        let recv_key = make_keypair();

        let mut receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap();

        // Add bilateral attestation
        let mut init_att = SessionAttestation::new(
            &receipt.session_id,
            &receipt.initiating_agent_did,
            SessionOutcome::Fulfilled,
            "schema:SearchAction",
        );
        init_att.sign(&init_key).unwrap();
        let mut recv_att = SessionAttestation::new(
            &receipt.session_id,
            &receipt.receiving_agent_did,
            SessionOutcome::Fulfilled,
            "schema:SearchAction",
        );
        recv_att.sign(&recv_key).unwrap();
        receipt.add_attestation(init_att).unwrap();
        receipt.add_attestation(recv_att).unwrap();

        let mut profile = ReputationProfile::new();
        profile.record_receipt(&receipt);

        let seg = profile.segment("schema:SearchAction").unwrap();
        assert_eq!(seg.bilateral_attestations, 1);
    }

    #[test]
    fn reputation_profile_does_not_count_unilateral_as_bilateral() {
        let session = make_executed_session();
        let init_key = make_keypair();

        let mut receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap();

        // Only initiator attests — unilateral
        let mut att = SessionAttestation::new(
            &receipt.session_id,
            &receipt.initiating_agent_did,
            SessionOutcome::Fulfilled,
            "schema:SearchAction",
        );
        att.sign(&init_key).unwrap();
        receipt.add_attestation(att).unwrap();

        let mut profile = ReputationProfile::new();
        profile.record_receipt(&receipt);

        let seg = profile.segment("schema:SearchAction").unwrap();
        assert_eq!(seg.total_receipts, 1);
        assert_eq!(seg.bilateral_attestations, 0);
    }

    #[test]
    fn reputation_profile_tracks_unique_counterparties() {
        let issuer_key = make_keypair();
        let issuer_did = did_from_key(&issuer_key);
        let target_did = "did:key:ztarget".to_string();

        // Two sessions with different counterparties
        let mut token1 = CapabilityToken::mint(
            target_did.clone(),
            "schema:SearchAction".into(),
            issuer_did.clone(),
            Utc::now() + Duration::hours(1),
        );
        token1.sign(&issuer_key).unwrap();
        let mut s1 = Session::initiate(&token1, &target_did, &issuer_key.verifying_key()).unwrap();
        s1.open("did:key:zinit_a".into(), "did:key:zrecv_a".into())
            .unwrap();
        s1.execute().unwrap();

        let mut token2 = CapabilityToken::mint(
            target_did.clone(),
            "schema:SearchAction".into(),
            issuer_did,
            Utc::now() + Duration::hours(1),
        );
        token2.sign(&issuer_key).unwrap();
        let mut s2 = Session::initiate(&token2, &target_did, &issuer_key.verifying_key()).unwrap();
        s2.open("did:key:zinit_b".into(), "did:key:zrecv_b".into())
            .unwrap();
        s2.execute().unwrap();

        let r1 =
            TransactionReceipt::from_session(&s1, vec![], vec![], "e".into(), "r".into()).unwrap();
        let r2 =
            TransactionReceipt::from_session(&s2, vec![], vec![], "e".into(), "r".into()).unwrap();

        let mut profile = ReputationProfile::new();
        profile.record_receipt(&r1);
        profile.record_receipt(&r2);

        let seg = profile.segment("schema:SearchAction").unwrap();
        assert_eq!(seg.total_receipts, 2);
        // 4 unique DIDs: zinit_a, zrecv_a, zinit_b, zrecv_b
        assert_eq!(seg.unique_counterparties, 4);
    }

    #[test]
    fn reputation_segment_serialization_roundtrip() {
        let seg = ReputationSegment::new("schema:SearchAction");
        let json = serde_json::to_string(&seg).unwrap();
        let seg2: ReputationSegment = serde_json::from_str(&json).unwrap();
        assert_eq!(seg.action_type, seg2.action_type);
        assert_eq!(seg.total_receipts, seg2.total_receipts);
    }

    #[test]
    fn reputation_profile_serialization_roundtrip() {
        let mut profile = ReputationProfile::new();

        let session = make_executed_session();
        let receipt = TransactionReceipt::from_session(
            &session,
            vec![],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap();
        profile.record_receipt(&receipt);

        let json = serde_json::to_string(&profile).unwrap();
        let profile2: ReputationProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile.total_receipts(), profile2.total_receipts());
        assert_eq!(profile.segment_count(), profile2.segment_count());
    }

    // ─── Disclosure Hash Tests ──────────────────────────────────────

    /// Two receipts built from the same session but with different Phase 3
    /// disclosure sets must produce different disclosure hashes, and their
    /// co-signatures must therefore differ.
    #[test]
    fn receipt_disclosure_hash_committed_in_canonical_bytes() {
        let session = make_executed_session();
        let signing_key = make_keypair();

        let disclosures_a =
            vec![serde_json::json!({"claim": "email", "value": "alice@example.com"})];
        let disclosures_b = vec![
            serde_json::json!({"claim": "email", "value": "alice@example.com"}),
            serde_json::json!({"claim": "dob", "value": "1990-01-01"}),
        ];

        let mut receipt_a = TransactionReceipt::from_session(
            &session,
            vec!["schema:Person.schema:email".into()],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap()
        .with_disclosure_hash(&disclosures_a);

        let mut receipt_b = TransactionReceipt::from_session(
            &session,
            vec![
                "schema:Person.schema:email".into(),
                "schema:Person.schema:birthDate".into(),
            ],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap()
        .with_disclosure_hash(&disclosures_b);

        // Hashes must differ
        assert_ne!(receipt_a.disclosure_hash, receipt_b.disclosure_hash);

        // Co-sign both with the same key — canonical bytes differ, so
        // signatures differ.
        receipt_a.co_sign(&signing_key);
        receipt_b.co_sign(&signing_key);

        assert_ne!(receipt_a.signatures[0], receipt_b.signatures[0]);
    }

    /// verify_disclosure_hash succeeds when the same disclosure set is
    /// provided as was committed via with_disclosure_hash.
    #[test]
    fn receipt_disclosure_hash_verification_passes() {
        let session = make_executed_session();
        let disclosures = vec![serde_json::json!({"claim": "email", "value": "bob@example.com"})];

        let receipt = TransactionReceipt::from_session(
            &session,
            vec!["schema:Person.schema:email".into()],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap()
        .with_disclosure_hash(&disclosures);

        assert!(receipt.disclosure_hash.is_some());
        assert!(receipt.verify_disclosure_hash(&disclosures).is_ok());
    }

    /// verify_disclosure_hash returns Err when a different disclosure set is
    /// provided, catching the case where an agent under-reports disclosures.
    #[test]
    fn receipt_disclosure_hash_verification_fails_on_mismatch() {
        let session = make_executed_session();
        let real_disclosures = vec![
            serde_json::json!({"claim": "email", "value": "carol@example.com"}),
            serde_json::json!({"claim": "ssn", "value": "123-45-6789"}),
        ];
        let claimed_disclosures =
            vec![serde_json::json!({"claim": "email", "value": "carol@example.com"})];

        // Receipt is built with the real (larger) disclosure set
        let receipt = TransactionReceipt::from_session(
            &session,
            vec!["schema:Person.schema:email".into()],
            vec![],
            "executed".into(),
            "returned".into(),
        )
        .unwrap()
        .with_disclosure_hash(&real_disclosures);

        // Verifying against the under-reported set must fail
        let result = receipt.verify_disclosure_hash(&claimed_disclosures);
        assert!(matches!(result, Err(PapError::ReceiptError(_))));
    }
}
