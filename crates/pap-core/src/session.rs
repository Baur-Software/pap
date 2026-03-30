use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

use crate::error::PapError;
use crate::scope::{DisclosureSet, Scope};

/// Result of validating disclosure requirements against TEE availability.
///
/// This enum communicates the enforcement level to callers without
/// making policy decisions (e.g., printing warnings or blocking).
/// Callers inspect the variant and decide their own response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureValidation {
    /// No `no_retention` entries — no TEE required.
    NotRequired,
    /// TEE attestation present — `no_retention` is cryptographically enforced.
    TeeEnforced,
    /// No TEE available — `no_retention` is a contractual term only.
    /// The protocol cannot prevent post-session data retention without TEE.
    ContractualOnly,
}

/// Session state machine: Initiated -> Open -> Executed -> Closed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Token presented, awaiting verification
    Initiated,
    /// Handshake complete, session DIDs exchanged
    Open,
    /// Transaction executed within session
    Executed,
    /// Session closed, ephemeral keys discarded
    Closed,
}

impl SessionState {
    pub fn can_transition_to(&self, next: SessionState) -> bool {
        matches!(
            (self, next),
            (SessionState::Initiated, SessionState::Open)
                | (SessionState::Open, SessionState::Executed)
                | (SessionState::Executed, SessionState::Closed)
                | (SessionState::Initiated, SessionState::Closed)
                | (SessionState::Open, SessionState::Closed)
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SessionState::Initiated => "Initiated",
            SessionState::Open => "Open",
            SessionState::Executed => "Executed",
            SessionState::Closed => "Closed",
        }
    }
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A capability token is a single-use proof that an agent is authorized to
/// open a session with a specific target for a specific action.
/// Bound to: target DID + action + nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// Unique token identifier
    pub id: String,
    /// DID of the target agent this token is valid for
    pub target_did: String,
    /// Schema.org action reference this token authorizes
    pub action: String,
    /// Single-use nonce — consumed when the session opens
    pub nonce: String,
    /// DID of the issuer (orchestrator)
    pub issuer_did: String,
    /// Issuance timestamp
    pub issued_at: DateTime<Utc>,
    /// Expiry timestamp
    pub expires_at: DateTime<Utc>,
    /// Signature by the issuer (base64-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl CapabilityToken {
    /// Mint a new capability token.
    pub fn mint(
        target_did: String,
        action: String,
        issuer_did: String,
        ttl: DateTime<Utc>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            target_did,
            action,
            nonce: Uuid::new_v4().to_string(),
            issuer_did,
            issued_at: Utc::now(),
            expires_at: ttl,
            signature: None,
        }
    }

    /// Sign the token with the issuer's key.
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        let bytes = self.canonical_bytes();
        let sig = signing_key.sign(&bytes);
        use base64::Engine;
        self.signature =
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()));
    }

    /// Verify the token's signature.
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<(), PapError> {
        let sig_b64 = self
            .signature
            .as_ref()
            .ok_or_else(|| PapError::TokenError("unsigned token".into()))?;
        use base64::Engine;
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| PapError::TokenError(format!("invalid signature encoding: {e}")))?;
        let signature = Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| PapError::TokenError("invalid signature length".into()))?,
        );
        let bytes = self.canonical_bytes();
        verifying_key
            .verify(&bytes, &signature)
            .map_err(|_| PapError::VerificationFailed)
    }

    /// Verify the token against a target DID and consumed nonce set.
    pub fn verify(
        &self,
        target_did: &str,
        issuer_key: &VerifyingKey,
        consumed_nonces: &HashSet<String>,
    ) -> Result<(), PapError> {
        if self.target_did != target_did {
            return Err(PapError::TokenTargetMismatch);
        }
        if consumed_nonces.contains(&self.nonce) {
            return Err(PapError::NonceConsumed);
        }
        if Utc::now() > self.expires_at {
            return Err(PapError::MandateExpired);
        }
        self.verify_signature(issuer_key)
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let canonical = serde_json::json!({
            "id": self.id,
            "target_did": self.target_did,
            "action": self.action,
            "nonce": self.nonce,
            "issuer_did": self.issuer_did,
            "issued_at": self.issued_at.to_rfc3339(),
            "expires_at": self.expires_at.to_rfc3339(),
        });
        serde_json::to_vec(&canonical).expect("canonical serialization cannot fail")
    }
}

/// A protocol session between two agents.
pub struct Session {
    pub id: String,
    pub state: SessionState,
    pub initiator_session_did: Option<String>,
    pub receiver_session_did: Option<String>,
    pub action: String,
    pub scope: Scope,
    pub created_at: DateTime<Utc>,
    consumed_nonces: HashSet<String>,
    /// Optional TEE attestation evidence (spec section 13.6).
    /// Present only when the `tee` feature is enabled and the
    /// receiving agent provides attestation during session open.
    #[cfg(feature = "tee")]
    pub attestation: Option<pap_tee::AttestationEvidence>,
}

impl Session {
    /// Initiate a new session with a capability token.
    pub fn initiate(
        token: &CapabilityToken,
        receiver_did: &str,
        issuer_key: &VerifyingKey,
    ) -> Result<Self, PapError> {
        let mut consumed = HashSet::new();
        token.verify(receiver_did, issuer_key, &consumed)?;
        consumed.insert(token.nonce.clone());

        Ok(Self {
            id: Uuid::new_v4().to_string(),
            state: SessionState::Initiated,
            initiator_session_did: None,
            receiver_session_did: None,
            action: token.action.clone(),
            scope: Scope::new(vec![crate::scope::ScopeAction::new(&token.action)]),
            created_at: Utc::now(),
            consumed_nonces: consumed,
            #[cfg(feature = "tee")]
            attestation: None,
        })
    }

    /// Validate that disclosure requirements are satisfiable for the
    /// current session. If any disclosure entry has `no_retention: true`,
    /// the session MUST have TEE attestation — without it, the protocol
    /// cannot enforce the retention constraint once plaintext enters
    /// untrusted host memory.
    ///
    /// Returns [`DisclosureValidation`] indicating the enforcement level:
    /// - `TeeEnforced` — TEE attestation present, retention constraint is cryptographic
    /// - `ContractualOnly` — no TEE available, `no_retention` is a contractual term only
    /// - `NotRequired` — no `no_retention` entries in the disclosure set
    ///
    /// With the `tee` feature enabled, `ContractualOnly` is promoted to an error
    /// (the caller opted into TEE enforcement but the session lacks attestation).
    pub fn validate_disclosure_requirements(
        &self,
        disclosure_set: &DisclosureSet,
    ) -> Result<DisclosureValidation, PapError> {
        if !disclosure_set.requires_tee() {
            return Ok(DisclosureValidation::NotRequired);
        }

        #[cfg(feature = "tee")]
        {
            if self.attestation.is_none() {
                return Err(PapError::NoRetentionRequiresTee(
                    "mandate contains no_retention disclosure but session has no TEE attestation"
                        .into(),
                ));
            }
            return Ok(DisclosureValidation::TeeEnforced);
        }

        #[cfg(not(feature = "tee"))]
        {
            Ok(DisclosureValidation::ContractualOnly)
        }
    }

    /// Open the session by exchanging ephemeral session DIDs.
    pub fn open(
        &mut self,
        initiator_session_did: String,
        receiver_session_did: String,
    ) -> Result<(), PapError> {
        self.transition(SessionState::Open)?;
        self.initiator_session_did = Some(initiator_session_did);
        self.receiver_session_did = Some(receiver_session_did);
        Ok(())
    }

    /// Open the session with TEE attestation evidence (spec section 13.6).
    ///
    /// Like [`open`](Self::open), but additionally stores attestation
    /// evidence provided by the receiving agent. The caller is responsible
    /// for verifying the evidence via [`pap_tee::AttestationVerifier`]
    /// before calling this method.
    #[cfg(feature = "tee")]
    pub fn open_with_attestation(
        &mut self,
        initiator_session_did: String,
        receiver_session_did: String,
        attestation: pap_tee::AttestationEvidence,
    ) -> Result<(), PapError> {
        self.open(initiator_session_did, receiver_session_did)?;
        self.attestation = Some(attestation);
        Ok(())
    }

    /// Mark the session as executed.
    pub fn execute(&mut self) -> Result<(), PapError> {
        self.transition(SessionState::Executed)
    }

    /// Close the session.
    pub fn close(&mut self) -> Result<(), PapError> {
        self.transition(SessionState::Closed)
    }

    /// Returns true if this session has TEE attestation evidence.
    pub fn has_tee_attestation(&self) -> bool {
        #[cfg(feature = "tee")]
        {
            self.attestation.is_some()
        }
        #[cfg(not(feature = "tee"))]
        {
            false
        }
    }

    /// Check if a nonce has been consumed in this session.
    pub fn is_nonce_consumed(&self, nonce: &str) -> bool {
        self.consumed_nonces.contains(nonce)
    }

    fn transition(&mut self, next: SessionState) -> Result<(), PapError> {
        if self.state.can_transition_to(next) {
            self.state = next;
            Ok(())
        } else {
            Err(PapError::InvalidSessionTransition(
                self.state.to_string(),
                next.to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
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
    fn capability_token_mint_sign_verify() {
        let issuer_key = make_keypair();
        let issuer_did = did_from_key(&issuer_key);
        let target_did = "did:key:ztarget".to_string();

        let mut token = CapabilityToken::mint(
            target_did.clone(),
            "schema:SearchAction".into(),
            issuer_did,
            Utc::now() + Duration::hours(1),
        );

        token.sign(&issuer_key);
        let consumed = HashSet::new();
        assert!(token
            .verify(&target_did, &issuer_key.verifying_key(), &consumed)
            .is_ok());
    }

    #[test]
    fn token_wrong_target_rejected() {
        let issuer_key = make_keypair();
        let issuer_did = did_from_key(&issuer_key);

        let mut token = CapabilityToken::mint(
            "did:key:ztarget".into(),
            "schema:SearchAction".into(),
            issuer_did,
            Utc::now() + Duration::hours(1),
        );
        token.sign(&issuer_key);

        let consumed = HashSet::new();
        assert!(matches!(
            token.verify(
                "did:key:zwrong_target",
                &issuer_key.verifying_key(),
                &consumed
            ),
            Err(PapError::TokenTargetMismatch)
        ));
    }

    #[test]
    fn token_nonce_replay_rejected() {
        let issuer_key = make_keypair();
        let issuer_did = did_from_key(&issuer_key);
        let target_did = "did:key:ztarget".to_string();

        let mut token = CapabilityToken::mint(
            target_did.clone(),
            "schema:SearchAction".into(),
            issuer_did,
            Utc::now() + Duration::hours(1),
        );
        token.sign(&issuer_key);

        let mut consumed = HashSet::new();
        consumed.insert(token.nonce.clone());
        assert!(matches!(
            token.verify(&target_did, &issuer_key.verifying_key(), &consumed),
            Err(PapError::NonceConsumed)
        ));
    }

    #[test]
    fn session_state_machine() {
        let issuer_key = make_keypair();
        let issuer_did = did_from_key(&issuer_key);
        let target_did = "did:key:ztarget".to_string();

        let mut token = CapabilityToken::mint(
            target_did.clone(),
            "schema:SearchAction".into(),
            issuer_did,
            Utc::now() + Duration::hours(1),
        );
        token.sign(&issuer_key);

        let mut session =
            Session::initiate(&token, &target_did, &issuer_key.verifying_key()).unwrap();
        assert_eq!(session.state, SessionState::Initiated);

        session
            .open("did:key:zinit_sess".into(), "did:key:zrecv_sess".into())
            .unwrap();
        assert_eq!(session.state, SessionState::Open);

        session.execute().unwrap();
        assert_eq!(session.state, SessionState::Executed);

        session.close().unwrap();
        assert_eq!(session.state, SessionState::Closed);
    }

    #[test]
    fn session_nonce_consumed_on_initiation() {
        let issuer_key = make_keypair();
        let issuer_did = did_from_key(&issuer_key);
        let target_did = "did:key:ztarget".to_string();

        let mut token = CapabilityToken::mint(
            target_did.clone(),
            "schema:SearchAction".into(),
            issuer_did,
            Utc::now() + Duration::hours(1),
        );
        token.sign(&issuer_key);

        let nonce = token.nonce.clone();
        let session = Session::initiate(&token, &target_did, &issuer_key.verifying_key()).unwrap();
        assert!(session.is_nonce_consumed(&nonce));
    }

    #[test]
    fn session_invalid_transition_rejected() {
        let issuer_key = make_keypair();
        let issuer_did = did_from_key(&issuer_key);
        let target_did = "did:key:ztarget".to_string();

        let mut token = CapabilityToken::mint(
            target_did.clone(),
            "schema:SearchAction".into(),
            issuer_did,
            Utc::now() + Duration::hours(1),
        );
        token.sign(&issuer_key);

        let mut session =
            Session::initiate(&token, &target_did, &issuer_key.verifying_key()).unwrap();
        assert!(session.execute().is_err());
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn has_tee_attestation_false_without_feature() {
        let issuer_key = make_keypair();
        let issuer_did = did_from_key(&issuer_key);
        let target_did = "did:key:ztarget".to_string();

        let mut token = CapabilityToken::mint(
            target_did.clone(),
            "schema:SearchAction".into(),
            issuer_did,
            Utc::now() + Duration::hours(1),
        );
        token.sign(&issuer_key);

        let _session = Session::initiate(&token, &target_did, &issuer_key.verifying_key()).unwrap();

        // Without tee feature, attestation is always absent
        assert!(!_session.has_tee_attestation());
    }

    #[test]
    fn validate_disclosure_ok_without_no_retention() {
        let issuer_key = make_keypair();
        let issuer_did = did_from_key(&issuer_key);
        let target_did = "did:key:ztarget".to_string();

        let mut token = CapabilityToken::mint(
            target_did.clone(),
            "schema:SearchAction".into(),
            issuer_did,
            Utc::now() + Duration::hours(1),
        );
        token.sign(&issuer_key);

        let session = Session::initiate(&token, &target_did, &issuer_key.verifying_key()).unwrap();

        // Disclosure set without no_retention should return NotRequired
        let ds = crate::scope::DisclosureSet::new(vec![crate::scope::DisclosureEntry::new(
            "schema:Person",
            vec!["schema:name".into()],
            vec![],
        )]);
        assert_eq!(
            session.validate_disclosure_requirements(&ds).unwrap(),
            DisclosureValidation::NotRequired
        );
    }

    #[test]
    fn validate_disclosure_ok_for_empty_set() {
        let issuer_key = make_keypair();
        let issuer_did = did_from_key(&issuer_key);
        let target_did = "did:key:ztarget".to_string();

        let mut token = CapabilityToken::mint(
            target_did.clone(),
            "schema:SearchAction".into(),
            issuer_did,
            Utc::now() + Duration::hours(1),
        );
        token.sign(&issuer_key);

        let session = Session::initiate(&token, &target_did, &issuer_key.verifying_key()).unwrap();

        let ds = crate::scope::DisclosureSet::empty();
        assert_eq!(
            session.validate_disclosure_requirements(&ds).unwrap(),
            DisclosureValidation::NotRequired
        );
    }

    /// When TEE feature is NOT enabled and no_retention is present,
    /// validation returns ContractualOnly (caller decides what to do).
    #[cfg(not(feature = "tee"))]
    #[test]
    fn validate_disclosure_contractual_without_tee_feature() {
        let issuer_key = make_keypair();
        let issuer_did = did_from_key(&issuer_key);
        let target_did = "did:key:ztarget".to_string();

        let mut token = CapabilityToken::mint(
            target_did.clone(),
            "schema:SearchAction".into(),
            issuer_did,
            Utc::now() + Duration::hours(1),
        );
        token.sign(&issuer_key);

        let session = Session::initiate(&token, &target_did, &issuer_key.verifying_key()).unwrap();

        let ds = crate::scope::DisclosureSet::new(vec![crate::scope::DisclosureEntry::new(
            "schema:Person",
            vec!["schema:name".into()],
            vec![],
        )
        .no_retention()]);
        // Without tee feature: returns ContractualOnly, caller decides policy
        assert_eq!(
            session.validate_disclosure_requirements(&ds).unwrap(),
            DisclosureValidation::ContractualOnly
        );
    }

    /// When TEE feature IS enabled and no_retention is present but
    /// no attestation was provided, validation must fail.
    #[cfg(feature = "tee")]
    #[test]
    fn validate_disclosure_fails_without_attestation() {
        let issuer_key = make_keypair();
        let issuer_did = did_from_key(&issuer_key);
        let target_did = "did:key:ztarget".to_string();

        let mut token = CapabilityToken::mint(
            target_did.clone(),
            "schema:SearchAction".into(),
            issuer_did,
            Utc::now() + Duration::hours(1),
        );
        token.sign(&issuer_key);

        let session = Session::initiate(&token, &target_did, &issuer_key.verifying_key()).unwrap();

        let ds = crate::scope::DisclosureSet::new(vec![crate::scope::DisclosureEntry::new(
            "schema:Person",
            vec!["schema:name".into()],
            vec![],
        )
        .no_retention()]);
        // With tee feature but no attestation: must fail
        let result = session.validate_disclosure_requirements(&ds);
        assert!(matches!(result, Err(PapError::NoRetentionRequiresTee(_))));
    }

    /// When TEE feature IS enabled and attestation is present,
    /// validation should pass even with no_retention.
    #[cfg(feature = "tee")]
    #[test]
    fn validate_disclosure_passes_with_attestation() {
        let issuer_key = make_keypair();
        let issuer_did = did_from_key(&issuer_key);
        let target_did = "did:key:ztarget".to_string();

        let mut token = CapabilityToken::mint(
            target_did.clone(),
            "schema:SearchAction".into(),
            issuer_did,
            Utc::now() + Duration::hours(1),
        );
        token.sign(&issuer_key);

        let mut session =
            Session::initiate(&token, &target_did, &issuer_key.verifying_key()).unwrap();

        // Open with attestation
        let measurement = pap_tee::AttestationEvidence::compute_measurement(b"test-enclave-v1");
        let report = {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"mock-report")
        };
        let evidence = pap_tee::AttestationEvidence {
            enclave_type: pap_tee::EnclaveType::Software,
            measurement,
            attestation_report: report,
            timestamp: Utc::now(),
            nonce: uuid::Uuid::new_v4().to_string(),
        };

        session
            .open_with_attestation(
                "did:key:zinit_sess".into(),
                "did:key:zrecv_sess".into(),
                evidence,
            )
            .unwrap();

        assert!(session.has_tee_attestation());

        let ds = crate::scope::DisclosureSet::new(vec![crate::scope::DisclosureEntry::new(
            "schema:Person",
            vec!["schema:name".into()],
            vec![],
        )
        .no_retention()]);
        assert_eq!(
            session.validate_disclosure_requirements(&ds).unwrap(),
            DisclosureValidation::TeeEnforced
        );
    }
}
