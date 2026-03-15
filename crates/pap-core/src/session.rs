use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

use crate::error::PapError;
use crate::scope::Scope;

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
        })
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

    /// Mark the session as executed.
    pub fn execute(&mut self) -> Result<(), PapError> {
        self.transition(SessionState::Executed)
    }

    /// Close the session.
    pub fn close(&mut self) -> Result<(), PapError> {
        self.transition(SessionState::Closed)
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
}
