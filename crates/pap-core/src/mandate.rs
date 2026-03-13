use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::PapError;
use crate::scope::{DisclosureSet, Scope};

/// Decay state for a mandate's scope as TTL progresses without renewal.
/// Active -> Degraded -> ReadOnly -> Suspended
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecayState {
    /// Full scope, within TTL
    Active,
    /// Reduced scope, TTL within decay window, renewal pending
    Degraded,
    /// No execution, observation only, TTL expired, root has not renewed
    ReadOnly,
    /// No activity, awaiting principal review
    Suspended,
}

impl DecayState {
    /// Valid transitions follow strict ordering.
    pub fn can_transition_to(&self, next: DecayState) -> bool {
        matches!(
            (self, next),
            (DecayState::Active, DecayState::Degraded)
                | (DecayState::Degraded, DecayState::ReadOnly)
                | (DecayState::ReadOnly, DecayState::Suspended)
                // Renewal can restore to Active from any non-Suspended state
                | (DecayState::Degraded, DecayState::Active)
                | (DecayState::ReadOnly, DecayState::Active)
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            DecayState::Active => "Active",
            DecayState::Degraded => "Degraded",
            DecayState::ReadOnly => "ReadOnly",
            DecayState::Suspended => "Suspended",
        }
    }
}

impl std::fmt::Display for DecayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A mandate is the core delegation primitive. It is signed by the issuing
/// agent's key, verifiable back to the root principal key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mandate {
    /// DID of the human principal (root of trust)
    pub principal_did: String,
    /// DID of the delegated agent receiving this mandate
    pub agent_did: String,
    /// DID of the issuing agent (signer)
    pub issuer_did: String,
    /// SHA-256 hash of the parent mandate, None if this is the root mandate
    pub parent_mandate_hash: Option<String>,
    /// Permitted actions — deny by default
    pub scope: Scope,
    /// Context classes held and shareable
    pub disclosure_set: DisclosureSet,
    /// Expiry timestamp
    pub ttl: DateTime<Utc>,
    /// Current decay state
    pub decay_state: DecayState,
    /// Issuance timestamp
    pub issued_at: DateTime<Utc>,
    /// Optional payment proof (Chaumian ecash blind-signed token or
    /// Lightning preimage). Presented alongside capability token in
    /// the session handshake. Unlinkable from principal identity.
    /// See PAP v0.1 spec section 9.1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_proof: Option<String>,
    /// Ed25519 signature by the issuer (base64-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Mandate {
    /// Create a new root mandate (issued directly by the principal).
    pub fn issue_root(
        principal_did: String,
        agent_did: String,
        scope: Scope,
        disclosure_set: DisclosureSet,
        ttl: DateTime<Utc>,
    ) -> Self {
        let now = Utc::now();
        Self {
            principal_did: principal_did.clone(),
            agent_did,
            issuer_did: principal_did,
            parent_mandate_hash: None,
            scope,
            disclosure_set,
            ttl,
            decay_state: DecayState::Active,
            issued_at: now,
            payment_proof: None,
            signature: None,
        }
    }

    /// Delegate a child mandate from this mandate.
    /// Enforces: child scope cannot exceed parent, child TTL cannot exceed parent.
    pub fn delegate(
        &self,
        agent_did: String,
        scope: Scope,
        disclosure_set: DisclosureSet,
        ttl: DateTime<Utc>,
    ) -> Result<Mandate, PapError> {
        if !self.scope.contains(&scope) {
            return Err(PapError::DelegationExceedsScope);
        }
        if ttl > self.ttl {
            return Err(PapError::DelegationExceedsTtl);
        }
        let parent_hash = self.hash();
        let now = Utc::now();
        Ok(Mandate {
            principal_did: self.principal_did.clone(),
            agent_did,
            issuer_did: self.agent_did.clone(),
            parent_mandate_hash: Some(parent_hash),
            scope,
            disclosure_set,
            ttl,
            decay_state: DecayState::Active,
            issued_at: now,
            payment_proof: None,
            signature: None,
        })
    }

    /// SHA-256 hash of the mandate's canonical form (excluding signature).
    pub fn hash(&self) -> String {
        let canonical = self.canonical_bytes();
        let digest = Sha256::digest(&canonical);
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    }

    /// Sign this mandate with the issuer's signing key.
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        let bytes = self.canonical_bytes();
        let sig = signing_key.sign(&bytes);
        use base64::Engine;
        self.signature = Some(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        );
    }

    /// Verify this mandate's signature against the issuer's public key.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), PapError> {
        let sig_b64 = self
            .signature
            .as_ref()
            .ok_or_else(|| PapError::MandateError("unsigned mandate".into()))?;
        use base64::Engine;
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| PapError::MandateError(format!("invalid signature encoding: {e}")))?;
        let signature = Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| PapError::MandateError("invalid signature length".into()))?,
        );
        let bytes = self.canonical_bytes();
        verifying_key
            .verify(&bytes, &signature)
            .map_err(|_| PapError::VerificationFailed)
    }

    /// Check if the mandate is expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.ttl
    }

    /// Compute the current decay state based on TTL.
    pub fn compute_decay_state(&self, decay_window_secs: i64) -> DecayState {
        let now = Utc::now();
        if now > self.ttl {
            if self.decay_state == DecayState::Suspended {
                DecayState::Suspended
            } else {
                DecayState::ReadOnly
            }
        } else {
            let remaining = (self.ttl - now).num_seconds();
            if remaining <= decay_window_secs {
                DecayState::Degraded
            } else {
                DecayState::Active
            }
        }
    }

    /// Transition the decay state, validating the transition.
    pub fn transition_decay(&mut self, next: DecayState) -> Result<(), PapError> {
        if self.decay_state.can_transition_to(next) {
            self.decay_state = next;
            Ok(())
        } else {
            Err(PapError::InvalidDecayTransition(
                self.decay_state.to_string(),
                next.to_string(),
            ))
        }
    }

    /// Canonical bytes for signing/hashing (excludes signature field).
    fn canonical_bytes(&self) -> Vec<u8> {
        let canonical = serde_json::json!({
            "principal_did": self.principal_did,
            "agent_did": self.agent_did,
            "issuer_did": self.issuer_did,
            "parent_mandate_hash": self.parent_mandate_hash,
            "scope": self.scope,
            "disclosure_set": self.disclosure_set,
            "ttl": self.ttl.to_rfc3339(),
            "issued_at": self.issued_at.to_rfc3339(),
            "payment_proof": self.payment_proof,
        });
        serde_json::to_vec(&canonical).expect("canonical serialization cannot fail")
    }
}

/// A chain of mandates from root to leaf, each signed by the previous.
#[derive(Debug, Clone)]
pub struct MandateChain {
    pub mandates: Vec<Mandate>,
}

impl MandateChain {
    pub fn new(root: Mandate) -> Self {
        Self {
            mandates: vec![root],
        }
    }

    pub fn push(&mut self, mandate: Mandate) {
        self.mandates.push(mandate);
    }

    /// The leaf (most recent) mandate in the chain.
    pub fn leaf(&self) -> &Mandate {
        self.mandates.last().expect("chain cannot be empty")
    }

    /// The root mandate in the chain.
    pub fn root(&self) -> &Mandate {
        self.mandates.first().expect("chain cannot be empty")
    }

    /// Verify the entire chain:
    /// 1. Root must have no parent hash
    /// 2. Each subsequent mandate's parent_mandate_hash == hash of previous
    /// 3. Each mandate's scope is a subset of its parent's scope
    /// 4. Each mandate's TTL does not exceed its parent's TTL
    /// 5. Each mandate's signature is valid
    pub fn verify_chain(&self, keys: &[VerifyingKey]) -> Result<(), PapError> {
        if self.mandates.len() != keys.len() {
            return Err(PapError::ChainVerificationFailed(
                "key count does not match mandate count".into(),
            ));
        }

        let root = &self.mandates[0];
        if root.parent_mandate_hash.is_some() {
            return Err(PapError::ChainVerificationFailed(
                "root mandate must not have a parent hash".into(),
            ));
        }
        root.verify(&keys[0])?;

        for i in 1..self.mandates.len() {
            let parent = &self.mandates[i - 1];
            let child = &self.mandates[i];

            let expected_hash = parent.hash();
            match &child.parent_mandate_hash {
                Some(h) if h == &expected_hash => {}
                _ => {
                    return Err(PapError::ChainVerificationFailed(format!(
                        "mandate {} parent hash mismatch",
                        i
                    )));
                }
            }

            if !parent.scope.contains(&child.scope) {
                return Err(PapError::DelegationExceedsScope);
            }

            if child.ttl > parent.ttl {
                return Err(PapError::DelegationExceedsTtl);
            }

            child.verify(&keys[i])?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::ScopeAction;
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
    fn root_mandate_sign_verify() {
        let principal_key = make_keypair();
        let principal_did = did_from_key(&principal_key);

        let mut mandate = Mandate::issue_root(
            principal_did,
            "did:key:zagent1".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(1),
        );

        mandate.sign(&principal_key);
        assert!(mandate.verify(&principal_key.verifying_key()).is_ok());
    }

    #[test]
    fn delegation_within_scope() {
        let principal_key = make_keypair();
        let principal_did = did_from_key(&principal_key);
        let ttl = Utc::now() + Duration::hours(1);

        let root = Mandate::issue_root(
            principal_did,
            "did:key:zorchestrator".into(),
            Scope::new(vec![
                ScopeAction::new("schema:SearchAction"),
                ScopeAction::new("schema:PayAction"),
            ]),
            DisclosureSet::empty(),
            ttl,
        );

        let child = root
            .delegate(
                "did:key:zagent".into(),
                Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
                DisclosureSet::empty(),
                ttl - Duration::minutes(30),
            )
            .unwrap();

        assert!(child.parent_mandate_hash.is_some());
        assert_eq!(child.parent_mandate_hash.unwrap(), root.hash());
    }

    #[test]
    fn delegation_exceeds_scope_rejected() {
        let root = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zorchestrator".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(1),
        );

        let result = root.delegate(
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:PayAction")]),
            DisclosureSet::empty(),
            Utc::now() + Duration::minutes(30),
        );

        assert!(matches!(result, Err(PapError::DelegationExceedsScope)));
    }

    #[test]
    fn delegation_exceeds_ttl_rejected() {
        let parent_ttl = Utc::now() + Duration::hours(1);
        let root = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zorchestrator".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            parent_ttl,
        );

        let result = root.delegate(
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            parent_ttl + Duration::hours(1),
        );

        assert!(matches!(result, Err(PapError::DelegationExceedsTtl)));
    }

    #[test]
    fn mandate_chain_verification() {
        let principal_key = make_keypair();
        let orchestrator_key = make_keypair();
        let principal_did = did_from_key(&principal_key);
        let orchestrator_did = did_from_key(&orchestrator_key);
        let ttl = Utc::now() + Duration::hours(1);

        let mut root = Mandate::issue_root(
            principal_did,
            orchestrator_did,
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            ttl,
        );
        root.sign(&principal_key);

        let mut child = root
            .delegate(
                "did:key:zagent".into(),
                Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
                DisclosureSet::empty(),
                ttl - Duration::minutes(10),
            )
            .unwrap();
        child.sign(&orchestrator_key);

        let chain = MandateChain {
            mandates: vec![root, child],
        };

        assert!(chain
            .verify_chain(&[
                principal_key.verifying_key(),
                orchestrator_key.verifying_key(),
            ])
            .is_ok());
    }

    #[test]
    fn decay_state_transitions() {
        assert!(DecayState::Active.can_transition_to(DecayState::Degraded));
        assert!(!DecayState::Active.can_transition_to(DecayState::Suspended));

        assert!(DecayState::Degraded.can_transition_to(DecayState::Active));
        assert!(DecayState::Degraded.can_transition_to(DecayState::ReadOnly));

        assert!(DecayState::ReadOnly.can_transition_to(DecayState::Suspended));
        assert!(DecayState::ReadOnly.can_transition_to(DecayState::Active));

        assert!(!DecayState::Suspended.can_transition_to(DecayState::Active));
    }

    #[test]
    fn mandate_decay_computation() {
        let ttl = Utc::now() + Duration::seconds(120);
        let mandate = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            ttl,
        );

        assert_eq!(mandate.compute_decay_state(60), DecayState::Active);
        assert_eq!(mandate.compute_decay_state(300), DecayState::Degraded);
    }

    #[test]
    fn mandate_hash_stability() {
        let mandate = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(1),
        );
        let h1 = mandate.hash();
        let h2 = mandate.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn unsigned_mandate_verify_fails() {
        let key = make_keypair();
        let mandate = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(1),
        );
        assert!(mandate.verify(&key.verifying_key()).is_err());
    }
}
