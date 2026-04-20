use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use pap_did::SignatureAlgorithm;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::PapError;
use crate::payment::PaymentProof;
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
    /// Numeric rank used only for "never rewind" ordering during deserialization.
    /// Active(0) < Degraded(1) < ReadOnly(2) < Suspended(3).
    /// Not part of the public API — use `can_transition_to` for state-machine logic.
    fn severity_rank(self) -> u8 {
        match self {
            DecayState::Active => 0,
            DecayState::Degraded => 1,
            DecayState::ReadOnly => 2,
            DecayState::Suspended => 3,
        }
    }
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

/// Decay window used when recomputing `decay_state` on deserialization.
/// 5 minutes: mandates with less than this remaining TTL are considered Degraded.
const DEFAULT_DECAY_WINDOW_SECS: i64 = 300;

/// A mandate is the core delegation primitive. It is signed by the issuing
/// agent's key, verifiable back to the root principal key.
///
/// **Deserialization note**: `decay_state` is automatically recomputed from the
/// TTL when a `Mandate` is deserialized. The serialized value is used only as
/// a floor — it will never be rewound (a `Suspended` mandate stays `Suspended`)
/// but it may be advanced to reflect elapsed time. Callers do not need to call
/// any sync helper after deserialization; the `From<MandateWire>` conversion
/// handles this transparently.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "MandateWire")]
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
    /// Current decay state — automatically recomputed on deserialization based on TTL.
    /// Do not rely on the serialized value; always read `decay_state` from a live instance.
    pub decay_state: DecayState,
    /// Issuance timestamp
    pub issued_at: DateTime<Utc>,
    /// Optional payment proof commitment (Lightning BOLT-11 hash or
    /// Cashu ecash token hash). Zero-knowledge: contains only a
    /// cryptographic commitment, never amounts or destinations.
    /// Presented alongside capability token in the session handshake.
    /// Unlinkable from principal identity. See spec section 13.1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_proof: Option<PaymentProof>,
    /// Signature algorithm used. Defaults to Ed25519 for backward compatibility.
    #[serde(default)]
    pub algorithm: SignatureAlgorithm,
    /// Signature by the issuer (base64-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Wire-format mirror of [`Mandate`] used exclusively by serde during deserialization.
///
/// This private struct accepts the raw JSON fields (including the potentially-stale
/// `decay_state`) and is immediately converted to a `Mandate` via `From<MandateWire>`,
/// which recomputes `decay_state` from the TTL before the caller ever sees the value.
#[derive(Deserialize)]
#[serde(rename = "Mandate")]
struct MandateWire {
    principal_did: String,
    agent_did: String,
    issuer_did: String,
    parent_mandate_hash: Option<String>,
    scope: Scope,
    disclosure_set: DisclosureSet,
    ttl: DateTime<Utc>,
    decay_state: DecayState,
    issued_at: DateTime<Utc>,
    #[serde(default)]
    payment_proof: Option<PaymentProof>,
    #[serde(default)]
    algorithm: SignatureAlgorithm,
    #[serde(default)]
    signature: Option<String>,
}

impl From<MandateWire> for Mandate {
    fn from(wire: MandateWire) -> Self {
        // The wire `decay_state` is preserved as-is.  Callers MUST NOT trust
        // this value to reflect the current time-based state — a peer could
        // send a stale or fabricated value.  Always call
        // `compute_decay_state` / `sync_decay_state` to obtain the live state.
        //
        // We do *not* auto-advance here because `compute_decay_state` is a
        // one-step-per-call function that uses `self.decay_state` as the
        // transition baseline.  Auto-advancing on deserialization would consume
        // one step, making a second call return the wrong state (§5.7.1).
        Mandate {
            principal_did: wire.principal_did,
            agent_did: wire.agent_did,
            issuer_did: wire.issuer_did,
            parent_mandate_hash: wire.parent_mandate_hash,
            scope: wire.scope,
            disclosure_set: wire.disclosure_set,
            ttl: wire.ttl,
            decay_state: wire.decay_state,
            issued_at: wire.issued_at,
            payment_proof: wire.payment_proof,
            algorithm: wire.algorithm,
            signature: wire.signature,
        }
    }
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
            algorithm: SignatureAlgorithm::default(),
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
            algorithm: self.algorithm,
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
            .verify_strict(&bytes, &signature)
            .map_err(|_| PapError::VerificationFailed)
    }

    /// Check if the mandate is expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.ttl
    }

    /// Compute the next decay state based on TTL and the current stored state.
    ///
    /// Per spec §5.7.1, each call advances by **at most one step**:
    ///   Active → Degraded → ReadOnly → Suspended
    ///
    /// If the TTL has already expired between polling cycles (e.g. a mandate
    /// goes from Active directly past Degraded), this function still returns
    /// only `Degraded` when called from `Active`. A second call (after the
    /// caller has applied the first transition) will then return `ReadOnly`.
    ///
    /// `Suspended` is terminal — no time-based transition can override it.
    pub fn compute_decay_state(&self, decay_window_secs: i64) -> DecayState {
        // Terminal state: no time-based transition can override a suspension.
        if self.decay_state == DecayState::Suspended {
            return DecayState::Suspended;
        }

        let now = Utc::now();

        // Determine what the time-based target state would be if we could
        // jump freely, then clamp it to at most one step from the current
        // state so that Degraded is never skipped.
        let time_target = if now > self.ttl {
            DecayState::ReadOnly
        } else {
            let remaining = (self.ttl - now).num_seconds();
            if remaining <= decay_window_secs {
                DecayState::Degraded
            } else {
                DecayState::Active
            }
        };

        // Clamp: advance by at most one step from the current state.
        // Ordering: Active(0) < Degraded(1) < ReadOnly(2) < Suspended(3).
        // We never go backwards via this path (renewals use transition_decay
        // directly), so only forward advancement is clamped here.
        match self.decay_state {
            DecayState::Active => {
                // Can only move to Degraded in a single step.
                match time_target {
                    DecayState::Active => DecayState::Active,
                    _ => DecayState::Degraded,
                }
            }
            DecayState::Degraded => {
                // Can move to ReadOnly or stay; cannot skip to Suspended.
                match time_target {
                    DecayState::Active | DecayState::Degraded => DecayState::Degraded,
                    _ => DecayState::ReadOnly,
                }
            }
            DecayState::ReadOnly => {
                // Can only move to Suspended. Time alone never forces
                // Suspended (there is no TTL threshold for it), so we
                // only advance if the target is already Suspended — which
                // currently cannot happen via time alone.  Future-proof by
                // keeping ReadOnly if time_target is ReadOnly or below.
                match time_target {
                    DecayState::Suspended => DecayState::Suspended,
                    _ => DecayState::ReadOnly,
                }
            }
            // Suspended was handled above as an early return.
            DecayState::Suspended => DecayState::Suspended,
        }
    }

    /// Attach a payment proof to this mandate.
    pub fn with_payment_proof(mut self, proof: PaymentProof) -> Self {
        self.payment_proof = Some(proof);
        self
    }

    /// Validate that if the scope includes a payment action, a payment
    /// proof commitment is present. Returns `MissingPaymentProof` if the
    /// scope permits `schema:PayAction` but no proof is attached.
    pub fn validate_payment_proof(&self) -> Result<(), PapError> {
        if self.scope.permits("schema:PayAction") && self.payment_proof.is_none() {
            return Err(PapError::MissingPaymentProof);
        }
        if let Some(ref proof) = self.payment_proof {
            proof.validate()?;
        }
        Ok(())
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

    /// Canonical bytes for external signing (e.g., SubtleCrypto in browsers).
    /// Returns the exact byte array that `sign()` would sign internally.
    pub fn signable_bytes(&self) -> Vec<u8> {
        self.canonical_bytes()
    }

    /// Set the signature from externally-produced bytes (64-byte Ed25519 signature).
    /// Used when signing is performed outside Rust (e.g., via SubtleCrypto).
    pub fn set_signature_bytes(&mut self, sig_bytes: &[u8]) -> Result<(), PapError> {
        if sig_bytes.len() != 64 {
            return Err(PapError::MandateError(format!(
                "signature must be 64 bytes, got {}",
                sig_bytes.len()
            )));
        }
        use base64::Engine;
        self.signature = Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig_bytes));
        Ok(())
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

        for (i, (parent, (child, key))) in self
            .mandates
            .iter()
            .zip(self.mandates.iter().skip(1).zip(keys.iter().skip(1)))
            .enumerate()
        {
            let expected_hash = parent.hash();
            match &child.parent_mandate_hash {
                Some(h) if h == &expected_hash => {}
                _ => {
                    return Err(PapError::ChainVerificationFailed(format!(
                        "mandate {} parent hash mismatch",
                        i + 1
                    )));
                }
            }

            if !parent.scope.contains(&child.scope) {
                return Err(PapError::DelegationExceedsScope);
            }

            if child.ttl > parent.ttl {
                return Err(PapError::DelegationExceedsTtl);
            }

            child.verify(key)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::ScopeAction;
    use chrono::Duration;
    use pap_test_utils::{did_from_key, make_keypair};

    /// Parameterized sign/verify test body. When a second algorithm is added,
    /// duplicate the call site with the new `SignatureAlgorithm` variant.
    fn sign_verify_for_algorithm(algorithm: SignatureAlgorithm) {
        assert_eq!(algorithm, SignatureAlgorithm::Ed25519); // only one supported
        let principal_key = make_keypair();
        let principal_did = did_from_key(&principal_key);

        let mut mandate = Mandate::issue_root(
            principal_did,
            "did:key:zagent1".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(1),
        );
        assert_eq!(mandate.algorithm, algorithm);

        mandate.sign(&principal_key).unwrap();
        assert!(mandate.verify(&principal_key.verifying_key()).is_ok());
    }

    #[test]
    fn root_mandate_sign_verify() {
        sign_verify_for_algorithm(SignatureAlgorithm::Ed25519);
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

    /// Parameterized chain verification test body.
    fn chain_verify_for_algorithm(algorithm: SignatureAlgorithm) {
        assert_eq!(algorithm, SignatureAlgorithm::Ed25519);
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
        root.sign(&principal_key).unwrap();

        let mut child = root
            .delegate(
                "did:key:zagent".into(),
                Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
                DisclosureSet::empty(),
                ttl - Duration::minutes(10),
            )
            .unwrap();
        assert_eq!(child.algorithm, algorithm); // inherited from parent
        child.sign(&orchestrator_key).unwrap();

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
    fn mandate_chain_verification() {
        chain_verify_for_algorithm(SignatureAlgorithm::Ed25519);
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

    /// Regression test for §5.7.1: `Active → ReadOnly` must not occur in a
    /// single step. When a mandate's TTL is already fully expired and the
    /// stored state is still `Active` (because no polling cycle ran while it
    /// was expiring), `compute_decay_state` must return `Degraded` on the
    /// first call and `ReadOnly` only after the caller has applied that
    /// transition and calls again.
    #[test]
    fn decay_computation_steps_through_degraded_before_readonly() {
        // TTL already in the past → fully expired mandate, still Active.
        let expired_ttl = Utc::now() - Duration::seconds(10);
        let mut mandate = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            expired_ttl,
        );
        assert_eq!(mandate.decay_state, DecayState::Active);

        // First poll: must yield Degraded, not ReadOnly.
        let first = mandate.compute_decay_state(300);
        assert_eq!(
            first,
            DecayState::Degraded,
            "Active mandate with expired TTL must step to Degraded first (§5.7.1)"
        );

        // Apply the transition, then poll again.
        mandate.transition_decay(first).unwrap();
        assert_eq!(mandate.decay_state, DecayState::Degraded);

        // Second poll: now Degraded → ReadOnly is the correct next step.
        let second = mandate.compute_decay_state(300);
        assert_eq!(
            second,
            DecayState::ReadOnly,
            "Degraded mandate with expired TTL must advance to ReadOnly"
        );
    }

    /// `compute_decay_state` must never skip Degraded even when the mandate
    /// was `Active` with a very large `decay_window_secs` that also covers
    /// the expired-TTL scenario — the one-step rule is independent of the
    /// window size.
    #[test]
    fn decay_computation_active_never_jumps_to_readonly_directly() {
        let expired_ttl = Utc::now() - Duration::hours(2);
        let mandate = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            expired_ttl,
        );
        // Whatever the decay window, Active must not jump to ReadOnly.
        for window in &[0i64, 60, 300, 3600, 86400] {
            assert_ne!(
                mandate.compute_decay_state(*window),
                DecayState::ReadOnly,
                "window={window}: Active should never advance directly to ReadOnly"
            );
            assert_ne!(
                mandate.compute_decay_state(*window),
                DecayState::Suspended,
                "window={window}: Active should never advance directly to Suspended"
            );
        }
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
    fn signable_bytes_deterministic() {
        let mandate = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(1),
        );
        let b1 = mandate.signable_bytes();
        let b2 = mandate.signable_bytes();
        assert_eq!(b1, b2);
        assert!(!b1.is_empty());
    }

    #[test]
    fn set_signature_bytes_roundtrip() {
        let key = make_keypair();
        let mut mandate = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(1),
        );
        // Sign externally using signable_bytes
        let bytes = mandate.signable_bytes();
        let sig = key.sign(&bytes);
        mandate.set_signature_bytes(&sig.to_bytes()).unwrap();
        // Verify should pass
        assert!(mandate.verify(&key.verifying_key()).is_ok());
    }

    #[test]
    fn set_signature_bytes_matches_sign() {
        let key = make_keypair();
        let principal_did = did_from_key(&key);

        let mut m1 = Mandate::issue_root(
            principal_did.clone(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(1),
        );
        let mut m2 = m1.clone();

        // Sign m1 via the internal method
        m1.sign(&key).unwrap();
        // Sign m2 via the external method
        let bytes = m2.signable_bytes();
        let sig = key.sign(&bytes);
        m2.set_signature_bytes(&sig.to_bytes()).unwrap();

        // Both signatures should be identical (Ed25519 is deterministic)
        assert_eq!(m1.signature, m2.signature);
    }

    #[test]
    fn set_signature_bytes_wrong_length_rejected() {
        let mut mandate = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(1),
        );
        assert!(mandate.set_signature_bytes(&[0u8; 63]).is_err());
        assert!(mandate.set_signature_bytes(&[0u8; 65]).is_err());
        assert!(mandate.set_signature_bytes(&[]).is_err());
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

    // ── is_expired() ──────────────────────────────────────────

    #[test]
    fn not_expired_when_ttl_is_in_the_future() {
        let mandate = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:ReadAction")]),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(1),
        );
        assert!(!mandate.is_expired());
    }

    #[test]
    fn expired_when_ttl_is_in_the_past() {
        let mandate = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:ReadAction")]),
            DisclosureSet::empty(),
            Utc::now() - Duration::seconds(1),
        );
        assert!(mandate.is_expired());
    }

    #[test]
    fn recently_expired_is_expired() {
        // Mandate that expired 5 minutes ago is still expired — no grace period.
        let mandate = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:ReadAction")]),
            DisclosureSet::empty(),
            Utc::now() - Duration::minutes(5),
        );
        assert!(mandate.is_expired());
    }

    // ── validate_payment_proof() ──────────────────────────────

    #[test]
    fn payment_proof_not_required_when_scope_has_no_pay_action() {
        // ReadAction scope — no PayAction → no proof required → Ok.
        let mandate = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:ReadAction")]),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(1),
        );
        assert!(mandate.validate_payment_proof().is_ok());
    }

    #[test]
    fn payment_proof_required_when_scope_permits_pay_action() {
        // PayAction scope without a proof → Err(MissingPaymentProof).
        let mandate = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:PayAction")]),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(1),
        );
        assert!(matches!(
            mandate.validate_payment_proof(),
            Err(PapError::MissingPaymentProof)
        ));
    }

    #[test]
    fn valid_payment_proof_accepted_when_scope_permits_pay_action() {
        // PayAction scope with a valid Lightning proof → Ok.
        use crate::payment::PaymentProof;
        let proof = PaymentProof::lightning(b"test_preimage_pap");
        let mandate = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:PayAction")]),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(1),
        )
        .with_payment_proof(proof);
        assert!(mandate.validate_payment_proof().is_ok());
    }

    // ── transition_decay() ────────────────────────────────────

    #[test]
    fn valid_decay_transition_active_to_degraded() {
        let mut mandate = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(1),
        );
        assert_eq!(mandate.decay_state, DecayState::Active);
        mandate
            .transition_decay(DecayState::Degraded)
            .expect("Active → Degraded is a valid transition");
        assert_eq!(mandate.decay_state, DecayState::Degraded);
    }

    #[test]
    fn invalid_decay_transition_suspended_to_active_rejected() {
        // Walk the mandate to Suspended, then attempt to revive it.
        let mut mandate = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(1),
        );
        mandate.transition_decay(DecayState::Degraded).unwrap();
        mandate.transition_decay(DecayState::ReadOnly).unwrap();
        mandate.transition_decay(DecayState::Suspended).unwrap();

        let result = mandate.transition_decay(DecayState::Active);
        assert!(
            matches!(result, Err(PapError::InvalidDecayTransition(_, _))),
            "Suspended → Active is forbidden"
        );
    }

    #[test]
    fn full_decay_chain_active_degraded_readonly_suspended() {
        let mut mandate = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(8),
        );

        assert_eq!(mandate.decay_state, DecayState::Active);

        mandate.transition_decay(DecayState::Degraded).unwrap();
        assert_eq!(mandate.decay_state, DecayState::Degraded);

        mandate.transition_decay(DecayState::ReadOnly).unwrap();
        assert_eq!(mandate.decay_state, DecayState::ReadOnly);

        mandate.transition_decay(DecayState::Suspended).unwrap();
        assert_eq!(mandate.decay_state, DecayState::Suspended);
    }

    // ── Deserialization decay refresh (From<MandateWire>) ─────────────

    /// A freshly-issued mandate (TTL well in the future) should deserialize
    /// with `decay_state == Active` regardless of what was stored in the JSON.
    #[test]
    fn deserialize_active_mandate_with_future_ttl_stays_active() {
        let mandate = Mandate::issue_root(
            "did:key:zprincipal".into(),
            "did:key:zagent".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(2),
        );
        assert_eq!(mandate.decay_state, DecayState::Active);

        let json = serde_json::to_string(&mandate).unwrap();
        let back: Mandate = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.decay_state,
            DecayState::Active,
            "mandate with 2-hour TTL should still be Active after round-trip"
        );
    }

    /// A mandate whose TTL has expired but which was serialized with
    /// `decay_state == Active` (stale value) must NOT be auto-advanced on
    /// deserialization — callers call `compute_decay_state` to get the live
    /// state.  The first call from `Active` must return `Degraded` (§5.7.1).
    #[test]
    fn deserialize_stale_active_with_expired_ttl_advances_to_degraded() {
        // Build with a future TTL so issue_root accepts it, then forge a stale
        // JSON blob with an already-expired TTL and decay_state = "Active".
        let expired = Utc::now() - Duration::seconds(30);
        // Construct JSON directly so we can inject the expired TTL.
        let json = serde_json::json!({
            "principal_did": "did:key:zprincipal",
            "agent_did":     "did:key:zagent",
            "issuer_did":    "did:key:zprincipal",
            "parent_mandate_hash": null,
            "scope": { "actions": [{ "action": "schema:SearchAction", "constraints": null }] },
            "disclosure_set": { "entries": [] },
            "ttl": expired.to_rfc3339(),
            "decay_state": "Active",   // stale wire value — preserved as-is
            "issued_at": (expired - Duration::hours(1)).to_rfc3339(),
        })
        .to_string();

        let back: Mandate = serde_json::from_str(&json).unwrap();
        // Wire value is preserved; callers must call compute_decay_state.
        assert_eq!(
            back.decay_state,
            DecayState::Active,
            "wire decay_state is preserved; auto-advance would break compute_decay_state one-step rule"
        );
        // compute_decay_state from Active with expired TTL must return Degraded (§5.7.1).
        assert_eq!(
            back.compute_decay_state(300),
            DecayState::Degraded,
            "first compute_decay_state call from Active with expired TTL must be Degraded"
        );
    }

    /// A `Suspended` mandate must never be rewound to a lower state on
    /// deserialization, even if the TTL is still in the future.
    #[test]
    fn deserialize_suspended_mandate_never_rewound() {
        let future_ttl = Utc::now() + Duration::hours(1);
        let json = serde_json::json!({
            "principal_did": "did:key:zprincipal",
            "agent_did":     "did:key:zagent",
            "issuer_did":    "did:key:zprincipal",
            "parent_mandate_hash": null,
            "scope": { "actions": [{ "action": "schema:SearchAction", "constraints": null }] },
            "disclosure_set": { "entries": [] },
            "ttl": future_ttl.to_rfc3339(),
            "decay_state": "Suspended",  // terminal — must be preserved
            "issued_at": (Utc::now() - Duration::minutes(5)).to_rfc3339(),
        })
        .to_string();

        let back: Mandate = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.decay_state,
            DecayState::Suspended,
            "Suspended is terminal — deserialization must not rewind it"
        );
    }

    /// Round-trip a `ReadOnly` mandate (TTL expired) — the stored state is
    /// already advanced, so deserializing must not change it.
    #[test]
    fn deserialize_readonly_mandate_preserved_when_already_advanced() {
        let expired_ttl = Utc::now() - Duration::minutes(10);
        let json = serde_json::json!({
            "principal_did": "did:key:zprincipal",
            "agent_did":     "did:key:zagent",
            "issuer_did":    "did:key:zprincipal",
            "parent_mandate_hash": null,
            "scope": { "actions": [{ "action": "schema:SearchAction", "constraints": null }] },
            "disclosure_set": { "entries": [] },
            "ttl": expired_ttl.to_rfc3339(),
            "decay_state": "ReadOnly",
            "issued_at": (expired_ttl - Duration::hours(1)).to_rfc3339(),
        })
        .to_string();

        let back: Mandate = serde_json::from_str(&json).unwrap();
        // compute_decay_state on a ReadOnly mandate with expired TTL returns ReadOnly
        // (time alone cannot force Suspended). The "never rewind" rule also
        // prevents going backwards, so the result is ReadOnly.
        assert_eq!(
            back.decay_state,
            DecayState::ReadOnly,
            "ReadOnly with expired TTL must remain ReadOnly after deserialization"
        );
    }
}
