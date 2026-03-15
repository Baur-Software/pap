//! Python bindings for the Principal Agent Protocol (PAP).
//!
//! Exposes all core PAP primitives to Python via PyO3:
//! - Key generation (PrincipalKeypair / SessionKeypair)
//! - Mandate issuance and delegation
//! - SD-JWT selective disclosure
//! - Marketplace registry query
//! - AgentClient HTTP transport
//! - Transaction receipt handling
#![allow(clippy::useless_conversion)]
// PyO3 0.22's `create_exception!` macro emits `cfg(gil-refs)` checks that
// trigger `unexpected_cfgs` on recent Rust nightlies. They are harmless —
// silence them so `cargo check` has a clean output.
#![allow(unexpected_cfgs)]

use chrono::DateTime;
use ed25519_dalek::VerifyingKey;
use once_cell::sync::Lazy;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Custom exception hierarchy
// ---------------------------------------------------------------------------

pyo3::create_exception!(
    pap._pap,
    PapError,
    pyo3::exceptions::PyException,
    "Base exception for all PAP protocol errors."
);
pyo3::create_exception!(
    pap._pap,
    PapSignatureError,
    PapError,
    "Raised when a signature is missing, invalid, or verification fails."
);
pyo3::create_exception!(
    pap._pap,
    PapScopeError,
    PapError,
    "Raised when a delegation would exceed the parent scope or TTL."
);
pyo3::create_exception!(
    pap._pap,
    PapSessionError,
    PapError,
    "Raised on invalid session state transitions or nonce replay."
);
pyo3::create_exception!(
    pap._pap,
    PapTransportError,
    PapError,
    "Raised on HTTP transport failures or unexpected server responses."
);

// ---------------------------------------------------------------------------
// Global tokio runtime for blocking on async transport methods
// ---------------------------------------------------------------------------

static RT: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime for pap-python")
});

// ---------------------------------------------------------------------------
// DateTime helper
// ---------------------------------------------------------------------------

fn parse_dt(s: &str) -> PyResult<DateTime<chrono::Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| PyValueError::new_err(format!("invalid datetime '{}': {}", s, e)))
}

fn verifying_key_from_bytes(bytes: &[u8]) -> PyResult<VerifyingKey> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PyValueError::new_err("public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| PyValueError::new_err(format!("invalid public key: {}", e)))
}

// ===========================================================================
// pap-did: PrincipalKeypair
// ===========================================================================

/// Root keypair bound to a human principal. Generated once and stored securely.
/// In production this wraps a WebAuthn / platform authenticator credential.
#[pyclass(module = "pap._pap")]
pub struct PrincipalKeypair {
    inner: pap_did::PrincipalKeypair,
}

#[pymethods]
impl PrincipalKeypair {
    /// Generate a fresh Ed25519 principal keypair.
    #[staticmethod]
    fn generate() -> Self {
        Self {
            inner: pap_did::PrincipalKeypair::generate(),
        }
    }

    /// Reconstruct a keypair from 32 raw secret key bytes.
    #[staticmethod]
    fn from_secret_bytes(bytes: &[u8]) -> PyResult<Self> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| PyValueError::new_err("expected 32 bytes for secret key"))?;
        pap_did::PrincipalKeypair::from_bytes(&arr)
            .map(|inner| Self { inner })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// The `did:key:z…` identifier derived from this keypair.
    fn did(&self) -> String {
        self.inner.did()
    }

    /// Raw 32-byte public key bytes.
    fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key_bytes().to_vec()
    }

    /// Sign arbitrary bytes. Returns 64-byte Ed25519 signature.
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        self.inner.signing_key().sign(message).to_bytes().to_vec()
    }

    /// Verify a 64-byte Ed25519 signature against this keypair's public key.
    fn verify(&self, message: &[u8], signature: &[u8]) -> PyResult<()> {
        let arr: [u8; 64] = signature
            .try_into()
            .map_err(|_| PyValueError::new_err("signature must be 64 bytes"))?;
        let sig = ed25519_dalek::Signature::from_bytes(&arr);
        use ed25519_dalek::Verifier;
        self.inner
            .verifying_key()
            .verify(message, &sig)
            .map_err(|_| PyValueError::new_err("signature verification failed"))
    }

    fn __repr__(&self) -> String {
        format!("PrincipalKeypair(did='{}')", self.inner.did())
    }
}

// ===========================================================================
// pap-did: SessionKeypair
// ===========================================================================

/// Ephemeral session keypair — generated fresh for each protocol session
/// and discarded at session close. Not linked to any persistent identity.
#[pyclass(module = "pap._pap")]
pub struct SessionKeypair {
    inner: pap_did::SessionKeypair,
}

#[pymethods]
impl SessionKeypair {
    /// Generate a fresh ephemeral session keypair.
    #[staticmethod]
    fn generate() -> Self {
        Self {
            inner: pap_did::SessionKeypair::generate(),
        }
    }

    /// The ephemeral `did:key:z…` identifier for this session.
    fn did(&self) -> String {
        self.inner.did()
    }

    /// Raw 32-byte public key bytes.
    fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key_bytes().to_vec()
    }

    /// Sign arbitrary bytes. Returns 64-byte Ed25519 signature.
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        self.inner.signing_key().sign(message).to_bytes().to_vec()
    }

    /// Verify a 64-byte Ed25519 signature against this session key.
    fn verify(&self, message: &[u8], signature: &[u8]) -> PyResult<()> {
        let arr: [u8; 64] = signature
            .try_into()
            .map_err(|_| PyValueError::new_err("signature must be 64 bytes"))?;
        let sig = ed25519_dalek::Signature::from_bytes(&arr);
        use ed25519_dalek::Verifier;
        self.inner
            .verifying_key()
            .verify(message, &sig)
            .map_err(|_| PyValueError::new_err("signature verification failed"))
    }

    fn __repr__(&self) -> String {
        format!("SessionKeypair(did='{}')", self.inner.did())
    }
}

// ===========================================================================
// pap-did: utility functions
// ===========================================================================

/// Convert raw 32-byte Ed25519 public key bytes to a `did:key:z…` identifier.
#[pyfunction]
fn public_key_to_did(public_key_bytes: &[u8]) -> PyResult<String> {
    let key = verifying_key_from_bytes(public_key_bytes)?;
    Ok(pap_did::public_key_to_did(&key))
}

/// Extract 32-byte public key bytes from a `did:key:z…` identifier.
#[pyfunction]
fn did_to_public_key_bytes(did: &str) -> PyResult<Vec<u8>> {
    pap_did::did_to_public_key_bytes(did)
        .map(|b| b.to_vec())
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

// ===========================================================================
// pap-core: ScopeAction
// ===========================================================================

/// A single permitted action in a mandate scope, expressed as a Schema.org
/// action reference with optional object-type constraint.
#[pyclass(module = "pap._pap")]
#[derive(Clone)]
pub struct ScopeAction {
    pub(crate) inner: pap_core::scope::ScopeAction,
}

#[pymethods]
impl ScopeAction {
    /// Create a scope action with no object constraint.
    /// `action` should be a Schema.org action like `"schema:SearchAction"`.
    #[new]
    fn new(action: String) -> Self {
        Self {
            inner: pap_core::scope::ScopeAction::new(action),
        }
    }

    /// Create a scope action with an object-type constraint.
    #[staticmethod]
    fn with_object(action: String, object: String) -> Self {
        Self {
            inner: pap_core::scope::ScopeAction::with_object(action, object),
        }
    }

    #[getter]
    fn action(&self) -> String {
        self.inner.action.clone()
    }

    #[getter]
    fn object(&self) -> Option<String> {
        self.inner.object.clone()
    }

    fn __repr__(&self) -> String {
        match &self.inner.object {
            Some(o) => format!("ScopeAction('{}', object='{}')", self.inner.action, o),
            None => format!("ScopeAction('{}')", self.inner.action),
        }
    }
}

// ===========================================================================
// pap-core: Scope
// ===========================================================================

/// Deny-by-default set of permitted actions for a mandate.
#[pyclass(module = "pap._pap")]
#[derive(Clone)]
pub struct Scope {
    pub(crate) inner: pap_core::scope::Scope,
}

#[pymethods]
impl Scope {
    /// Create a scope permitting the given actions.
    #[new]
    fn new(actions: Vec<PyRef<ScopeAction>>) -> Self {
        Self {
            inner: pap_core::scope::Scope::new(actions.iter().map(|a| a.inner.clone()).collect()),
        }
    }

    /// Create an empty scope that denies everything.
    #[staticmethod]
    fn deny_all() -> Self {
        Self {
            inner: pap_core::scope::Scope::deny_all(),
        }
    }

    /// Returns True if this scope permits the given Schema.org action string.
    fn permits(&self, action: &str) -> bool {
        self.inner.permits(action)
    }

    /// Returns True if `child` is a strict subset of this scope.
    fn contains(&self, child: PyRef<Scope>) -> bool {
        self.inner.contains(&child.inner)
    }

    #[getter]
    fn actions(&self) -> Vec<ScopeAction> {
        self.inner
            .actions
            .iter()
            .map(|a| ScopeAction { inner: a.clone() })
            .collect()
    }

    fn __repr__(&self) -> String {
        let actions: Vec<_> = self.inner.actions.iter().map(|a| &a.action).collect();
        format!(
            "Scope({})",
            actions
                .iter()
                .map(|a| format!("'{}'", a))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

// ===========================================================================
// pap-core: DisclosureEntry / DisclosureSet
// ===========================================================================

/// A single entry in a disclosure set: which Schema.org type properties
/// are permitted or prohibited for sharing, with optional retention constraints.
#[pyclass(module = "pap._pap")]
#[derive(Clone)]
pub struct DisclosureEntry {
    pub(crate) inner: pap_core::scope::DisclosureEntry,
}

#[pymethods]
impl DisclosureEntry {
    /// Create a disclosure entry.
    ///
    /// Args:
    ///   schema_type: Schema.org type, e.g. `"schema:Person"`
    ///   permitted: list of property names that may be disclosed
    ///   prohibited: list of property names that must never be disclosed
    #[new]
    fn new(schema_type: String, permitted: Vec<String>, prohibited: Vec<String>) -> Self {
        Self {
            inner: pap_core::scope::DisclosureEntry::new(schema_type, permitted, prohibited),
        }
    }

    /// Mark this entry as session-only (data valid only during the session).
    ///
    /// Returns `self` for chaining: `entry.session_only().no_retention()`
    fn session_only(mut slf: PyRefMut<'_, Self>) -> PyRefMut<'_, Self> {
        slf.inner.session_only = true;
        slf
    }

    /// Mark this entry as no-retention (receiver must not store the data).
    ///
    /// Returns `self` for chaining: `entry.session_only().no_retention()`
    fn no_retention(mut slf: PyRefMut<'_, Self>) -> PyRefMut<'_, Self> {
        slf.inner.no_retention = true;
        slf
    }

    #[getter]
    fn schema_type(&self) -> String {
        self.inner.schema_type.clone()
    }

    #[getter]
    fn permitted_properties(&self) -> Vec<String> {
        self.inner.permitted_properties.clone()
    }

    #[getter]
    fn prohibited_properties(&self) -> Vec<String> {
        self.inner.prohibited_properties.clone()
    }

    #[getter]
    fn is_session_only(&self) -> bool {
        self.inner.session_only
    }

    #[getter]
    fn is_no_retention(&self) -> bool {
        self.inner.no_retention
    }

    fn __repr__(&self) -> String {
        format!(
            "DisclosureEntry(type='{}', permitted={:?})",
            self.inner.schema_type, self.inner.permitted_properties
        )
    }
}

/// The set of context classes an agent holds and the conditions for sharing.
#[pyclass(module = "pap._pap")]
#[derive(Clone)]
pub struct DisclosureSet {
    pub(crate) inner: pap_core::scope::DisclosureSet,
}

#[pymethods]
impl DisclosureSet {
    /// Create a disclosure set from entries.
    #[new]
    fn new(entries: Vec<PyRef<DisclosureEntry>>) -> Self {
        Self {
            inner: pap_core::scope::DisclosureSet::new(
                entries.iter().map(|e| e.inner.clone()).collect(),
            ),
        }
    }

    /// Create an empty disclosure set (disclose nothing).
    #[staticmethod]
    fn empty() -> Self {
        Self {
            inner: pap_core::scope::DisclosureSet::empty(),
        }
    }

    /// Returns property references (type.property format) without values.
    /// Used in transaction receipts.
    fn property_refs(&self) -> Vec<String> {
        self.inner.property_refs()
    }

    fn __repr__(&self) -> String {
        format!("DisclosureSet({} entries)", self.inner.entries.len())
    }
}

// ===========================================================================
// pap-core: DecayState
// ===========================================================================

/// Mandate decay state as TTL approaches expiry without renewal.
/// Progression: Active → Degraded → ReadOnly → Suspended
#[pyclass(module = "pap._pap", eq, eq_int)]
#[derive(Clone, Copy, PartialEq)]
pub enum DecayState {
    Active,
    Degraded,
    ReadOnly,
    Suspended,
}

impl From<pap_core::mandate::DecayState> for DecayState {
    fn from(s: pap_core::mandate::DecayState) -> Self {
        match s {
            pap_core::mandate::DecayState::Active => DecayState::Active,
            pap_core::mandate::DecayState::Degraded => DecayState::Degraded,
            pap_core::mandate::DecayState::ReadOnly => DecayState::ReadOnly,
            pap_core::mandate::DecayState::Suspended => DecayState::Suspended,
        }
    }
}

impl From<DecayState> for pap_core::mandate::DecayState {
    fn from(s: DecayState) -> Self {
        match s {
            DecayState::Active => pap_core::mandate::DecayState::Active,
            DecayState::Degraded => pap_core::mandate::DecayState::Degraded,
            DecayState::ReadOnly => pap_core::mandate::DecayState::ReadOnly,
            DecayState::Suspended => pap_core::mandate::DecayState::Suspended,
        }
    }
}

// ===========================================================================
// pap-core: Mandate
// ===========================================================================

/// The core delegation primitive. Signed by the issuing agent, verifiable
/// back to the root principal key. Encodes scope, disclosure policy, and TTL.
#[pyclass(module = "pap._pap")]
#[derive(Clone)]
pub struct Mandate {
    pub(crate) inner: pap_core::mandate::Mandate,
}

#[pymethods]
impl Mandate {
    /// Issue a root mandate directly from a principal to an agent.
    ///
    /// Args:
    ///   principal_did: DID of the human principal (root of trust)
    ///   agent_did: DID of the agent receiving the mandate
    ///   scope: permitted actions
    ///   disclosure_set: context the agent may share
    ///   ttl: expiry timestamp as ISO 8601 string (e.g. "2025-01-01T00:00:00Z")
    #[staticmethod]
    fn issue_root(
        principal_did: String,
        agent_did: String,
        scope: PyRef<Scope>,
        disclosure_set: PyRef<DisclosureSet>,
        ttl: &str,
    ) -> PyResult<Self> {
        let ttl_dt = parse_dt(ttl)?;
        Ok(Self {
            inner: pap_core::mandate::Mandate::issue_root(
                principal_did,
                agent_did,
                scope.inner.clone(),
                disclosure_set.inner.clone(),
                ttl_dt,
            ),
        })
    }

    /// Delegate a child mandate from this mandate.
    ///
    /// Enforces: child scope ⊆ parent scope, child TTL ≤ parent TTL.
    ///
    /// Args:
    ///   agent_did: DID of the agent receiving the delegated mandate
    ///   scope: subset of this mandate's scope
    ///   disclosure_set: subset of this mandate's disclosure policy
    ///   ttl: expiry no later than this mandate's TTL
    fn delegate(
        &self,
        agent_did: String,
        scope: PyRef<Scope>,
        disclosure_set: PyRef<DisclosureSet>,
        ttl: &str,
    ) -> PyResult<Mandate> {
        let ttl_dt = parse_dt(ttl)?;
        self.inner
            .delegate(
                agent_did,
                scope.inner.clone(),
                disclosure_set.inner.clone(),
                ttl_dt,
            )
            .map(|inner| Mandate { inner })
            .map_err(|e| PapScopeError::new_err(e.to_string()))
    }

    /// Sign this mandate with the issuer's keypair.
    fn sign(&mut self, keypair: PyRef<PrincipalKeypair>) {
        self.inner.sign(keypair.inner.signing_key());
    }

    /// Sign this mandate with an ephemeral session keypair (for delegated mandates).
    fn sign_with_session_key(&mut self, keypair: PyRef<SessionKeypair>) {
        self.inner.sign(keypair.inner.signing_key());
    }

    /// Verify this mandate's signature using the issuer's public key bytes.
    fn verify(&self, public_key_bytes: &[u8]) -> PyResult<()> {
        let key = verifying_key_from_bytes(public_key_bytes)?;
        self.inner
            .verify(&key)
            .map_err(|e| PapSignatureError::new_err(e.to_string()))
    }

    /// Verify using a PrincipalKeypair (extracts public key automatically).
    fn verify_with_keypair(&self, keypair: PyRef<PrincipalKeypair>) -> PyResult<()> {
        self.inner
            .verify(&keypair.inner.verifying_key())
            .map_err(|e| PapSignatureError::new_err(e.to_string()))
    }

    /// SHA-256 hash of this mandate's canonical form (base64url, no padding).
    fn hash(&self) -> String {
        self.inner.hash()
    }

    /// Returns True if this mandate has expired.
    fn is_expired(&self) -> bool {
        self.inner.is_expired()
    }

    /// Compute the current decay state given a decay window in seconds.
    fn compute_decay_state(&self, decay_window_secs: i64) -> DecayState {
        self.inner.compute_decay_state(decay_window_secs).into()
    }

    /// Transition the decay state. Raises ValueError on invalid transition.
    fn transition_decay(&mut self, next: DecayState) -> PyResult<()> {
        self.inner
            .transition_decay(next.into())
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Serialize to JSON string.
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&self.inner).map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Deserialize from JSON string.
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Mandate> {
        serde_json::from_str::<pap_core::mandate::Mandate>(json)
            .map(|inner| Mandate { inner })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    #[getter]
    fn principal_did(&self) -> String {
        self.inner.principal_did.clone()
    }

    #[getter]
    fn agent_did(&self) -> String {
        self.inner.agent_did.clone()
    }

    #[getter]
    fn issuer_did(&self) -> String {
        self.inner.issuer_did.clone()
    }

    #[getter]
    fn parent_mandate_hash(&self) -> Option<String> {
        self.inner.parent_mandate_hash.clone()
    }

    #[getter]
    fn scope(&self) -> Scope {
        Scope {
            inner: self.inner.scope.clone(),
        }
    }

    #[getter]
    fn disclosure_set(&self) -> DisclosureSet {
        DisclosureSet {
            inner: self.inner.disclosure_set.clone(),
        }
    }

    #[getter]
    fn ttl(&self) -> String {
        self.inner.ttl.to_rfc3339()
    }

    #[getter]
    fn issued_at(&self) -> String {
        self.inner.issued_at.to_rfc3339()
    }

    #[getter]
    fn decay_state(&self) -> DecayState {
        self.inner.decay_state.into()
    }

    #[getter]
    fn signature(&self) -> Option<String> {
        self.inner.signature.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "Mandate(principal='{}', agent='{}', ttl='{}')",
            self.inner.principal_did,
            self.inner.agent_did,
            self.inner.ttl.to_rfc3339()
        )
    }
}

// ===========================================================================
// pap-core: MandateChain
// ===========================================================================

/// A chain of mandates from root to leaf, each signed by the previous issuer.
#[pyclass(module = "pap._pap")]
#[derive(Clone)]
pub struct MandateChain {
    pub(crate) inner: pap_core::mandate::MandateChain,
}

#[pymethods]
impl MandateChain {
    /// Create a mandate chain with a root mandate.
    #[new]
    fn new(root: PyRef<Mandate>) -> Self {
        Self {
            inner: pap_core::mandate::MandateChain::new(root.inner.clone()),
        }
    }

    /// Append a delegated mandate to the chain.
    fn push(&mut self, mandate: PyRef<Mandate>) {
        self.inner.push(mandate.inner.clone());
    }

    /// The leaf (most-recently delegated) mandate in the chain.
    fn leaf(&self) -> Mandate {
        Mandate {
            inner: self.inner.leaf().clone(),
        }
    }

    /// The root mandate in the chain.
    fn root(&self) -> Mandate {
        Mandate {
            inner: self.inner.root().clone(),
        }
    }

    /// Verify the entire chain. Pass one keypair per mandate (root first).
    ///
    /// Each element may be a `PrincipalKeypair` (root / long-term key) or a
    /// `SessionKeypair` (ephemeral key used for sub-delegations).
    ///
    /// Verifies: parent hashes, scope containment, TTL ordering, signatures.
    fn verify_chain(&self, py: Python<'_>, keypairs: Vec<PyObject>) -> PyResult<()> {
        let mut keys: Vec<VerifyingKey> = Vec::with_capacity(keypairs.len());
        for kp in &keypairs {
            if let Ok(pk) = kp.extract::<PyRef<PrincipalKeypair>>(py) {
                keys.push(pk.inner.verifying_key());
            } else if let Ok(sk) = kp.extract::<PyRef<SessionKeypair>>(py) {
                keys.push(sk.inner.verifying_key());
            } else {
                return Err(PyValueError::new_err(
                    "each keypair must be a PrincipalKeypair or SessionKeypair",
                ));
            }
        }
        self.inner
            .verify_chain(&keys)
            .map_err(|e| PapSignatureError::new_err(e.to_string()))
    }

    /// Number of mandates in the chain.
    fn __len__(&self) -> usize {
        self.inner.mandates.len()
    }

    fn __repr__(&self) -> String {
        format!("MandateChain(len={})", self.inner.mandates.len())
    }
}

// ===========================================================================
// pap-core: CapabilityToken
// ===========================================================================

/// Single-use proof of authorization. Bound to a specific target DID, action,
/// and nonce. Consumed when the session opens.
#[pyclass(module = "pap._pap")]
#[derive(Clone)]
pub struct CapabilityToken {
    pub(crate) inner: pap_core::session::CapabilityToken,
}

#[pymethods]
impl CapabilityToken {
    /// Mint a new capability token.
    ///
    /// Args:
    ///   target_did: DID of the agent this token is valid for
    ///   action: Schema.org action reference, e.g. `"schema:SearchAction"`
    ///   issuer_did: DID of the orchestrator issuing the token
    ///   expires_at: expiry timestamp as ISO 8601 string
    #[staticmethod]
    fn mint(
        target_did: String,
        action: String,
        issuer_did: String,
        expires_at: &str,
    ) -> PyResult<Self> {
        let ttl_dt = parse_dt(expires_at)?;
        Ok(Self {
            inner: pap_core::session::CapabilityToken::mint(target_did, action, issuer_did, ttl_dt),
        })
    }

    /// Sign the token with the issuer's keypair.
    fn sign(&mut self, keypair: PyRef<PrincipalKeypair>) {
        self.inner.sign(keypair.inner.signing_key());
    }

    /// Sign the token with an ephemeral session keypair.
    fn sign_with_session_key(&mut self, keypair: PyRef<SessionKeypair>) {
        self.inner.sign(keypair.inner.signing_key());
    }

    /// Verify the token's signature using the issuer's public key bytes.
    fn verify_signature(&self, public_key_bytes: &[u8]) -> PyResult<()> {
        let key = verifying_key_from_bytes(public_key_bytes)?;
        self.inner
            .verify_signature(&key)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Serialize to JSON string.
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&self.inner).map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Deserialize from JSON string.
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<CapabilityToken> {
        serde_json::from_str::<pap_core::session::CapabilityToken>(json)
            .map(|inner| CapabilityToken { inner })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    #[getter]
    fn id(&self) -> String {
        self.inner.id.clone()
    }

    #[getter]
    fn target_did(&self) -> String {
        self.inner.target_did.clone()
    }

    #[getter]
    fn action(&self) -> String {
        self.inner.action.clone()
    }

    #[getter]
    fn nonce(&self) -> String {
        self.inner.nonce.clone()
    }

    #[getter]
    fn issuer_did(&self) -> String {
        self.inner.issuer_did.clone()
    }

    #[getter]
    fn issued_at(&self) -> String {
        self.inner.issued_at.to_rfc3339()
    }

    #[getter]
    fn expires_at(&self) -> String {
        self.inner.expires_at.to_rfc3339()
    }

    fn __repr__(&self) -> String {
        format!(
            "CapabilityToken(id='{}', target='{}', action='{}')",
            self.inner.id, self.inner.target_did, self.inner.action
        )
    }
}

// ===========================================================================
// pap-core: SessionState
// ===========================================================================

/// Protocol session state machine: Initiated → Open → Executed → Closed.
#[pyclass(module = "pap._pap", eq, eq_int)]
#[derive(Clone, Copy, PartialEq)]
pub enum SessionState {
    Initiated,
    Open,
    Executed,
    Closed,
}

// ===========================================================================
// pap-core: Session
// ===========================================================================

/// A protocol session between two agents, tracking state transitions
/// and consuming nonces.
///
/// `unsendable` because `pap_core::session::Session` contains a `HashSet`
/// of consumed nonces which is not `Send`. Each `Session` must be used
/// from the same Python thread that created it.
#[pyclass(module = "pap._pap", unsendable)]
pub struct Session {
    pub(crate) inner: pap_core::session::Session,
}

#[pymethods]
impl Session {
    /// Initiate a session from a capability token.
    ///
    /// Verifies the token against the given issuer public key bytes,
    /// consumes the nonce, and sets state to Initiated.
    #[staticmethod]
    fn initiate(
        token: PyRef<CapabilityToken>,
        receiver_did: &str,
        issuer_public_key_bytes: &[u8],
    ) -> PyResult<Self> {
        let key = verifying_key_from_bytes(issuer_public_key_bytes)?;
        pap_core::session::Session::initiate(&token.inner, receiver_did, &key)
            .map(|inner| Session { inner })
            .map_err(|e| PapSessionError::new_err(e.to_string()))
    }

    /// Open the session by recording both parties' ephemeral session DIDs.
    fn open(
        &mut self,
        initiator_session_did: String,
        receiver_session_did: String,
    ) -> PyResult<()> {
        self.inner
            .open(initiator_session_did, receiver_session_did)
            .map_err(|e| PapSessionError::new_err(e.to_string()))
    }

    /// Mark the session as executed.
    fn execute(&mut self) -> PyResult<()> {
        self.inner
            .execute()
            .map_err(|e| PapSessionError::new_err(e.to_string()))
    }

    /// Close the session.
    fn close(&mut self) -> PyResult<()> {
        self.inner
            .close()
            .map_err(|e| PapSessionError::new_err(e.to_string()))
    }

    /// Returns True if the given nonce has been consumed in this session.
    fn is_nonce_consumed(&self, nonce: &str) -> bool {
        self.inner.is_nonce_consumed(nonce)
    }

    #[getter]
    fn id(&self) -> String {
        self.inner.id.clone()
    }

    #[getter]
    fn state(&self) -> SessionState {
        match self.inner.state {
            pap_core::session::SessionState::Initiated => SessionState::Initiated,
            pap_core::session::SessionState::Open => SessionState::Open,
            pap_core::session::SessionState::Executed => SessionState::Executed,
            pap_core::session::SessionState::Closed => SessionState::Closed,
        }
    }

    #[getter]
    fn action(&self) -> String {
        self.inner.action.clone()
    }

    #[getter]
    fn initiator_session_did(&self) -> Option<String> {
        self.inner.initiator_session_did.clone()
    }

    #[getter]
    fn receiver_session_did(&self) -> Option<String> {
        self.inner.receiver_session_did.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "Session(id='{}', state={:?})",
            self.inner.id,
            self.inner.state.as_str()
        )
    }
}

// ===========================================================================
// pap-core: TransactionReceipt
// ===========================================================================

/// Co-signed transaction record. Contains property references only (never values).
/// Auditable by both principals. Not stored by any platform.
#[pyclass(module = "pap._pap")]
#[derive(Clone)]
pub struct TransactionReceipt {
    pub(crate) inner: pap_core::receipt::TransactionReceipt,
}

#[pymethods]
impl TransactionReceipt {
    /// Build a receipt from a completed session.
    ///
    /// Session must be in Executed state.
    #[staticmethod]
    fn from_session(
        session: PyRef<Session>,
        disclosed_by_initiator: Vec<String>,
        disclosed_by_receiver: Vec<String>,
        executed: String,
        returned: String,
    ) -> PyResult<Self> {
        pap_core::receipt::TransactionReceipt::from_session(
            &session.inner,
            disclosed_by_initiator,
            disclosed_by_receiver,
            executed,
            returned,
        )
        .map(|inner| TransactionReceipt { inner })
        .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Create a receipt directly from its fields (for deserialization / testing).
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        serde_json::from_str::<pap_core::receipt::TransactionReceipt>(json)
            .map(|inner| TransactionReceipt { inner })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Co-sign the receipt with a keypair. Call once per party.
    fn co_sign(&mut self, keypair: PyRef<PrincipalKeypair>) {
        self.inner.co_sign(keypair.inner.signing_key());
    }

    /// Co-sign the receipt with an ephemeral session keypair.
    fn co_sign_with_session_key(&mut self, keypair: PyRef<SessionKeypair>) {
        self.inner.co_sign(keypair.inner.signing_key());
    }

    /// Verify both co-signatures.
    ///
    /// Args:
    ///   initiator_public_key_bytes: 32-byte public key of the initiating agent
    ///   receiver_public_key_bytes: 32-byte public key of the receiving agent
    fn verify_both(
        &self,
        initiator_public_key_bytes: &[u8],
        receiver_public_key_bytes: &[u8],
    ) -> PyResult<()> {
        let init_key = verifying_key_from_bytes(initiator_public_key_bytes)?;
        let recv_key = verifying_key_from_bytes(receiver_public_key_bytes)?;
        self.inner
            .verify_both(&init_key, &recv_key)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Serialize to pretty JSON string.
    fn to_json(&self) -> String {
        self.inner.to_json()
    }

    #[getter]
    fn session_id(&self) -> String {
        self.inner.session_id.clone()
    }

    #[getter]
    fn action(&self) -> String {
        self.inner.action.clone()
    }

    #[getter]
    fn initiating_agent_did(&self) -> String {
        self.inner.initiating_agent_did.clone()
    }

    #[getter]
    fn receiving_agent_did(&self) -> String {
        self.inner.receiving_agent_did.clone()
    }

    #[getter]
    fn disclosed_by_initiator(&self) -> Vec<String> {
        self.inner.disclosed_by_initiator.clone()
    }

    #[getter]
    fn disclosed_by_receiver(&self) -> Vec<String> {
        self.inner.disclosed_by_receiver.clone()
    }

    #[getter]
    fn executed(&self) -> String {
        self.inner.executed.clone()
    }

    #[getter]
    fn returned(&self) -> String {
        self.inner.returned.clone()
    }

    #[getter]
    fn timestamp(&self) -> String {
        self.inner.timestamp.to_rfc3339()
    }

    #[getter]
    fn signatures(&self) -> Vec<String> {
        self.inner.signatures.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "TransactionReceipt(session='{}', action='{}', signatures={})",
            self.inner.session_id,
            self.inner.action,
            self.inner.signatures.len()
        )
    }
}

// ===========================================================================
// pap-credential: SelectiveDisclosureJwt / Disclosure
// ===========================================================================

/// A single disclosed claim (salt + key + value).
#[pyclass(module = "pap._pap")]
#[derive(Clone)]
pub struct Disclosure {
    pub(crate) inner: pap_credential::Disclosure,
}

#[pymethods]
impl Disclosure {
    #[getter]
    fn salt(&self) -> String {
        self.inner.salt.clone()
    }

    #[getter]
    fn key(&self) -> String {
        self.inner.key.clone()
    }

    /// The claim value as a JSON string.
    fn value_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner.value).map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// SHA-256 hash of this disclosure (base64url, no padding).
    fn hash(&self) -> String {
        self.inner.hash()
    }

    fn __repr__(&self) -> String {
        format!("Disclosure(key='{}')", self.inner.key)
    }
}

/// Selective Disclosure JWT — sign a set of claims and later reveal only
/// the subset the mandate permits.
#[pyclass(module = "pap._pap")]
#[derive(Clone)]
pub struct SelectiveDisclosureJwt {
    pub(crate) inner: pap_credential::SelectiveDisclosureJwt,
}

#[pymethods]
impl SelectiveDisclosureJwt {
    /// Create a new SD-JWT with the given claims dict (JSON-serializable values).
    ///
    /// Claims should be a dict mapping string keys to JSON-serializable values.
    /// Salts are auto-generated.
    #[new]
    fn new(issuer: String, claims_json: &str) -> PyResult<Self> {
        let claims: HashMap<String, serde_json::Value> = serde_json::from_str(claims_json)
            .map_err(|e| PyValueError::new_err(format!("invalid claims JSON: {}", e)))?;
        Ok(Self {
            inner: pap_credential::SelectiveDisclosureJwt::new(issuer, claims),
        })
    }

    /// Sign the SD-JWT with the issuer's keypair.
    fn sign(&mut self, keypair: PyRef<PrincipalKeypair>) {
        self.inner.sign(keypair.inner.signing_key());
    }

    /// Verify the SD-JWT signature using the issuer's public key bytes.
    fn verify_signature(&self, public_key_bytes: &[u8]) -> PyResult<()> {
        let key = verifying_key_from_bytes(public_key_bytes)?;
        self.inner
            .verify_signature(&key)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Produce disclosures for the specified claim keys only.
    ///
    /// This is the selective disclosure step — the holder reveals only what
    /// the mandate permits.
    fn disclose(&self, keys: Vec<String>) -> PyResult<Vec<Disclosure>> {
        let key_refs: Vec<&str> = keys.iter().map(|s| s.as_str()).collect();
        self.inner
            .disclose(&key_refs)
            .map(|ds| ds.into_iter().map(|inner| Disclosure { inner }).collect())
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Verify that the given disclosures match the signed commitments.
    fn verify_disclosures(
        &self,
        disclosures: Vec<PyRef<Disclosure>>,
        public_key_bytes: &[u8],
    ) -> PyResult<()> {
        let key = verifying_key_from_bytes(public_key_bytes)?;
        let ds: Vec<pap_credential::Disclosure> =
            disclosures.iter().map(|d| d.inner.clone()).collect();
        self.inner
            .verify_disclosures(&ds, &key)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// List all claim keys in this SD-JWT.
    fn claim_keys(&self) -> Vec<String> {
        self.inner
            .claim_keys()
            .into_iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[getter]
    fn issuer(&self) -> String {
        self.inner.issuer.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "SelectiveDisclosureJwt(issuer='{}', claims={})",
            self.inner.issuer,
            self.inner.claim_keys().len()
        )
    }
}

// ===========================================================================
// pap-marketplace: AgentAdvertisement / MarketplaceRegistry
// ===========================================================================

/// Signed JSON-LD agent capability advertisement published by an operator.
#[pyclass(module = "pap._pap")]
#[derive(Clone)]
pub struct AgentAdvertisement {
    pub(crate) inner: pap_marketplace::AgentAdvertisement,
}

#[pymethods]
impl AgentAdvertisement {
    /// Create a new agent advertisement.
    ///
    /// Args:
    ///   name: human-readable agent name
    ///   provider_name: name of the operator organization
    ///   operator_did: DID of the operator who will sign
    ///   capability: list of Schema.org action types, e.g. `["schema:SearchAction"]`
    ///   object_types: Schema.org object types operated on
    ///   requires_disclosure: property refs the agent requires
    ///   returns: Schema.org return types
    #[new]
    fn new(
        name: String,
        provider_name: String,
        operator_did: String,
        capability: Vec<String>,
        object_types: Vec<String>,
        requires_disclosure: Vec<String>,
        returns: Vec<String>,
    ) -> Self {
        Self {
            inner: pap_marketplace::AgentAdvertisement::new(
                name,
                provider_name,
                operator_did,
                capability,
                object_types,
                requires_disclosure,
                returns,
            ),
        }
    }

    /// Sign the advertisement with the operator's keypair.
    fn sign(&mut self, keypair: PyRef<PrincipalKeypair>) {
        self.inner.sign(keypair.inner.signing_key());
    }

    /// Verify the advertisement's signature using the operator's public key bytes.
    fn verify(&self, public_key_bytes: &[u8]) -> PyResult<()> {
        let key = verifying_key_from_bytes(public_key_bytes)?;
        self.inner
            .verify(&key)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Returns True if this agent supports the given Schema.org action.
    fn supports_action(&self, action: &str) -> bool {
        self.inner.supports_action(action)
    }

    /// Returns True if the given available properties satisfy this agent's
    /// disclosure requirements.
    fn disclosure_satisfiable(&self, available: Vec<String>) -> bool {
        self.inner.disclosure_satisfiable(&available)
    }

    /// SHA-256 hash of the advertisement (base64url, no padding).
    fn hash(&self) -> String {
        self.inner.hash()
    }

    /// Serialize to pretty JSON-LD string.
    fn to_json(&self) -> String {
        self.inner.to_json()
    }

    /// Deserialize from JSON string.
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<AgentAdvertisement> {
        serde_json::from_str::<pap_marketplace::AgentAdvertisement>(json)
            .map(|inner| AgentAdvertisement { inner })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    #[getter]
    fn name(&self) -> String {
        self.inner.name.clone()
    }

    #[getter]
    fn capability(&self) -> Vec<String> {
        self.inner.capability.clone()
    }

    #[getter]
    fn object_types(&self) -> Vec<String> {
        self.inner.object_types.clone()
    }

    #[getter]
    fn requires_disclosure(&self) -> Vec<String> {
        self.inner.requires_disclosure.clone()
    }

    #[getter]
    fn returns(&self) -> Vec<String> {
        self.inner.returns.clone()
    }

    #[getter]
    fn signed_by(&self) -> String {
        self.inner.signed_by.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "AgentAdvertisement(name='{}', capability={:?})",
            self.inner.name, self.inner.capability
        )
    }
}

/// In-memory agent advertisement registry. Supports discovery by action.
#[pyclass(module = "pap._pap")]
pub struct MarketplaceRegistry {
    inner: pap_marketplace::MarketplaceRegistry,
}

#[pymethods]
impl MarketplaceRegistry {
    #[new]
    fn new() -> Self {
        Self {
            inner: pap_marketplace::MarketplaceRegistry::new(),
        }
    }

    /// Register a signed advertisement. Raises ValueError if unsigned.
    fn register(&mut self, ad: PyRef<AgentAdvertisement>) -> PyResult<()> {
        self.inner
            .register(ad.inner.clone())
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Query for agents that support the given Schema.org action.
    fn query_by_action(&self, action: &str) -> Vec<AgentAdvertisement> {
        self.inner
            .query_by_action(action)
            .into_iter()
            .map(|inner| AgentAdvertisement {
                inner: inner.clone(),
            })
            .collect()
    }

    /// Query for agents that support `action` and whose disclosure requirements
    /// are satisfied by `available_properties`.
    fn query_satisfiable(
        &self,
        action: &str,
        available_properties: Vec<String>,
    ) -> Vec<AgentAdvertisement> {
        self.inner
            .query_satisfiable(action, &available_properties)
            .into_iter()
            .map(|inner| AgentAdvertisement {
                inner: inner.clone(),
            })
            .collect()
    }

    /// Number of registered advertisements.
    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn __repr__(&self) -> String {
        format!("MarketplaceRegistry({} agents)", self.inner.len())
    }
}

// ===========================================================================
// pap-transport: AgentClient
// ===========================================================================

/// HTTP client for an initiating PAP agent.
///
/// Drives the six-phase handshake by posting protocol messages to a receiving
/// agent's HTTP server. All methods are synchronous in Python (backed by
/// a dedicated tokio runtime).
#[pyclass(module = "pap._pap")]
pub struct AgentClient {
    inner: pap_transport::AgentClient,
    /// Stored so `__repr__` can show the URL without needing access to the
    /// private field inside `pap_transport::AgentClient`.
    base_url: String,
}

#[pymethods]
impl AgentClient {
    /// Create a client pointing at `base_url` (e.g. `"http://localhost:8080"`).
    #[new]
    fn new(base_url: &str) -> Self {
        Self {
            inner: pap_transport::AgentClient::new(base_url),
            base_url: base_url.to_string(),
        }
    }

    /// The base URL this client connects to.
    #[getter]
    fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Phase 1 — Present a capability token. Returns the response as a JSON string.
    ///
    /// On success: `{"type": "TokenAccepted", "session_id": "...", "receiver_session_did": "..."}`
    fn present_token(&self, token: PyRef<CapabilityToken>) -> PyResult<String> {
        let token_inner = token.inner.clone();
        let result = RT
            .block_on(self.inner.present_token(token_inner))
            .map_err(|e| PapTransportError::new_err(e.to_string()))?;
        serde_json::to_string(&result).map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Phase 2 — Send the initiator's ephemeral session DID. Returns JSON string.
    fn exchange_did(&self, session_id: &str, initiator_session_did: &str) -> PyResult<String> {
        let result = RT
            .block_on(
                self.inner
                    .exchange_did(session_id, initiator_session_did.to_string()),
            )
            .map_err(|e| PapTransportError::new_err(e.to_string()))?;
        serde_json::to_string(&result).map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Phase 3 — Send selective disclosures. Returns JSON string acknowledgement.
    ///
    /// Pass an empty list (`[]`) for zero-disclosure sessions.
    fn send_disclosures(
        &self,
        session_id: &str,
        disclosures: Vec<PyRef<Disclosure>>,
    ) -> PyResult<String> {
        let values: Vec<serde_json::Value> = disclosures
            .iter()
            .map(|d| serde_json::to_value(&d.inner))
            .collect::<Result<_, _>>()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let result = RT
            .block_on(self.inner.send_disclosures(session_id, values))
            .map_err(|e| PapTransportError::new_err(e.to_string()))?;
        serde_json::to_string(&result).map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Phase 4 — Request execution. Returns the execution result as a JSON string.
    fn request_execution(&self, session_id: &str) -> PyResult<String> {
        let result = RT
            .block_on(self.inner.request_execution(session_id))
            .map_err(|e| PapTransportError::new_err(e.to_string()))?;
        serde_json::to_string(&result).map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Phase 5 — Send receipt for co-signing. Returns the co-signed receipt as JSON.
    fn exchange_receipt(
        &self,
        session_id: &str,
        receipt: PyRef<TransactionReceipt>,
    ) -> PyResult<String> {
        let receipt_inner = receipt.inner.clone();
        let result = RT
            .block_on(self.inner.exchange_receipt(session_id, receipt_inner))
            .map_err(|e| PapTransportError::new_err(e.to_string()))?;
        serde_json::to_string(&result).map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Phase 6 — Close the session. Returns JSON confirmation.
    fn close_session(&self, session_id: &str) -> PyResult<String> {
        let result = RT
            .block_on(self.inner.close_session(session_id))
            .map_err(|e| PapTransportError::new_err(e.to_string()))?;
        serde_json::to_string(&result).map_err(|e| PyValueError::new_err(e.to_string()))
    }

    fn __repr__(&self) -> String {
        format!("AgentClient(base_url='{}')", self.base_url)
    }
}

// ===========================================================================
// Module registration
// ===========================================================================

/// Python bindings for the Principal Agent Protocol (PAP).
#[pymodule]
fn _pap(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Exception hierarchy (register before classes so they can be caught in tests)
    m.add("PapError", m.py().get_type_bound::<PapError>())?;
    m.add(
        "PapSignatureError",
        m.py().get_type_bound::<PapSignatureError>(),
    )?;
    m.add("PapScopeError", m.py().get_type_bound::<PapScopeError>())?;
    m.add(
        "PapSessionError",
        m.py().get_type_bound::<PapSessionError>(),
    )?;
    m.add(
        "PapTransportError",
        m.py().get_type_bound::<PapTransportError>(),
    )?;

    // Keys
    m.add_class::<PrincipalKeypair>()?;
    m.add_class::<SessionKeypair>()?;

    // DID utilities
    m.add_function(wrap_pyfunction!(public_key_to_did, m)?)?;
    m.add_function(wrap_pyfunction!(did_to_public_key_bytes, m)?)?;

    // Core scope / disclosure
    m.add_class::<ScopeAction>()?;
    m.add_class::<Scope>()?;
    m.add_class::<DisclosureEntry>()?;
    m.add_class::<DisclosureSet>()?;

    // Mandate / delegation
    m.add_class::<DecayState>()?;
    m.add_class::<Mandate>()?;
    m.add_class::<MandateChain>()?;

    // Session / token
    m.add_class::<SessionState>()?;
    m.add_class::<CapabilityToken>()?;
    m.add_class::<Session>()?;

    // Receipt
    m.add_class::<TransactionReceipt>()?;

    // Credentials
    m.add_class::<Disclosure>()?;
    m.add_class::<SelectiveDisclosureJwt>()?;

    // Marketplace
    m.add_class::<AgentAdvertisement>()?;
    m.add_class::<MarketplaceRegistry>()?;

    // Transport
    m.add_class::<AgentClient>()?;

    Ok(())
}
