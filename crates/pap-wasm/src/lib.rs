//! WebAssembly bindings for the Principal Agent Protocol.
//!
//! Built with `wasm-bindgen`; type declarations are auto-generated.
//!
//! Build with:
//!   wasm-pack build crates/pap-wasm --target bundler --out-dir pkg
//!
//! The resulting `pkg/` directory is a ready-to-publish npm package.
//!
//! # Transport
//! `pap-transport` (reqwest-based) is excluded from WASM because reqwest
//! requires a native runtime. The core protocol primitives — keys, mandates,
//! scopes, sessions, and tokens — are fully available.
//!
//! # Transport
//! [`TransportSession`] drives the 6-phase PAP handshake from any browser
//! context using the Fetch API via `web-sys`. It speaks the same
//! `ProtocolMessage` JSON wire format over the same REST endpoints as
//! `pap_transport::AgentClient`, ensuring wire compatibility between
//! native and WASM handshake paths.
//!
//! # Federation
//! `WasmFederationClient` wraps the browser-native `FetchFederationClient`
//! and lets JavaScript code discover agents via the PAP federation protocol.

pub mod federation;
pub use federation::*;

mod transport;
pub use transport::TransportSession;

use wasm_bindgen::prelude::*;

use pap_core::mandate::DecayState;

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

fn to_js_err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn parse_ttl(s: &str) -> Result<chrono::DateTime<chrono::Utc>, JsError> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&chrono::Utc))
        .map_err(|e| JsError::new(&format!("invalid RFC 3339 timestamp: {e}")))
}

// ---------------------------------------------------------------------------
// PrincipalKeypair
// ---------------------------------------------------------------------------

/// Root Ed25519 keypair bound to the human principal.
/// In production this is backed by a platform authenticator (WebAuthn).
#[wasm_bindgen]
pub struct PrincipalKeypair {
    inner: pap_did::PrincipalKeypair,
}

#[wasm_bindgen]
impl PrincipalKeypair {
    /// Generate a new random principal keypair.
    pub fn generate() -> PrincipalKeypair {
        PrincipalKeypair {
            inner: pap_did::PrincipalKeypair::generate(),
        }
    }

    /// Reconstruct from 32 raw secret-key bytes.
    #[wasm_bindgen(js_name = fromSecretBytes)]
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<PrincipalKeypair, JsError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| JsError::new("secret key must be exactly 32 bytes"))?;
        pap_did::PrincipalKeypair::from_bytes(&arr)
            .map(|inner| PrincipalKeypair { inner })
            .map_err(to_js_err)
    }

    /// The `did:key` identifier derived from this keypair.
    pub fn did(&self) -> String {
        self.inner.did()
    }

    /// The raw 32-byte public key.
    #[wasm_bindgen(js_name = publicKeyBytes)]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key_bytes().to_vec()
    }

    /// Sign arbitrary bytes; returns the 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        self.inner.signing_key().sign(message).to_bytes().to_vec()
    }
}

// ---------------------------------------------------------------------------
// SessionKeypair
// ---------------------------------------------------------------------------

/// Ephemeral session keypair — single-use, not linked to principal identity.
/// Generate fresh for each session handshake and discard at session close.
#[wasm_bindgen]
pub struct SessionKeypair {
    inner: pap_did::SessionKeypair,
}

#[wasm_bindgen]
impl SessionKeypair {
    /// Generate a new ephemeral session keypair.
    pub fn generate() -> SessionKeypair {
        SessionKeypair {
            inner: pap_did::SessionKeypair::generate(),
        }
    }

    /// The ephemeral `did:key` identifier (unlinked to principal).
    pub fn did(&self) -> String {
        self.inner.did()
    }

    /// The raw 32-byte public key.
    #[wasm_bindgen(js_name = publicKeyBytes)]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key_bytes().to_vec()
    }
}

// ---------------------------------------------------------------------------
// DID utilities (free functions)
// ---------------------------------------------------------------------------

/// Convert a `did:key` string to its 32-byte Ed25519 public key.
#[wasm_bindgen(js_name = didToPublicKeyBytes)]
pub fn did_to_public_key_bytes(did: &str) -> Result<Vec<u8>, JsError> {
    pap_did::did_to_public_key_bytes(did)
        .map(|b| b.to_vec())
        .map_err(to_js_err)
}

/// Derive a `did:key` string from a 32-byte Ed25519 public key.
#[wasm_bindgen(js_name = publicKeyBytesToDid)]
pub fn public_key_bytes_to_did(bytes: &[u8]) -> Result<String, JsError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| JsError::new("public key must be exactly 32 bytes"))?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(to_js_err)?;
    Ok(pap_did::public_key_to_did(&vk))
}

// ---------------------------------------------------------------------------
// ScopeAction
// ---------------------------------------------------------------------------

/// A single Schema.org action reference (the "what" of a scope entry).
#[wasm_bindgen]
pub struct ScopeAction {
    inner: pap_core::scope::ScopeAction,
}

#[wasm_bindgen]
impl ScopeAction {
    /// Create an action with no object constraint.
    /// e.g. `ScopeAction.new("schema:SearchAction")`
    #[wasm_bindgen(constructor)]
    pub fn new(action: &str) -> ScopeAction {
        ScopeAction {
            inner: pap_core::scope::ScopeAction::new(action),
        }
    }

    /// Create an action with an object type constraint.
    /// e.g. `ScopeAction.withObject("schema:ReserveAction", "schema:Flight")`
    #[wasm_bindgen(js_name = withObject)]
    pub fn with_object(action: &str, object: &str) -> ScopeAction {
        ScopeAction {
            inner: pap_core::scope::ScopeAction::with_object(action, object),
        }
    }

    /// The Schema.org action string, e.g. `"schema:SearchAction"`.
    pub fn action(&self) -> String {
        self.inner.action.clone()
    }

    /// The optional object type constraint, or `undefined`.
    pub fn object(&self) -> Option<String> {
        self.inner.object.clone()
    }
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// Deny-by-default set of permitted actions.
/// An agent can only perform actions explicitly listed in its mandate scope.
#[wasm_bindgen]
pub struct Scope {
    inner: pap_core::scope::Scope,
}

#[wasm_bindgen]
impl Scope {
    /// Build a scope from an array of ScopeAction objects.
    /// Passing an empty array produces a deny-all scope.
    #[wasm_bindgen(constructor)]
    pub fn new(actions: Vec<ScopeAction>) -> Scope {
        Scope {
            inner: pap_core::scope::Scope::new(actions.into_iter().map(|a| a.inner).collect()),
        }
    }

    /// Create a deny-all scope.
    #[wasm_bindgen(js_name = denyAll)]
    pub fn deny_all() -> Scope {
        Scope {
            inner: pap_core::scope::Scope::deny_all(),
        }
    }

    /// Returns `true` if the scope permits `action`.
    pub fn permits(&self, action: &str) -> bool {
        self.inner.permits(action)
    }

    /// Returns `true` if this scope contains `child` (child ⊆ self).
    pub fn contains(&self, child: &Scope) -> bool {
        self.inner.contains(&child.inner)
    }
}

// ---------------------------------------------------------------------------
// DisclosureEntry
// ---------------------------------------------------------------------------

/// A single context-class entry specifying which properties an agent may share.
#[wasm_bindgen]
pub struct DisclosureEntry {
    inner: pap_core::scope::DisclosureEntry,
}

#[wasm_bindgen]
impl DisclosureEntry {
    /// Create a disclosure entry.
    /// `schemaType` — e.g. `"schema:Person"`
    /// `permitted`  — property names the agent may disclose
    /// `prohibited` — property names the agent must never disclose
    #[wasm_bindgen(constructor)]
    pub fn new(
        schema_type: &str,
        permitted: Vec<String>,
        prohibited: Vec<String>,
    ) -> DisclosureEntry {
        DisclosureEntry {
            inner: pap_core::scope::DisclosureEntry::new(schema_type, permitted, prohibited),
        }
    }

    /// Mark the entry as session-only (data valid only for session duration).
    #[wasm_bindgen(js_name = setSessionOnly)]
    pub fn set_session_only(&mut self, value: bool) {
        self.inner.session_only = value;
    }

    /// Mark the entry as no-retention (receiver must not store disclosed data).
    #[wasm_bindgen(js_name = setNoRetention)]
    pub fn set_no_retention(&mut self, value: bool) {
        self.inner.no_retention = value;
    }
}

// ---------------------------------------------------------------------------
// DisclosureSet
// ---------------------------------------------------------------------------

/// Collection of disclosure entries for a mandate.
#[wasm_bindgen]
pub struct DisclosureSet {
    inner: pap_core::scope::DisclosureSet,
}

#[wasm_bindgen]
impl DisclosureSet {
    /// Create an empty disclosure set (disclose nothing).
    #[wasm_bindgen(js_name = empty)]
    pub fn empty() -> DisclosureSet {
        DisclosureSet {
            inner: pap_core::scope::DisclosureSet::empty(),
        }
    }

    /// Build a disclosure set from an array of DisclosureEntry objects.
    #[wasm_bindgen(constructor)]
    pub fn new(entries: Vec<DisclosureEntry>) -> DisclosureSet {
        DisclosureSet {
            inner: pap_core::scope::DisclosureSet::new(
                entries.into_iter().map(|e| e.inner).collect(),
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Mandate
// ---------------------------------------------------------------------------

/// The core delegation primitive. Signed by the issuing agent's key;
/// verifiable back to the root principal key.
#[wasm_bindgen]
pub struct Mandate {
    inner: pap_core::mandate::Mandate,
}

#[wasm_bindgen]
impl Mandate {
    /// Issue a root mandate directly by the principal.
    /// `ttlRfc3339` — RFC 3339 expiry timestamp, e.g. `"2026-03-22T12:00:00Z"`.
    #[wasm_bindgen(js_name = issueRoot)]
    pub fn issue_root(
        principal_did: &str,
        agent_did: &str,
        scope: &Scope,
        disclosure_set: &DisclosureSet,
        ttl_rfc3339: &str,
    ) -> Result<Mandate, JsError> {
        let ttl = parse_ttl(ttl_rfc3339)?;
        Ok(Mandate {
            inner: pap_core::mandate::Mandate::issue_root(
                principal_did.to_string(),
                agent_did.to_string(),
                scope.inner.clone(),
                disclosure_set.inner.clone(),
                ttl,
            ),
        })
    }

    /// Delegate a child mandate from this mandate.
    /// Enforces: child scope ⊆ parent scope AND child TTL ≤ parent TTL.
    pub fn delegate(
        &self,
        agent_did: &str,
        scope: &Scope,
        disclosure_set: &DisclosureSet,
        ttl_rfc3339: &str,
    ) -> Result<Mandate, JsError> {
        let ttl = parse_ttl(ttl_rfc3339)?;
        self.inner
            .delegate(
                agent_did.to_string(),
                scope.inner.clone(),
                disclosure_set.inner.clone(),
                ttl,
            )
            .map(|inner| Mandate { inner })
            .map_err(to_js_err)
    }

    /// Sign the mandate with the issuer's keypair.
    pub fn sign(&mut self, keypair: &PrincipalKeypair) -> Result<(), JsError> {
        self.inner
            .sign(keypair.inner.signing_key())
            .map_err(to_js_err)
    }

    /// Get the canonical bytes to be signed externally (e.g., by SubtleCrypto).
    /// Returns the exact byte array that `sign()` would sign internally.
    #[wasm_bindgen(js_name = signableBytes)]
    pub fn signable_bytes(&self) -> Vec<u8> {
        self.inner.signable_bytes()
    }

    /// Set the signature from externally-computed bytes (64 bytes).
    /// Use after signing `signableBytes()` with SubtleCrypto Ed25519.
    #[wasm_bindgen(js_name = setSignatureBytes)]
    pub fn set_signature_bytes(&mut self, sig: &[u8]) -> Result<(), JsError> {
        self.inner.set_signature_bytes(sig).map_err(to_js_err)
    }

    /// Verify the mandate's signature against the given public key bytes (32 bytes).
    pub fn verify(&self, public_key_bytes: &[u8]) -> Result<(), JsError> {
        let arr: [u8; 32] = public_key_bytes
            .try_into()
            .map_err(|_| JsError::new("public key must be exactly 32 bytes"))?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(to_js_err)?;
        self.inner.verify(&vk).map_err(to_js_err)
    }

    /// Serialize to a JSON string.
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsError> {
        serde_json::to_string(&self.inner).map_err(to_js_err)
    }

    /// Deserialize from a JSON string.
    /// NOTE: `decayState` in the JSON is NOT covered by the signature.
    /// Always call `syncDecayState()` after deserialization.
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(json: &str) -> Result<Mandate, JsError> {
        serde_json::from_str::<pap_core::mandate::Mandate>(json)
            .map(|inner| Mandate { inner })
            .map_err(to_js_err)
    }

    /// The SHA-256 hash (base64url) of the signed fields. Excludes
    /// `decay_state` and `signature`.
    pub fn hash(&self) -> String {
        self.inner.hash()
    }

    /// Current decay state as a string: `"Active"`, `"Degraded"`,
    /// `"ReadOnly"`, or `"Suspended"`.
    #[wasm_bindgen(js_name = decayState)]
    pub fn decay_state(&self) -> String {
        self.inner.decay_state.to_string()
    }

    /// Compute the time-based decay state without mutating the mandate.
    /// `decayWindowSecs` is seconds before TTL at which Degraded begins.
    ///
    /// Returns `"Active"`, `"Degraded"`, `"ReadOnly"`, or `"Suspended"`.
    ///
    /// This is a pure computation. To apply the result call `syncDecayState()`.
    #[wasm_bindgen(js_name = computeDecayState)]
    pub fn compute_decay_state(&self, decay_window_secs: i64) -> String {
        self.inner
            .compute_decay_state(decay_window_secs)
            .to_string()
    }

    /// Synchronize the stored decay state to the time-computed value.
    ///
    /// Handles two correctness traps:
    /// 1. **TTL-expiry jump** — if TTL expires between polling cycles while
    ///    the state is Active, the computed state jumps to ReadOnly. Since
    ///    Active→ReadOnly is not a valid single step, this method inserts the
    ///    intermediate Degraded step automatically.
    /// 2. **Self-transition guard** — transition() rejects X→X; this is a
    ///    no-op when computed state equals current state.
    #[wasm_bindgen(js_name = syncDecayState)]
    pub fn sync_decay_state(&mut self, decay_window_secs: i64) -> Result<(), JsError> {
        let target = self.inner.compute_decay_state(decay_window_secs);

        // No-op guard (also prevents X→X self-transition errors)
        if target == self.inner.decay_state {
            return Ok(());
        }

        // Handle Active→ReadOnly jump: step through Degraded first
        if self.inner.decay_state == DecayState::Active && target == DecayState::ReadOnly {
            self.inner
                .transition_decay(DecayState::Degraded)
                .map_err(to_js_err)?;
        }

        self.inner.transition_decay(target).map_err(to_js_err)
    }

    /// Explicitly transition the decay state (validates the transition).
    /// Use `syncDecayState()` for time-driven changes; this is for explicit
    /// renewal (`"Degraded"` → `"Active"`) or suspension flows.
    ///
    /// Valid state strings: `"Active"`, `"Degraded"`, `"ReadOnly"`, `"Suspended"`.
    #[wasm_bindgen(js_name = transitionDecay)]
    pub fn transition_decay(&mut self, next_state: &str) -> Result<(), JsError> {
        let next = match next_state {
            "Active" => DecayState::Active,
            "Degraded" => DecayState::Degraded,
            "ReadOnly" => DecayState::ReadOnly,
            "Suspended" => DecayState::Suspended,
            other => return Err(JsError::new(&format!("unknown decay state: {other}"))),
        };
        self.inner.transition_decay(next).map_err(to_js_err)
    }

    /// Returns `true` if `now > TTL`.
    #[wasm_bindgen(js_name = isExpired)]
    pub fn is_expired(&self) -> bool {
        self.inner.is_expired()
    }

    /// The principal DID (root of trust).
    #[wasm_bindgen(js_name = principalDid)]
    pub fn principal_did(&self) -> String {
        self.inner.principal_did.clone()
    }

    /// The agent DID (delegate receiving this mandate).
    #[wasm_bindgen(js_name = agentDid)]
    pub fn agent_did(&self) -> String {
        self.inner.agent_did.clone()
    }

    /// The issuer DID (signer of this mandate).
    #[wasm_bindgen(js_name = issuerDid)]
    pub fn issuer_did(&self) -> String {
        self.inner.issuer_did.clone()
    }

    /// The TTL as an RFC 3339 string.
    pub fn ttl(&self) -> String {
        self.inner.ttl.to_rfc3339()
    }
}

// ---------------------------------------------------------------------------
// CapabilityToken
// ---------------------------------------------------------------------------

/// A single-use proof that an agent is authorized to open a session with a
/// specific target for a specific action. Bound to target DID + action + nonce.
#[wasm_bindgen]
pub struct CapabilityToken {
    inner: pap_core::session::CapabilityToken,
}

#[wasm_bindgen]
impl CapabilityToken {
    /// Mint a new capability token.
    /// `expiresAtRfc3339` — RFC 3339 expiry timestamp.
    pub fn mint(
        target_did: &str,
        action: &str,
        issuer_did: &str,
        expires_at_rfc3339: &str,
    ) -> Result<CapabilityToken, JsError> {
        let expires_at = parse_ttl(expires_at_rfc3339)?;
        Ok(CapabilityToken {
            inner: pap_core::session::CapabilityToken::mint(
                target_did.to_string(),
                action.to_string(),
                issuer_did.to_string(),
                expires_at,
            ),
        })
    }

    /// Sign the token with the issuer's keypair.
    pub fn sign(&mut self, keypair: &PrincipalKeypair) -> Result<(), JsError> {
        self.inner
            .sign(keypair.inner.signing_key())
            .map_err(to_js_err)
    }

    /// Get the canonical bytes to be signed externally (e.g., by SubtleCrypto).
    #[wasm_bindgen(js_name = signableBytes)]
    pub fn signable_bytes(&self) -> Vec<u8> {
        self.inner.signable_bytes()
    }

    /// Set the signature from externally-computed bytes (64 bytes).
    #[wasm_bindgen(js_name = setSignatureBytes)]
    pub fn set_signature_bytes(&mut self, sig: &[u8]) -> Result<(), JsError> {
        self.inner.set_signature_bytes(sig).map_err(to_js_err)
    }

    /// Serialize to a JSON string.
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> Result<String, JsError> {
        serde_json::to_string(&self.inner).map_err(to_js_err)
    }

    /// Deserialize from a JSON string.
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(json: &str) -> Result<CapabilityToken, JsError> {
        serde_json::from_str::<pap_core::session::CapabilityToken>(json)
            .map(|inner| CapabilityToken { inner })
            .map_err(to_js_err)
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Protocol session state machine: Initiated → Open → Executed → Closed.
#[wasm_bindgen]
pub struct Session {
    inner: pap_core::session::Session,
}

#[wasm_bindgen]
impl Session {
    /// Initiate a session from a capability token.
    /// `issuerPublicKeyBytes` — 32-byte public key of the token issuer.
    pub fn initiate(
        token: &CapabilityToken,
        receiver_did: &str,
        issuer_public_key_bytes: &[u8],
    ) -> Result<Session, JsError> {
        let arr: [u8; 32] = issuer_public_key_bytes
            .try_into()
            .map_err(|_| JsError::new("issuer public key must be exactly 32 bytes"))?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(to_js_err)?;
        pap_core::session::Session::initiate(&token.inner, receiver_did, &vk)
            .map(|inner| Session { inner })
            .map_err(to_js_err)
    }

    /// Open the session by exchanging ephemeral session DIDs.
    pub fn open(
        &mut self,
        initiator_session_did: &str,
        receiver_session_did: &str,
    ) -> Result<(), JsError> {
        self.inner
            .open(
                initiator_session_did.to_string(),
                receiver_session_did.to_string(),
            )
            .map_err(to_js_err)
    }

    /// Transition to Executed state.
    pub fn execute(&mut self) -> Result<(), JsError> {
        self.inner.execute().map_err(to_js_err)
    }

    /// Close the session.
    pub fn close(&mut self) -> Result<(), JsError> {
        self.inner.close().map_err(to_js_err)
    }

    /// Current session state: `"Initiated"`, `"Open"`, `"Executed"`, or `"Closed"`.
    pub fn state(&self) -> String {
        self.inner.state.to_string()
    }

    /// The session UUID.
    pub fn id(&self) -> String {
        self.inner.id.clone()
    }
}
