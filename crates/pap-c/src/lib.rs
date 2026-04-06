//! C FFI layer for the Principal Agent Protocol.
//!
//! Exposes the core PAP primitives through a stable C ABI so that C, C++,
//! C#, and Java (via JNA) can consume the library without knowing Rust.
//!
//! # Memory contract
//! Every `pap_*_generate / new / from_*` call returns a `Box`-allocated
//! opaque handle. The caller owns it and must call the matching `pap_*_free`.
//! Strings returned by any function are `CString`-allocated; free them with
//! `pap_string_free`. Input `*const c_char` pointers are borrowed.
//!
//! # Error handling
//! Functions that fail return `NULL` (pointers) or `-1` (ints). Call
//! `pap_last_error_message()` for a human-readable description; free that
//! string with `pap_string_free`.
#![allow(clippy::missing_safety_doc, clippy::not_unsafe_ptr_arg_deref)]

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

use pap_core::mandate::{DecayState, Mandate};
use pap_core::receipt::TransactionReceipt;
use pap_core::scope::{DisclosureEntry, DisclosureSet, Scope, ScopeAction};
use pap_core::session::{CapabilityToken, Session, SessionState};
use pap_did::{PrincipalKeypair, SessionKeypair};
use pap_marketplace::{AgentAdvertisement, MarketplaceRegistry};

// ---------------------------------------------------------------------------
// Thread-local last-error storage
// ---------------------------------------------------------------------------

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn set_last_error(msg: &str) {
    LAST_ERROR.with(|c| *c.borrow_mut() = Some(msg.to_string()));
}

/// Returns the most recent error message as a heap-allocated C string,
/// or NULL if no error has occurred. Caller must free with `pap_string_free`.
#[no_mangle]
pub extern "C" fn pap_last_error_message() -> *mut c_char {
    LAST_ERROR.with(|c| match c.borrow_mut().take() {
        Some(s) => match CString::new(s) {
            Ok(cs) => cs.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        None => std::ptr::null_mut(),
    })
}

/// Alias for `pap_last_error_message`.
/// Returns the most recent error message as a heap-allocated C string,
/// or NULL if no error has occurred. Caller must free with `pap_string_free`.
#[no_mangle]
pub extern "C" fn pap_last_error() -> *mut c_char {
    pap_last_error_message()
}

/// Free a string returned by any `pap_*` function.
/// # Safety
/// `s` must be a pointer previously returned by a PAP function, or NULL.
#[no_mangle]
pub unsafe extern "C" fn pap_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

// ---------------------------------------------------------------------------
// Internal helpers — not exported
// ---------------------------------------------------------------------------

/// Build a heap-allocated C string, setting last_error and returning NULL on
/// embedded null bytes (which CString::new rejects).
macro_rules! cstring_or_null {
    ($s:expr) => {{
        match CString::new($s) {
            Ok(cs) => cs.into_raw(),
            Err(e) => {
                set_last_error(&format!("string contains null byte: {e}"));
                return std::ptr::null_mut();
            }
        }
    }};
}

/// Borrow a `*const c_char` as `&str`, returning null on failure.
macro_rules! cstr_or_null {
    ($ptr:expr) => {{
        if $ptr.is_null() {
            set_last_error("null string pointer");
            return std::ptr::null_mut();
        }
        match unsafe { CStr::from_ptr($ptr) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_last_error("invalid UTF-8 in string argument");
                return std::ptr::null_mut();
            }
        }
    }};
}

/// Borrow a `*const c_char` as `&str`, returning -1 on failure.
macro_rules! cstr_or_err {
    ($ptr:expr) => {{
        if $ptr.is_null() {
            set_last_error("null string pointer");
            return -1;
        }
        match unsafe { CStr::from_ptr($ptr) }.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_last_error("invalid UTF-8 in string argument");
                return -1;
            }
        }
    }};
}

/// Borrow an opaque pointer as `&T`, returning null on null input.
macro_rules! ref_or_null {
    ($ptr:expr) => {{
        match unsafe { ($ptr).as_ref() } {
            Some(v) => v,
            None => {
                set_last_error("null pointer argument");
                return std::ptr::null_mut();
            }
        }
    }};
}

/// Borrow an opaque pointer as `&T`, returning -1 on null input.
macro_rules! ref_or_err {
    ($ptr:expr) => {{
        match unsafe { ($ptr).as_ref() } {
            Some(v) => v,
            None => {
                set_last_error("null pointer argument");
                return -1;
            }
        }
    }};
}

/// Borrow an opaque pointer as `&mut T`, returning -1 on null input.
macro_rules! mut_or_err {
    ($ptr:expr) => {{
        match unsafe { ($ptr).as_mut() } {
            Some(v) => v,
            None => {
                set_last_error("null pointer argument");
                return -1;
            }
        }
    }};
}

// ---------------------------------------------------------------------------
// Decay / session state integer encoding
// ---------------------------------------------------------------------------
//
// These integer constants are part of the ABI and must never be renumbered.

/// Active — full scope, within TTL.
pub const PAP_DECAY_ACTIVE: c_int = 0;
/// Degraded — reduced scope, TTL within decay window, renewal pending.
pub const PAP_DECAY_DEGRADED: c_int = 1;
/// ReadOnly — TTL expired, no execution, observation only.
pub const PAP_DECAY_READ_ONLY: c_int = 2;
/// Suspended — awaiting principal review; terminal state (no renewal).
pub const PAP_DECAY_SUSPENDED: c_int = 3;

fn decay_to_int(d: DecayState) -> c_int {
    match d {
        DecayState::Active => PAP_DECAY_ACTIVE,
        DecayState::Degraded => PAP_DECAY_DEGRADED,
        DecayState::ReadOnly => PAP_DECAY_READ_ONLY,
        DecayState::Suspended => PAP_DECAY_SUSPENDED,
    }
}

fn int_to_decay(i: c_int) -> Option<DecayState> {
    match i {
        PAP_DECAY_ACTIVE => Some(DecayState::Active),
        PAP_DECAY_DEGRADED => Some(DecayState::Degraded),
        PAP_DECAY_READ_ONLY => Some(DecayState::ReadOnly),
        PAP_DECAY_SUSPENDED => Some(DecayState::Suspended),
        _ => None,
    }
}

/// Initiated — token presented, awaiting verification.
pub const PAP_SESSION_INITIATED: c_int = 0;
/// Open — handshake complete, session DIDs exchanged.
pub const PAP_SESSION_OPEN: c_int = 1;
/// Executed — transaction completed within session.
pub const PAP_SESSION_EXECUTED: c_int = 2;
/// Closed — session closed, ephemeral keys discarded.
pub const PAP_SESSION_CLOSED: c_int = 3;

fn session_state_to_int(s: SessionState) -> c_int {
    match s {
        SessionState::Initiated => PAP_SESSION_INITIATED,
        SessionState::Open => PAP_SESSION_OPEN,
        SessionState::Executed => PAP_SESSION_EXECUTED,
        SessionState::Closed => PAP_SESSION_CLOSED,
    }
}

// ---------------------------------------------------------------------------
// Opaque handle wrapper types
// ---------------------------------------------------------------------------

pub struct PapPrincipalKeypair {
    inner: PrincipalKeypair,
}
pub struct PapSessionKeypair {
    inner: SessionKeypair,
}
pub struct PapScopeAction {
    inner: ScopeAction,
}
pub struct PapScope {
    inner: Scope,
}
pub struct PapDisclosureEntry {
    inner: DisclosureEntry,
}
pub struct PapDisclosureSet {
    inner: DisclosureSet,
}
pub struct PapMandate {
    inner: Mandate,
}
pub struct PapCapabilityToken {
    inner: CapabilityToken,
}
pub struct PapSession {
    inner: Session,
}
pub struct PapReceipt {
    inner: TransactionReceipt,
}
pub struct PapAdvertisement {
    inner: AgentAdvertisement,
}
pub struct PapMarketplaceRegistry {
    inner: MarketplaceRegistry,
}
pub struct PapMarketplaceClient {
    registry: MarketplaceRegistry,
    #[allow(dead_code)]
    registry_url: String,
}
pub struct PapAgentList {
    dids: Vec<CString>,
    names: Vec<CString>,
    len: usize,
}

// ---------------------------------------------------------------------------
// PrincipalKeypair
// ---------------------------------------------------------------------------

/// Generate a new Ed25519 principal keypair.
#[no_mangle]
pub extern "C" fn pap_keypair_generate() -> *mut PapPrincipalKeypair {
    Box::into_raw(Box::new(PapPrincipalKeypair {
        inner: PrincipalKeypair::generate(),
    }))
}

/// Reconstruct a keypair from 32 raw secret-key bytes.
/// `bytes` must point to exactly 32 bytes.
/// # Safety
/// `bytes` must be a valid pointer to at least `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn pap_keypair_from_bytes(
    bytes: *const u8,
    len: usize,
) -> *mut PapPrincipalKeypair {
    if bytes.is_null() || len != 32 {
        set_last_error("pap_keypair_from_bytes requires exactly 32 bytes");
        return std::ptr::null_mut();
    }
    let slice = unsafe { std::slice::from_raw_parts(bytes, 32) };
    let arr: [u8; 32] = slice.try_into().expect("slice length verified to be 32 above");
    match PrincipalKeypair::from_bytes(&arr) {
        Ok(kp) => Box::into_raw(Box::new(PapPrincipalKeypair { inner: kp })),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Free a PapPrincipalKeypair. Passing NULL is a no-op.
/// # Safety
/// `kp` must be a pointer previously returned by a `pap_keypair_*` function.
#[no_mangle]
pub unsafe extern "C" fn pap_keypair_free(kp: *mut PapPrincipalKeypair) {
    if !kp.is_null() {
        drop(unsafe { Box::from_raw(kp) });
    }
}

/// Returns the `did:key` identifier as a heap-allocated C string.
/// Caller must free with `pap_string_free`.
#[no_mangle]
pub extern "C" fn pap_keypair_did(kp: *const PapPrincipalKeypair) -> *mut c_char {
    let kp = ref_or_null!(kp);
    cstring_or_null!(kp.inner.did())
}

/// Writes the 32-byte public key into `out` (caller-allocated 32-byte buffer).
/// Returns 0 on success, -1 on error.
/// # Safety
/// `out` must point to a buffer of at least 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn pap_keypair_public_bytes(
    kp: *const PapPrincipalKeypair,
    out: *mut u8,
) -> c_int {
    let kp = ref_or_err!(kp);
    if out.is_null() {
        set_last_error("null output buffer");
        return -1;
    }
    let bytes = kp.inner.public_key_bytes();
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 32) };
    0
}

/// Sign `msg_len` bytes at `msg`, writing the 64-byte signature into `sig_out`.
/// Returns 0 on success, -1 on error.
/// # Safety
/// `msg` must be valid for `msg_len` bytes; `sig_out` must be at least 64 bytes.
#[no_mangle]
pub unsafe extern "C" fn pap_keypair_sign(
    kp: *const PapPrincipalKeypair,
    msg: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
) -> c_int {
    let kp = ref_or_err!(kp);
    if msg.is_null() || sig_out.is_null() {
        set_last_error("null buffer argument");
        return -1;
    }
    let message = unsafe { std::slice::from_raw_parts(msg, msg_len) };
    use ed25519_dalek::Signer;
    let sig = kp.inner.signing_key().sign(message);
    unsafe { std::ptr::copy_nonoverlapping(sig.to_bytes().as_ptr(), sig_out, 64) };
    0
}

// ---------------------------------------------------------------------------
// SessionKeypair
// ---------------------------------------------------------------------------

/// Generate an ephemeral session keypair (single-use, not linked to principal).
#[no_mangle]
pub extern "C" fn pap_session_keypair_generate() -> *mut PapSessionKeypair {
    Box::into_raw(Box::new(PapSessionKeypair {
        inner: SessionKeypair::generate(),
    }))
}

/// Free a PapSessionKeypair. Passing NULL is a no-op.
/// # Safety
/// `kp` must be a pointer previously returned by `pap_session_keypair_generate`.
#[no_mangle]
pub unsafe extern "C" fn pap_session_keypair_free(kp: *mut PapSessionKeypair) {
    if !kp.is_null() {
        drop(unsafe { Box::from_raw(kp) });
    }
}

/// Returns the ephemeral session `did:key`. Caller frees with `pap_string_free`.
#[no_mangle]
pub extern "C" fn pap_session_keypair_did(kp: *const PapSessionKeypair) -> *mut c_char {
    let kp = ref_or_null!(kp);
    cstring_or_null!(kp.inner.did())
}

// ---------------------------------------------------------------------------
// DID utilities
// ---------------------------------------------------------------------------

/// Extract the 32-byte Ed25519 public key from a `did:key` string.
/// `out` must be a caller-allocated 32-byte buffer.
/// Returns 0 on success, -1 on invalid DID.
/// # Safety
/// `out` must point to at least 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn pap_did_to_public_key_bytes(did: *const c_char, out: *mut u8) -> c_int {
    let did_str = cstr_or_err!(did);
    if out.is_null() {
        set_last_error("null output buffer");
        return -1;
    }
    match pap_did::did_to_public_key_bytes(did_str) {
        Ok(bytes) => {
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 32) };
            0
        }
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

// ---------------------------------------------------------------------------
// ScopeAction
// ---------------------------------------------------------------------------

/// Create a scope action with no object constraint.
/// `action` is a Schema.org action string, e.g. `"schema:SearchAction"`.
#[no_mangle]
pub extern "C" fn pap_scope_action_new(action: *const c_char) -> *mut PapScopeAction {
    let action_str = cstr_or_null!(action);
    Box::into_raw(Box::new(PapScopeAction {
        inner: ScopeAction::new(action_str),
    }))
}

/// Create a scope action with an object type constraint,
/// e.g. action=`"schema:ReserveAction"`, object=`"schema:Flight"`.
#[no_mangle]
pub extern "C" fn pap_scope_action_with_object(
    action: *const c_char,
    object: *const c_char,
) -> *mut PapScopeAction {
    let action_str = cstr_or_null!(action);
    let object_str = cstr_or_null!(object);
    Box::into_raw(Box::new(PapScopeAction {
        inner: ScopeAction::with_object(action_str, object_str),
    }))
}

/// Free a PapScopeAction. Passing NULL is a no-op.
/// # Safety
/// `a` must be a pointer previously returned by a `pap_scope_action_*` function.
#[no_mangle]
pub unsafe extern "C" fn pap_scope_action_free(a: *mut PapScopeAction) {
    if !a.is_null() {
        drop(unsafe { Box::from_raw(a) });
    }
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// Build a Scope from an array of PapScopeAction pointers.
/// The actions are cloned; ownership of the action handles stays with the caller.
/// `actions` may be NULL when `count` is 0 (produces deny-all scope).
/// # Safety
/// `actions` must be a valid array of `count` non-null `*const PapScopeAction` pointers.
#[no_mangle]
pub unsafe extern "C" fn pap_scope_new(
    actions: *const *const PapScopeAction,
    count: usize,
) -> *mut PapScope {
    let mut vec = Vec::with_capacity(count);
    if count > 0 {
        if actions.is_null() {
            set_last_error("null actions array with non-zero count");
            return std::ptr::null_mut();
        }
        for i in 0..count {
            let ptr = unsafe { *actions.add(i) };
            match unsafe { ptr.as_ref() } {
                Some(a) => vec.push(a.inner.clone()),
                None => {
                    set_last_error("null ScopeAction pointer in actions array");
                    return std::ptr::null_mut();
                }
            }
        }
    }
    Box::into_raw(Box::new(PapScope {
        inner: Scope::new(vec),
    }))
}

/// Create an empty (deny-all) scope.
#[no_mangle]
pub extern "C" fn pap_scope_deny_all() -> *mut PapScope {
    Box::into_raw(Box::new(PapScope {
        inner: Scope::deny_all(),
    }))
}

/// Free a PapScope. Passing NULL is a no-op.
/// # Safety
/// `s` must be a pointer previously returned by a `pap_scope_*` function.
#[no_mangle]
pub unsafe extern "C" fn pap_scope_free(s: *mut PapScope) {
    if !s.is_null() {
        drop(unsafe { Box::from_raw(s) });
    }
}

/// Returns 1 if the scope permits `action`, 0 otherwise (including on null input).
#[no_mangle]
pub extern "C" fn pap_scope_permits(scope: *const PapScope, action: *const c_char) -> c_int {
    let scope = match unsafe { scope.as_ref() } {
        Some(s) => s,
        None => return 0,
    };
    if action.is_null() {
        return 0;
    }
    let action_str = match unsafe { CStr::from_ptr(action) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    if scope.inner.permits(action_str) {
        1
    } else {
        0
    }
}

/// Returns 1 if every action in `child` is also in `parent` (child ⊆ parent).
/// Returns 0 on any error or if the check fails.
#[no_mangle]
pub extern "C" fn pap_scope_contains(parent: *const PapScope, child: *const PapScope) -> c_int {
    match (unsafe { parent.as_ref() }, unsafe { child.as_ref() }) {
        (Some(p), Some(c)) => {
            if p.inner.contains(&c.inner) {
                1
            } else {
                0
            }
        }
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// DisclosureEntry
// ---------------------------------------------------------------------------

/// Create a disclosure entry describing what context an agent may share.
/// `permitted` and `prohibited` are arrays of C strings of the given lengths.
/// # Safety
/// All pointer arrays must be valid for their given counts.
#[no_mangle]
pub unsafe extern "C" fn pap_disclosure_entry_new(
    schema_type: *const c_char,
    permitted: *const *const c_char,
    permitted_count: usize,
    prohibited: *const *const c_char,
    prohibited_count: usize,
) -> *mut PapDisclosureEntry {
    let type_str = cstr_or_null!(schema_type);
    if permitted_count > 0 && permitted.is_null() {
        set_last_error("null permitted array with non-zero permitted_count");
        return std::ptr::null_mut();
    }
    if prohibited_count > 0 && prohibited.is_null() {
        set_last_error("null prohibited array with non-zero prohibited_count");
        return std::ptr::null_mut();
    }
    let mut perm_vec = Vec::with_capacity(permitted_count);
    for i in 0..permitted_count {
        let ptr = unsafe { *permitted.add(i) };
        if ptr.is_null() {
            set_last_error(&format!("null permitted[{i}] string pointer"));
            return std::ptr::null_mut();
        }
        match unsafe { CStr::from_ptr(ptr) }.to_str() {
            Ok(s) => perm_vec.push(s.to_string()),
            Err(_) => {
                set_last_error(&format!("permitted[{i}] is not valid UTF-8"));
                return std::ptr::null_mut();
            }
        }
    }
    let mut prohib_vec = Vec::with_capacity(prohibited_count);
    for i in 0..prohibited_count {
        let ptr = unsafe { *prohibited.add(i) };
        if ptr.is_null() {
            set_last_error(&format!("null prohibited[{i}] string pointer"));
            return std::ptr::null_mut();
        }
        match unsafe { CStr::from_ptr(ptr) }.to_str() {
            Ok(s) => prohib_vec.push(s.to_string()),
            Err(_) => {
                set_last_error(&format!("prohibited[{i}] is not valid UTF-8"));
                return std::ptr::null_mut();
            }
        }
    }
    Box::into_raw(Box::new(PapDisclosureEntry {
        inner: DisclosureEntry::new(type_str, perm_vec, prohib_vec),
    }))
}

/// Set the `session_only` flag (non-zero = true). Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn pap_disclosure_entry_set_session_only(
    e: *mut PapDisclosureEntry,
    session_only: c_int,
) -> c_int {
    let e = mut_or_err!(e);
    e.inner.session_only = session_only != 0;
    0
}

/// Set the `no_retention` flag (non-zero = true). Returns 0 on success.
#[no_mangle]
pub unsafe extern "C" fn pap_disclosure_entry_set_no_retention(
    e: *mut PapDisclosureEntry,
    no_retention: c_int,
) -> c_int {
    let e = mut_or_err!(e);
    e.inner.no_retention = no_retention != 0;
    0
}

/// Free a PapDisclosureEntry. Passing NULL is a no-op.
/// # Safety
/// `e` must be a pointer previously returned by `pap_disclosure_entry_new`.
#[no_mangle]
pub unsafe extern "C" fn pap_disclosure_entry_free(e: *mut PapDisclosureEntry) {
    if !e.is_null() {
        drop(unsafe { Box::from_raw(e) });
    }
}

// ---------------------------------------------------------------------------
// DisclosureSet
// ---------------------------------------------------------------------------

/// Create an empty disclosure set (disclose nothing).
#[no_mangle]
pub extern "C" fn pap_disclosure_set_empty() -> *mut PapDisclosureSet {
    Box::into_raw(Box::new(PapDisclosureSet {
        inner: DisclosureSet::empty(),
    }))
}

/// Build a DisclosureSet from an array of PapDisclosureEntry pointers (cloned).
/// `entries` may be NULL when `count` is 0.
/// # Safety
/// `entries` must be a valid array of `count` non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn pap_disclosure_set_new(
    entries: *const *const PapDisclosureEntry,
    count: usize,
) -> *mut PapDisclosureSet {
    let mut vec = Vec::with_capacity(count);
    if count > 0 {
        if entries.is_null() {
            set_last_error("null entries array with non-zero count");
            return std::ptr::null_mut();
        }
        for i in 0..count {
            let ptr = unsafe { *entries.add(i) };
            match unsafe { ptr.as_ref() } {
                Some(e) => vec.push(e.inner.clone()),
                None => {
                    set_last_error("null DisclosureEntry pointer in entries array");
                    return std::ptr::null_mut();
                }
            }
        }
    }
    Box::into_raw(Box::new(PapDisclosureSet {
        inner: DisclosureSet::new(vec),
    }))
}

/// Free a PapDisclosureSet. Passing NULL is a no-op.
/// # Safety
/// `ds` must be a pointer previously returned by a `pap_disclosure_set_*` function.
#[no_mangle]
pub unsafe extern "C" fn pap_disclosure_set_free(ds: *mut PapDisclosureSet) {
    if !ds.is_null() {
        drop(unsafe { Box::from_raw(ds) });
    }
}

// ---------------------------------------------------------------------------
// Mandate
// ---------------------------------------------------------------------------

/// Issue a root mandate directly by the principal.
/// `ttl_rfc3339` is an RFC 3339 timestamp, e.g. `"2026-03-22T12:00:00Z"`.
/// Returns NULL on parse error or null pointer argument.
#[no_mangle]
pub extern "C" fn pap_mandate_issue_root(
    principal_did: *const c_char,
    agent_did: *const c_char,
    scope: *const PapScope,
    disclosure_set: *const PapDisclosureSet,
    ttl_rfc3339: *const c_char,
) -> *mut PapMandate {
    let principal = cstr_or_null!(principal_did);
    let agent = cstr_or_null!(agent_did);
    let scope_ref = ref_or_null!(scope);
    let ds_ref = ref_or_null!(disclosure_set);
    let ttl_str = cstr_or_null!(ttl_rfc3339);

    let ttl = match chrono::DateTime::parse_from_rfc3339(ttl_str) {
        Ok(t) => t.with_timezone(&chrono::Utc),
        Err(e) => {
            set_last_error(&format!("invalid TTL timestamp: {e}"));
            return std::ptr::null_mut();
        }
    };

    Box::into_raw(Box::new(PapMandate {
        inner: Mandate::issue_root(
            principal.to_string(),
            agent.to_string(),
            scope_ref.inner.clone(),
            ds_ref.inner.clone(),
            ttl,
        ),
    }))
}

/// Delegate a child mandate from an existing parent mandate.
/// Enforces: child scope ⊆ parent scope; child TTL ≤ parent TTL.
/// Returns NULL on scope/TTL violation.
#[no_mangle]
pub extern "C" fn pap_mandate_delegate(
    parent: *const PapMandate,
    agent_did: *const c_char,
    scope: *const PapScope,
    disclosure_set: *const PapDisclosureSet,
    ttl_rfc3339: *const c_char,
) -> *mut PapMandate {
    let parent = ref_or_null!(parent);
    let agent = cstr_or_null!(agent_did);
    let scope_ref = ref_or_null!(scope);
    let ds_ref = ref_or_null!(disclosure_set);
    let ttl_str = cstr_or_null!(ttl_rfc3339);

    let ttl = match chrono::DateTime::parse_from_rfc3339(ttl_str) {
        Ok(t) => t.with_timezone(&chrono::Utc),
        Err(e) => {
            set_last_error(&format!("invalid TTL timestamp: {e}"));
            return std::ptr::null_mut();
        }
    };

    match parent.inner.delegate(
        agent.to_string(),
        scope_ref.inner.clone(),
        ds_ref.inner.clone(),
        ttl,
    ) {
        Ok(child) => Box::into_raw(Box::new(PapMandate { inner: child })),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Free a PapMandate. Passing NULL is a no-op.
/// # Safety
/// `m` must be a pointer previously returned by a `pap_mandate_*` function.
#[no_mangle]
pub unsafe extern "C" fn pap_mandate_free(m: *mut PapMandate) {
    if !m.is_null() {
        drop(unsafe { Box::from_raw(m) });
    }
}

/// Sign the mandate with the issuer's keypair. Must be called before use.
/// Returns 0 on success, -1 on null pointer.
/// # Safety
/// Both `m` and `kp` must be valid non-null handles.
#[no_mangle]
pub unsafe extern "C" fn pap_mandate_sign(
    m: *mut PapMandate,
    kp: *const PapPrincipalKeypair,
) -> c_int {
    let m = mut_or_err!(m);
    let kp = ref_or_err!(kp);
    if let Err(e) = m.inner.sign(kp.inner.signing_key()) {
        set_last_error(&e.to_string());
        return -1;
    }
    0
}

/// Verify the mandate's Ed25519 signature against `pubkey_bytes` (32 bytes).
/// Returns 0 on success, -1 on failure.
/// # Safety
/// `pubkey_bytes` must point to exactly 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn pap_mandate_verify(
    m: *const PapMandate,
    pubkey_bytes: *const u8,
    pubkey_len: usize,
) -> c_int {
    let m = ref_or_err!(m);
    if pubkey_bytes.is_null() || pubkey_len != 32 {
        set_last_error("pubkey_bytes must be exactly 32 bytes");
        return -1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(pubkey_bytes, 32) };
    let arr: [u8; 32] = bytes.try_into().expect("slice length verified to be 32 above");
    match ed25519_dalek::VerifyingKey::from_bytes(&arr) {
        Ok(vk) => match m.inner.verify(&vk) {
            Ok(()) => 0,
            Err(e) => {
                set_last_error(&e.to_string());
                -1
            }
        },
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

/// Serialize the mandate to a JSON C string. Caller frees with `pap_string_free`.
#[no_mangle]
pub extern "C" fn pap_mandate_to_json(m: *const PapMandate) -> *mut c_char {
    let m = ref_or_null!(m);
    match serde_json::to_string(&m.inner) {
        Ok(s) => cstring_or_null!(s),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Deserialize a mandate from a JSON C string. Caller frees with `pap_mandate_free`.
/// NOTE: `decay_state` in the JSON is *not* covered by the signature.
/// Always call `pap_mandate_sync_decay_state` after deserialization to get the
/// correct time-computed decay state.
#[no_mangle]
pub extern "C" fn pap_mandate_from_json(json: *const c_char) -> *mut PapMandate {
    let json_str = cstr_or_null!(json);
    match serde_json::from_str::<Mandate>(json_str) {
        Ok(m) => Box::into_raw(Box::new(PapMandate { inner: m })),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Returns the mandate's SHA-256 hash (base64url) as a C string.
/// Caller frees with `pap_string_free`.
/// The hash covers all signed fields but excludes `decay_state` and `signature`.
#[no_mangle]
pub extern "C" fn pap_mandate_hash(m: *const PapMandate) -> *mut c_char {
    let m = ref_or_null!(m);
    cstring_or_null!(m.inner.hash())
}

/// Returns the current decay state as an integer constant.
/// See `PAP_DECAY_*` constants. Returns -1 on null input.
#[no_mangle]
pub extern "C" fn pap_mandate_decay_state(m: *const PapMandate) -> c_int {
    match unsafe { m.as_ref() } {
        Some(m) => decay_to_int(m.inner.decay_state),
        None => -1,
    }
}

/// Compute the time-based decay state without mutating the mandate.
/// `decay_window_secs` is the number of seconds before TTL at which the
/// mandate enters Degraded state (e.g. 3600 for a 1-hour warning).
///
/// IMPORTANT: This is a pure computation. The mandate's stored `decay_state`
/// is NOT updated. Call `pap_mandate_sync_decay_state` to apply the result.
///
/// Returns the computed state integer, or -1 on null input.
#[no_mangle]
pub extern "C" fn pap_mandate_compute_decay_state(
    m: *const PapMandate,
    decay_window_secs: i64,
) -> c_int {
    match unsafe { m.as_ref() } {
        Some(m) => decay_to_int(m.inner.compute_decay_state(decay_window_secs)),
        None => -1,
    }
}

/// Explicitly transition the mandate's decay state.
/// Valid transitions (per spec): Active→Degraded, Degraded→ReadOnly,
/// ReadOnly→Suspended, Degraded→Active (renewal), ReadOnly→Active (renewal).
/// Suspended is terminal — no further transitions are allowed.
///
/// NOTE: If the TTL has expired before a polling cycle ran, calling this with
/// ReadOnly on an Active mandate will fail (Active→ReadOnly is not a valid
/// single-step transition). Use `pap_mandate_sync_decay_state` instead, which
/// handles multi-step transitions automatically.
///
/// Returns 0 on success, -1 on invalid transition.
#[no_mangle]
pub extern "C" fn pap_mandate_transition_decay(m: *mut PapMandate, next_state: c_int) -> c_int {
    let m = mut_or_err!(m);
    let next = match int_to_decay(next_state) {
        Some(s) => s,
        None => {
            set_last_error(&format!("invalid decay state integer: {next_state}"));
            return -1;
        }
    };
    match m.inner.transition_decay(next) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

/// Synchronize the mandate's stored decay state to the time-computed value.
///
/// This is the safe high-level alternative to calling `compute_decay_state`
/// and `transition_decay` manually. It handles two correctness traps:
///
/// 1. **TTL-expiry jump**: if the TTL expires between polling cycles while the
///    mandate is still Active, the computed state jumps straight to ReadOnly.
///    Active→ReadOnly is not a valid single-step transition, so this function
///    automatically steps through Degraded first.
///
/// 2. **Self-transition guard**: calling `transition_decay` with the current
///    state is rejected by the spec state machine. This function is a no-op
///    when the computed state equals the current state.
///
/// Returns 0 on success (including no-op), -1 on error.
#[no_mangle]
pub extern "C" fn pap_mandate_sync_decay_state(
    m: *mut PapMandate,
    decay_window_secs: i64,
) -> c_int {
    let m = mut_or_err!(m);
    let target = m.inner.compute_decay_state(decay_window_secs);

    // No-op guard: also prevents the X→X self-transition that the state
    // machine rejects.
    if target == m.inner.decay_state {
        return 0;
    }

    // Handle the Active→ReadOnly jump that occurs when the TTL expires before
    // the polling cycle transitions through Degraded.
    if m.inner.decay_state == DecayState::Active && target == DecayState::ReadOnly {
        if let Err(e) = m.inner.transition_decay(DecayState::Degraded) {
            set_last_error(&e.to_string());
            return -1;
        }
    }

    match m.inner.transition_decay(target) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

/// Returns 1 if `now > ttl`, 0 otherwise. Returns -1 on null input.
#[no_mangle]
pub extern "C" fn pap_mandate_is_expired(m: *const PapMandate) -> c_int {
    match unsafe { m.as_ref() } {
        Some(m) => {
            if m.inner.is_expired() {
                1
            } else {
                0
            }
        }
        None => -1,
    }
}

/// Returns the principal DID. Caller frees with `pap_string_free`.
#[no_mangle]
pub extern "C" fn pap_mandate_principal_did(m: *const PapMandate) -> *mut c_char {
    let m = ref_or_null!(m);
    CString::new(m.inner.principal_did.as_str())
        .map(|cs| cs.into_raw())
        .unwrap_or_else(|e| {
            set_last_error(&format!("string contains null byte: {e}"));
            std::ptr::null_mut()
        })
}

/// Returns the agent DID. Caller frees with `pap_string_free`.
#[no_mangle]
pub extern "C" fn pap_mandate_agent_did(m: *const PapMandate) -> *mut c_char {
    let m = ref_or_null!(m);
    CString::new(m.inner.agent_did.as_str())
        .map(|cs| cs.into_raw())
        .unwrap_or_else(|e| {
            set_last_error(&format!("string contains null byte: {e}"));
            std::ptr::null_mut()
        })
}

/// Returns the issuer DID. Caller frees with `pap_string_free`.
#[no_mangle]
pub extern "C" fn pap_mandate_issuer_did(m: *const PapMandate) -> *mut c_char {
    let m = ref_or_null!(m);
    CString::new(m.inner.issuer_did.as_str())
        .map(|cs| cs.into_raw())
        .unwrap_or_else(|e| {
            set_last_error(&format!("string contains null byte: {e}"));
            std::ptr::null_mut()
        })
}

/// Returns the TTL as an RFC 3339 string. Caller frees with `pap_string_free`.
#[no_mangle]
pub extern "C" fn pap_mandate_ttl(m: *const PapMandate) -> *mut c_char {
    let m = ref_or_null!(m);
    CString::new(m.inner.ttl.to_rfc3339())
        .map(|cs| cs.into_raw())
        .unwrap_or_else(|e| {
            set_last_error(&format!("string contains null byte: {e}"));
            std::ptr::null_mut()
        })
}

// ---------------------------------------------------------------------------
// CapabilityToken
// ---------------------------------------------------------------------------

/// Mint a new capability token.
/// `expires_at_rfc3339` is an RFC 3339 expiry timestamp.
#[no_mangle]
pub extern "C" fn pap_token_mint(
    target_did: *const c_char,
    action: *const c_char,
    issuer_did: *const c_char,
    expires_at_rfc3339: *const c_char,
) -> *mut PapCapabilityToken {
    let target = cstr_or_null!(target_did);
    let action_str = cstr_or_null!(action);
    let issuer = cstr_or_null!(issuer_did);
    let exp_str = cstr_or_null!(expires_at_rfc3339);

    let expires_at = match chrono::DateTime::parse_from_rfc3339(exp_str) {
        Ok(t) => t.with_timezone(&chrono::Utc),
        Err(e) => {
            set_last_error(&format!("invalid expires_at: {e}"));
            return std::ptr::null_mut();
        }
    };

    Box::into_raw(Box::new(PapCapabilityToken {
        inner: CapabilityToken::mint(
            target.to_string(),
            action_str.to_string(),
            issuer.to_string(),
            expires_at,
        ),
    }))
}

/// Free a PapCapabilityToken. Passing NULL is a no-op.
/// # Safety
/// `t` must be a pointer previously returned by a `pap_token_*` function.
#[no_mangle]
pub unsafe extern "C" fn pap_token_free(t: *mut PapCapabilityToken) {
    if !t.is_null() {
        drop(unsafe { Box::from_raw(t) });
    }
}

/// Sign the token with the issuer's keypair. Returns 0 on success.
/// # Safety
/// Both `t` and `kp` must be valid non-null handles.
#[no_mangle]
pub unsafe extern "C" fn pap_token_sign(
    t: *mut PapCapabilityToken,
    kp: *const PapPrincipalKeypair,
) -> c_int {
    let t = mut_or_err!(t);
    let kp = ref_or_err!(kp);
    if let Err(e) = t.inner.sign(kp.inner.signing_key()) {
        set_last_error(&e.to_string());
        return -1;
    }
    0
}

/// Serialize the token to a JSON C string. Caller frees with `pap_string_free`.
#[no_mangle]
pub extern "C" fn pap_token_to_json(t: *const PapCapabilityToken) -> *mut c_char {
    let t = ref_or_null!(t);
    match serde_json::to_string(&t.inner) {
        Ok(s) => cstring_or_null!(s),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Deserialize a capability token from JSON. Caller frees with `pap_token_free`.
#[no_mangle]
pub extern "C" fn pap_token_from_json(json: *const c_char) -> *mut PapCapabilityToken {
    let json_str = cstr_or_null!(json);
    match serde_json::from_str::<CapabilityToken>(json_str) {
        Ok(t) => Box::into_raw(Box::new(PapCapabilityToken { inner: t })),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Initiate a new session from a capability token.
/// `issuer_pubkey` must point to exactly 32 bytes (Ed25519 public key of the
/// token issuer, used to verify the token signature).
/// Returns NULL on verification failure.
/// # Safety
/// `issuer_pubkey` must point to at least 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn pap_session_initiate(
    token: *const PapCapabilityToken,
    receiver_did: *const c_char,
    issuer_pubkey: *const u8,
    pubkey_len: usize,
) -> *mut PapSession {
    let token = ref_or_null!(token);
    let recv_str = cstr_or_null!(receiver_did);
    if issuer_pubkey.is_null() || pubkey_len != 32 {
        set_last_error("issuer_pubkey must be exactly 32 bytes");
        return std::ptr::null_mut();
    }
    let bytes = unsafe { std::slice::from_raw_parts(issuer_pubkey, 32) };
    let arr: [u8; 32] = bytes.try_into().expect("slice length verified to be 32 above");
    let vk = match ed25519_dalek::VerifyingKey::from_bytes(&arr) {
        Ok(k) => k,
        Err(e) => {
            set_last_error(&e.to_string());
            return std::ptr::null_mut();
        }
    };
    match Session::initiate(&token.inner, recv_str, &vk) {
        Ok(s) => Box::into_raw(Box::new(PapSession { inner: s })),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Free a PapSession. Passing NULL is a no-op.
/// # Safety
/// `s` must be a pointer previously returned by `pap_session_initiate`.
#[no_mangle]
pub unsafe extern "C" fn pap_session_free(s: *mut PapSession) {
    if !s.is_null() {
        drop(unsafe { Box::from_raw(s) });
    }
}

/// Open the session by exchanging ephemeral session DIDs.
/// Both DIDs are typically `did:key` identifiers from freshly-generated
/// `PapSessionKeypair`s. Returns 0 on success.
#[no_mangle]
pub extern "C" fn pap_session_open(
    s: *mut PapSession,
    initiator_session_did: *const c_char,
    receiver_session_did: *const c_char,
) -> c_int {
    let s = mut_or_err!(s);
    let init_did = cstr_or_err!(initiator_session_did);
    let recv_did = cstr_or_err!(receiver_session_did);
    match s.inner.open(init_did.to_string(), recv_did.to_string()) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

/// Transition the session to Executed state. Returns 0 on success.
#[no_mangle]
pub extern "C" fn pap_session_execute(s: *mut PapSession) -> c_int {
    let s = mut_or_err!(s);
    match s.inner.execute() {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

/// Close the session and discard ephemeral state. Returns 0 on success.
#[no_mangle]
pub extern "C" fn pap_session_close(s: *mut PapSession) -> c_int {
    let s = mut_or_err!(s);
    match s.inner.close() {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

/// Returns the session state as an integer.
/// See `PAP_SESSION_*` constants. Returns -1 on null input.
#[no_mangle]
pub extern "C" fn pap_session_state(s: *const PapSession) -> c_int {
    match unsafe { s.as_ref() } {
        Some(s) => session_state_to_int(s.inner.state),
        None => -1,
    }
}

/// Returns the session UUID as a C string. Caller frees with `pap_string_free`.
#[no_mangle]
pub extern "C" fn pap_session_id(s: *const PapSession) -> *mut c_char {
    let s = ref_or_null!(s);
    cstring_or_null!(s.inner.id.as_str())
}

// ---------------------------------------------------------------------------
// TransactionReceipt
// ---------------------------------------------------------------------------

/// Create a receipt from an executed session.
/// `init_disc` / `recv_disc` are arrays of C strings describing property refs.
/// # Safety
/// All pointer arrays must be valid for their given counts.
#[no_mangle]
pub unsafe extern "C" fn pap_receipt_from_session(
    session: *const PapSession,
    init_disc: *const *const c_char,
    init_disc_count: usize,
    recv_disc: *const *const c_char,
    recv_disc_count: usize,
    executed: *const c_char,
    returned: *const c_char,
) -> *mut PapReceipt {
    let session = ref_or_null!(session);
    let executed_str = cstr_or_null!(executed);
    let returned_str = cstr_or_null!(returned);

    let mut init_vec = Vec::with_capacity(init_disc_count);
    for i in 0..init_disc_count {
        if init_disc.is_null() {
            set_last_error("null init_disc array");
            return std::ptr::null_mut();
        }
        let ptr = unsafe { *init_disc.add(i) };
        let s = cstr_or_null!(ptr);
        init_vec.push(s.to_string());
    }

    let mut recv_vec = Vec::with_capacity(recv_disc_count);
    for i in 0..recv_disc_count {
        if recv_disc.is_null() {
            set_last_error("null recv_disc array");
            return std::ptr::null_mut();
        }
        let ptr = unsafe { *recv_disc.add(i) };
        let s = cstr_or_null!(ptr);
        recv_vec.push(s.to_string());
    }

    match TransactionReceipt::from_session(
        &session.inner,
        init_vec,
        recv_vec,
        executed_str.to_string(),
        returned_str.to_string(),
    ) {
        Ok(r) => Box::into_raw(Box::new(PapReceipt { inner: r })),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Free a PapReceipt. Passing NULL is a no-op.
/// # Safety
/// `r` must be a pointer previously returned by a `pap_receipt_*` function.
#[no_mangle]
pub unsafe extern "C" fn pap_receipt_free(r: *mut PapReceipt) {
    if !r.is_null() {
        drop(unsafe { Box::from_raw(r) });
    }
}

/// Co-sign the receipt with a keypair. Returns 0 on success.
/// # Safety
/// Both `r` and `kp` must be valid non-null handles.
#[no_mangle]
pub unsafe extern "C" fn pap_receipt_co_sign(
    r: *mut PapReceipt,
    kp: *const PapPrincipalKeypair,
) -> c_int {
    let r = mut_or_err!(r);
    let kp = ref_or_err!(kp);
    r.inner.co_sign(kp.inner.signing_key());
    0
}

/// Verify a specific co-signature on the receipt.
/// `pubkey_bytes` must point to exactly 32 bytes.
/// Returns 0 on success, -1 on failure.
/// # Safety
/// `pubkey_bytes` must point to at least 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn pap_receipt_verify_signature(
    r: *const PapReceipt,
    index: usize,
    pubkey_bytes: *const u8,
    pubkey_len: usize,
) -> c_int {
    let r = ref_or_err!(r);
    if pubkey_bytes.is_null() || pubkey_len != 32 {
        set_last_error("pubkey_bytes must be exactly 32 bytes");
        return -1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(pubkey_bytes, 32) };
    let arr: [u8; 32] = bytes.try_into().expect("slice length verified to be 32 above");
    match ed25519_dalek::VerifyingKey::from_bytes(&arr) {
        Ok(vk) => match r.inner.verify_signature(index, &vk) {
            Ok(()) => 0,
            Err(e) => {
                set_last_error(&e.to_string());
                -1
            }
        },
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

/// Verify both co-signatures on the receipt.
/// Both key buffers must be exactly 32 bytes.
/// Returns 0 on success, -1 on failure.
/// # Safety
/// Both pubkey pointers must point to at least 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn pap_receipt_verify_both(
    r: *const PapReceipt,
    init_pubkey: *const u8,
    init_len: usize,
    recv_pubkey: *const u8,
    recv_len: usize,
) -> c_int {
    let r = ref_or_err!(r);
    if init_pubkey.is_null() || init_len != 32 || recv_pubkey.is_null() || recv_len != 32 {
        set_last_error("both pubkey buffers must be exactly 32 bytes");
        return -1;
    }
    let init_bytes = unsafe { std::slice::from_raw_parts(init_pubkey, 32) };
    let recv_bytes = unsafe { std::slice::from_raw_parts(recv_pubkey, 32) };
    let init_arr: [u8; 32] = init_bytes.try_into().expect("slice length verified to be 32 above");
    let recv_arr: [u8; 32] = recv_bytes.try_into().expect("slice length verified to be 32 above");
    let init_vk = match ed25519_dalek::VerifyingKey::from_bytes(&init_arr) {
        Ok(k) => k,
        Err(e) => {
            set_last_error(&e.to_string());
            return -1;
        }
    };
    let recv_vk = match ed25519_dalek::VerifyingKey::from_bytes(&recv_arr) {
        Ok(k) => k,
        Err(e) => {
            set_last_error(&e.to_string());
            return -1;
        }
    };
    match r.inner.verify_both(&init_vk, &recv_vk) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

/// Serialize the receipt to a JSON C string. Caller frees with `pap_string_free`.
#[no_mangle]
pub extern "C" fn pap_receipt_to_json(r: *const PapReceipt) -> *mut c_char {
    let r = ref_or_null!(r);
    cstring_or_null!(r.inner.to_json())
}

/// Deserialize a receipt from a JSON C string. Caller frees with `pap_receipt_free`.
#[no_mangle]
pub extern "C" fn pap_receipt_from_json(json: *const c_char) -> *mut PapReceipt {
    let json_str = cstr_or_null!(json);
    match serde_json::from_str::<TransactionReceipt>(json_str) {
        Ok(r) => Box::into_raw(Box::new(PapReceipt { inner: r })),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Returns the receipt's session ID. Caller frees with `pap_string_free`.
#[no_mangle]
pub extern "C" fn pap_receipt_session_id(r: *const PapReceipt) -> *mut c_char {
    let r = ref_or_null!(r);
    cstring_or_null!(r.inner.session_id.clone())
}

/// Returns the receipt's action. Caller frees with `pap_string_free`.
#[no_mangle]
pub extern "C" fn pap_receipt_action(r: *const PapReceipt) -> *mut c_char {
    let r = ref_or_null!(r);
    cstring_or_null!(r.inner.action.clone())
}

/// Returns the number of co-signatures on the receipt.
/// Returns -1 on null input.
#[no_mangle]
pub extern "C" fn pap_receipt_signature_count(r: *const PapReceipt) -> c_int {
    match unsafe { r.as_ref() } {
        Some(r) => r.inner.signatures.len() as c_int,
        None => -1,
    }
}

// ---------------------------------------------------------------------------
// AgentAdvertisement
// ---------------------------------------------------------------------------

/// Create a new agent advertisement.
/// All string arrays are borrowed C strings.
/// # Safety
/// All pointer arrays must be valid for their given counts.
#[no_mangle]
pub unsafe extern "C" fn pap_advertisement_new(
    name: *const c_char,
    provider_name: *const c_char,
    operator_did: *const c_char,
    capabilities: *const *const c_char,
    cap_count: usize,
    object_types: *const *const c_char,
    obj_count: usize,
    requires_disclosure: *const *const c_char,
    disc_count: usize,
    returns: *const *const c_char,
    ret_count: usize,
) -> *mut PapAdvertisement {
    let name_str = cstr_or_null!(name);
    let provider_str = cstr_or_null!(provider_name);
    let did_str = cstr_or_null!(operator_did);

    macro_rules! collect_strings {
        ($arr:expr, $count:expr) => {{
            let mut v = Vec::with_capacity($count);
            for i in 0..$count {
                if $arr.is_null() {
                    set_last_error("null string array");
                    return std::ptr::null_mut();
                }
                let ptr = unsafe { *$arr.add(i) };
                let s = cstr_or_null!(ptr);
                v.push(s.to_string());
            }
            v
        }};
    }

    let caps = collect_strings!(capabilities, cap_count);
    let objs = collect_strings!(object_types, obj_count);
    let disc = collect_strings!(requires_disclosure, disc_count);
    let rets = collect_strings!(returns, ret_count);

    Box::into_raw(Box::new(PapAdvertisement {
        inner: AgentAdvertisement::new(name_str, provider_str, did_str, caps, objs, disc, rets),
    }))
}

/// Free a PapAdvertisement. Passing NULL is a no-op.
/// # Safety
/// `a` must be a pointer previously returned by a `pap_advertisement_*` function.
#[no_mangle]
pub unsafe extern "C" fn pap_advertisement_free(a: *mut PapAdvertisement) {
    if !a.is_null() {
        drop(unsafe { Box::from_raw(a) });
    }
}

/// Sign the advertisement with the operator's keypair. Returns 0 on success.
/// # Safety
/// Both `a` and `kp` must be valid non-null handles.
#[no_mangle]
pub unsafe extern "C" fn pap_advertisement_sign(
    a: *mut PapAdvertisement,
    kp: *const PapPrincipalKeypair,
) -> c_int {
    let a = mut_or_err!(a);
    let kp = ref_or_err!(kp);
    if let Err(e) = a.inner.sign(kp.inner.signing_key()) {
        set_last_error(&e.to_string());
        return -1;
    }
    0
}

/// Verify the advertisement's signature. Returns 0 on success, -1 on failure.
/// `pubkey_bytes` must point to exactly 32 bytes.
/// # Safety
/// `pubkey_bytes` must point to at least 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn pap_advertisement_verify(
    a: *const PapAdvertisement,
    pubkey_bytes: *const u8,
    pubkey_len: usize,
) -> c_int {
    let a = ref_or_err!(a);
    if pubkey_bytes.is_null() || pubkey_len != 32 {
        set_last_error("pubkey_bytes must be exactly 32 bytes");
        return -1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(pubkey_bytes, 32) };
    let arr: [u8; 32] = bytes.try_into().expect("slice length verified to be 32 above");
    match ed25519_dalek::VerifyingKey::from_bytes(&arr) {
        Ok(vk) => match a.inner.verify(&vk) {
            Ok(()) => 0,
            Err(e) => {
                set_last_error(&e.to_string());
                -1
            }
        },
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

/// Returns 1 if the advertisement supports `action`, 0 otherwise.
#[no_mangle]
pub extern "C" fn pap_advertisement_supports_action(
    a: *const PapAdvertisement,
    action: *const c_char,
) -> c_int {
    let a = match unsafe { a.as_ref() } {
        Some(a) => a,
        None => return 0,
    };
    if action.is_null() {
        return 0;
    }
    let action_str = match unsafe { CStr::from_ptr(action) }.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };
    if a.inner.supports_action(action_str) {
        1
    } else {
        0
    }
}

/// Serialize the advertisement to a JSON C string. Caller frees with `pap_string_free`.
#[no_mangle]
pub extern "C" fn pap_advertisement_to_json(a: *const PapAdvertisement) -> *mut c_char {
    let a = ref_or_null!(a);
    cstring_or_null!(a.inner.to_json())
}

/// Deserialize an advertisement from JSON. Caller frees with `pap_advertisement_free`.
#[no_mangle]
pub extern "C" fn pap_advertisement_from_json(json: *const c_char) -> *mut PapAdvertisement {
    let json_str = cstr_or_null!(json);
    match serde_json::from_str::<AgentAdvertisement>(json_str) {
        Ok(a) => Box::into_raw(Box::new(PapAdvertisement { inner: a })),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Returns the advertisement name. Caller frees with `pap_string_free`.
#[no_mangle]
pub extern "C" fn pap_advertisement_name(a: *const PapAdvertisement) -> *mut c_char {
    let a = ref_or_null!(a);
    cstring_or_null!(a.inner.name.clone())
}

// ---------------------------------------------------------------------------
// MarketplaceRegistry
// ---------------------------------------------------------------------------

/// Create an empty marketplace registry.
#[no_mangle]
pub extern "C" fn pap_registry_new() -> *mut PapMarketplaceRegistry {
    Box::into_raw(Box::new(PapMarketplaceRegistry {
        inner: MarketplaceRegistry::new(),
    }))
}

/// Free a PapMarketplaceRegistry. Passing NULL is a no-op.
/// # Safety
/// `r` must be a pointer previously returned by `pap_registry_new`.
#[no_mangle]
pub unsafe extern "C" fn pap_registry_free(r: *mut PapMarketplaceRegistry) {
    if !r.is_null() {
        drop(unsafe { Box::from_raw(r) });
    }
}

/// Register an advertisement with the registry. The advertisement is cloned.
/// Returns 0 on success, -1 if the advertisement is unsigned.
/// # Safety
/// Both `r` and `a` must be valid non-null handles.
#[no_mangle]
pub unsafe extern "C" fn pap_registry_register(
    r: *mut PapMarketplaceRegistry,
    a: *const PapAdvertisement,
) -> c_int {
    let r = mut_or_err!(r);
    let a = ref_or_err!(a);
    match r.inner.register(a.inner.clone()) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

/// Query for advertisements matching `action`. Returns results as a JSON array
/// C string. Caller frees with `pap_string_free`.
/// Returns NULL on error.
#[no_mangle]
pub extern "C" fn pap_registry_query_by_action(
    r: *const PapMarketplaceRegistry,
    action: *const c_char,
) -> *mut c_char {
    let r = ref_or_null!(r);
    let action_str = cstr_or_null!(action);
    let results: Vec<&AgentAdvertisement> = r.inner.query_by_action(action_str);
    match serde_json::to_string(&results) {
        Ok(s) => cstring_or_null!(s),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Returns the number of advertisements in the registry. -1 on null input.
#[no_mangle]
pub extern "C" fn pap_registry_len(r: *const PapMarketplaceRegistry) -> c_int {
    match unsafe { r.as_ref() } {
        Some(r) => r.inner.len() as c_int,
        None => -1,
    }
}

// ---------------------------------------------------------------------------
// M-of-N Shamir Secret Sharing recovery (spec §13.5)
// ---------------------------------------------------------------------------

use pap_core::shamir::{RecoveryShard as InnerRecoveryShard, ShardManifest};

/// Opaque handle for a single Shamir recovery shard.
pub struct PapRecoveryShard {
    inner: InnerRecoveryShard,
}

/// Opaque handle for a set of N Shamir recovery shards from one ceremony.
pub struct PapRecoveryShardSet {
    /// Wrapped shard handles (one per trustee), in index order.
    shards: Vec<PapRecoveryShard>,
    manifest: ShardManifest,
}

/// Create M-of-N Shamir shards from a 32-byte Ed25519 seed.
///
/// `seed_bytes` must point to exactly 32 bytes.
/// `threshold` is M (minimum shards required to reconstruct).
/// `total_shares` is N (number of shards to produce).
///
/// Returns an opaque shard-set handle on success, NULL on error.
/// The caller owns the set and must free it with `pap_recovery_shard_set_free`.
///
/// # Safety
/// `seed_bytes` must be valid for 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn pap_recovery_create_shards(
    seed_bytes: *const u8,
    threshold: u8,
    total_shares: u8,
) -> *mut PapRecoveryShardSet {
    if seed_bytes.is_null() {
        set_last_error("null seed_bytes pointer");
        return std::ptr::null_mut();
    }
    let mut seed: [u8; 32] = match unsafe { std::slice::from_raw_parts(seed_bytes, 32) }.try_into()
    {
        Ok(b) => b,
        Err(_) => {
            set_last_error("seed_bytes must be exactly 32 bytes");
            return std::ptr::null_mut();
        }
    };
    let result = pap_core::shamir::create_shards(&seed, threshold, total_shares);
    use zeroize::Zeroize;
    seed.zeroize();
    match result {
        Ok((shards, manifest)) => {
            let wrapped: Vec<PapRecoveryShard> = shards
                .into_iter()
                .map(|inner| PapRecoveryShard { inner })
                .collect();
            Box::into_raw(Box::new(PapRecoveryShardSet {
                shards: wrapped,
                manifest,
            }))
        }
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Free a shard set (and all shards within it). Passing NULL is a no-op.
/// # Safety
/// `set` must be a pointer previously returned by `pap_recovery_create_shards`, or NULL.
#[no_mangle]
pub unsafe extern "C" fn pap_recovery_shard_set_free(set: *mut PapRecoveryShardSet) {
    if !set.is_null() {
        drop(unsafe { Box::from_raw(set) });
    }
}

/// Returns the number of shards in the set, or -1 on null input.
#[no_mangle]
pub extern "C" fn pap_recovery_shard_count(set: *const PapRecoveryShardSet) -> c_int {
    match unsafe { set.as_ref() } {
        Some(s) => s.shards.len() as c_int,
        None => {
            set_last_error("null shard set");
            -1
        }
    }
}

/// Borrow the shard at position `index` (0-based) from a shard set.
///
/// The returned pointer is **borrowed** — do NOT free it individually; free the entire
/// set with `pap_recovery_shard_set_free`.  The pointer is valid until the set is freed.
///
/// Returns NULL if `index` is out of range or `set` is NULL.
#[no_mangle]
pub extern "C" fn pap_recovery_shard_get(
    set: *const PapRecoveryShardSet,
    index: c_int,
) -> *const PapRecoveryShard {
    let set = match unsafe { set.as_ref() } {
        Some(s) => s,
        None => {
            set_last_error("null shard set");
            return std::ptr::null();
        }
    };
    if index < 0 || index as usize >= set.shards.len() {
        set_last_error(&format!(
            "shard index {} out of range (0..{})",
            index,
            set.shards.len()
        ));
        return std::ptr::null();
    }
    // Return a pointer to the PapRecoveryShard inside the Vec storage.
    // The Vec owns the element; its lifetime is tied to the PapRecoveryShardSet box.
    &set.shards[index as usize] as *const PapRecoveryShard
}

/// Serialize the shard manifest (public commitment document) to JSON.
///
/// Returns a heap-allocated C string. Caller must free with `pap_string_free`.
/// Returns NULL on error.
#[no_mangle]
pub extern "C" fn pap_recovery_shard_set_manifest_json(
    set: *const PapRecoveryShardSet,
) -> *mut c_char {
    let set = ref_or_null!(set);
    match serde_json::to_string_pretty(&set.manifest) {
        Ok(s) => cstring_or_null!(s),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Reconstruct a 32-byte seed from M or more Shamir shards.
///
/// `shards` is an array of `shard_count` pointers to `PapRecoveryShard`.
/// These may be borrowed from a `PapRecoveryShardSet` or owned handles returned
/// by `pap_recovery_shard_from_json`.
///
/// `seed_out` must point to a caller-allocated 32-byte buffer.
///
/// Returns 0 on success, -1 on error. On error, `seed_out` is zeroed.
///
/// # Safety
/// `shards` must be a valid array of `shard_count` non-null `PapRecoveryShard` pointers.
/// `seed_out` must point to at least 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn pap_recovery_reconstruct(
    shards: *const *const PapRecoveryShard,
    shard_count: c_int,
    seed_out: *mut u8,
) -> c_int {
    if shards.is_null() || shard_count <= 0 || shard_count > 255 || seed_out.is_null() {
        set_last_error("null or invalid argument to pap_recovery_reconstruct");
        return -1;
    }

    let count = shard_count as usize;
    let shard_ptrs = unsafe { std::slice::from_raw_parts(shards, count) };

    // Collect references to the inner RecoveryShards.
    let mut shard_refs: Vec<&InnerRecoveryShard> = Vec::with_capacity(count);
    for &ptr in shard_ptrs {
        if ptr.is_null() {
            set_last_error("null shard pointer in array");
            unsafe { std::ptr::write_bytes(seed_out, 0, 32) };
            return -1;
        }
        // Safety: ptr is non-null and points to a valid PapRecoveryShard.
        shard_refs.push(unsafe { &(*ptr).inner });
    }

    match pap_core::shamir::reconstruct(&shard_refs) {
        Ok(mut seed) => {
            unsafe { std::ptr::copy_nonoverlapping(seed.as_ptr(), seed_out, 32) };
            // Zeroize the stack copy so the seed does not linger in memory.
            use zeroize::Zeroize;
            seed.zeroize();
            0
        }
        Err(e) => {
            set_last_error(&e.to_string());
            unsafe { std::ptr::write_bytes(seed_out, 0, 32) };
            -1
        }
    }
}

/// Serialize a single shard to a JSON string for distribution to a trustee.
///
/// Returns a heap-allocated C string. Caller must free with `pap_string_free`.
/// Returns NULL on error.
///
/// # Safety
/// `shard` must be a valid pointer (borrowed from a shard set or owned from
/// `pap_recovery_shard_from_json`).
#[no_mangle]
pub extern "C" fn pap_recovery_shard_to_json(shard: *const PapRecoveryShard) -> *mut c_char {
    let shard = ref_or_null!(shard);
    match shard.inner.to_json() {
        Ok(s) => cstring_or_null!(s),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Deserialize a shard from a JSON string received from a trustee.
///
/// Returns an owned `PapRecoveryShard` handle. The caller must free it with
/// `pap_recovery_shard_free`. Returns NULL on parse error.
#[no_mangle]
pub extern "C" fn pap_recovery_shard_from_json(json: *const c_char) -> *mut PapRecoveryShard {
    let json_str = cstr_or_null!(json);
    match InnerRecoveryShard::from_json(json_str) {
        Ok(shard) => Box::into_raw(Box::new(PapRecoveryShard { inner: shard })),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Free a standalone shard handle (one returned by `pap_recovery_shard_from_json`).
///
/// Do NOT use this on shards borrowed from a `PapRecoveryShardSet` — free the set instead.
/// Passing NULL is a no-op.
///
/// # Safety
/// `shard` must be a pointer previously returned by `pap_recovery_shard_from_json`, or NULL.
#[no_mangle]
pub unsafe extern "C" fn pap_recovery_shard_free(shard: *mut PapRecoveryShard) {
    if !shard.is_null() {
        drop(unsafe { Box::from_raw(shard) });
    }
}

// ---------------------------------------------------------------------------
// MarketplaceClient — high-level query API (ISS-825)
// ---------------------------------------------------------------------------

/// Create a marketplace client wrapping a local registry.
///
/// `registry_url` is stored for forward compatibility with networked
/// federation but has no runtime effect in this PoC.
/// Returns NULL on null or invalid UTF-8 input.
#[no_mangle]
pub extern "C" fn pap_marketplace_client_new(
    registry_url: *const c_char,
) -> *mut PapMarketplaceClient {
    let url_str = cstr_or_null!(registry_url);
    Box::into_raw(Box::new(PapMarketplaceClient {
        registry: MarketplaceRegistry::new(),
        registry_url: url_str.to_string(),
    }))
}

/// Free a PapMarketplaceClient. Passing NULL is a no-op.
/// # Safety
/// `client` must be a pointer previously returned by `pap_marketplace_client_new`.
#[no_mangle]
pub unsafe extern "C" fn pap_marketplace_client_free(client: *mut PapMarketplaceClient) {
    if !client.is_null() {
        drop(unsafe { Box::from_raw(client) });
    }
}

/// Register an advertisement with the client's internal registry.
/// The advertisement is cloned. Returns 0 on success, -1 if unsigned.
/// # Safety
/// Both `client` and `a` must be valid non-null handles.
#[no_mangle]
pub unsafe extern "C" fn pap_marketplace_client_register(
    client: *mut PapMarketplaceClient,
    a: *const PapAdvertisement,
) -> c_int {
    let client = mut_or_err!(client);
    let a = ref_or_err!(a);
    match client.registry.register(a.inner.clone()) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

/// Query the client's registry for agents matching a capability.
///
/// `capability_json` is a JSON object with:
///   - `"action"` (required): Schema.org action type string
///   - `"available_properties"` (optional): JSON array of property strings
///
/// If `available_properties` is present, uses disclosure-filtered matching;
/// otherwise matches by action alone.
///
/// Returns a `PapAgentList` handle that the caller must free with
/// `pap_agent_list_free`. Returns NULL on error.
#[no_mangle]
pub extern "C" fn pap_marketplace_query(
    client: *const PapMarketplaceClient,
    capability_json: *const c_char,
) -> *mut PapAgentList {
    let client = ref_or_null!(client);
    let json_str = cstr_or_null!(capability_json);

    let parsed: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => {
            set_last_error(&format!("invalid capability JSON: {e}"));
            return std::ptr::null_mut();
        }
    };

    let action = match parsed.get("action").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => {
            set_last_error("capability JSON must contain an \"action\" string field");
            return std::ptr::null_mut();
        }
    };

    let results: Vec<&AgentAdvertisement> = if let Some(props_val) =
        parsed.get("available_properties")
    {
        match props_val.as_array() {
            Some(arr) => {
                let mut props = Vec::with_capacity(arr.len());
                for (i, v) in arr.iter().enumerate() {
                    match v.as_str() {
                        Some(s) => props.push(String::from(s)),
                        None => {
                            set_last_error(&format!("available_properties[{i}] must be a string"));
                            return std::ptr::null_mut();
                        }
                    }
                }
                client.registry.query_satisfiable(action, &props)
            }
            None => {
                set_last_error("\"available_properties\" must be a JSON array");
                return std::ptr::null_mut();
            }
        }
    } else {
        client.registry.query_by_action(action)
    };

    let len = results.len();
    let mut dids = Vec::with_capacity(len);
    let mut names = Vec::with_capacity(len);

    for ad in &results {
        let did_cs = match CString::new(ad.provider.did.clone()) {
            Ok(cs) => cs,
            Err(e) => {
                set_last_error(&format!("DID contains null byte: {e}"));
                return std::ptr::null_mut();
            }
        };
        let name_cs = match CString::new(ad.name.clone()) {
            Ok(cs) => cs,
            Err(e) => {
                set_last_error(&format!("name contains null byte: {e}"));
                return std::ptr::null_mut();
            }
        };
        dids.push(did_cs);
        names.push(name_cs);
    }

    Box::into_raw(Box::new(PapAgentList { dids, names, len }))
}

/// Returns the number of agents in the result list. Returns 0 on null input.
#[no_mangle]
pub extern "C" fn pap_agent_list_len(list: *const PapAgentList) -> usize {
    match unsafe { list.as_ref() } {
        Some(l) => l.len,
        None => 0,
    }
}

/// Returns the DID of the agent at `index` as a borrowed C string.
///
/// The returned pointer is valid until `pap_agent_list_free` is called.
/// Do NOT free this pointer with `pap_string_free`.
/// Returns NULL if `list` is null or `index` is out of bounds.
#[no_mangle]
pub extern "C" fn pap_agent_list_get_did(list: *const PapAgentList, index: usize) -> *const c_char {
    let list = match unsafe { list.as_ref() } {
        Some(l) => l,
        None => {
            set_last_error("null list pointer");
            return std::ptr::null();
        }
    };
    if index >= list.len {
        set_last_error(&format!(
            "index {index} out of bounds for list of length {}",
            list.len
        ));
        return std::ptr::null();
    }
    list.dids[index].as_ptr()
}

/// Returns the name of the agent at `index` as a borrowed C string.
///
/// The returned pointer is valid until `pap_agent_list_free` is called.
/// Do NOT free this pointer with `pap_string_free`.
/// Returns NULL if `list` is null or `index` is out of bounds.
#[no_mangle]
pub extern "C" fn pap_agent_list_get_name(
    list: *const PapAgentList,
    index: usize,
) -> *const c_char {
    let list = match unsafe { list.as_ref() } {
        Some(l) => l,
        None => {
            set_last_error("null list pointer");
            return std::ptr::null();
        }
    };
    if index >= list.len {
        set_last_error(&format!(
            "index {index} out of bounds for list of length {}",
            list.len
        ));
        return std::ptr::null();
    }
    list.names[index].as_ptr()
}

/// Free a PapAgentList and all its owned strings. Passing NULL is a no-op.
///
/// After this call, all pointers previously returned by
/// `pap_agent_list_get_did` and `pap_agent_list_get_name` for this
/// list are invalidated.
/// # Safety
/// `list` must be a pointer previously returned by `pap_marketplace_query`.
#[no_mangle]
pub unsafe extern "C" fn pap_agent_list_free(list: *mut PapAgentList) {
    if !list.is_null() {
        drop(unsafe { Box::from_raw(list) });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// Helper: create a CString and return its pointer. The CString is returned
    /// so the caller can keep it alive for the duration of the FFI call.
    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    /// Helper: create a signed PapAdvertisement via FFI functions.
    /// Returns (ad, keypair) — caller must free both.
    unsafe fn make_signed_ad_ffi(
        name: &str,
        capabilities: &[&str],
        requires_disclosure: &[&str],
    ) -> (*mut PapAdvertisement, *mut PapPrincipalKeypair) {
        let kp = pap_keypair_generate();
        assert!(!kp.is_null());

        let name_c = c(name);
        let provider_c = c("TestCorp");
        let did_ptr = pap_keypair_did(kp);
        assert!(!did_ptr.is_null());

        let cap_cstrings: Vec<CString> = capabilities.iter().map(|s| c(s)).collect();
        let cap_ptrs: Vec<*const c_char> = cap_cstrings.iter().map(|s| s.as_ptr()).collect();

        let disc_cstrings: Vec<CString> = requires_disclosure.iter().map(|s| c(s)).collect();
        let disc_ptrs: Vec<*const c_char> = disc_cstrings.iter().map(|s| s.as_ptr()).collect();

        let empty: Vec<*const c_char> = vec![];

        let ad = unsafe {
            pap_advertisement_new(
                name_c.as_ptr(),
                provider_c.as_ptr(),
                did_ptr,
                cap_ptrs.as_ptr(),
                cap_ptrs.len(),
                empty.as_ptr(),
                0,
                disc_ptrs.as_ptr(),
                disc_ptrs.len(),
                empty.as_ptr(),
                0,
            )
        };
        assert!(!ad.is_null());

        // Free the DID string we borrowed for construction
        unsafe { pap_string_free(did_ptr) };

        let rc = unsafe { pap_advertisement_sign(ad, kp) };
        assert_eq!(rc, 0);

        (ad, kp)
    }

    #[test]
    fn client_new_and_free() {
        let url = c("https://registry.example.com");
        let client = pap_marketplace_client_new(url.as_ptr());
        assert!(!client.is_null());
        unsafe { pap_marketplace_client_free(client) };
        // Null free is a no-op
        unsafe { pap_marketplace_client_free(std::ptr::null_mut()) };
    }

    #[test]
    fn client_new_null_url_returns_null() {
        let client = pap_marketplace_client_new(std::ptr::null());
        assert!(client.is_null());
        let err = pap_last_error();
        assert!(!err.is_null());
        let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap();
        assert!(msg.contains("null"), "error: {msg}");
        unsafe { pap_string_free(err) };
    }

    #[test]
    fn query_empty_registry_returns_empty_list() {
        let url = c("https://registry.example.com");
        let client = pap_marketplace_client_new(url.as_ptr());
        assert!(!client.is_null());

        let query = c(r#"{"action": "schema:SearchAction"}"#);
        let list = pap_marketplace_query(client, query.as_ptr());
        assert!(!list.is_null());
        assert_eq!(pap_agent_list_len(list), 0);

        unsafe { pap_agent_list_free(list) };
        unsafe { pap_marketplace_client_free(client) };
    }

    #[test]
    fn register_and_query_by_action() {
        let url = c("https://registry.example.com");
        let client = pap_marketplace_client_new(url.as_ptr());

        let (ad, kp) = unsafe { make_signed_ad_ffi("Search Agent", &["schema:SearchAction"], &[]) };

        let rc = unsafe { pap_marketplace_client_register(client, ad) };
        assert_eq!(rc, 0);

        let query = c(r#"{"action": "schema:SearchAction"}"#);
        let list = pap_marketplace_query(client, query.as_ptr());
        assert!(!list.is_null());
        assert_eq!(pap_agent_list_len(list), 1);

        // Check DID
        let did = pap_agent_list_get_did(list, 0);
        assert!(!did.is_null());
        let did_str = unsafe { CStr::from_ptr(did) }.to_str().unwrap();
        assert!(did_str.starts_with("did:key:z"), "DID: {did_str}");

        // Check name
        let name = pap_agent_list_get_name(list, 0);
        assert!(!name.is_null());
        let name_str = unsafe { CStr::from_ptr(name) }.to_str().unwrap();
        assert_eq!(name_str, "Search Agent");

        unsafe { pap_agent_list_free(list) };
        unsafe { pap_advertisement_free(ad) };
        unsafe { pap_keypair_free(kp) };
        unsafe { pap_marketplace_client_free(client) };
    }

    #[test]
    fn query_satisfiable_filters_by_disclosure() {
        let url = c("https://registry.example.com");
        let client = pap_marketplace_client_new(url.as_ptr());

        let (ad1, kp1) =
            unsafe { make_signed_ad_ffi("Open Search", &["schema:SearchAction"], &[]) };
        let (ad2, kp2) = unsafe {
            make_signed_ad_ffi(
                "Restricted Search",
                &["schema:SearchAction"],
                &["schema:Person.name"],
            )
        };

        unsafe {
            assert_eq!(pap_marketplace_client_register(client, ad1), 0);
            assert_eq!(pap_marketplace_client_register(client, ad2), 0);
        }

        // Without available_properties key → query_by_action → both match
        let q1 = c(r#"{"action": "schema:SearchAction"}"#);
        let list1 = pap_marketplace_query(client, q1.as_ptr());
        assert_eq!(pap_agent_list_len(list1), 2);
        unsafe { pap_agent_list_free(list1) };

        // With empty available_properties → query_satisfiable → only open matches
        let q2 = c(r#"{"action": "schema:SearchAction", "available_properties": []}"#);
        let list2 = pap_marketplace_query(client, q2.as_ptr());
        assert_eq!(pap_agent_list_len(list2), 1);
        let name = pap_agent_list_get_name(list2, 0);
        let name_str = unsafe { CStr::from_ptr(name) }.to_str().unwrap();
        assert_eq!(name_str, "Open Search");
        unsafe { pap_agent_list_free(list2) };

        // With required property → both match
        let q3 = c(
            r#"{"action": "schema:SearchAction", "available_properties": ["schema:Person.name"]}"#,
        );
        let list3 = pap_marketplace_query(client, q3.as_ptr());
        assert_eq!(pap_agent_list_len(list3), 2);
        unsafe { pap_agent_list_free(list3) };

        unsafe {
            pap_advertisement_free(ad1);
            pap_advertisement_free(ad2);
            pap_keypair_free(kp1);
            pap_keypair_free(kp2);
            pap_marketplace_client_free(client);
        }
    }

    #[test]
    fn agent_list_out_of_bounds_returns_null() {
        let url = c("https://registry.example.com");
        let client = pap_marketplace_client_new(url.as_ptr());

        let (ad, kp) = unsafe { make_signed_ad_ffi("Agent", &["schema:SearchAction"], &[]) };
        unsafe { pap_marketplace_client_register(client, ad) };

        let query = c(r#"{"action": "schema:SearchAction"}"#);
        let list = pap_marketplace_query(client, query.as_ptr());
        assert_eq!(pap_agent_list_len(list), 1);

        // Index 0 works
        assert!(!pap_agent_list_get_did(list, 0).is_null());
        assert!(!pap_agent_list_get_name(list, 0).is_null());

        // Index 1 is out of bounds
        assert!(pap_agent_list_get_did(list, 1).is_null());
        let err = pap_last_error();
        assert!(!err.is_null());
        let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap();
        assert!(msg.contains("out of bounds"), "error: {msg}");
        unsafe { pap_string_free(err) };

        assert!(pap_agent_list_get_name(list, 1).is_null());

        unsafe {
            pap_agent_list_free(list);
            pap_advertisement_free(ad);
            pap_keypair_free(kp);
            pap_marketplace_client_free(client);
        }
    }

    #[test]
    fn agent_list_null_returns_safely() {
        assert_eq!(pap_agent_list_len(std::ptr::null()), 0);
        assert!(pap_agent_list_get_did(std::ptr::null(), 0).is_null());
        assert!(pap_agent_list_get_name(std::ptr::null(), 0).is_null());
    }

    #[test]
    fn query_invalid_json_returns_null() {
        let url = c("https://registry.example.com");
        let client = pap_marketplace_client_new(url.as_ptr());

        let bad = c("not json");
        let list = pap_marketplace_query(client, bad.as_ptr());
        assert!(list.is_null());

        let err = pap_last_error();
        assert!(!err.is_null());
        let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap();
        assert!(msg.contains("invalid capability JSON"), "error: {msg}");
        unsafe { pap_string_free(err) };

        unsafe { pap_marketplace_client_free(client) };
    }

    #[test]
    fn query_missing_action_field_returns_null() {
        let url = c("https://registry.example.com");
        let client = pap_marketplace_client_new(url.as_ptr());

        let bad = c("{}");
        let list = pap_marketplace_query(client, bad.as_ptr());
        assert!(list.is_null());

        let err = pap_last_error();
        assert!(!err.is_null());
        let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap();
        assert!(msg.contains("action"), "error: {msg}");
        unsafe { pap_string_free(err) };

        unsafe { pap_marketplace_client_free(client) };
    }

    #[test]
    fn pap_last_error_alias_works() {
        // Trigger an error
        let url = c("https://registry.example.com");
        let client = pap_marketplace_client_new(url.as_ptr());
        let bad = c("not json");
        let list = pap_marketplace_query(client, bad.as_ptr());
        assert!(list.is_null());

        // pap_last_error() returns the message
        let err = pap_last_error();
        assert!(!err.is_null());
        unsafe { pap_string_free(err) };

        // Second call returns null (consumed)
        let err2 = pap_last_error();
        assert!(err2.is_null());

        unsafe { pap_marketplace_client_free(client) };
    }

    #[test]
    fn register_unsigned_ad_fails() {
        let url = c("https://registry.example.com");
        let client = pap_marketplace_client_new(url.as_ptr());

        let name = c("Unsigned Agent");
        let provider = c("Corp");
        let did = c("did:key:zunsigned");
        let cap_str = c("schema:SearchAction");
        let caps: Vec<*const c_char> = vec![cap_str.as_ptr()];
        let empty: Vec<*const c_char> = vec![];

        let ad = unsafe {
            pap_advertisement_new(
                name.as_ptr(),
                provider.as_ptr(),
                did.as_ptr(),
                caps.as_ptr(),
                1,
                empty.as_ptr(),
                0,
                empty.as_ptr(),
                0,
                empty.as_ptr(),
                0,
            )
        };
        assert!(!ad.is_null());

        // Don't sign — register should fail
        let rc = unsafe { pap_marketplace_client_register(client, ad) };
        assert_eq!(rc, -1);

        let err = pap_last_error();
        assert!(!err.is_null());
        let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap();
        assert!(msg.contains("signed"), "error: {msg}");
        unsafe { pap_string_free(err) };

        unsafe {
            pap_advertisement_free(ad);
            pap_marketplace_client_free(client);
        }
    }
}
