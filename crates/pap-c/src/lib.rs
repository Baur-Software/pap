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
#![allow(clippy::missing_safety_doc)]

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

use pap_core::mandate::{DecayState, Mandate};
use pap_core::scope::{DisclosureEntry, DisclosureSet, Scope, ScopeAction};
use pap_core::session::{CapabilityToken, Session, SessionState};
use pap_did::{PrincipalKeypair, SessionKeypair};

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
    let arr: [u8; 32] = slice.try_into().unwrap();
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
    m.inner.sign(kp.inner.signing_key());
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
    let arr: [u8; 32] = bytes.try_into().unwrap();
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
    t.inner.sign(kp.inner.signing_key());
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
    let arr: [u8; 32] = bytes.try_into().unwrap();
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
