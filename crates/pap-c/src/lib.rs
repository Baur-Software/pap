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
///
/// ⚠️ THREAD-SAFETY WARNING: This function reads from thread-local storage.
/// In async runtimes (tokio, async-std) where tasks migrate between threads,
/// the error set by one operation may not be visible on the thread that calls
/// this function. For async contexts, use `pap_last_error_out` pattern or
/// ensure all PAP calls happen on a single dedicated thread.
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
///
/// ⚠️ THREAD-SAFETY WARNING: This function reads from thread-local storage.
/// In async runtimes (tokio, async-std) where tasks migrate between threads,
/// the error set by one operation may not be visible on the thread that calls
/// this function. For async contexts, use `pap_last_error_out` pattern or
/// ensure all PAP calls happen on a single dedicated thread.
#[no_mangle]
pub extern "C" fn pap_last_error() -> *mut c_char {
    pap_last_error_message()
}

/// Alias for `pap_last_error_message`, explicitly named to signal thread-local
/// storage semantics. Only safe in synchronous (non-async, non-task-migrating)
/// calling contexts where the caller is guaranteed to remain on the same OS
/// thread as the PAP function that set the error.
///
/// ⚠️ THREAD-SAFETY WARNING: This function reads from thread-local storage.
/// In async runtimes (tokio, async-std) where tasks migrate between threads,
/// the error set by one operation may not be visible on the thread that calls
/// this function. For async contexts, use `pap_last_error_out` pattern or
/// ensure all PAP calls happen on a single dedicated thread.
#[no_mangle]
pub extern "C" fn pap_last_error_message_tl() -> *mut c_char {
    pap_last_error_message()
}

/// Thread-safe alternative to `pap_last_error_message`.
/// Writes the last error into `out_msg` if non-null.
/// Returns 1 if an error was present, 0 if none.
/// The written string must be freed with `pap_string_free`.
///
/// # Safety
/// `out_msg` must be either null or a valid pointer to a `*mut c_char` that
/// this function may write to.
#[no_mangle]
pub unsafe extern "C" fn pap_get_last_error(out_msg: *mut *mut c_char) -> c_int {
    LAST_ERROR.with(|c| match c.borrow_mut().take() {
        Some(s) => {
            if !out_msg.is_null() {
                match CString::new(s) {
                    Ok(cs) => unsafe { *out_msg = cs.into_raw() },
                    Err(_) => unsafe { *out_msg = std::ptr::null_mut() },
                }
            }
            1
        }
        None => 0,
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
    let arr: [u8; 32] = slice
        .try_into()
        .expect("slice length verified to be 32 above");
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
        (Some(p), Some(c)) if p.inner.contains(&c.inner) => 1,
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
    let arr: [u8; 32] = bytes
        .try_into()
        .expect("slice length verified to be 32 above");
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
/// and `transition_decay` manually. It handles the self-transition guard:
/// calling `transition_decay` with the current state is rejected by the spec
/// state machine, so this function is a no-op when the computed state equals
/// the current state.
///
/// The one-step guarantee (Active→Degraded→ReadOnly→Suspended, never
/// skipping an intermediate) is now enforced by `compute_decay_state` itself
/// per spec §5.7.1 — no special handling is needed here.
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
    let arr: [u8; 32] = bytes
        .try_into()
        .expect("slice length verified to be 32 above");
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
    let arr: [u8; 32] = bytes
        .try_into()
        .expect("slice length verified to be 32 above");
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
    let init_arr: [u8; 32] = init_bytes
        .try_into()
        .expect("slice length verified to be 32 above");
    let recv_arr: [u8; 32] = recv_bytes
        .try_into()
        .expect("slice length verified to be 32 above");
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
    let arr: [u8; 32] = bytes
        .try_into()
        .expect("slice length verified to be 32 above");
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

// ---------------------------------------------------------------------------
// Ecash — Chaumian blind-signed payment tokens (spec §13.1)
// ---------------------------------------------------------------------------

use pap_ecash::{
    EcashBlindToken as RustBlindToken, EcashMintKeypair as RustMintKeypair,
    EcashMintPublicKey as RustMintPublicKey, EcashSpentRegistry as RustSpentRegistry,
    EcashToken as RustEcashToken,
};

/// Opaque handle wrapping an [`EcashMintKeypair`].
pub struct PapEcashMintKeypair {
    inner: RustMintKeypair,
}

/// Opaque handle wrapping an [`EcashBlindToken`].
pub struct PapEcashBlindToken {
    inner: RustBlindToken,
}

/// Opaque handle wrapping an [`EcashToken`] (serial + unblinded signature).
pub struct PapEcashToken {
    inner: RustEcashToken,
}

/// Opaque handle wrapping an [`EcashSpentRegistry`] (in-memory double-spend set).
pub struct PapEcashSpentRegistry {
    inner: RustSpentRegistry,
}

// ── Keypair ─────────────────────────────────────────────────────────────────

/// Generate a new ecash mint keypair.
///
/// `key_bits` MUST be ≥ 2048 for production; 1024 is acceptable for tests.
/// Returns NULL on failure; call `pap_last_error_message()` for details.
/// Caller must free with `pap_ecash_mint_keypair_free`.
#[no_mangle]
pub extern "C" fn pap_ecash_mint_keypair_generate(
    key_bits: std::os::raw::c_uint,
) -> *mut PapEcashMintKeypair {
    match RustMintKeypair::generate(key_bits as usize) {
        Ok(inner) => Box::into_raw(Box::new(PapEcashMintKeypair { inner })),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Free a keypair returned by `pap_ecash_mint_keypair_generate`.
/// # Safety
/// `kp` must be a pointer previously returned by that function, or NULL.
#[no_mangle]
pub unsafe extern "C" fn pap_ecash_mint_keypair_free(kp: *mut PapEcashMintKeypair) {
    if !kp.is_null() {
        drop(unsafe { Box::from_raw(kp) });
    }
}

/// Serialize the mint public key as a PKCS#1 PEM string.
///
/// Returns NULL on failure. Caller must free the returned string with
/// `pap_string_free`.
#[no_mangle]
pub extern "C" fn pap_ecash_mint_keypair_public_pem(kp: *const PapEcashMintKeypair) -> *mut c_char {
    let kp = ref_or_null!(kp);
    match kp.inner.public_key_to_pem() {
        Ok(pem) => cstring_or_null!(pem),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

// ── Blinding (client) ────────────────────────────────────────────────────────

/// **Client:** Blind a serial number against the mint's public key.
///
/// `mint_public_pem` — PKCS#1 PEM string from `pap_ecash_mint_keypair_public_pem`.
/// `serial` — pointer to `serial_len` bytes (typically 32).
///
/// Returns an opaque handle or NULL on failure.
/// Caller must free with `pap_ecash_blind_token_free`.
/// Only `pap_ecash_blind_message_bytes` should be sent to the mint.
#[no_mangle]
pub extern "C" fn pap_ecash_blind(
    mint_public_pem: *const c_char,
    serial: *const u8,
    serial_len: usize,
) -> *mut PapEcashBlindToken {
    let pem = cstr_or_null!(mint_public_pem);
    if serial.is_null() || serial_len != 32 {
        set_last_error("serial must be exactly 32 bytes");
        return std::ptr::null_mut();
    }
    let serial_slice = unsafe { std::slice::from_raw_parts(serial, serial_len) };
    let serial_arr: [u8; 32] = match serial_slice.try_into() {
        Ok(a) => a,
        Err(_) => {
            set_last_error("serial must be exactly 32 bytes");
            return std::ptr::null_mut();
        }
    };

    let pk = match RustMintPublicKey::from_pem(pem) {
        Ok(pk) => pk,
        Err(e) => {
            set_last_error(&e.to_string());
            return std::ptr::null_mut();
        }
    };

    match pap_ecash::ecash_request(&serial_arr, &pk) {
        Ok(inner) => Box::into_raw(Box::new(PapEcashBlindToken { inner })),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Return the blinded-message bytes from a blind token — the only bytes to
/// transmit to the mint.
///
/// `out_len` — written with the byte count (may be NULL if unneeded).
/// Returns a heap-allocated byte array. Free with `pap_bytes_free(ptr, len)`.
/// Returns NULL on failure.
#[no_mangle]
pub extern "C" fn pap_ecash_blind_message_bytes(
    bt: *const PapEcashBlindToken,
    out_len: *mut usize,
) -> *mut u8 {
    let bt = ref_or_null!(bt);
    let bytes = bt.inner.blinded_message().to_vec();
    let len = bytes.len();
    if !out_len.is_null() {
        unsafe { *out_len = len };
    }
    let mut boxed = bytes.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);
    ptr
}

/// Free a blind token returned by `pap_ecash_blind`.
/// # Safety
/// `bt` must be a pointer previously returned by that function, or NULL.
#[no_mangle]
pub unsafe extern "C" fn pap_ecash_blind_token_free(bt: *mut PapEcashBlindToken) {
    if !bt.is_null() {
        drop(unsafe { Box::from_raw(bt) });
    }
}

// ── Signing (mint) ───────────────────────────────────────────────────────────

/// **Mint:** Sign a blinded message and return the raw blind-signature bytes.
///
/// `blinded_msg` — bytes from `pap_ecash_blind_message_bytes` on the client.
/// `out_sig_len` — if non-NULL, written with the byte count of the returned array.
///
/// Returns a heap-allocated byte array. Free with `pap_bytes_free(ptr, len)`.
/// Returns NULL on failure.
#[no_mangle]
pub extern "C" fn pap_ecash_mint_sign(
    kp: *const PapEcashMintKeypair,
    blinded_msg: *const u8,
    blinded_len: usize,
    out_sig_len: *mut usize,
) -> *mut u8 {
    let kp = ref_or_null!(kp);
    if blinded_msg.is_null() {
        set_last_error("null blinded_msg pointer");
        return std::ptr::null_mut();
    }
    let msg = unsafe { std::slice::from_raw_parts(blinded_msg, blinded_len) };
    match pap_ecash::ecash_mint_sign(msg, &kp.inner) {
        Ok(sig_bytes) => {
            let len = sig_bytes.len();
            if !out_sig_len.is_null() {
                unsafe { *out_sig_len = len };
            }
            let mut boxed = sig_bytes.into_boxed_slice();
            let ptr = boxed.as_mut_ptr();
            std::mem::forget(boxed);
            ptr
        }
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

// ── Unblinding (client) ──────────────────────────────────────────────────────

/// **Client:** Unblind the mint's signature to produce a redeemable token.
///
/// `mint_public_pem` — same PKCS#1 PEM used during blinding.
/// `bt` — the blind token from `pap_ecash_blind` (still held by the client).
/// `blind_sig` / `blind_sig_len` — bytes returned by the mint.
///
/// Returns an opaque token handle or NULL on failure.
/// Caller must free with `pap_ecash_token_free`.
#[no_mangle]
pub extern "C" fn pap_ecash_unblind(
    mint_public_pem: *const c_char,
    bt: *const PapEcashBlindToken,
    blind_sig: *const u8,
    blind_sig_len: usize,
) -> *mut PapEcashToken {
    let pem = cstr_or_null!(mint_public_pem);
    let bt = ref_or_null!(bt);
    if blind_sig.is_null() {
        set_last_error("null blind_sig pointer");
        return std::ptr::null_mut();
    }
    let sig_bytes = unsafe { std::slice::from_raw_parts(blind_sig, blind_sig_len) };

    let pk = match RustMintPublicKey::from_pem(pem) {
        Ok(pk) => pk,
        Err(e) => {
            set_last_error(&e.to_string());
            return std::ptr::null_mut();
        }
    };

    match pap_ecash::ecash_unblind(&bt.inner, sig_bytes, &pk) {
        Ok(inner) => Box::into_raw(Box::new(PapEcashToken { inner })),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Return the base64url-no-pad SHA-256 payment-proof commitment for a token.
///
/// Caller must free the returned string with `pap_string_free`.
/// Returns NULL on failure.
#[no_mangle]
pub extern "C" fn pap_ecash_token_payment_proof_commitment(
    token: *const PapEcashToken,
) -> *mut c_char {
    let token = ref_or_null!(token);
    cstring_or_null!(token.inner.commitment())
}

/// Return the 32-byte serial from an ecash token.
///
/// `out_len` — if non-NULL, written with the byte count (always 32).
/// Returns a heap-allocated byte array. Free with `pap_bytes_free(ptr, len)`.
/// Returns NULL on failure.
#[no_mangle]
pub extern "C" fn pap_ecash_token_serial(
    token: *const PapEcashToken,
    out_len: *mut usize,
) -> *mut u8 {
    let token = ref_or_null!(token);
    let bytes = token.inner.serial.to_vec();
    let len = bytes.len();
    if !out_len.is_null() {
        unsafe { *out_len = len };
    }
    let mut boxed = bytes.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);
    ptr
}

/// Return the unblinded signature bytes from an ecash token.
///
/// `out_len` — if non-NULL, written with the byte count.
/// Returns a heap-allocated byte array. Free with `pap_bytes_free(ptr, len)`.
/// Returns NULL on failure.
#[no_mangle]
pub extern "C" fn pap_ecash_token_signature(
    token: *const PapEcashToken,
    out_len: *mut usize,
) -> *mut u8 {
    let token = ref_or_null!(token);
    let bytes = token.inner.signature.clone();
    let len = bytes.len();
    if !out_len.is_null() {
        unsafe { *out_len = len };
    }
    let mut boxed = bytes.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);
    ptr
}

/// Free a token returned by `pap_ecash_unblind`.
/// # Safety
/// `token` must be a pointer previously returned by that function, or NULL.
#[no_mangle]
pub unsafe extern "C" fn pap_ecash_token_free(token: *mut PapEcashToken) {
    if !token.is_null() {
        drop(unsafe { Box::from_raw(token) });
    }
}

// ── Verify / Redeem ──────────────────────────────────────────────────────────

/// **Payee:** Verify a token without recording it in the spent registry.
///
/// Returns `0` if the signature is valid, `-1` otherwise.
/// Does not protect against double-spend — use `pap_ecash_redeem` for that.
#[no_mangle]
pub extern "C" fn pap_ecash_verify(
    mint_public_pem: *const c_char,
    serial: *const u8,
    serial_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> c_int {
    let pem = cstr_or_err!(mint_public_pem);
    if serial.is_null() || serial_len != 32 || sig.is_null() {
        set_last_error("null or incorrect-length argument");
        return -1;
    }
    let serial_slice = unsafe { std::slice::from_raw_parts(serial, serial_len) };
    let serial_arr: [u8; 32] = match serial_slice.try_into() {
        Ok(a) => a,
        Err(_) => {
            set_last_error("serial must be exactly 32 bytes");
            return -1;
        }
    };
    let sig_bytes = unsafe { std::slice::from_raw_parts(sig, sig_len) };

    let pk = match RustMintPublicKey::from_pem(pem) {
        Ok(pk) => pk,
        Err(e) => {
            set_last_error(&e.to_string());
            return -1;
        }
    };

    let token = RustEcashToken {
        serial: serial_arr,
        signature: sig_bytes.to_vec(),
    };

    if pap_ecash::ecash_verify(&token, &pk) {
        0
    } else {
        set_last_error("ecash verification failed");
        -1
    }
}

/// Create a new empty double-spend registry.
/// Caller must free with `pap_ecash_spent_registry_free`.
#[no_mangle]
pub extern "C" fn pap_ecash_spent_registry_new() -> *mut PapEcashSpentRegistry {
    Box::into_raw(Box::new(PapEcashSpentRegistry {
        inner: RustSpentRegistry::new(),
    }))
}

/// Free a registry returned by `pap_ecash_spent_registry_new`.
/// # Safety
/// `r` must be a pointer previously returned by that function, or NULL.
#[no_mangle]
pub unsafe extern "C" fn pap_ecash_spent_registry_free(r: *mut PapEcashSpentRegistry) {
    if !r.is_null() {
        drop(unsafe { Box::from_raw(r) });
    }
}

/// **Payee:** Verify a token and atomically record its serial as spent.
///
/// Returns `0` on success (first redemption of a valid token).
/// Returns `-1` with a descriptive last-error on double-spend or invalid sig.
#[no_mangle]
pub extern "C" fn pap_ecash_redeem(
    mint_public_pem: *const c_char,
    serial: *const u8,
    serial_len: usize,
    sig: *const u8,
    sig_len: usize,
    registry: *mut PapEcashSpentRegistry,
) -> c_int {
    let pem = cstr_or_err!(mint_public_pem);
    if serial.is_null() || serial_len != 32 || sig.is_null() {
        set_last_error("null or incorrect-length argument");
        return -1;
    }
    let serial_slice = unsafe { std::slice::from_raw_parts(serial, serial_len) };
    let serial_arr: [u8; 32] = match serial_slice.try_into() {
        Ok(a) => a,
        Err(_) => {
            set_last_error("serial must be exactly 32 bytes");
            return -1;
        }
    };
    let sig_bytes = unsafe { std::slice::from_raw_parts(sig, sig_len) };
    let reg = mut_or_err!(registry);

    let pk = match RustMintPublicKey::from_pem(pem) {
        Ok(pk) => pk,
        Err(e) => {
            set_last_error(&e.to_string());
            return -1;
        }
    };

    let token = RustEcashToken {
        serial: serial_arr,
        signature: sig_bytes.to_vec(),
    };

    match pap_ecash::ecash_redeem(&token, &pk, &mut reg.inner) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

// ── Byte array allocator / deallocator ───────────────────────────────────────

/// Free a byte array previously returned by `pap_ecash_blind_message_bytes`
/// or `pap_ecash_mint_sign`.
///
/// # Safety
/// `ptr` must be a pointer previously returned by one of those functions (or
/// NULL). `len` must be the exact length reported by that call.
#[no_mangle]
pub unsafe extern "C" fn pap_bytes_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
        drop(unsafe { Box::from_raw(slice) });
    }
}

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

    #[test]
    fn get_last_error_returns_zero_when_no_error() {
        let mut out: *mut c_char = std::ptr::null_mut();
        let result = unsafe { pap_get_last_error(&mut out as *mut _) };
        assert_eq!(result, 0);
        assert!(out.is_null());
    }

    // -------------------------------------------------------------------------
    // pap_get_last_error / pap_last_error_message tests
    // -------------------------------------------------------------------------

    /// Trigger an error via pap_mandate_from_json (invalid JSON), then verify
    /// pap_get_last_error returns 1 and writes the error message.
    #[test]
    fn get_last_error_returns_one_when_error_set() {
        let bad_json = c("not valid json at all");
        // pap_mandate_from_json sets an error and returns null on bad input.
        let m = pap_mandate_from_json(bad_json.as_ptr());
        assert!(m.is_null(), "expected null from invalid JSON");

        let mut out: *mut c_char = std::ptr::null_mut();
        let result = unsafe { pap_get_last_error(&mut out as *mut _) };
        assert_eq!(result, 1, "expected 1 (error present)");
        assert!(
            !out.is_null(),
            "out should be non-null when error is present"
        );

        let msg = unsafe { std::ffi::CStr::from_ptr(out) }
            .to_str()
            .expect("error message should be valid UTF-8");
        assert!(!msg.is_empty(), "error message should not be empty");

        unsafe { pap_string_free(out) };
    }

    /// After reading the error with pap_get_last_error, a second call should
    /// return 0 (the error is consumed on read — no double-read).
    #[test]
    fn get_last_error_consumes_error_on_read() {
        // Trigger an error
        let bad_json = c("{invalid}");
        let m = pap_mandate_from_json(bad_json.as_ptr());
        assert!(m.is_null());

        // First read — error should be present
        let mut out: *mut c_char = std::ptr::null_mut();
        let first = unsafe { pap_get_last_error(&mut out as *mut _) };
        assert_eq!(first, 1);
        assert!(!out.is_null());
        unsafe { pap_string_free(out) };

        // Second read — error should be consumed, nothing to report
        let mut out2: *mut c_char = std::ptr::null_mut();
        let second = unsafe { pap_get_last_error(&mut out2 as *mut _) };
        assert_eq!(second, 0, "error should be consumed after first read");
        assert!(out2.is_null());
    }

    /// Passing a null out-param to pap_get_last_error should still return 1
    /// (error exists) but must not crash or write through a null pointer.
    #[test]
    fn get_last_error_with_null_out_param() {
        // Trigger an error
        let bad_json = c("totally not json");
        let m = pap_mandate_from_json(bad_json.as_ptr());
        assert!(m.is_null());

        // Pass null as out_msg — must not crash
        let result = unsafe { pap_get_last_error(std::ptr::null_mut()) };
        assert_eq!(result, 1, "should return 1 even when out_msg is null");

        // Error is consumed even with a null out param — subsequent call returns 0
        let mut out: *mut c_char = std::ptr::null_mut();
        let second = unsafe { pap_get_last_error(&mut out as *mut _) };
        assert_eq!(second, 0);
        assert!(out.is_null());
    }

    /// pap_last_error_message() should return the error string and consume it;
    /// a second call should return null.
    #[test]
    fn pap_last_error_message_consumes_error_on_read() {
        // Trigger an error
        let bad_json = c("{}broken");
        let m = pap_mandate_from_json(bad_json.as_ptr());
        assert!(m.is_null());

        // First call — non-null
        let msg1 = pap_last_error_message();
        assert!(
            !msg1.is_null(),
            "pap_last_error_message should return non-null when error exists"
        );
        unsafe { pap_string_free(msg1) };

        // Second call — null (consumed)
        let msg2 = pap_last_error_message();
        assert!(
            msg2.is_null(),
            "pap_last_error_message should return null after error is consumed"
        );
    }

    /// pap_string_free(NULL) must be a no-op and must not panic.
    #[test]
    fn pap_string_free_null_is_safe() {
        // This must not crash.
        unsafe { pap_string_free(std::ptr::null_mut()) };
    }

    /// pap_mandate_from_json with invalid JSON must return null and set an error.
    #[test]
    fn mandate_from_json_invalid_returns_null_and_sets_error() {
        // First consume any stale error from a prior test on this thread.
        let _ = pap_last_error_message();

        let bad = c("this is not a mandate");
        let m = pap_mandate_from_json(bad.as_ptr());
        assert!(
            m.is_null(),
            "pap_mandate_from_json should return null for invalid JSON"
        );

        // The error should have been set
        let mut out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe { pap_get_last_error(&mut out as *mut _) };
        assert_eq!(
            rc, 1,
            "an error should be set after a failed pap_mandate_from_json"
        );
        assert!(!out.is_null());
        unsafe { pap_string_free(out) };
    }

    /// pap_keypair_generate() must return a non-null handle; pap_keypair_free()
    /// must not panic on a valid handle. Null-free must also be a no-op.
    #[test]
    fn keypair_generate_and_free_roundtrip() {
        let kp = pap_keypair_generate();
        assert!(
            !kp.is_null(),
            "pap_keypair_generate should return a valid handle"
        );
        // Free the handle — must not crash
        unsafe { pap_keypair_free(kp) };
        // Freeing null is also a no-op
        unsafe { pap_keypair_free(std::ptr::null_mut()) };
    }

    /// pap_session_keypair_generate() must return a non-null handle;
    /// pap_session_keypair_free() must not panic on a valid or null handle.
    #[test]
    fn session_keypair_generate_and_free_roundtrip() {
        let kp = pap_session_keypair_generate();
        assert!(
            !kp.is_null(),
            "pap_session_keypair_generate should return a valid handle"
        );
        // Free the handle — must not crash
        unsafe { pap_session_keypair_free(kp) };
        // Freeing null is also a no-op
        unsafe { pap_session_keypair_free(std::ptr::null_mut()) };
    }

    /// pap_last_error_message_tl() and pap_last_error_message() are both aliases
    /// that consume the error. Verify both behave identically: return non-null
    /// after an error is set, then return null on the next call.
    #[test]
    fn pap_last_error_message_tl_equivalent_to_pap_last_error_message() {
        // --- Round 1: use pap_last_error_message_tl ---
        let bad1 = c("bad json for tl test");
        let m1 = pap_mandate_from_json(bad1.as_ptr());
        assert!(m1.is_null());

        let tl_msg = pap_last_error_message_tl();
        assert!(
            !tl_msg.is_null(),
            "pap_last_error_message_tl should return non-null when error exists"
        );
        unsafe { pap_string_free(tl_msg) };

        // Error should now be consumed
        let tl_msg2 = pap_last_error_message_tl();
        assert!(
            tl_msg2.is_null(),
            "pap_last_error_message_tl should return null after consumption"
        );

        // --- Round 2: use pap_last_error_message ---
        let bad2 = c("also bad json for message test");
        let m2 = pap_mandate_from_json(bad2.as_ptr());
        assert!(m2.is_null());

        let msg = pap_last_error_message();
        assert!(
            !msg.is_null(),
            "pap_last_error_message should return non-null when error exists"
        );
        unsafe { pap_string_free(msg) };

        // Error should now be consumed
        let msg2 = pap_last_error_message();
        assert!(
            msg2.is_null(),
            "pap_last_error_message should return null after consumption"
        );
    }
}

// ---------------------------------------------------------------------------
// Sandbox execution bindings
// ---------------------------------------------------------------------------

pub struct PapCapabilityPolicy {
    inner: pap_sandbox::CapabilityPolicy,
}
pub struct PapExecutionHandle {
    inner: pap_sandbox::ExecutionHandle,
}
pub struct PapExecutionContext {
    inner: pap_sandbox::ExecutionContext,
}
pub struct PapAttestationReceipt {
    inner: pap_sandbox::AttestationReceipt,
}
pub struct PapAgentSpawner {
    inner: Box<dyn pap_sandbox::AgentSpawner>,
    rt: tokio::runtime::Runtime,
}

/// ExecutionState integer constants returned by `pap_spawner_poll_state`.
pub const PAP_EXEC_STATE_PENDING: i32 = 0;
pub const PAP_EXEC_STATE_RUNNING: i32 = 1;
pub const PAP_EXEC_STATE_COMPLETED: i32 = 2;
pub const PAP_EXEC_STATE_TIMED_OUT: i32 = 3;
pub const PAP_EXEC_STATE_KILLED: i32 = 4;
pub const PAP_EXEC_STATE_FAILED: i32 = 5;

// ── CapabilityPolicy ──────────────────────────────────────────────────────────

/// Create a default CapabilityPolicy (deny-all, 30s timeout).
#[no_mangle]
pub extern "C" fn pap_capability_policy_new() -> *mut PapCapabilityPolicy {
    Box::into_raw(Box::new(PapCapabilityPolicy {
        inner: pap_sandbox::CapabilityPolicy::default(),
    }))
}

/// Free a PapCapabilityPolicy. Passing NULL is a no-op.
/// # Safety
/// `p` must be a pointer previously returned by `pap_capability_policy_new`.
#[no_mangle]
pub unsafe extern "C" fn pap_capability_policy_free(p: *mut PapCapabilityPolicy) {
    if !p.is_null() {
        drop(unsafe { Box::from_raw(p) });
    }
}

/// Set execution timeout in seconds. Returns 0 on success, -1 on null input.
#[no_mangle]
pub unsafe extern "C" fn pap_capability_policy_set_timeout(
    p: *mut PapCapabilityPolicy,
    secs: u64,
) -> c_int {
    if p.is_null() {
        set_last_error("pap_capability_policy_set_timeout: null pointer");
        return -1;
    }
    unsafe { (*p).inner.execution_timeout_secs = secs };
    0
}

/// Set whether network access is permitted. `allowed` non-zero means true.
#[no_mangle]
pub unsafe extern "C" fn pap_capability_policy_set_network(
    p: *mut PapCapabilityPolicy,
    allowed: c_int,
) -> c_int {
    if p.is_null() {
        set_last_error("pap_capability_policy_set_network: null pointer");
        return -1;
    }
    unsafe { (*p).inner.network_allowed = allowed != 0 };
    0
}

/// Set whether filesystem access is permitted. `allowed` non-zero means true.
#[no_mangle]
pub unsafe extern "C" fn pap_capability_policy_set_filesystem(
    p: *mut PapCapabilityPolicy,
    allowed: c_int,
) -> c_int {
    if p.is_null() {
        set_last_error("pap_capability_policy_set_filesystem: null pointer");
        return -1;
    }
    unsafe { (*p).inner.filesystem_allowed = allowed != 0 };
    0
}

/// Set whether subprocess spawning is permitted. `allowed` non-zero means true.
#[no_mangle]
pub unsafe extern "C" fn pap_capability_policy_set_subprocess(
    p: *mut PapCapabilityPolicy,
    allowed: c_int,
) -> c_int {
    if p.is_null() {
        set_last_error("pap_capability_policy_set_subprocess: null pointer");
        return -1;
    }
    unsafe { (*p).inner.subprocess_allowed = allowed != 0 };
    0
}

// ── ExecutionContext ──────────────────────────────────────────────────────────

/// Create an ExecutionContext with identity fields set and empty encrypted payloads.
/// Populate payloads with `pap_sandbox_encrypt` before passing to `pap_spawner_spawn`.
///
/// # Safety
/// All pointer arguments must be valid, null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn pap_execution_context_new(
    agent_did: *const c_char,
    agent_name: *const c_char,
    action_type: *const c_char,
    session_id: *const c_char,
) -> *mut PapExecutionContext {
    if agent_did.is_null() || agent_name.is_null() || action_type.is_null() || session_id.is_null()
    {
        set_last_error("pap_execution_context_new: null argument");
        return std::ptr::null_mut();
    }
    let agent_did = match unsafe { CStr::from_ptr(agent_did) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_last_error("pap_execution_context_new: invalid utf-8 in agent_did");
            return std::ptr::null_mut();
        }
    };
    let agent_name = match unsafe { CStr::from_ptr(agent_name) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_last_error("pap_execution_context_new: invalid utf-8 in agent_name");
            return std::ptr::null_mut();
        }
    };
    let action_type = match unsafe { CStr::from_ptr(action_type) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_last_error("pap_execution_context_new: invalid utf-8 in action_type");
            return std::ptr::null_mut();
        }
    };
    let session_id = match unsafe { CStr::from_ptr(session_id) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => {
            set_last_error("pap_execution_context_new: invalid utf-8 in session_id");
            return std::ptr::null_mut();
        }
    };
    Box::into_raw(Box::new(PapExecutionContext {
        inner: pap_sandbox::ExecutionContext {
            query_enc: Vec::new(),
            disclosure_enc: Vec::new(),
            session_token_enc: Vec::new(),
            nonce: Vec::new(),
            ephemeral_public_key: Vec::new(),
            agent_did,
            agent_name,
            action_type,
            session_id,
        },
    }))
}

/// Free a PapExecutionContext. Passing NULL is a no-op.
/// # Safety
/// `ctx` must be a pointer previously returned by `pap_execution_context_new`.
#[no_mangle]
pub unsafe extern "C" fn pap_execution_context_free(ctx: *mut PapExecutionContext) {
    if !ctx.is_null() {
        drop(unsafe { Box::from_raw(ctx) });
    }
}

// ── Spawner ───────────────────────────────────────────────────────────────────

/// Create the platform-appropriate sandbox spawner.
/// Returns NULL on failure; call `pap_last_error_message()` for details.
#[no_mangle]
pub extern "C" fn pap_spawner_new() -> *mut PapAgentSpawner {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            set_last_error(&format!("pap_spawner_new: runtime: {e}"));
            return std::ptr::null_mut();
        }
    };
    match pap_sandbox::new_spawner() {
        Ok(inner) => Box::into_raw(Box::new(PapAgentSpawner { inner, rt })),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Free a PapAgentSpawner. Passing NULL is a no-op.
/// # Safety
/// `s` must be a pointer previously returned by `pap_spawner_new`.
#[no_mangle]
pub unsafe extern "C" fn pap_spawner_free(s: *mut PapAgentSpawner) {
    if !s.is_null() {
        drop(unsafe { Box::from_raw(s) });
    }
}

/// Spawn a sandboxed agent execution.
/// Writes the new handle to `*out_handle` on success.
/// Returns 0 on success, -1 on error (call `pap_last_error_message` for details).
///
/// # Safety
/// `spawner`, `policy`, `context`, and `out_handle` must be valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn pap_spawner_spawn(
    spawner: *const PapAgentSpawner,
    policy: *const PapCapabilityPolicy,
    context: *const PapExecutionContext,
    out_handle: *mut *mut PapExecutionHandle,
) -> c_int {
    if spawner.is_null() || policy.is_null() || context.is_null() || out_handle.is_null() {
        set_last_error("pap_spawner_spawn: null argument");
        return -1;
    }
    let s = unsafe { &*spawner };
    let pol = unsafe { (*policy).inner.clone() };
    let ctx = unsafe { (*context).inner.clone() };
    match s.rt.block_on(s.inner.spawn(pol, ctx)) {
        Ok(handle) => {
            unsafe { *out_handle = Box::into_raw(Box::new(PapExecutionHandle { inner: handle })) };
            0
        }
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

/// Free a PapExecutionHandle. Passing NULL is a no-op.
/// # Safety
/// `h` must be a pointer previously returned by `pap_spawner_spawn`.
#[no_mangle]
pub unsafe extern "C" fn pap_execution_handle_free(h: *mut PapExecutionHandle) {
    if !h.is_null() {
        drop(unsafe { Box::from_raw(h) });
    }
}

/// Poll the state of a running sandbox. Returns a PAP_EXEC_STATE_* constant,
/// or -1 on error (call `pap_last_error_message` for details).
///
/// # Safety
/// `spawner` and `handle` must be valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn pap_spawner_poll_state(
    spawner: *const PapAgentSpawner,
    handle: *const PapExecutionHandle,
) -> c_int {
    if spawner.is_null() || handle.is_null() {
        set_last_error("pap_spawner_poll_state: null argument");
        return -1;
    }
    let s = unsafe { &*spawner };
    let h = unsafe { &(*handle).inner };
    match s.rt.block_on(s.inner.poll_state(h)) {
        Ok(pap_sandbox::ExecutionState::Pending) => PAP_EXEC_STATE_PENDING,
        Ok(pap_sandbox::ExecutionState::Running { .. }) => PAP_EXEC_STATE_RUNNING,
        Ok(pap_sandbox::ExecutionState::Completed { .. }) => PAP_EXEC_STATE_COMPLETED,
        Ok(pap_sandbox::ExecutionState::TimedOut { .. }) => PAP_EXEC_STATE_TIMED_OUT,
        Ok(pap_sandbox::ExecutionState::Killed { .. }) => PAP_EXEC_STATE_KILLED,
        Ok(pap_sandbox::ExecutionState::Failed { .. }) => PAP_EXEC_STATE_FAILED,
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

/// Terminate a running sandbox.
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `spawner`, `handle`, and `reason` must be valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn pap_spawner_terminate(
    spawner: *const PapAgentSpawner,
    handle: *const PapExecutionHandle,
    reason: *const c_char,
) -> c_int {
    if spawner.is_null() || handle.is_null() || reason.is_null() {
        set_last_error("pap_spawner_terminate: null argument");
        return -1;
    }
    let s = unsafe { &*spawner };
    let h = unsafe { &(*handle).inner };
    let reason_str = match unsafe { CStr::from_ptr(reason) }.to_str() {
        Ok(r) => r,
        Err(_) => {
            set_last_error("pap_spawner_terminate: invalid utf-8 in reason");
            return -1;
        }
    };
    match s.rt.block_on(s.inner.terminate(h, reason_str)) {
        Ok(()) => 0,
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

/// Collect the attestation receipt after a completed sandbox execution.
/// Writes the receipt to `*out_receipt` on success.
/// Returns 0 on success, -1 on error.
///
/// The caller owns the returned receipt and must free it with
/// `pap_attestation_receipt_free`.
///
/// # Safety
/// `spawner`, `handle`, and `out_receipt` must be valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn pap_spawner_collect_receipt(
    spawner: *const PapAgentSpawner,
    handle: *const PapExecutionHandle,
    out_receipt: *mut *mut PapAttestationReceipt,
) -> c_int {
    if spawner.is_null() || handle.is_null() || out_receipt.is_null() {
        set_last_error("pap_spawner_collect_receipt: null argument");
        return -1;
    }
    let s = unsafe { &*spawner };
    let h = unsafe { &(*handle).inner };
    match s.rt.block_on(s.inner.collect_result(h)) {
        Ok((_result, receipt)) => {
            unsafe {
                *out_receipt =
                    Box::into_raw(Box::new(PapAttestationReceipt { inner: receipt }))
            };
            0
        }
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

// ── AttestationReceipt accessors ──────────────────────────────────────────────

/// Return the session_id field. Caller must free with `pap_string_free`.
/// # Safety
/// `r` must be a valid non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn pap_attestation_receipt_session_id(
    r: *const PapAttestationReceipt,
) -> *mut c_char {
    if r.is_null() {
        return std::ptr::null_mut();
    }
    CString::new(unsafe { (*r).inner.session_id.as_str() })
        .map(|cs| cs.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Return the agent_did field. Caller must free with `pap_string_free`.
/// # Safety
/// `r` must be a valid non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn pap_attestation_receipt_agent_did(
    r: *const PapAttestationReceipt,
) -> *mut c_char {
    if r.is_null() {
        return std::ptr::null_mut();
    }
    CString::new(unsafe { (*r).inner.agent_did.as_str() })
        .map(|cs| cs.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Return the result_hash field. Caller must free with `pap_string_free`.
/// # Safety
/// `r` must be a valid non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn pap_attestation_receipt_result_hash(
    r: *const PapAttestationReceipt,
) -> *mut c_char {
    if r.is_null() {
        return std::ptr::null_mut();
    }
    CString::new(unsafe { (*r).inner.result_hash.as_str() })
        .map(|cs| cs.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Return the exit_code field.
/// # Safety
/// `r` must be a valid non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn pap_attestation_receipt_exit_code(
    r: *const PapAttestationReceipt,
) -> c_int {
    if r.is_null() {
        return -1;
    }
    unsafe { (*r).inner.exit_code }
}

/// Return 1 if the execution was aborted, 0 otherwise. Returns -1 on null input.
/// # Safety
/// `r` must be a valid non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn pap_attestation_receipt_aborted(
    r: *const PapAttestationReceipt,
) -> c_int {
    if r.is_null() {
        return -1;
    }
    if unsafe { (*r).inner.aborted } {
        1
    } else {
        0
    }
}

/// Return the execution_duration_ms field.
/// # Safety
/// `r` must be a valid non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn pap_attestation_receipt_duration_ms(
    r: *const PapAttestationReceipt,
) -> u64 {
    if r.is_null() {
        return 0;
    }
    unsafe { (*r).inner.execution_duration_ms }
}

/// Return the full receipt as a JSON string. Caller must free with `pap_string_free`.
/// Returns NULL on serialization error.
/// # Safety
/// `r` must be a valid non-null pointer.
#[no_mangle]
pub unsafe extern "C" fn pap_attestation_receipt_to_json(
    r: *const PapAttestationReceipt,
) -> *mut c_char {
    if r.is_null() {
        return std::ptr::null_mut();
    }
    match serde_json::to_string(&unsafe { &(*r).inner }) {
        Ok(s) => CString::new(s)
            .map(|cs| cs.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(e) => {
            set_last_error(&e.to_string());
            std::ptr::null_mut()
        }
    }
}

/// Free a PapAttestationReceipt. Passing NULL is a no-op.
/// # Safety
/// `r` must be a pointer previously returned by `pap_spawner_collect_receipt`.
#[no_mangle]
pub unsafe extern "C" fn pap_attestation_receipt_free(r: *mut PapAttestationReceipt) {
    if !r.is_null() {
        drop(unsafe { Box::from_raw(r) });
    }
}

// ── Encryption utilities ──────────────────────────────────────────────────────

/// AES-256-GCM encryption.
///
/// Writes ciphertext to `*out_ciphertext` (length in `*out_ciphertext_len`)
/// and nonce to `*out_nonce` (length in `*out_nonce_len`).
/// Caller must free both buffers with `pap_sandbox_bytes_free`.
///
/// `key` must be exactly 32 bytes.
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// All pointer arguments must be valid.
#[no_mangle]
pub unsafe extern "C" fn pap_sandbox_encrypt(
    plaintext: *const u8,
    plaintext_len: usize,
    key_32: *const u8,
    out_ciphertext: *mut *mut u8,
    out_ciphertext_len: *mut usize,
    out_nonce: *mut *mut u8,
    out_nonce_len: *mut usize,
) -> c_int {
    if plaintext.is_null()
        || key_32.is_null()
        || out_ciphertext.is_null()
        || out_ciphertext_len.is_null()
        || out_nonce.is_null()
        || out_nonce_len.is_null()
    {
        set_last_error("pap_sandbox_encrypt: null argument");
        return -1;
    }
    let pt = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };
    let key_slice = unsafe { std::slice::from_raw_parts(key_32, 32) };
    let key: [u8; 32] = match key_slice.try_into() {
        Ok(k) => k,
        Err(_) => {
            set_last_error("pap_sandbox_encrypt: key must be 32 bytes");
            return -1;
        }
    };
    match pap_sandbox::encrypt(pt, &key) {
        Ok((ct, nonce)) => {
            let ct_len = ct.len();
            let nonce_len = nonce.len();
            let ct_ptr = ct.into_boxed_slice();
            let nonce_ptr = nonce.into_boxed_slice();
            unsafe {
                *out_ciphertext = Box::into_raw(ct_ptr) as *mut u8;
                *out_ciphertext_len = ct_len;
                *out_nonce = Box::into_raw(nonce_ptr) as *mut u8;
                *out_nonce_len = nonce_len;
            }
            0
        }
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

/// AES-256-GCM decryption.
///
/// Writes plaintext to `*out_plaintext` (length in `*out_plaintext_len`).
/// Caller must free with `pap_sandbox_bytes_free`.
///
/// `key` must be exactly 32 bytes.
/// Returns 0 on success, -1 on error (authentication failure or bad nonce length).
///
/// # Safety
/// All pointer arguments must be valid.
#[no_mangle]
pub unsafe extern "C" fn pap_sandbox_decrypt(
    ciphertext: *const u8,
    ciphertext_len: usize,
    key_32: *const u8,
    nonce: *const u8,
    nonce_len: usize,
    out_plaintext: *mut *mut u8,
    out_plaintext_len: *mut usize,
) -> c_int {
    if ciphertext.is_null()
        || key_32.is_null()
        || nonce.is_null()
        || out_plaintext.is_null()
        || out_plaintext_len.is_null()
    {
        set_last_error("pap_sandbox_decrypt: null argument");
        return -1;
    }
    let ct = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_len) };
    let key_slice = unsafe { std::slice::from_raw_parts(key_32, 32) };
    let key: [u8; 32] = match key_slice.try_into() {
        Ok(k) => k,
        Err(_) => {
            set_last_error("pap_sandbox_decrypt: key must be 32 bytes");
            return -1;
        }
    };
    let nonce_slice = unsafe { std::slice::from_raw_parts(nonce, nonce_len) };
    match pap_sandbox::decrypt(ct, &key, nonce_slice) {
        Ok(pt) => {
            let pt_len = pt.len();
            let pt_ptr = pt.into_boxed_slice();
            unsafe {
                *out_plaintext = Box::into_raw(pt_ptr) as *mut u8;
                *out_plaintext_len = pt_len;
            }
            0
        }
        Err(e) => {
            set_last_error(&e.to_string());
            -1
        }
    }
}

/// Free a byte buffer returned by `pap_sandbox_encrypt` or `pap_sandbox_decrypt`.
///
/// # Safety
/// `ptr` must be a pointer previously returned by one of those functions,
/// and `len` must be the length that was written to the corresponding `*_len` out-parameter.
#[no_mangle]
pub unsafe extern "C" fn pap_sandbox_bytes_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        drop(unsafe { Box::from_raw(std::slice::from_raw_parts_mut(ptr, len)) });
    }
}
