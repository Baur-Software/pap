/**
 * pap.hpp — C++ RAII wrapper for the Principal Agent Protocol C API.
 *
 * Header-only. Requires pap.h and the compiled libpap_c on the link path.
 *
 * Usage:
 *   #include "pap.hpp"
 *   auto kp = pap::PrincipalKeypair::generate();
 *   auto scope = pap::Scope::from({pap::ScopeAction{"schema:SearchAction"}});
 *   auto ds    = pap::DisclosureSet::empty();
 *   auto m     = pap::Mandate::issue_root(kp.did(), "did:key:zagent", scope, ds,
 *                                         "2026-03-23T12:00:00Z");
 *   m.sign(kp);
 *
 * Build (CMake example):
 *   find_library(PAP_C pap_c PATHS /path/to/release)
 *   target_link_libraries(myapp PRIVATE ${PAP_C})
 *   target_include_directories(myapp PRIVATE /path/to/pap/crates/pap-c/include
 *                                            /path/to/pap/bindings/cpp)
 */

#pragma once

#include <stdexcept>
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <array>
#include <cstring>

#include "../../crates/pap-c/include/pap.h"

namespace pap {

// ---------------------------------------------------------------------------
// Exception
// ---------------------------------------------------------------------------

/// Thrown by any pap::* operation that maps to a -1 / NULL return.
class PapException : public std::runtime_error {
public:
    explicit PapException(const std::string& msg) : std::runtime_error(msg) {}
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

namespace detail {

/// Read the last error from the C layer, free the string, and throw.
[[noreturn]] inline void throw_last_error(const char* context = nullptr) {
    char* msg = pap_last_error_message();
    std::string s = msg ? msg : "unknown PAP error";
    pap_string_free(msg);
    if (context) s = std::string(context) + ": " + s;
    throw PapException(s);
}

/// Wrap a char* returned by a pap_* function into a std::string and free it.
inline std::string owned_string(char* raw) {
    if (!raw) throw_last_error();
    std::string s(raw);
    pap_string_free(raw);
    return s;
}

} // namespace detail

// ---------------------------------------------------------------------------
// PrincipalKeypair
// ---------------------------------------------------------------------------

/// Root Ed25519 keypair bound to the human principal.
class PrincipalKeypair {
    PapPrincipalKeypair* h_;

    explicit PrincipalKeypair(PapPrincipalKeypair* h) : h_(h) {}

public:
    PrincipalKeypair(const PrincipalKeypair&) = delete;
    PrincipalKeypair& operator=(const PrincipalKeypair&) = delete;

    PrincipalKeypair(PrincipalKeypair&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
    PrincipalKeypair& operator=(PrincipalKeypair&& o) noexcept {
        if (this != &o) { pap_keypair_free(h_); h_ = o.h_; o.h_ = nullptr; }
        return *this;
    }

    ~PrincipalKeypair() { pap_keypair_free(h_); }

    /// Generate a new random principal keypair.
    static PrincipalKeypair generate() {
        auto* p = pap_keypair_generate();
        if (!p) detail::throw_last_error("keypair_generate");
        return PrincipalKeypair{p};
    }

    /// Reconstruct from 32 raw secret-key bytes.
    static PrincipalKeypair from_bytes(const uint8_t* bytes, size_t len) {
        auto* p = pap_keypair_from_bytes(bytes, len);
        if (!p) detail::throw_last_error("keypair_from_bytes");
        return PrincipalKeypair{p};
    }

    /// The `did:key` identifier.
    std::string did() const {
        return detail::owned_string(pap_keypair_did(h_));
    }

    /// The raw 32-byte public key.
    std::array<uint8_t, 32> public_key_bytes() const {
        std::array<uint8_t, 32> out{};
        if (pap_keypair_public_bytes(h_, out.data()) != 0)
            detail::throw_last_error("keypair_public_bytes");
        return out;
    }

    /// Sign `msg_len` bytes at `msg`; returns the 64-byte signature.
    std::array<uint8_t, 64> sign(const uint8_t* msg, size_t msg_len) const {
        std::array<uint8_t, 64> sig{};
        if (pap_keypair_sign(h_, msg, msg_len, sig.data()) != 0)
            detail::throw_last_error("keypair_sign");
        return sig;
    }

    /// Expose the raw handle for functions that need it (sign, token_sign, etc.).
    const PapPrincipalKeypair* raw() const noexcept { return h_; }
};

// ---------------------------------------------------------------------------
// SessionKeypair
// ---------------------------------------------------------------------------

/// Ephemeral session keypair — single-use, not linked to principal identity.
class SessionKeypair {
    PapSessionKeypair* h_;

    explicit SessionKeypair(PapSessionKeypair* h) : h_(h) {}

public:
    SessionKeypair(const SessionKeypair&) = delete;
    SessionKeypair& operator=(const SessionKeypair&) = delete;

    SessionKeypair(SessionKeypair&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
    SessionKeypair& operator=(SessionKeypair&& o) noexcept {
        if (this != &o) { pap_session_keypair_free(h_); h_ = o.h_; o.h_ = nullptr; }
        return *this;
    }

    ~SessionKeypair() { pap_session_keypair_free(h_); }

    static SessionKeypair generate() {
        auto* p = pap_session_keypair_generate();
        if (!p) detail::throw_last_error("session_keypair_generate");
        return SessionKeypair{p};
    }

    std::string did() const {
        return detail::owned_string(pap_session_keypair_did(h_));
    }
};

// ---------------------------------------------------------------------------
// ScopeAction
// ---------------------------------------------------------------------------

/// A single Schema.org action reference with optional object constraint.
struct ScopeAction {
    std::string action;
    std::optional<std::string> object;

    explicit ScopeAction(std::string a) : action(std::move(a)) {}
    ScopeAction(std::string a, std::string o)
        : action(std::move(a)), object(std::move(o)) {}
};

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// Deny-by-default set of permitted actions.
class Scope {
    PapScope* h_;

    explicit Scope(PapScope* h) : h_(h) {}

public:
    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;

    Scope(Scope&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
    Scope& operator=(Scope&& o) noexcept {
        if (this != &o) { pap_scope_free(h_); h_ = o.h_; o.h_ = nullptr; }
        return *this;
    }

    ~Scope() { pap_scope_free(h_); }

    /// Build a scope from a list of ScopeAction values.
    static Scope from(const std::vector<ScopeAction>& actions) {
        // Build C-side handles, collect raw pointers, then free them.
        std::vector<PapScopeAction*> handles;
        handles.reserve(actions.size());
        for (const auto& a : actions) {
            PapScopeAction* h = a.object
                ? pap_scope_action_with_object(a.action.c_str(), a.object->c_str())
                : pap_scope_action_new(a.action.c_str());
            if (!h) {
                for (auto* x : handles) pap_scope_action_free(x);
                detail::throw_last_error("scope_action_new");
            }
            handles.push_back(h);
        }
        std::vector<const PapScopeAction*> ptrs(handles.begin(), handles.end());
        PapScope* s = pap_scope_new(ptrs.data(), ptrs.size());
        for (auto* h : handles) pap_scope_action_free(h);
        if (!s) detail::throw_last_error("scope_new");
        return Scope{s};
    }

    /// Create a deny-all scope.
    static Scope deny_all() {
        auto* p = pap_scope_deny_all();
        if (!p) detail::throw_last_error("scope_deny_all");
        return Scope{p};
    }

    bool permits(const std::string& action) const {
        return pap_scope_permits(h_, action.c_str()) == 1;
    }

    bool contains(const Scope& child) const {
        return pap_scope_contains(h_, child.h_) == 1;
    }

    const PapScope* raw() const noexcept { return h_; }
};

// ---------------------------------------------------------------------------
// DisclosureSet
// ---------------------------------------------------------------------------

/// Context classes an agent may share and the conditions for sharing.
class DisclosureSet {
    PapDisclosureSet* h_;

    explicit DisclosureSet(PapDisclosureSet* h) : h_(h) {}

public:
    DisclosureSet(const DisclosureSet&) = delete;
    DisclosureSet& operator=(const DisclosureSet&) = delete;

    DisclosureSet(DisclosureSet&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
    DisclosureSet& operator=(DisclosureSet&& o) noexcept {
        if (this != &o) { pap_disclosure_set_free(h_); h_ = o.h_; o.h_ = nullptr; }
        return *this;
    }

    ~DisclosureSet() { pap_disclosure_set_free(h_); }

    /// Create an empty (disclose-nothing) set.
    static DisclosureSet empty() {
        auto* p = pap_disclosure_set_empty();
        if (!p) detail::throw_last_error("disclosure_set_empty");
        return DisclosureSet{p};
    }

    const PapDisclosureSet* raw() const noexcept { return h_; }
};

// ---------------------------------------------------------------------------
// DecayState
// ---------------------------------------------------------------------------

enum class DecayState {
    Active    = PAP_DECAY_ACTIVE,
    Degraded  = PAP_DECAY_DEGRADED,
    ReadOnly  = PAP_DECAY_READ_ONLY,
    Suspended = PAP_DECAY_SUSPENDED,
};

inline std::string to_string(DecayState d) {
    switch (d) {
        case DecayState::Active:    return "Active";
        case DecayState::Degraded:  return "Degraded";
        case DecayState::ReadOnly:  return "ReadOnly";
        case DecayState::Suspended: return "Suspended";
    }
    return "Unknown";
}

// ---------------------------------------------------------------------------
// Mandate
// ---------------------------------------------------------------------------

/// Core delegation primitive. Signed by the issuer; verifiable to the root.
class Mandate {
    PapMandate* h_;

    explicit Mandate(PapMandate* h) : h_(h) {}

public:
    Mandate(const Mandate&) = delete;
    Mandate& operator=(const Mandate&) = delete;

    Mandate(Mandate&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
    Mandate& operator=(Mandate&& o) noexcept {
        if (this != &o) { pap_mandate_free(h_); h_ = o.h_; o.h_ = nullptr; }
        return *this;
    }

    ~Mandate() { pap_mandate_free(h_); }

    static Mandate issue_root(
        const std::string& principal_did,
        const std::string& agent_did,
        const Scope& scope,
        const DisclosureSet& disclosure_set,
        const std::string& ttl_rfc3339)
    {
        auto* p = pap_mandate_issue_root(
            principal_did.c_str(), agent_did.c_str(),
            scope.raw(), disclosure_set.raw(), ttl_rfc3339.c_str());
        if (!p) detail::throw_last_error("mandate_issue_root");
        return Mandate{p};
    }

    Mandate delegate(
        const std::string& agent_did,
        const Scope& scope,
        const DisclosureSet& disclosure_set,
        const std::string& ttl_rfc3339) const
    {
        auto* p = pap_mandate_delegate(
            h_, agent_did.c_str(),
            scope.raw(), disclosure_set.raw(), ttl_rfc3339.c_str());
        if (!p) detail::throw_last_error("mandate_delegate");
        return Mandate{p};
    }

    void sign(const PrincipalKeypair& kp) {
        if (pap_mandate_sign(h_, kp.raw()) != 0)
            detail::throw_last_error("mandate_sign");
    }

    void verify(const std::array<uint8_t, 32>& pubkey) const {
        if (pap_mandate_verify(h_, pubkey.data(), 32) != 0)
            detail::throw_last_error("mandate_verify");
    }

    std::string to_json() const {
        return detail::owned_string(pap_mandate_to_json(h_));
    }

    static Mandate from_json(const std::string& json) {
        auto* p = pap_mandate_from_json(json.c_str());
        if (!p) detail::throw_last_error("mandate_from_json");
        return Mandate{p};
    }

    std::string hash() const {
        return detail::owned_string(pap_mandate_hash(h_));
    }

    DecayState decay_state() const {
        int v = pap_mandate_decay_state(h_);
        if (v < 0) detail::throw_last_error("mandate_decay_state");
        return static_cast<DecayState>(v);
    }

    /// Compute the time-based decay state without mutating the mandate.
    DecayState compute_decay_state(int64_t decay_window_secs) const {
        int v = pap_mandate_compute_decay_state(h_, decay_window_secs);
        if (v < 0) detail::throw_last_error("compute_decay_state");
        return static_cast<DecayState>(v);
    }

    /// Synchronize stored decay state to the time-computed value.
    /// Handles the Active→ReadOnly TTL-expiry jump automatically.
    void sync_decay_state(int64_t decay_window_secs) {
        if (pap_mandate_sync_decay_state(h_, decay_window_secs) != 0)
            detail::throw_last_error("sync_decay_state");
    }

    /// Explicit single-step transition (validates via spec state machine).
    void transition_decay(DecayState next) {
        if (pap_mandate_transition_decay(h_, static_cast<int>(next)) != 0)
            detail::throw_last_error("transition_decay");
    }

    bool is_expired() const { return pap_mandate_is_expired(h_) == 1; }

    std::string principal_did() const {
        return detail::owned_string(pap_mandate_principal_did(h_));
    }
    std::string agent_did() const {
        return detail::owned_string(pap_mandate_agent_did(h_));
    }
    std::string issuer_did() const {
        return detail::owned_string(pap_mandate_issuer_did(h_));
    }
    std::string ttl() const {
        return detail::owned_string(pap_mandate_ttl(h_));
    }

    const PapMandate* raw() const noexcept { return h_; }
};

// ---------------------------------------------------------------------------
// CapabilityToken
// ---------------------------------------------------------------------------

/// Single-use proof authorizing a session. Bound to target DID + action + nonce.
class CapabilityToken {
    PapCapabilityToken* h_;

    explicit CapabilityToken(PapCapabilityToken* h) : h_(h) {}

public:
    CapabilityToken(const CapabilityToken&) = delete;
    CapabilityToken& operator=(const CapabilityToken&) = delete;

    CapabilityToken(CapabilityToken&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
    CapabilityToken& operator=(CapabilityToken&& o) noexcept {
        if (this != &o) { pap_token_free(h_); h_ = o.h_; o.h_ = nullptr; }
        return *this;
    }

    ~CapabilityToken() { pap_token_free(h_); }

    static CapabilityToken mint(
        const std::string& target_did,
        const std::string& action,
        const std::string& issuer_did,
        const std::string& expires_at_rfc3339)
    {
        auto* p = pap_token_mint(
            target_did.c_str(), action.c_str(),
            issuer_did.c_str(), expires_at_rfc3339.c_str());
        if (!p) detail::throw_last_error("token_mint");
        return CapabilityToken{p};
    }

    void sign(const PrincipalKeypair& kp) {
        if (pap_token_sign(h_, kp.raw()) != 0)
            detail::throw_last_error("token_sign");
    }

    std::string to_json() const {
        return detail::owned_string(pap_token_to_json(h_));
    }

    static CapabilityToken from_json(const std::string& json) {
        auto* p = pap_token_from_json(json.c_str());
        if (!p) detail::throw_last_error("token_from_json");
        return CapabilityToken{p};
    }

    const PapCapabilityToken* raw() const noexcept { return h_; }
};

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

enum class SessionState {
    Initiated = PAP_SESSION_INITIATED,
    Open      = PAP_SESSION_OPEN,
    Executed  = PAP_SESSION_EXECUTED,
    Closed    = PAP_SESSION_CLOSED,
};

/// Protocol session state machine: Initiated → Open → Executed → Closed.
class Session {
    PapSession* h_;

    explicit Session(PapSession* h) : h_(h) {}

public:
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    Session(Session&& o) noexcept : h_(o.h_) { o.h_ = nullptr; }
    Session& operator=(Session&& o) noexcept {
        if (this != &o) { pap_session_free(h_); h_ = o.h_; o.h_ = nullptr; }
        return *this;
    }

    ~Session() { pap_session_free(h_); }

    static Session initiate(
        const CapabilityToken& token,
        const std::string& receiver_did,
        const std::array<uint8_t, 32>& issuer_pubkey)
    {
        auto* p = pap_session_initiate(
            token.raw(), receiver_did.c_str(), issuer_pubkey.data(), 32);
        if (!p) detail::throw_last_error("session_initiate");
        return Session{p};
    }

    void open(const std::string& initiator_did, const std::string& receiver_did) {
        if (pap_session_open(h_, initiator_did.c_str(), receiver_did.c_str()) != 0)
            detail::throw_last_error("session_open");
    }

    void execute() {
        if (pap_session_execute(h_) != 0)
            detail::throw_last_error("session_execute");
    }

    void close() {
        if (pap_session_close(h_) != 0)
            detail::throw_last_error("session_close");
    }

    SessionState state() const {
        int v = pap_session_state(h_);
        if (v < 0) detail::throw_last_error("session_state");
        return static_cast<SessionState>(v);
    }

    std::string id() const {
        return detail::owned_string(pap_session_id(h_));
    }
};

// ---------------------------------------------------------------------------
// DID utilities
// ---------------------------------------------------------------------------

inline std::array<uint8_t, 32> did_to_public_key_bytes(const std::string& did) {
    std::array<uint8_t, 32> out{};
    if (pap_did_to_public_key_bytes(did.c_str(), out.data()) != 0)
        detail::throw_last_error("did_to_public_key_bytes");
    return out;
}

} // namespace pap
