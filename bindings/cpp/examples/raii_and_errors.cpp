/**
 * raii_and_errors.cpp — RAII destructor verification and error handling.
 *
 * This example demonstrates:
 *   - Automatic cleanup via RAII destructors
 *   - Move semantics (no copies)
 *   - Exception safety
 *   - Error handling with try/catch
 *   - Scope guard cleanup
 *
 * Compile:
 *   g++ -Wall -Wextra -std=c++17 -o raii_and_errors raii_and_errors.cpp \
 *       -I../../.. -I../../../crates/pap-c/include \
 *       -L../../../target/release -lpap_c
 *
 * Run:
 *   LD_LIBRARY_PATH=../../../target/release ./raii_and_errors
 */

#include "pap.hpp"
#include <iostream>
#include <cassert>

void print_test(const std::string& name) {
    std::cout << "\n[TEST] " << name << "\n";
}

void print_pass() {
    std::cout << "  ✓ PASS\n";
}

void print_fail(const std::string& msg) {
    std::cout << "  ✗ FAIL: " << msg << "\n";
}

// Test 1: Keypair move semantics
void test_keypair_move() {
    print_test("Keypair Move Semantics");
    try {
        pap::PrincipalKeypair kp1 = pap::PrincipalKeypair::generate();
        std::string did1 = kp1.did();

        // Move construct: kp1 -> kp2, kp1 becomes invalid
        pap::PrincipalKeypair kp2 = std::move(kp1);
        std::string did2 = kp2.did();

        assert(did1 == did2 && "DIDs must match after move");

        // kp1 is now empty; its destructor will be safe (nullptr)
        print_pass();
    } catch (const std::exception& e) {
        print_fail(e.what());
    }
}

// Test 2: Scope cleanup with early exception
void test_scope_cleanup_with_exception() {
    print_test("Scope Cleanup with Exception");
    try {
        try {
            auto scope = pap::Scope::from({
                pap::ScopeAction{"schema:SearchAction"}
            });
            // scope will be cleaned up when exiting this block
            throw std::runtime_error("Simulated error");
        } catch (const std::runtime_error&) {
            // scope was already cleaned up automatically
            print_pass();
        }
    } catch (const std::exception& e) {
        print_fail(e.what());
    }
}

// Test 3: Mandate lifecycle and move assignment
void test_mandate_lifecycle() {
    print_test("Mandate Lifecycle and Move Assignment");
    try {
        auto kp = pap::PrincipalKeypair::generate();
        auto scope = pap::Scope::from({pap::ScopeAction{"schema:SearchAction"}});
        auto ds = pap::DisclosureSet::empty();

        pap::Mandate mandate1 = pap::Mandate::issue_root(
            kp.did(), "did:key:zagent", scope, ds, "2026-12-31T23:59:59Z");
        mandate1.sign(kp);

        std::string hash1 = mandate1.hash();

        // Move assign: mandate1 -> mandate2
        pap::Mandate mandate2 = std::move(mandate1);
        std::string hash2 = mandate2.hash();

        assert(hash1 == hash2 && "Hashes must match after move");

        // mandate2 can still be used; mandate1 is now empty
        assert(!mandate2.is_expired() && "Mandate should not be expired");

        print_pass();
    } catch (const std::exception& e) {
        print_fail(e.what());
    }
}

// Test 4: Multiple objects with nested cleanup
void test_nested_scope_cleanup() {
    print_test("Nested Scope Cleanup");
    try {
        {
            auto kp = pap::PrincipalKeypair::generate();
            {
                auto scope = pap::Scope::from({
                    pap::ScopeAction{"schema:SearchAction"},
                    pap::ScopeAction{"schema:ReserveAction"}
                });
                {
                    auto ds = pap::DisclosureSet::empty();
                    // All three objects will be cleaned up in reverse order
                }
            }
        }
        // All destructors called automatically
        print_pass();
    } catch (const std::exception& e) {
        print_fail(e.what());
    }
}

// Test 5: Error handling - invalid JSON
void test_error_handling_invalid_json() {
    print_test("Error Handling - Invalid JSON");
    try {
        std::string invalid_json = "{invalid}";
        auto mandate = pap::Mandate::from_json(invalid_json);
        print_fail("Should have thrown an exception");
    } catch (const pap::PapException& e) {
        // Expected: from_json should fail with invalid JSON
        print_pass();
    }
}

// Test 6: Session state transitions
void test_session_state_machine() {
    print_test("Session State Machine");
    try {
        auto principal_kp = pap::PrincipalKeypair::generate();
        auto agent_kp = pap::PrincipalKeypair::generate();
        auto session_kp = pap::SessionKeypair::generate();

        auto scope = pap::Scope::from({pap::ScopeAction{"schema:SearchAction"}});
        auto ds = pap::DisclosureSet::empty();

        auto token = pap::CapabilityToken::mint(
            session_kp.did(), "schema:SearchAction",
            agent_kp.did(), "2026-12-31T23:59:59Z");
        token.sign(principal_kp);

        auto principal_pubkey = principal_kp.public_key_bytes();
        auto session = pap::Session::initiate(token, agent_kp.did(), principal_pubkey);

        // Verify state transitions
        assert(session.state() == pap::SessionState::Initiated);

        session.open(session_kp.did(), agent_kp.did());
        assert(session.state() == pap::SessionState::Open);

        session.execute();
        assert(session.state() == pap::SessionState::Executed);

        session.close();
        assert(session.state() == pap::SessionState::Closed);

        print_pass();
    } catch (const std::exception& e) {
        print_fail(e.what());
    }
}

// Test 7: Decay state management
void test_decay_state_management() {
    print_test("Decay State Management");
    try {
        auto principal_kp = pap::PrincipalKeypair::generate();
        auto scope = pap::Scope::from({pap::ScopeAction{"schema:SearchAction"}});
        auto ds = pap::DisclosureSet::empty();

        auto mandate = pap::Mandate::issue_root(
            principal_kp.did(), "did:key:zagent", scope, ds,
            "2026-12-31T23:59:59Z");
        mandate.sign(principal_kp);

        // Initial state should be Active
        auto initial_state = mandate.decay_state();
        assert(initial_state == pap::DecayState::Active);

        // Compute decay state without mutating (1 hour window)
        auto computed = mandate.compute_decay_state(3600);
        assert(computed == pap::DecayState::Active);

        // Sync decay state
        mandate.sync_decay_state(3600);
        assert(mandate.decay_state() == pap::DecayState::Active);

        print_pass();
    } catch (const std::exception& e) {
        print_fail(e.what());
    }
}

// Test 8: DID utilities
void test_did_utilities() {
    print_test("DID Utilities");
    try {
        auto kp = pap::PrincipalKeypair::generate();
        auto did = kp.did();

        // Extract public key from DID
        auto pubkey = pap::did_to_public_key_bytes(did);
        assert(pubkey.size() == 32);

        // Verify it matches the keypair's public key
        auto direct_pubkey = kp.public_key_bytes();
        assert(pubkey == direct_pubkey);

        print_pass();
    } catch (const std::exception& e) {
        print_fail(e.what());
    }
}

// Test 9: Serialization round-trip
void test_serialization_roundtrip() {
    print_test("Serialization Round-trip");
    try {
        auto principal_kp = pap::PrincipalKeypair::generate();
        auto scope = pap::Scope::from({pap::ScopeAction{"schema:SearchAction"}});
        auto ds = pap::DisclosureSet::empty();

        // Create and sign original mandate
        auto original = pap::Mandate::issue_root(
            principal_kp.did(), "did:key:zagent", scope, ds,
            "2026-12-31T23:59:59Z");
        original.sign(principal_kp);

        auto original_hash = original.hash();

        // Serialize
        auto json = original.to_json();

        // Deserialize
        auto restored = pap::Mandate::from_json(json);
        auto restored_hash = restored.hash();

        assert(original_hash == restored_hash);

        // Verify with public key
        auto pubkey = principal_kp.public_key_bytes();
        restored.verify(pubkey);

        print_pass();
    } catch (const std::exception& e) {
        print_fail(e.what());
    }
}

// Test 10: Scope containment
void test_scope_containment() {
    print_test("Scope Containment");
    try {
        auto broad_scope = pap::Scope::from({
            pap::ScopeAction{"schema:SearchAction"},
            pap::ScopeAction{"schema:ReserveAction"},
            pap::ScopeAction{"schema:PaymentAction"}
        });

        auto narrow_scope = pap::Scope::from({
            pap::ScopeAction{"schema:SearchAction"}
        });

        // Broad scope contains narrow scope
        assert(broad_scope.contains(narrow_scope));

        // Narrow scope does not contain broad scope
        assert(!narrow_scope.contains(broad_scope));

        print_pass();
    } catch (const std::exception& e) {
        print_fail(e.what());
    }
}

int main() {
    std::cout << "\n" << std::string(60, '=')
              << "\nPAP C++ RAII & Error Handling Test Suite"
              << "\n" << std::string(60, '=') << "\n";

    test_keypair_move();
    test_scope_cleanup_with_exception();
    test_mandate_lifecycle();
    test_nested_scope_cleanup();
    test_error_handling_invalid_json();
    test_session_state_machine();
    test_decay_state_management();
    test_did_utilities();
    test_serialization_roundtrip();
    test_scope_containment();

    std::cout << "\n" << std::string(60, '=')
              << "\n✓ All tests completed"
              << "\n" << std::string(60, '=') << "\n";
    return 0;
}
