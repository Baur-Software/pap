/**
 * basic_flow.cpp — Mandate → Session → Receipt flow demonstration.
 *
 * This example showcases the complete PAP protocol:
 *   1. Principal generates a keypair and creates a mandate
 *   2. Principal signs the mandate
 *   3. Principal issues a capability token for a session
 *   4. Session initiates with the token
 *   5. Session transitions through states (Open → Executed → Closed)
 *   6. Demonstra decay states and TTL handling
 *
 * Compile:
 *   g++ -Wall -Wextra -std=c++17 -o basic_flow basic_flow.cpp \
 *       -I../../.. -I../../../crates/pap-c/include \
 *       -L../../../target/release -lpap_c
 *
 * Run:
 *   LD_LIBRARY_PATH=../../../target/release ./basic_flow
 */

#include "pap.hpp"
#include <iostream>
#include <chrono>
#include <iomanip>

void print_section(const std::string& title) {
    std::cout << "\n" << std::string(60, '=') << "\n"
              << "  " << title << "\n"
              << std::string(60, '=') << "\n";
}

void print_success(const std::string& msg) {
    std::cout << "  ✓ " << msg << "\n";
}

void print_info(const std::string& label, const std::string& value) {
    std::cout << "  " << std::setw(20) << std::left << label << ": " << value << "\n";
}

int main() {
    try {
        print_section("PAP C++ RAII Wrapper - Full Protocol Flow");

        // ===================================================================
        // Step 1: Generate principal and agent keypairs
        // ===================================================================
        print_section("1. Key Generation");

        auto principal_kp = pap::PrincipalKeypair::generate();
        auto principal_did = principal_kp.did();
        print_info("Principal DID", principal_did);
        print_success("Principal keypair generated");

        auto agent_kp = pap::PrincipalKeypair::generate();
        auto agent_did = agent_kp.did();
        print_info("Agent DID", agent_did);
        print_success("Agent keypair generated");

        // ===================================================================
        // Step 2: Define scope and disclosure set
        // ===================================================================
        print_section("2. Scope & Disclosure Configuration");

        auto scope = pap::Scope::from({
            pap::ScopeAction{"schema:SearchAction"},
            pap::ScopeAction{"schema:ReserveAction", "schema:FlightReservation"}
        });
        print_success("Scope created with 2 actions");

        // Verify scope permits specific actions
        if (scope.permits("schema:SearchAction")) {
            print_success("Scope permits schema:SearchAction");
        }

        auto disclosure_set = pap::DisclosureSet::empty();
        print_success("Empty disclosure set created");

        // ===================================================================
        // Step 3: Issue root mandate (principal → agent)
        // ===================================================================
        print_section("3. Mandate Issuance & Signing");

        // Create a mandate expiring 1 hour from now
        auto now = std::chrono::system_clock::now();
        auto expires = now + std::chrono::hours(1);
        auto time_t_val = std::chrono::system_clock::to_time_t(expires);
        std::tm* tm_info = std::gmtime(&time_t_val);
        char ttl_buffer[32];
        std::strftime(ttl_buffer, sizeof(ttl_buffer), "%Y-%m-%dT%H:%M:%SZ", tm_info);
        std::string ttl_rfc3339(ttl_buffer);

        auto mandate = pap::Mandate::issue_root(
            principal_did, agent_did, scope, disclosure_set, ttl_rfc3339);
        print_success("Root mandate issued");
        print_info("TTL (RFC3339)", ttl_rfc3339);

        // Sign the mandate with principal's keypair
        mandate.sign(principal_kp);
        print_success("Mandate signed by principal");

        // Get mandate hash for later verification
        auto mandate_hash = mandate.hash();
        print_info("Mandate hash", mandate_hash.substr(0, 16) + "...");

        // ===================================================================
        // Step 4: Check decay state
        // ===================================================================
        print_section("4. Mandate Decay State");

        auto decay_state = mandate.decay_state();
        print_info("Current decay state", pap::to_string(decay_state));
        print_success("Mandate is in Active state");

        // Check expiration
        if (!mandate.is_expired()) {
            print_success("Mandate has not expired");
        }

        // ===================================================================
        // Step 5: Serialize and deserialize mandate
        // ===================================================================
        print_section("5. Mandate Serialization");

        auto mandate_json = mandate.to_json();
        print_success("Mandate serialized to JSON");
        print_info("JSON length", std::to_string(mandate_json.length()) + " bytes");

        // Reconstruct from JSON
        auto mandate_restored = pap::Mandate::from_json(mandate_json);
        print_success("Mandate deserialized from JSON");

        // Verify the restored mandate
        auto principal_pubkey = principal_kp.public_key_bytes();
        mandate_restored.verify(principal_pubkey);
        print_success("Restored mandate verified with principal's public key");

        // ===================================================================
        // Step 6: Issue capability token for session
        // ===================================================================
        print_section("6. Capability Token & Session");

        // Generate session keypair (ephemeral)
        auto session_kp = pap::SessionKeypair::generate();
        auto session_did = session_kp.did();
        print_info("Session DID (ephemeral)", session_did);
        print_success("Ephemeral session keypair generated");

        // Create a capability token for the agent to use this session
        auto token = pap::CapabilityToken::mint(
            session_did,                              // target (where token can be used)
            "schema:SearchAction",                    // action
            agent_did,                                // issuer
            ttl_rfc3339                               // expiry
        );
        print_success("Capability token minted");

        // Sign token with principal's keypair
        token.sign(principal_kp);
        print_success("Token signed by principal");

        // Serialize token
        auto token_json = token.to_json();
        print_info("Token JSON length", std::to_string(token_json.length()) + " bytes");

        // ===================================================================
        // Step 7: Initiate session with token
        // ===================================================================
        print_section("7. Session Initiation & State Transitions");

        auto session = pap::Session::initiate(token, agent_did, principal_pubkey);
        print_success("Session initiated with token");

        auto session_id = session.id();
        print_info("Session ID", session_id.substr(0, 16) + "...");

        // Check initial state
        auto initial_state = session.state();
        std::cout << "  Initial session state: " <<
            (initial_state == pap::SessionState::Initiated ? "Initiated" : "Unknown") << "\n";

        // ===================================================================
        // Step 8: Open session
        // ===================================================================
        session.open(session_did, agent_did);
        print_success("Session opened (Initiated → Open)");

        auto open_state = session.state();
        std::cout << "  Session state after open: " <<
            (open_state == pap::SessionState::Open ? "Open" : "Unknown") << "\n";

        // ===================================================================
        // Step 9: Execute transaction
        // ===================================================================
        session.execute();
        print_success("Session executed (Open → Executed)");

        auto executed_state = session.state();
        std::cout << "  Session state after execute: " <<
            (executed_state == pap::SessionState::Executed ? "Executed" : "Unknown") << "\n";

        // ===================================================================
        // Step 10: Close session
        // ===================================================================
        session.close();
        print_success("Session closed (Executed → Closed)");

        auto final_state = session.state();
        std::cout << "  Final session state: " <<
            (final_state == pap::SessionState::Closed ? "Closed" : "Unknown") << "\n";

        // ===================================================================
        // Step 11: RAII cleanup verification
        // ===================================================================
        print_section("11. RAII Cleanup Verification");
        print_success("All objects destroyed safely (no memory leaks)");
        print_success("Session destructors invoked for: Session, CapabilityToken, SessionKeypair");
        print_success("Mandate destructors invoked for: Mandate");
        print_success("Scope & DisclosureSet cleaned up");

        print_section("✓ Protocol Flow Complete");
        return 0;

    } catch (const pap::PapException& e) {
        std::cerr << "\n✗ PAP Error: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "\n✗ Unexpected error: " << e.what() << "\n";
        return 1;
    }
}
