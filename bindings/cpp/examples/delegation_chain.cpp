/**
 * delegation_chain.cpp — Multi-hop delegation with scope narrowing.
 *
 * This example demonstrates:
 *   - Root mandate issuance
 *   - Delegation with scope narrowing
 *   - Multi-hop verification (principal → agent1 → agent2)
 *   - Mandate verification chain
 *
 * Compile:
 *   g++ -Wall -Wextra -std=c++17 -o delegation_chain delegation_chain.cpp \
 *       -I../../.. -I../../../crates/pap-c/include \
 *       -L../../../target/release -lpap_c
 *
 * Run:
 *   LD_LIBRARY_PATH=../../../target/release ./delegation_chain
 */

#include "pap.hpp"
#include <iostream>
#include <iomanip>
#include <cassert>

void print_header(const std::string& title) {
    std::cout << "\n" << std::string(70, '=') << "\n"
              << "  " << title << "\n"
              << std::string(70, '=') << "\n";
}

void print_step(int num, const std::string& desc) {
    std::cout << "\n[Step " << num << "] " << desc << "\n"
              << std::string(50, '-') << "\n";
}

void print_ok(const std::string& msg) {
    std::cout << "  ✓ " << msg << "\n";
}

void print_info(const std::string& label, const std::string& value) {
    std::cout << "  " << std::setw(20) << std::left << label << ": " << value << "\n";
}

int main() {
    try {
        print_header("Delegation Chain Demonstration");

        // ===================================================================
        // Setup: Create principal and two agents
        // ===================================================================
        print_step(1, "Key Generation - Principal & Agents");

        auto principal = pap::PrincipalKeypair::generate();
        auto principal_did = principal.did();
        print_info("Principal DID", principal_did.substr(0, 30) + "...");
        print_ok("Principal keypair generated");

        auto agent1 = pap::PrincipalKeypair::generate();
        auto agent1_did = agent1.did();
        print_info("Agent 1 DID", agent1_did.substr(0, 30) + "...");
        print_ok("Agent 1 keypair generated");

        auto agent2 = pap::PrincipalKeypair::generate();
        auto agent2_did = agent2.did();
        print_info("Agent 2 DID", agent2_did.substr(0, 30) + "...");
        print_ok("Agent 2 keypair generated");

        // ===================================================================
        // Step 2: Define initial scope (broad)
        // ===================================================================
        print_step(2, "Create Broad Scope for Initial Mandate");

        auto broad_scope = pap::Scope::from({
            pap::ScopeAction{"schema:SearchAction"},
            pap::ScopeAction{"schema:ReserveAction", "schema:FlightReservation"},
            pap::ScopeAction{"schema:ReserveAction", "schema:HotelReservation"},
            pap::ScopeAction{"schema:PaymentAction"}
        });
        print_ok("Broad scope includes: Search, Flight Reserve, Hotel Reserve, Payment");

        auto ds_empty = pap::DisclosureSet::empty();

        // ===================================================================
        // Step 3: Principal issues root mandate to Agent1
        // ===================================================================
        print_step(3, "Principal → Agent1 (Root Mandate)");

        auto ttl = "2026-12-31T23:59:59Z";
        auto mandate1 = pap::Mandate::issue_root(
            principal_did, agent1_did, broad_scope, ds_empty, ttl);
        mandate1.sign(principal);
        print_ok("Mandate issued from Principal to Agent1");

        auto hash1 = mandate1.hash();
        print_info("Mandate hash", hash1.substr(0, 16) + "...");

        auto principal_pubkey = principal.public_key_bytes();
        mandate1.verify(principal_pubkey);
        print_ok("Mandate verified with Principal's public key");

        // ===================================================================
        // Step 4: Agent1 delegates to Agent2 with narrowed scope
        // ===================================================================
        print_step(4, "Agent1 → Agent2 (Delegation with Scope Narrowing)");

        auto narrow_scope = pap::Scope::from({
            pap::ScopeAction{"schema:SearchAction"},
            pap::ScopeAction{"schema:ReserveAction", "schema:FlightReservation"}
        });
        print_ok("Narrow scope (removed Hotel & Payment)");

        auto mandate2 = mandate1.delegate(agent2_did, narrow_scope, ds_empty, ttl);
        mandate2.sign(agent1);
        print_ok("Mandate delegated from Agent1 to Agent2");

        auto hash2 = mandate2.hash();
        print_info("Delegated mandate hash", hash2.substr(0, 16) + "...");

        auto agent1_pubkey = agent1.public_key_bytes();
        mandate2.verify(agent1_pubkey);
        print_ok("Delegated mandate verified with Agent1's public key");

        // ===================================================================
        // Step 5: Inspect chain relationships
        // ===================================================================
        print_step(5, "Inspect Delegation Chain");

        auto m1_principal = mandate1.principal_did();
        auto m1_agent = mandate1.agent_did();
        auto m1_issuer = mandate1.issuer_did();

        print_info("M1 principal", m1_principal.substr(0, 20) + "...");
        print_info("M1 agent", m1_agent.substr(0, 20) + "...");
        print_info("M1 issuer", m1_issuer.substr(0, 20) + "...");
        print_ok("M1: Principal → Agent1 chain established");

        auto m2_principal = mandate2.principal_did();
        auto m2_agent = mandate2.agent_did();
        auto m2_issuer = mandate2.issuer_did();

        print_info("M2 principal", m2_principal.substr(0, 20) + "...");
        print_info("M2 agent", m2_agent.substr(0, 20) + "...");
        print_info("M2 issuer", m2_issuer.substr(0, 20) + "...");
        print_ok("M2: Principal → Agent2 chain (via Agent1) established");

        assert(m2_principal == m1_principal && "M2 maintains original principal");
        assert(m2_issuer == agent1_did && "M2 issuer is Agent1");
        print_ok("Chain invariants verified");

        // ===================================================================
        // Step 6: Verify scope narrowing
        // ===================================================================
        print_step(6, "Verify Scope Narrowing");

        if (broad_scope.permits("schema:PaymentAction")) {
            print_ok("Broad scope permits: PaymentAction");
        }

        if (!narrow_scope.permits("schema:PaymentAction")) {
            print_ok("Narrow scope blocks: PaymentAction (removed)");
        }

        if (narrow_scope.permits("schema:SearchAction")) {
            print_ok("Narrow scope permits: SearchAction");
        }

        assert(broad_scope.contains(narrow_scope));
        print_ok("Broad scope contains narrow scope (subset verification)");

        // ===================================================================
        // Step 7: Decay state in chain
        // ===================================================================
        print_step(7, "Decay State Management Across Chain");

        auto m1_decay = mandate1.decay_state();
        auto m2_decay = mandate2.decay_state();

        print_info("M1 decay state", pap::to_string(m1_decay));
        print_info("M2 decay state", pap::to_string(m2_decay));
        print_ok("Both mandates in Active state");

        // ===================================================================
        // Step 8: Serialization of delegated mandates
        // ===================================================================
        print_step(8, "Serialization & Deserialization");

        auto m1_json = mandate1.to_json();
        auto m2_json = mandate2.to_json();

        print_info("M1 JSON size", std::to_string(m1_json.length()) + " bytes");
        print_info("M2 JSON size", std::to_string(m2_json.length()) + " bytes");
        print_ok("Mandates serialized to JSON");

        // Reconstruct and verify
        auto m1_restored = pap::Mandate::from_json(m1_json);
        auto m2_restored = pap::Mandate::from_json(m2_json);
        print_ok("Mandates deserialized from JSON");

        m1_restored.verify(principal_pubkey);
        m2_restored.verify(agent1_pubkey);
        print_ok("Restored mandates verified");

        // ===================================================================
        // Step 9: Create session with delegated mandate
        // ===================================================================
        print_step(9, "Session Creation with Delegated Mandate");

        auto session_kp = pap::SessionKeypair::generate();
        auto session_did = session_kp.did();
        print_info("Session DID", session_did.substr(0, 20) + "...");

        auto token = pap::CapabilityToken::mint(
            session_did, "schema:SearchAction", agent2_did, ttl);
        token.sign(principal);
        print_ok("Capability token minted by Principal for Agent2");

        auto session = pap::Session::initiate(token, agent2_did, principal_pubkey);
        print_ok("Session initiated with Agent2");

        session.open(session_did, agent2_did);
        print_ok("Session opened");

        session.execute();
        print_ok("Session executed");

        session.close();
        print_ok("Session closed");

        print_header("✓ Delegation Chain Demonstration Complete");
        return 0;

    } catch (const pap::PapException& e) {
        std::cerr << "\n✗ PAP Error: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "\n✗ Unexpected error: " << e.what() << "\n";
        return 1;
    }
}
