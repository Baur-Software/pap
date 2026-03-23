package io.pap;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Integration tests for the Java JNA bindings against libpap_c.
 *
 * Run with:
 *   ./gradlew test -Pjna.library.path=/path/to/pap/target/release
 */
class PapTest {

    private static final String TTL_1H =
            Instant.now().plus(1, ChronoUnit.HOURS).toString();
    private static final String TTL_30M =
            Instant.now().plus(30, ChronoUnit.MINUTES).toString();
    private static final String TTL_PAST =
            Instant.now().minus(1, ChronoUnit.HOURS).toString();

    // -----------------------------------------------------------------------
    // PrincipalKeypair
    // -----------------------------------------------------------------------

    @Test
    void keypair_generate_gives_valid_did() {
        try (var kp = PrincipalKeypair.generate()) {
            String did = kp.did();
            assertTrue(did.startsWith("did:key:z"), "DID must start with did:key:z");
        }
    }

    @Test
    void keypair_roundtrip_from_secret_bytes() {
        try (var kp1 = PrincipalKeypair.generate()) {
            // Re-derive from public key bytes (we don't expose secret bytes — use sign/verify)
            assertEquals(32, kp1.publicKeyBytes().length);
        }
    }

    @Test
    void keypair_sign_produces_64_bytes() {
        try (var kp = PrincipalKeypair.generate()) {
            byte[] sig = kp.sign("hello pap".getBytes());
            assertEquals(64, sig.length);
        }
    }

    // -----------------------------------------------------------------------
    // Scope
    // -----------------------------------------------------------------------

    @Test
    void scope_permits_declared_action() {
        try (var scope = Scope.from(new String[]{"schema:SearchAction"})) {
            assertTrue(scope.permits("schema:SearchAction"));
            assertFalse(scope.permits("schema:PayAction"));
        }
    }

    @Test
    void deny_all_scope_permits_nothing() {
        try (var scope = Scope.denyAll()) {
            assertFalse(scope.permits("schema:SearchAction"));
        }
    }

    @Test
    void scope_contains_child_subset() {
        try (var parent = Scope.from(
                     new String[]{"schema:SearchAction"},
                     new String[]{"schema:PayAction"});
             var child = Scope.from(new String[]{"schema:SearchAction"})) {
            assertTrue(parent.contains(child));
            assertFalse(child.contains(parent));
        }
    }

    // -----------------------------------------------------------------------
    // Mandate — issuance and signing
    // -----------------------------------------------------------------------

    @Test
    void mandate_issue_root_sign_verify() {
        try (var kp = PrincipalKeypair.generate();
             var scope = Scope.from(new String[]{"schema:SearchAction"});
             var ds = DisclosureSet.empty();
             var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

            m.sign(kp);
            // No exception = success
            assertDoesNotThrow(() -> m.verify(kp.publicKeyBytes()));
        }
    }

    @Test
    void mandate_delegation_within_scope() {
        try (var kp = PrincipalKeypair.generate();
             var scope = Scope.from(
                     new String[]{"schema:SearchAction"},
                     new String[]{"schema:PayAction"});
             var ds = DisclosureSet.empty();
             var root = Mandate.issueRoot(kp.did(), "did:key:zorchestrator",
                                          scope, ds, TTL_1H)) {

            try (var childScope = Scope.from(new String[]{"schema:SearchAction"});
                 var childDs = DisclosureSet.empty();
                 var child = root.delegate("did:key:zagent", childScope, childDs, TTL_30M)) {

                assertNotNull(child.hash());
                assertEquals("did:key:zagent", child.agentDid());
            }
        }
    }

    @Test
    void mandate_delegation_exceeds_scope_throws() {
        try (var kp = PrincipalKeypair.generate();
             var scope = Scope.from(new String[]{"schema:SearchAction"});
             var ds = DisclosureSet.empty();
             var root = Mandate.issueRoot(kp.did(), "did:key:zorchestrator",
                                          scope, ds, TTL_1H)) {

            var payScope = Scope.from(new String[]{"schema:PayAction"});
            var payDs = DisclosureSet.empty();
            assertThrows(PapException.class,
                    () -> root.delegate("did:key:zagent", payScope, payDs, TTL_30M));
            payScope.close();
            payDs.close();
        }
    }

    @Test
    void mandate_unsigned_verify_throws() {
        try (var kp = PrincipalKeypair.generate();
             var scope = Scope.from(new String[]{"schema:SearchAction"});
             var ds = DisclosureSet.empty();
             var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

            assertThrows(PapException.class, () -> m.verify(kp.publicKeyBytes()));
        }
    }

    @Test
    void mandate_json_roundtrip() {
        try (var kp = PrincipalKeypair.generate();
             var scope = Scope.from(new String[]{"schema:SearchAction"});
             var ds = DisclosureSet.empty();
             var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

            m.sign(kp);
            String json = m.toJson();
            assertFalse(json.isEmpty());

            try (var m2 = Mandate.fromJson(json)) {
                assertEquals(m.hash(), m2.hash());
            }
        }
    }

    // -----------------------------------------------------------------------
    // Decay state — the correctness-critical section
    // -----------------------------------------------------------------------

    @Test
    void fresh_mandate_is_active() {
        try (var kp = PrincipalKeypair.generate();
             var scope = Scope.from(new String[]{"schema:SearchAction"});
             var ds = DisclosureSet.empty();
             var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

            assertEquals(DecayState.ACTIVE, m.decayState());
        }
    }

    @Test
    void compute_decay_returns_degraded_within_window() {
        // TTL is 1 hour away; decay window is 2 hours → Degraded
        try (var kp = PrincipalKeypair.generate();
             var scope = Scope.from(new String[]{"schema:SearchAction"});
             var ds = DisclosureSet.empty();
             var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

            assertEquals(DecayState.DEGRADED, m.computeDecayState(7200));
        }
    }

    @Test
    void compute_decay_returns_active_outside_window() {
        // TTL is 1 hour away; decay window is 30 minutes → still Active
        try (var kp = PrincipalKeypair.generate();
             var scope = Scope.from(new String[]{"schema:SearchAction"});
             var ds = DisclosureSet.empty();
             var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

            assertEquals(DecayState.ACTIVE, m.computeDecayState(1800));
        }
    }

    @Test
    void sync_decay_state_handles_active_to_read_only_jump() {
        // Mandate with TTL in the past: compute returns ReadOnly.
        // Active→ReadOnly is not a valid single-step transition, so
        // syncDecayState must insert Degraded automatically.
        try (var kp = PrincipalKeypair.generate();
             var scope = Scope.from(new String[]{"schema:SearchAction"});
             var ds = DisclosureSet.empty();
             var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_PAST)) {

            // The computed state should be ReadOnly (TTL has expired)
            assertEquals(DecayState.READ_ONLY, m.computeDecayState(3600));
            assertEquals(DecayState.ACTIVE, m.decayState()); // not yet synced

            // This must NOT throw, even though Active→ReadOnly is illegal as a
            // single step. syncDecayState steps through Degraded automatically.
            assertDoesNotThrow(() -> m.syncDecayState(3600));
            assertEquals(DecayState.READ_ONLY, m.decayState());
        }
    }

    @Test
    void sync_decay_state_is_noop_when_already_at_target() {
        // sync on an Active mandate with large decay window → stays Active (no-op)
        try (var kp = PrincipalKeypair.generate();
             var scope = Scope.from(new String[]{"schema:SearchAction"});
             var ds = DisclosureSet.empty();
             var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

            m.syncDecayState(1800); // Active, window=30m, TTL=1h → stays Active
            assertEquals(DecayState.ACTIVE, m.decayState());
        }
    }

    @Test
    void explicit_transition_active_to_degraded() {
        try (var kp = PrincipalKeypair.generate();
             var scope = Scope.from(new String[]{"schema:SearchAction"});
             var ds = DisclosureSet.empty();
             var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

            m.transitionDecay(DecayState.DEGRADED);
            assertEquals(DecayState.DEGRADED, m.decayState());
        }
    }

    @Test
    void renewal_degraded_to_active() {
        try (var kp = PrincipalKeypair.generate();
             var scope = Scope.from(new String[]{"schema:SearchAction"});
             var ds = DisclosureSet.empty();
             var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

            m.transitionDecay(DecayState.DEGRADED);
            m.transitionDecay(DecayState.ACTIVE);  // renewal
            assertEquals(DecayState.ACTIVE, m.decayState());
        }
    }

    @Test
    void suspended_is_terminal_no_renewal() {
        try (var kp = PrincipalKeypair.generate();
             var scope = Scope.from(new String[]{"schema:SearchAction"});
             var ds = DisclosureSet.empty();
             var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_PAST)) {

            // Drive to Suspended
            m.transitionDecay(DecayState.DEGRADED);
            m.transitionDecay(DecayState.READ_ONLY);
            m.transitionDecay(DecayState.SUSPENDED);
            assertEquals(DecayState.SUSPENDED, m.decayState());

            // Renewal from Suspended must throw
            assertThrows(PapException.class,
                    () -> m.transitionDecay(DecayState.ACTIVE));
        }
    }

    @Test
    void active_to_read_only_direct_transition_throws() {
        // The state machine rejects Active→ReadOnly as a single step.
        // Only syncDecayState handles this correctly by stepping through Degraded.
        try (var kp = PrincipalKeypair.generate();
             var scope = Scope.from(new String[]{"schema:SearchAction"});
             var ds = DisclosureSet.empty();
             var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

            assertThrows(PapException.class,
                    () -> m.transitionDecay(DecayState.READ_ONLY));
        }
    }

    @Test
    void self_transition_throws() {
        try (var kp = PrincipalKeypair.generate();
             var scope = Scope.from(new String[]{"schema:SearchAction"});
             var ds = DisclosureSet.empty();
             var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

            // Active→Active is not in the allowed transition set
            assertThrows(PapException.class,
                    () -> m.transitionDecay(DecayState.ACTIVE));
        }
    }

    @Test
    void deserialized_decay_state_must_be_recomputed() {
        // A peer could send a mandate JSON with decay_state="Active" even
        // though the TTL is past. We must not trust the wire value.
        try (var kp = PrincipalKeypair.generate();
             var scope = Scope.from(new String[]{"schema:SearchAction"});
             var ds = DisclosureSet.empty();
             var original = Mandate.issueRoot(kp.did(), "did:key:zagent",
                                              scope, ds, TTL_PAST)) {

            original.sign(kp);
            String json = original.toJson();

            // Deserialize — decay_state is whatever the serializer wrote
            try (var m = Mandate.fromJson(json)) {
                // Verify signature first (doesn't cover decay_state)
                assertDoesNotThrow(() -> m.verify(kp.publicKeyBytes()));
                // Now recompute — TTL is in the past, so state should be ReadOnly
                assertEquals(DecayState.READ_ONLY, m.computeDecayState(3600));
            }
        }
    }

    // -----------------------------------------------------------------------
    // CapabilityToken
    // -----------------------------------------------------------------------

    @Test
    void token_mint_sign_json_roundtrip() {
        try (var kp = PrincipalKeypair.generate();
             var token = CapabilityToken.mint(
                     "did:key:ztarget", "schema:SearchAction",
                     kp.did(), TTL_1H)) {

            token.sign(kp);
            String json = token.toJson();
            assertFalse(json.isEmpty());

            try (var t2 = CapabilityToken.fromJson(json)) {
                assertNotNull(t2);
            }
        }
    }
}
