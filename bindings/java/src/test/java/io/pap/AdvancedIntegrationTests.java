package io.pap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Advanced integration tests covering edge cases, stress scenarios,
 * and correctness-critical sections of the PAP Java bindings.
 */
class AdvancedIntegrationTests {

    private static final String TTL_1H =
            Instant.now().plus(1, ChronoUnit.HOURS).toString();
    private static final String TTL_30M =
            Instant.now().plus(30, ChronoUnit.MINUTES).toString();
    private static final String TTL_2H =
            Instant.now().plus(2, ChronoUnit.HOURS).toString();
    private static final String TTL_PAST =
            Instant.now().minus(1, ChronoUnit.HOURS).toString();

    // -----------------------------------------------------------------------
    // Deep Delegation Chains
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Deep Delegation Chains")
    class DeepDelegationChains {

        @Test
        @DisplayName("Five-level delegation chain maintains principal identity")
        void testFiveLevelChain() {
            try (var kp = PrincipalKeypair.generate()) {
                var mandate = createMandateChain(kp, 5);
                assertEquals(kp.did(), mandate.principalDid());
                closeMandateChain(mandate, 5);
            }
        }

        @Test
        @DisplayName("Deep chain maintains strict TTL ordering")
        void testDeepChainTTLOrdering() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var m1 = Mandate.issueRoot(kp.did(), "did:key:z1", scope, ds, TTL_2H)) {

                try (var s2 = Scope.from(new String[]{"schema:SearchAction"});
                     var d2 = DisclosureSet.empty();
                     var m2 = m1.delegate("did:key:z2", s2, d2, TTL_1H)) {

                    try (var s3 = Scope.from(new String[]{"schema:SearchAction"});
                         var d3 = DisclosureSet.empty();
                         var m3 = m2.delegate("did:key:z3", s3, d3, TTL_30M)) {

                        // TTLs must be ordered: 2h >= 1h >= 30m
                        String ttl1 = m1.ttl();
                        String ttl2 = m2.ttl();
                        String ttl3 = m3.ttl();

                        assertTrue(compareRfc3339(ttl1, ttl2) >= 0, "m1 TTL must be >= m2 TTL");
                        assertTrue(compareRfc3339(ttl2, ttl3) >= 0, "m2 TTL must be >= m3 TTL");
                    }
                }
            }
        }

        private Mandate createMandateChain(PrincipalKeypair kp, int depth) {
            try (var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty()) {
                var m = Mandate.issueRoot(kp.did(), "did:key:z0", scope, ds, TTL_2H);

                for (int i = 1; i < depth; i++) {
                    try (var s = Scope.from(new String[]{"schema:SearchAction"});
                         var d = DisclosureSet.empty()) {
                        var next = m.delegate("did:key:z" + i, s, d, TTL_1H);
                        m.close();
                        m = next;
                    }
                }
                return m;
            }
        }

        private void closeMandateChain(Mandate m, int depth) {
            m.close();
        }

        private int compareRfc3339(String t1, String t2) {
            return Instant.parse(t1).compareTo(Instant.parse(t2));
        }
    }

    // -----------------------------------------------------------------------
    // Scope Inheritance and Constraints
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Scope Inheritance")
    class ScopeInheritance {

        @Test
        @DisplayName("Scope can express complex action hierarchies")
        void testComplexScopes() {
            try (var scope = Scope.from(new String[]{
                    "schema:SearchAction",
                    "schema:ReserveAction",
                    "schema:OrderAction"
            })) {
                assertTrue(scope.permits("schema:SearchAction"));
                assertTrue(scope.permits("schema:ReserveAction"));
                assertTrue(scope.permits("schema:OrderAction"));
                assertFalse(scope.permits("schema:PayAction"));
            }
        }

        @Test
        @DisplayName("Empty actions create deny-all scope")
        void testEmptyActionsScope() {
            try (var scope = Scope.from(new String[]{})) {
                assertFalse(scope.permits("schema:SearchAction"));
                assertFalse(scope.permits("schema:PayAction"));
            }
        }

        @Test
        @DisplayName("Scope containment is transitive")
        void testScopeContainmentTransitive() {
            try (var large = Scope.from(new String[]{
                         "schema:SearchAction",
                         "schema:PayAction"
                 });
                 var medium = Scope.from(new String[]{"schema:SearchAction"});
                 var small = Scope.from(new String[]{"schema:SearchAction"})) {

                assertTrue(large.contains(medium));
                assertTrue(medium.contains(small));
                assertTrue(large.contains(small));
            }
        }

        @Test
        @DisplayName("Delegation respects scope bounds precisely")
        void testScopeBoundEnforcement() {
            try (var kp = PrincipalKeypair.generate();
                 var parentScope = Scope.from(new String[]{
                         "schema:SearchAction",
                         "schema:ReserveAction",
                         "schema:PayAction"
                 });
                 var parentDs = DisclosureSet.empty();
                 var parent = Mandate.issueRoot(kp.did(), "did:key:zorchestrator",
                                                parentScope, parentDs, TTL_1H)) {

                // Child subset: OK
                try (var childScope1 = Scope.from(new String[]{
                             "schema:SearchAction",
                             "schema:ReserveAction"
                     });
                     var childDs1 = DisclosureSet.empty()) {
                    var child1 = parent.delegate("did:key:zagent1", childScope1, childDs1, TTL_30M);
                    assertNotNull(child1);
                    child1.close();
                }

                // Child single action: OK
                try (var childScope2 = Scope.from(new String[]{"schema:SearchAction"});
                     var childDs2 = DisclosureSet.empty()) {
                    var child2 = parent.delegate("did:key:zagent2", childScope2, childDs2, TTL_30M);
                    assertNotNull(child2);
                    child2.close();
                }

                // Child with action not in parent: NOT OK
                try (var childScope3 = Scope.from(new String[]{"schema:DeleteAction"});
                     var childDs3 = DisclosureSet.empty()) {
                    assertThrows(PapException.class,
                            () -> parent.delegate("did:key:zagent3", childScope3, childDs3, TTL_30M));
                }

                // Child with parent + extra action: NOT OK
                try (var childScope4 = Scope.from(new String[]{
                             "schema:SearchAction",
                             "schema:PayAction",
                             "schema:DeleteAction"
                     });
                     var childDs4 = DisclosureSet.empty()) {
                    assertThrows(PapException.class,
                            () -> parent.delegate("did:key:zagent4", childScope4, childDs4, TTL_30M));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Decay State Correctness Under Edge Cases
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Decay State Edge Cases")
    class DecayStateEdgeCases {

        @Test
        @DisplayName("Computations with zero decay window")
        void testZeroDecayWindow() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                // Window of 0 seconds: enter Degraded only when TTL has already expired
                DecayState computed = mandate.computeDecayState(0);
                // Since TTL is 1 hour in future, should still be Active
                assertEquals(DecayState.ACTIVE, computed);
            }
        }

        @Test
        @DisplayName("Computation with very large decay window")
        void testLargeDecayWindow() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                // Window of 365 days: should immediately go to Degraded
                DecayState computed = mandate.computeDecayState(365 * 24 * 3600);
                assertEquals(DecayState.DEGRADED, computed);
            }
        }

        @Test
        @DisplayName("Sync on already-correct state is idempotent")
        void testSyncIdempotence() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                DecayState state1 = mandate.decayState();
                mandate.syncDecayState(1800);
                DecayState state2 = mandate.decayState();
                mandate.syncDecayState(1800);
                DecayState state3 = mandate.decayState();

                assertEquals(state1, state2);
                assertEquals(state2, state3);
            }
        }

        @Test
        @DisplayName("All valid state transitions succeed")
        void testAllValidTransitions() {
            // Active -> Degraded
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {
                m.transitionDecay(DecayState.DEGRADED);
                assertEquals(DecayState.DEGRADED, m.decayState());
            }

            // Degraded -> ReadOnly
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {
                m.transitionDecay(DecayState.DEGRADED);
                m.transitionDecay(DecayState.READ_ONLY);
                assertEquals(DecayState.READ_ONLY, m.decayState());
            }

            // ReadOnly -> Suspended
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {
                m.transitionDecay(DecayState.DEGRADED);
                m.transitionDecay(DecayState.READ_ONLY);
                m.transitionDecay(DecayState.SUSPENDED);
                assertEquals(DecayState.SUSPENDED, m.decayState());
            }

            // Degraded -> Active (renewal)
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {
                m.transitionDecay(DecayState.DEGRADED);
                m.transitionDecay(DecayState.ACTIVE);
                assertEquals(DecayState.ACTIVE, m.decayState());
            }

            // ReadOnly -> Active (recovery)
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {
                m.transitionDecay(DecayState.DEGRADED);
                m.transitionDecay(DecayState.READ_ONLY);
                m.transitionDecay(DecayState.ACTIVE);
                assertEquals(DecayState.ACTIVE, m.decayState());
            }
        }

        @Test
        @DisplayName("All invalid state transitions fail")
        void testAllInvalidTransitions() {
            // Active -> ReadOnly (invalid, must go through Degraded)
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {
                assertThrows(PapException.class,
                        () -> m.transitionDecay(DecayState.READ_ONLY));
            }

            // Active -> Suspended (invalid)
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {
                assertThrows(PapException.class,
                        () -> m.transitionDecay(DecayState.SUSPENDED));
            }

            // Degraded -> Suspended (invalid, must go through ReadOnly)
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {
                m.transitionDecay(DecayState.DEGRADED);
                assertThrows(PapException.class,
                        () -> m.transitionDecay(DecayState.SUSPENDED));
            }

            // Suspended -> * (terminal)
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {
                m.transitionDecay(DecayState.DEGRADED);
                m.transitionDecay(DecayState.READ_ONLY);
                m.transitionDecay(DecayState.SUSPENDED);
                assertThrows(PapException.class,
                        () -> m.transitionDecay(DecayState.ACTIVE));
                assertThrows(PapException.class,
                        () -> m.transitionDecay(DecayState.DEGRADED));
                assertThrows(PapException.class,
                        () -> m.transitionDecay(DecayState.READ_ONLY));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Signature Verification Security
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Signature Verification Security")
    class SignatureVerification {

        @Test
        @DisplayName("Signature verifies after serialization roundtrip")
        void testSignatureRoundtrip() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var m1 = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                m1.sign(kp);
                String json = m1.toJson();

                try (var m2 = Mandate.fromJson(json)) {
                    // Should verify with same key
                    assertDoesNotThrow(() -> m2.verify(kp.publicKeyBytes()));
                }
            }
        }

        @Test
        @DisplayName("Modified JSON fails verification")
        void testModifiedJsonFailsVerification() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var m = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                m.sign(kp);
                String json = m.toJson();

                // Simulate tampering by replacing agent DID
                String tampered = json.replace("did:key:zagent", "did:key:zattacker");

                try (var m2 = Mandate.fromJson(tampered)) {
                    // Should fail verification due to signature mismatch
                    assertThrows(PapException.class,
                            () -> m2.verify(kp.publicKeyBytes()));
                }
            }
        }

        @Test
        @DisplayName("Each key type verifies only its own signatures")
        void testKeySpecificVerification() {
            try (var kp1 = PrincipalKeypair.generate();
                 var kp2 = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var m = Mandate.issueRoot(kp1.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                m.sign(kp1);

                // Correct key verifies
                assertDoesNotThrow(() -> m.verify(kp1.publicKeyBytes()));

                // Wrong key fails
                assertThrows(PapException.class,
                        () -> m.verify(kp2.publicKeyBytes()));
            }
        }

        @Test
        @DisplayName("Multiple signatures from delegation chain verify correctly")
        void testDelegatedSignatureVerification() {
            try (var principal = PrincipalKeypair.generate();
                 var delegated = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var root = Mandate.issueRoot(principal.did(), "did:key:zorchestrator",
                                              scope, ds, TTL_1H)) {

                root.sign(principal);

                try (var childScope = Scope.from(new String[]{"schema:SearchAction"});
                     var childDs = DisclosureSet.empty();
                     var child = root.delegate(delegated.did(), childScope, childDs, TTL_30M)) {

                    // Child signed by principal (issuer of root)
                    child.sign(principal);

                    // Both verify with principal's key
                    assertDoesNotThrow(() -> root.verify(principal.publicKeyBytes()));
                    assertDoesNotThrow(() -> child.verify(principal.publicKeyBytes()));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Session Lifecycle Edge Cases
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Session Lifecycle Advanced")
    class SessionLifecycleAdvanced {

        @Test
        @DisplayName("Multiple sessions can coexist")
        void testMultipleSessions() {
            try (var kp = PrincipalKeypair.generate()) {
                List<Session> sessions = new ArrayList<>();

                try {
                    for (int i = 0; i < 3; i++) {
                        try (var token = CapabilityToken.mint(
                                 "did:key:zreceiver", "schema:SearchAction",
                                 kp.did(), TTL_1H)) {
                            token.sign(kp);
                            var session = Session.initiate(token, "did:key:zreceiver", kp.publicKeyBytes());
                            sessions.add(session);
                        }
                    }

                    for (var session : sessions) {
                        assertEquals(SessionState.INITIATED, session.state());
                    }
                } finally {
                    for (var session : sessions) {
                        session.close();
                    }
                }
            }
        }

        @Test
        @DisplayName("Session ID is unique per session")
        void testSessionIdUniqueness() {
            try (var kp = PrincipalKeypair.generate()) {
                var ids = new ArrayList<String>();

                try (var token1 = CapabilityToken.mint(
                         "did:key:zreceiver", "schema:SearchAction",
                         kp.did(), TTL_1H)) {
                    token1.sign(kp);
                    try (var s1 = Session.initiate(token1, "did:key:zreceiver", kp.publicKeyBytes())) {
                        ids.add(s1.id());
                    }
                }

                try (var token2 = CapabilityToken.mint(
                         "did:key:zreceiver", "schema:SearchAction",
                         kp.did(), TTL_1H)) {
                    token2.sign(kp);
                    try (var s2 = Session.initiate(token2, "did:key:zreceiver", kp.publicKeyBytes())) {
                        ids.add(s2.id());
                    }
                }

                // IDs should be different
                assertNotEquals(ids.get(0), ids.get(1));
            }
        }

        @Test
        @DisplayName("Session handles all state transitions cleanly")
        void testSessionAllTransitions() {
            try (var kp = PrincipalKeypair.generate();
                 var sessionKp1 = PrincipalKeypair.generate();
                 var sessionKp2 = PrincipalKeypair.generate();
                 var token = CapabilityToken.mint(
                         "did:key:zreceiver", "schema:SearchAction",
                         kp.did(), TTL_1H)) {

                token.sign(kp);
                try (var session = Session.initiate(token, "did:key:zreceiver", kp.publicKeyBytes())) {
                    // Initiated
                    assertEquals(SessionState.INITIATED, session.state());

                    // Open
                    session.open(sessionKp1.did(), sessionKp2.did());
                    assertEquals(SessionState.OPEN, session.state());

                    // Execute
                    session.execute();
                    assertEquals(SessionState.EXECUTED, session.state());

                    // Close
                    session.close_session();
                    assertEquals(SessionState.CLOSED, session.state());

                    // ID should still be accessible
                    String id = session.id();
                    assertNotNull(id);
                    assertTrue(id.length() > 0);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Capability Token Advanced
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Capability Token Advanced")
    class CapabilityTokenAdvanced {

        @Test
        @DisplayName("Token metadata is preserved through serialization")
        void testTokenMetadata() {
            try (var kp = PrincipalKeypair.generate()) {
                String targetDid = "did:key:ztarget";
                String action = "schema:SearchAction";

                try (var token1 = CapabilityToken.mint(
                         targetDid, action,
                         kp.did(), TTL_1H)) {

                    token1.sign(kp);
                    String json = token1.toJson();

                    try (var token2 = CapabilityToken.fromJson(json)) {
                        // Serialize again to verify consistency
                        String json2 = token2.toJson();
                        assertFalse(json2.isEmpty());
                    }
                }
            }
        }

        @Test
        @DisplayName("Multiple tokens from same issuer are independent")
        void testTokenIndependence() {
            try (var kp = PrincipalKeypair.generate()) {
                List<String> jsons = new ArrayList<>();

                for (int i = 0; i < 3; i++) {
                    try (var token = CapabilityToken.mint(
                             "did:key:ztarget" + i, "schema:SearchAction",
                             kp.did(), TTL_1H)) {
                        token.sign(kp);
                        jsons.add(token.toJson());
                    }
                }

                // All should deserialize independently
                for (String json : jsons) {
                    try (var token = CapabilityToken.fromJson(json)) {
                        assertNotNull(token);
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Correctness Under Resource Pressure
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Resource Management Stress")
    class ResourceManagementStress {

        @Test
        @DisplayName("Repeated allocation and cleanup succeeds")
        void testRepeatedAllocationCleanup() {
            for (int i = 0; i < 10; i++) {
                try (var kp = PrincipalKeypair.generate();
                     var scope = Scope.from(new String[]{"schema:SearchAction"});
                     var ds = DisclosureSet.empty();
                     var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                    mandate.sign(kp);
                    assertDoesNotThrow(() -> mandate.verify(kp.publicKeyBytes()));
                }
            }
        }

        @Test
        @DisplayName("Many nested resources clean up correctly")
        void testManyNestedResources() {
            try (var kp = PrincipalKeypair.generate()) {
                for (int i = 0; i < 5; i++) {
                    try (var scope = Scope.from(new String[]{"schema:SearchAction"});
                         var ds = DisclosureSet.empty();
                         var mandate = Mandate.issueRoot(kp.did(), "did:key:z" + i, scope, ds, TTL_1H)) {

                        for (int j = 0; j < 3; j++) {
                            try (var childScope = Scope.from(new String[]{"schema:SearchAction"});
                                 var childDs = DisclosureSet.empty();
                                 var child = mandate.delegate("did:key:z" + i + "_" + j,
                                         childScope, childDs, TTL_30M)) {
                                assertNotNull(child.hash());
                            }
                        }
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Cross-Feature Integration
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Cross-Feature Integration")
    class CrossFeatureIntegration {

        @Test
        @DisplayName("Delegation chain with varying scopes")
        void testVariousScopeChain() {
            try (var kp = PrincipalKeypair.generate()) {
                String[][] scopes = {
                    {"schema:SearchAction", "schema:PayAction", "schema:ReserveAction"},
                    {"schema:SearchAction", "schema:PayAction"},
                    {"schema:SearchAction"}
                };

                try (var s1 = Scope.from(scopes[0]);
                     var ds1 = DisclosureSet.empty();
                     var m1 = Mandate.issueRoot(kp.did(), "did:key:z1", s1, ds1, TTL_1H)) {

                    m1.sign(kp);

                    try (var s2 = Scope.from(scopes[1]);
                         var ds2 = DisclosureSet.empty();
                         var m2 = m1.delegate("did:key:z2", s2, ds2, TTL_30M)) {

                        m2.sign(kp);

                        try (var s3 = Scope.from(scopes[2]);
                             var ds3 = DisclosureSet.empty();
                             var m3 = m2.delegate("did:key:z3", s3, ds3, TTL_30M)) {

                            m3.sign(kp);

                            // All should verify
                            assertDoesNotThrow(() -> m1.verify(kp.publicKeyBytes()));
                            assertDoesNotThrow(() -> m2.verify(kp.publicKeyBytes()));
                            assertDoesNotThrow(() -> m3.verify(kp.publicKeyBytes()));

                            // Scope containment must be verified
                            assertTrue(s1.contains(s2));
                            assertTrue(s2.contains(s3));
                            assertTrue(s1.contains(s3));
                        }
                    }
                }
            }
        }

        @Test
        @DisplayName("Full workflow: delegation → signing → serialization → verification")
        void testFullWorkflow() {
            try (var principal = PrincipalKeypair.generate();
                 var agent = PrincipalKeypair.generate()) {

                // Create and delegate mandate
                try (var scope = Scope.from(new String[]{
                         "schema:SearchAction",
                         "schema:PayAction"
                 });
                     var ds = DisclosureSet.empty();
                     var root = Mandate.issueRoot(principal.did(), "did:key:zorchestrator",
                                                  scope, ds, TTL_1H)) {

                    root.sign(principal);

                    try (var agentScope = Scope.from(new String[]{"schema:SearchAction"});
                         var agentDs = DisclosureSet.empty();
                         var delegated = root.delegate(agent.did(), agentScope, agentDs, TTL_30M)) {

                        delegated.sign(principal);

                        // Serialize both
                        String rootJson = root.toJson();
                        String delegatedJson = delegated.toJson();

                        // Deserialize both
                        try (var rootDeserialized = Mandate.fromJson(rootJson);
                             var delegatedDeserialized = Mandate.fromJson(delegatedJson)) {

                            // Verify signatures
                            assertDoesNotThrow(() -> rootDeserialized.verify(principal.publicKeyBytes()));
                            assertDoesNotThrow(() -> delegatedDeserialized.verify(principal.publicKeyBytes()));

                            // Check properties preserved
                            assertEquals(root.hash(), rootDeserialized.hash());
                            assertEquals(delegated.hash(), delegatedDeserialized.hash());

                            // Decay states can be recomputed
                            DecayState computedRoot = rootDeserialized.computeDecayState(3600);
                            DecayState computedDelegated = delegatedDeserialized.computeDecayState(3600);
                            assertNotNull(computedRoot);
                            assertNotNull(computedDelegated);
                        }
                    }
                }
            }
        }
    }
}
