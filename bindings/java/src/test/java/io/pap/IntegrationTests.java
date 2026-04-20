package io.pap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive integration tests for the Java JNA bindings against libpap_c.
 *
 * These tests exercise:
 * - Mandate creation and delegation chains
 * - Scope validation and inheritance
 * - Session lifecycle state machine
 * - Decay state transitions
 * - Receipt verification (via mandate signing and verification)
 * - AutoCloseable resource cleanup
 * - Exception hierarchy and error handling
 *
 * Run with:
 *   ./gradlew test -Pjna.library.path=/path/to/pap/target/release
 */
class IntegrationTests {

    private static final String TTL_1H =
            Instant.now().plus(1, ChronoUnit.HOURS).toString();
    private static final String TTL_30M =
            Instant.now().plus(30, ChronoUnit.MINUTES).toString();
    private static final String TTL_PAST =
            Instant.now().minus(1, ChronoUnit.HOURS).toString();
    private static final String TTL_2H =
            Instant.now().plus(2, ChronoUnit.HOURS).toString();

    // -----------------------------------------------------------------------
    // Mandate Creation and Signing (Receipt Foundation)
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Mandate Creation")
    class MandateCreation {

        @Test
        @DisplayName("Root mandate issues successfully with valid parameters")
        void testRootMandateIssue() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                assertNotNull(mandate);
                assertEquals(kp.did(), mandate.principalDid());
                assertEquals("did:key:zagent", mandate.agentDid());
            }
        }

        @Test
        @DisplayName("Root mandate is initially in Active decay state")
        void testRootMandateInitialState() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                assertEquals(DecayState.ACTIVE, mandate.decayState());
            }
        }

        @Test
        @DisplayName("Expired mandate is not active")
        void testExpiredMandateNotActive() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_PAST)) {

                assertTrue(mandate.isExpired());
            }
        }

        @Test
        @DisplayName("Mandate hash is consistent")
        void testMandateHashConsistency() {
            String hash1, hash2;
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                hash1 = mandate.hash();
                hash2 = mandate.hash();
                assertEquals(hash1, hash2);
                assertTrue(hash1.length() > 0);
            }
        }

        @Test
        @DisplayName("Mandate properties are accessible after creation")
        void testMandateProperties() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                assertNotNull(mandate.principalDid());
                assertNotNull(mandate.agentDid());
                assertNotNull(mandate.issuerDid());
                assertNotNull(mandate.ttl());
                assertEquals(kp.did(), mandate.principalDid());
                assertEquals(kp.did(), mandate.issuerDid());
            }
        }
    }

    // -----------------------------------------------------------------------
    // Mandate Delegation Chain
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Mandate Delegation")
    class MandateDelegation {

        @Test
        @DisplayName("Child mandate delegates within parent scope")
        void testDelegateWithinScope() {
            try (var kp = PrincipalKeypair.generate();
                 var parentScope = Scope.from(
                         new String[]{"schema:SearchAction"},
                         new String[]{"schema:PayAction"});
                 var ds = DisclosureSet.empty();
                 var parent = Mandate.issueRoot(kp.did(), "did:key:zorchestrator",
                                                parentScope, ds, TTL_1H)) {

                try (var childScope = Scope.from(new String[]{"schema:SearchAction"});
                     var childDs = DisclosureSet.empty();
                     var child = parent.delegate("did:key:zagent", childScope, childDs, TTL_30M)) {

                    assertNotNull(child);
                    assertEquals("did:key:zagent", child.agentDid());
                    assertTrue(child.hash().length() > 0);
                }
            }
        }

        @Test
        @DisplayName("Delegation chain preserves principal identity")
        void testDelegationChainPrincipal() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var root = Mandate.issueRoot(kp.did(), "did:key:zorchestrator",
                                              scope, ds, TTL_1H)) {

                try (var childScope = Scope.from(new String[]{"schema:SearchAction"});
                     var childDs = DisclosureSet.empty();
                     var child = root.delegate("did:key:zagent", childScope, childDs, TTL_30M)) {

                    // Principal should be the same at root of delegation chain
                    assertEquals(root.principalDid(), child.principalDid());
                }
            }
        }

        @Test
        @DisplayName("Three-level delegation chain works")
        void testThreeLevelDelegation() {
            try (var kp = PrincipalKeypair.generate();
                 var scope1 = Scope.from(
                         new String[]{"schema:SearchAction"},
                         new String[]{"schema:PayAction"});
                 var ds1 = DisclosureSet.empty();
                 var level1 = Mandate.issueRoot(kp.did(), "did:key:z1",
                                                scope1, ds1, TTL_2H)) {

                try (var scope2 = Scope.from(
                             new String[]{"schema:SearchAction"},
                             new String[]{"schema:PayAction"});
                     var ds2 = DisclosureSet.empty();
                     var level2 = level1.delegate("did:key:z2", scope2, ds2, TTL_1H)) {

                    try (var scope3 = Scope.from(new String[]{"schema:SearchAction"});
                         var ds3 = DisclosureSet.empty();
                         var level3 = level2.delegate("did:key:z3", scope3, ds3, TTL_30M)) {

                        assertEquals(kp.did(), level3.principalDid());
                        assertEquals("did:key:z3", level3.agentDid());
                    }
                }
            }
        }

        @Test
        @DisplayName("Delegation exceeding parent scope throws PapException")
        void testDelegationExceedsScope() {
            try (var kp = PrincipalKeypair.generate();
                 var parentScope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var parent = Mandate.issueRoot(kp.did(), "did:key:zorchestrator",
                                                parentScope, ds, TTL_1H)) {

                var childScope = Scope.from(new String[]{"schema:PayAction"});
                var childDs = DisclosureSet.empty();
                assertThrows(PapException.class,
                        () -> parent.delegate("did:key:zagent", childScope, childDs, TTL_30M));
                childScope.close();
                childDs.close();
            }
        }

        @Test
        @DisplayName("Delegation with TTL exceeding parent TTL throws")
        void testDelegationExceedsTTL() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var parent = Mandate.issueRoot(kp.did(), "did:key:zorchestrator",
                                                scope, ds, TTL_1H)) {

                var childScope = Scope.from(new String[]{"schema:SearchAction"});
                var childDs = DisclosureSet.empty();
                var extendedTTL = Instant.now().plus(2, ChronoUnit.HOURS).toString();
                assertThrows(PapException.class,
                        () -> parent.delegate("did:key:zagent", childScope, childDs, extendedTTL));
                childScope.close();
                childDs.close();
            }
        }
    }

    // -----------------------------------------------------------------------
    // Mandate Signing and Verification (Receipt Verification)
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Mandate Signing and Verification")
    class SigningAndVerification {

        @Test
        @DisplayName("Signed mandate verifies successfully")
        void testSignAndVerify() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                mandate.sign(kp);
                assertDoesNotThrow(() -> mandate.verify(kp.publicKeyBytes()));
            }
        }

        @Test
        @DisplayName("Unsigned mandate fails verification")
        void testUnsignedVerifyFails() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                assertThrows(PapException.class, () -> mandate.verify(kp.publicKeyBytes()));
            }
        }

        @Test
        @DisplayName("Wrong public key fails verification")
        void testWrongKeyFailsVerification() {
            try (var kp1 = PrincipalKeypair.generate();
                 var kp2 = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp1.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                mandate.sign(kp1);
                assertThrows(PapException.class, () -> mandate.verify(kp2.publicKeyBytes()));
            }
        }

        @Test
        @DisplayName("Verification succeeds for delegated mandate with correct key")
        void testDelegatedMandateVerification() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var root = Mandate.issueRoot(kp.did(), "did:key:zorchestrator",
                                              scope, ds, TTL_1H)) {

                root.sign(kp);

                try (var childScope = Scope.from(new String[]{"schema:SearchAction"});
                     var childDs = DisclosureSet.empty();
                     var child = root.delegate("did:key:zagent", childScope, childDs, TTL_30M)) {

                    child.sign(kp);
                    assertDoesNotThrow(() -> child.verify(kp.publicKeyBytes()));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Scope Validation
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Scope Validation")
    class ScopeValidation {

        @Test
        @DisplayName("Scope permits declared action")
        void testScopePermitsAction() {
            try (var scope = Scope.from(new String[]{"schema:SearchAction"})) {
                assertTrue(scope.permits("schema:SearchAction"));
            }
        }

        @Test
        @DisplayName("Scope denies undeclared action")
        void testScopeDeniesAction() {
            try (var scope = Scope.from(new String[]{"schema:SearchAction"})) {
                assertFalse(scope.permits("schema:PayAction"));
            }
        }

        @Test
        @DisplayName("Multiple actions in scope")
        void testMultipleActions() {
            try (var scope = Scope.from(new String[]{
                    "schema:SearchAction",
                    "schema:ReserveAction"
            })) {
                assertTrue(scope.permits("schema:SearchAction"));
                assertTrue(scope.permits("schema:ReserveAction"));
                assertFalse(scope.permits("schema:PayAction"));
            }
        }

        @Test
        @DisplayName("Deny-all scope permits nothing")
        void testDenyAllScope() {
            try (var scope = Scope.denyAll()) {
                assertFalse(scope.permits("schema:SearchAction"));
                assertFalse(scope.permits("schema:PayAction"));
            }
        }

        @Test
        @DisplayName("Parent scope contains child scope")
        void testScopeContainment() {
            try (var parent = Scope.from(
                         new String[]{"schema:SearchAction"},
                         new String[]{"schema:PayAction"});
                 var child = Scope.from(new String[]{"schema:SearchAction"})) {

                assertTrue(parent.contains(child));
                assertFalse(child.contains(parent));
            }
        }

        @Test
        @DisplayName("Identical scopes contain each other")
        void testIdenticalScopesContain() {
            try (var scope1 = Scope.from(new String[]{"schema:SearchAction"});
                 var scope2 = Scope.from(new String[]{"schema:SearchAction"})) {

                assertTrue(scope1.contains(scope2));
                assertTrue(scope2.contains(scope1));
            }
        }

        @Test
        @DisplayName("Scope does not contain superset")
        void testScopeDoesNotContainSuperset() {
            try (var small = Scope.from(new String[]{"schema:SearchAction"});
                 var large = Scope.from(new String[]{
                         "schema:SearchAction",
                         "schema:PayAction"
                 })) {

                assertFalse(small.contains(large));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Decay State Management
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Decay State Transitions")
    class DecayStateTransitions {

        @Test
        @DisplayName("Fresh mandate is Active")
        void testFreshMandateActive() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                assertEquals(DecayState.ACTIVE, mandate.decayState());
            }
        }

        @Test
        @DisplayName("Compute decay reflects time window")
        void testComputeDecayWindow() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                // TTL is 1 hour; window is 2 hours → Degraded
                assertEquals(DecayState.DEGRADED, mandate.computeDecayState(7200));

                // TTL is 1 hour; window is 30 minutes → Active
                assertEquals(DecayState.ACTIVE, mandate.computeDecayState(1800));
            }
        }

        @Test
        @DisplayName("Expired mandate computes as Degraded (first step from Active)")
        void testExpiredMandateComputesDegraded() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_PAST)) {

                // Per spec §5.7.1 Active→ReadOnly is not a valid single-step transition.
                // computeDecayState steps by one: Active → Degraded.
                assertEquals(DecayState.DEGRADED, mandate.computeDecayState(3600));
            }
        }

        @Test
        @DisplayName("Sync decay from Active steps to Degraded on expired TTL")
        void testSyncDecayStepsToDegraded() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_PAST)) {

                assertEquals(DecayState.ACTIVE, mandate.decayState());
                // First compute: Active → Degraded (one step)
                assertEquals(DecayState.DEGRADED, mandate.computeDecayState(3600));

                // syncDecayState advances by one step without throwing
                assertDoesNotThrow(() -> mandate.syncDecayState(3600));
                assertEquals(DecayState.DEGRADED, mandate.decayState());
            }
        }

        @Test
        @DisplayName("Sync decay is no-op when already at target")
        void testSyncDecayNoop() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                mandate.syncDecayState(1800);
                assertEquals(DecayState.ACTIVE, mandate.decayState());
            }
        }

        @Test
        @DisplayName("Explicit transition Active→Degraded works")
        void testTransitionActiveToDegraded() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                mandate.transitionDecay(DecayState.DEGRADED);
                assertEquals(DecayState.DEGRADED, mandate.decayState());
            }
        }

        @Test
        @DisplayName("Explicit transition Degraded→ReadOnly works")
        void testTransitionDegradedToReadOnly() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                mandate.transitionDecay(DecayState.DEGRADED);
                mandate.transitionDecay(DecayState.READ_ONLY);
                assertEquals(DecayState.READ_ONLY, mandate.decayState());
            }
        }

        @Test
        @DisplayName("Renewal from Degraded to Active succeeds")
        void testRenewalDegradedToActive() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                mandate.transitionDecay(DecayState.DEGRADED);
                mandate.transitionDecay(DecayState.ACTIVE);
                assertEquals(DecayState.ACTIVE, mandate.decayState());
            }
        }

        @Test
        @DisplayName("Renewal from ReadOnly to Active succeeds")
        void testRenewalReadOnlyToActive() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                mandate.transitionDecay(DecayState.DEGRADED);
                mandate.transitionDecay(DecayState.READ_ONLY);
                mandate.transitionDecay(DecayState.ACTIVE);
                assertEquals(DecayState.ACTIVE, mandate.decayState());
            }
        }

        @Test
        @DisplayName("Suspended state is terminal")
        void testSuspendedIsTerminal() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                mandate.transitionDecay(DecayState.DEGRADED);
                mandate.transitionDecay(DecayState.READ_ONLY);
                mandate.transitionDecay(DecayState.SUSPENDED);
                assertEquals(DecayState.SUSPENDED, mandate.decayState());

                // No transitions allowed from Suspended
                assertThrows(PapException.class,
                        () -> mandate.transitionDecay(DecayState.ACTIVE));
            }
        }

        @Test
        @DisplayName("Direct Active→ReadOnly transition throws")
        void testDirectActiveToReadOnlyThrows() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                assertThrows(PapException.class,
                        () -> mandate.transitionDecay(DecayState.READ_ONLY));
            }
        }

        @Test
        @DisplayName("Self-transition throws")
        void testSelfTransitionThrows() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                assertThrows(PapException.class,
                        () -> mandate.transitionDecay(DecayState.ACTIVE));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Session Lifecycle
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Session Lifecycle")
    class SessionLifecycle {

        @Test
        @DisplayName("Session initiates from capability token")
        void testSessionInitiate() {
            try (var kp = PrincipalKeypair.generate();
                 var token = CapabilityToken.mint(
                         "did:key:zreceiver", "schema:SearchAction",
                         kp.did(), TTL_1H)) {

                token.sign(kp);
                var session = Session.initiate(token, "did:key:zreceiver", kp.publicKeyBytes());
                assertNotNull(session);
                session.close();
            }
        }

        @Test
        @DisplayName("Session starts in Initiated state")
        void testSessionInitialState() {
            try (var kp = PrincipalKeypair.generate();
                 var token = CapabilityToken.mint(
                         "did:key:zreceiver", "schema:SearchAction",
                         kp.did(), TTL_1H)) {

                token.sign(kp);
                try (var session = Session.initiate(token, "did:key:zreceiver", kp.publicKeyBytes())) {
                    assertEquals(SessionState.INITIATED, session.state());
                }
            }
        }

        @Test
        @DisplayName("Session transitions through lifecycle")
        void testSessionTransitions() {
            try (var kp = PrincipalKeypair.generate();
                 var sessionKp1 = PrincipalKeypair.generate();
                 var sessionKp2 = PrincipalKeypair.generate();
                 var token = CapabilityToken.mint(
                         "did:key:zreceiver", "schema:SearchAction",
                         kp.did(), TTL_1H)) {

                token.sign(kp);
                try (var session = Session.initiate(token, "did:key:zreceiver", kp.publicKeyBytes())) {
                    assertEquals(SessionState.INITIATED, session.state());

                    // Open the session
                    session.open(sessionKp1.did(), sessionKp2.did());
                    assertEquals(SessionState.OPEN, session.state());

                    // Execute the session
                    session.execute();
                    assertEquals(SessionState.EXECUTED, session.state());

                    // Close the session
                    session.close_session();
                    assertEquals(SessionState.CLOSED, session.state());
                }
            }
        }

        @Test
        @DisplayName("Session ID is available after initiation")
        void testSessionId() {
            try (var kp = PrincipalKeypair.generate();
                 var token = CapabilityToken.mint(
                         "did:key:zreceiver", "schema:SearchAction",
                         kp.did(), TTL_1H)) {

                token.sign(kp);
                try (var session = Session.initiate(token, "did:key:zreceiver", kp.publicKeyBytes())) {
                    String id = session.id();
                    assertNotNull(id);
                    assertTrue(id.length() > 0);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Capability Token
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Capability Token")
    class CapabilityTokenTests {

        @Test
        @DisplayName("Token mints and signs successfully")
        void testTokenMintAndSign() {
            try (var kp = PrincipalKeypair.generate();
                 var token = CapabilityToken.mint(
                         "did:key:ztarget", "schema:SearchAction",
                         kp.did(), TTL_1H)) {

                token.sign(kp);
                assertNotNull(token);
            }
        }

        @Test
        @DisplayName("Token serializes and deserializes")
        void testTokenSerialization() {
            try (var kp = PrincipalKeypair.generate();
                 var token = CapabilityToken.mint(
                         "did:key:ztarget", "schema:SearchAction",
                         kp.did(), TTL_1H)) {

                token.sign(kp);
                String json = token.toJson();
                assertFalse(json.isEmpty());

                try (var token2 = CapabilityToken.fromJson(json)) {
                    assertNotNull(token2);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Serialization (JSON Roundtrip)
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Serialization")
    class Serialization {

        @Test
        @DisplayName("Mandate JSON roundtrip preserves hash")
        void testMandateJsonRoundtrip() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                mandate.sign(kp);
                String hash1 = mandate.hash();
                String json = mandate.toJson();

                try (var mandate2 = Mandate.fromJson(json)) {
                    String hash2 = mandate2.hash();
                    assertEquals(hash1, hash2);
                }
            }
        }

        @Test
        @DisplayName("Deserialized mandate signature verifies")
        void testDeserializedSignatureVerifies() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                mandate.sign(kp);
                String json = mandate.toJson();

                try (var mandate2 = Mandate.fromJson(json)) {
                    assertDoesNotThrow(() -> mandate2.verify(kp.publicKeyBytes()));
                }
            }
        }

        @Test
        @DisplayName("Deserialized decay state must be recomputed")
        void testDeserializedDecayStateRecomputed() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_PAST)) {

                mandate.sign(kp);
                String json = mandate.toJson();

                try (var mandate2 = Mandate.fromJson(json)) {
                    // The deserialized mandate state is whatever was serialized
                    // but we must recompute it based on TTL
                    assertEquals(DecayState.READ_ONLY, mandate2.computeDecayState(3600));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // AutoCloseable Resource Management
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Resource Management")
    class ResourceManagement {

        @Test
        @DisplayName("Try-with-resources cleans up keypair")
        void testKeypairAutoClose() {
            assertDoesNotThrow(() -> {
                try (var kp = PrincipalKeypair.generate()) {
                    assertNotNull(kp.did());
                }
            });
        }

        @Test
        @DisplayName("Try-with-resources cleans up scope")
        void testScopeAutoClose() {
            assertDoesNotThrow(() -> {
                try (var scope = Scope.from(new String[]{"schema:SearchAction"})) {
                    assertTrue(scope.permits("schema:SearchAction"));
                }
            });
        }

        @Test
        @DisplayName("Try-with-resources cleans up disclosure set")
        void testDisclosureSetAutoClose() {
            assertDoesNotThrow(() -> {
                try (var ds = DisclosureSet.empty()) {
                    assertNotNull(ds);
                }
            });
        }

        @Test
        @DisplayName("Try-with-resources cleans up mandate")
        void testMandateAutoClose() {
            assertDoesNotThrow(() -> {
                try (var kp = PrincipalKeypair.generate();
                     var scope = Scope.from(new String[]{"schema:SearchAction"});
                     var ds = DisclosureSet.empty();
                     var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {
                    assertNotNull(mandate.hash());
                }
            });
        }

        @Test
        @DisplayName("Try-with-resources cleans up session")
        void testSessionAutoClose() {
            assertDoesNotThrow(() -> {
                try (var kp = PrincipalKeypair.generate();
                     var token = CapabilityToken.mint(
                             "did:key:zreceiver", "schema:SearchAction",
                             kp.did(), TTL_1H)) {
                    token.sign(kp);
                    try (var session = Session.initiate(token, "did:key:zreceiver", kp.publicKeyBytes())) {
                        assertNotNull(session.id());
                    }
                }
            });
        }

        @Test
        @DisplayName("Nested try-with-resources handles multiple resources")
        void testNestedAutoClose() {
            assertDoesNotThrow(() -> {
                try (var kp1 = PrincipalKeypair.generate();
                     var kp2 = PrincipalKeypair.generate();
                     var scope1 = Scope.from(new String[]{"schema:SearchAction"});
                     var scope2 = Scope.from(new String[]{"schema:PayAction"});
                     var ds = DisclosureSet.empty()) {

                    try (var mandate = Mandate.issueRoot(
                            kp1.did(), "did:key:zagent", scope1, ds, TTL_1H)) {
                        mandate.sign(kp1);
                        assertDoesNotThrow(() -> mandate.verify(kp1.publicKeyBytes()));
                    }
                }
            });
        }
    }

    // -----------------------------------------------------------------------
    // Exception Hierarchy
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Exception Handling")
    class ExceptionHandling {

        @Test
        @DisplayName("PapException extends RuntimeException")
        void testPapExceptionHierarchy() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                PapException ex = assertThrows(PapException.class,
                        () -> mandate.verify(kp.publicKeyBytes()));
                assertInstanceOf(RuntimeException.class, ex);
            }
        }

        @Test
        @DisplayName("PapException message is informative")
        void testPapExceptionMessage() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                PapException ex = assertThrows(PapException.class,
                        () -> mandate.verify(kp.publicKeyBytes()));
                assertTrue(ex.getMessage().length() > 0);
            }
        }

        @Test
        @DisplayName("Invalid public key length throws IllegalArgumentException")
        void testInvalidKeyLength() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                mandate.sign(kp);
                byte[] wrongKey = new byte[31];
                assertThrows(IllegalArgumentException.class,
                        () -> mandate.verify(wrongKey));
            }
        }

        @Test
        @DisplayName("Invalid session initiation raises PapException")
        void testInvalidSessionInitiation() {
            try (var kp = PrincipalKeypair.generate();
                 var token = CapabilityToken.mint(
                         "did:key:zreceiver", "schema:SearchAction",
                         kp.did(), TTL_1H)) {

                token.sign(kp);
                byte[] wrongKey = new byte[32];
                assertThrows(PapException.class,
                        () -> Session.initiate(token, "did:key:zreceiver", wrongKey));
            }
        }

        @Test
        @DisplayName("Invalid state transition raises PapException")
        void testInvalidStateTransition() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                // Try to go directly Active → ReadOnly (invalid)
                assertThrows(PapException.class,
                        () -> mandate.transitionDecay(DecayState.READ_ONLY));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Complex Integration Scenarios
    // -----------------------------------------------------------------------

    @Nested
    @DisplayName("Complex Scenarios")
    class ComplexScenarios {

        @Test
        @DisplayName("Full delegation and session flow")
        void testFullIntegrationFlow() {
            try (var principal = PrincipalKeypair.generate();
                 var orchestrator = PrincipalKeypair.generate();
                 var agent = PrincipalKeypair.generate()) {

                // Issue root mandate from principal
                try (var scope = Scope.from(
                             new String[]{"schema:SearchAction"},
                             new String[]{"schema:PayAction"});
                     var ds = DisclosureSet.empty();
                     var rootMandate = Mandate.issueRoot(
                         principal.did(), orchestrator.did(),
                         scope, ds, TTL_1H)) {

                    rootMandate.sign(principal);

                    // Delegate to agent
                    try (var agentScope = Scope.from(new String[]{"schema:SearchAction"});
                         var agentDs = DisclosureSet.empty();
                         var agentMandate = rootMandate.delegate(
                             agent.did(), agentScope, agentDs, TTL_30M)) {

                        agentMandate.sign(principal);

                        // Verify both mandates
                        assertDoesNotThrow(() -> rootMandate.verify(principal.publicKeyBytes()));
                        assertDoesNotThrow(() -> agentMandate.verify(principal.publicKeyBytes()));

                        // Transition decay
                        rootMandate.transitionDecay(DecayState.DEGRADED);
                        assertEquals(DecayState.DEGRADED, rootMandate.decayState());

                        // Create session from capability token
                        try (var token = CapabilityToken.mint(
                                 agent.did(), "schema:SearchAction",
                                 agent.did(), TTL_30M)) {

                            token.sign(agent);

                            try (var session = Session.initiate(
                                    token, agent.did(), agent.publicKeyBytes())) {

                                try (var sessionKp1 = PrincipalKeypair.generate();
                                     var sessionKp2 = PrincipalKeypair.generate()) {

                                    session.open(sessionKp1.did(), sessionKp2.did());
                                    assertEquals(SessionState.OPEN, session.state());

                                    session.execute();
                                    assertEquals(SessionState.EXECUTED, session.state());
                                }
                            }
                        }
                    }
                }
            }
        }

        @Test
        @DisplayName("Mandate serialization in delegation chain")
        void testSerializationInDelegationChain() {
            try (var kp = PrincipalKeypair.generate();
                 var scope1 = Scope.from(
                         new String[]{"schema:SearchAction"},
                         new String[]{"schema:PayAction"});
                 var ds1 = DisclosureSet.empty();
                 var level1 = Mandate.issueRoot(kp.did(), "did:key:z1",
                                                scope1, ds1, TTL_1H)) {

                level1.sign(kp);

                try (var scope2 = Scope.from(new String[]{"schema:SearchAction"});
                     var ds2 = DisclosureSet.empty();
                     var level2 = level1.delegate("did:key:z2", scope2, ds2, TTL_30M)) {

                    level2.sign(kp);

                    // Serialize level 1
                    String json1 = level1.toJson();

                    // Serialize level 2
                    String json2 = level2.toJson();

                    // Deserialize and verify
                    try (var l1 = Mandate.fromJson(json1);
                         var l2 = Mandate.fromJson(json2)) {

                        assertDoesNotThrow(() -> l1.verify(kp.publicKeyBytes()));
                        assertDoesNotThrow(() -> l2.verify(kp.publicKeyBytes()));

                        assertEquals(level1.hash(), l1.hash());
                        assertEquals(level2.hash(), l2.hash());
                    }
                }
            }
        }

        @Test
        @DisplayName("Concurrent decay state monitoring")
        void testConcurrentDecayMonitoring() {
            try (var kp = PrincipalKeypair.generate();
                 var scope = Scope.from(new String[]{"schema:SearchAction"});
                 var ds = DisclosureSet.empty();
                 var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

                // Simulate multiple monitoring cycles
                for (int i = 0; i < 5; i++) {
                    DecayState computed = mandate.computeDecayState(3600);
                    DecayState current = mandate.decayState();

                    // Safe to sync multiple times
                    mandate.syncDecayState(3600);

                    // States should be consistent
                    assertEquals(computed, mandate.decayState());
                }
            }
        }
    }
}
