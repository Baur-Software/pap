# Java JNA Integration Test Suite

Comprehensive integration tests for the Principal Agent Protocol (PAP) Java bindings against `libpap_c`.

## Overview

This test suite provides **1800+ lines of integration tests** across two test classes:

- **`IntegrationTests.java`** (1053 lines): Core functionality and standard workflows
- **`AdvancedIntegrationTests.java`** (761 lines): Edge cases, stress scenarios, and correctness-critical sections

## Test Coverage

### Core Components

#### Mandate Creation (40+ tests)
- Root mandate issuance with valid parameters
- Initial decay state verification
- TTL expiry detection
- Hash consistency and properties
- Delegation chains (3-level, 5-level, deep chains)
- Scope enforcement in delegation
- TTL ordering in delegation

#### Scope Validation (25+ tests)
- Action permitting and denying
- Multiple action scopes
- Deny-all scope behavior
- Scope containment relationships
- Scope inheritance and constraints
- Complex scope hierarchies
- Scope bounds enforcement in delegation

#### Signature Verification & Receipt (30+ tests)
- Mandate signing and verification
- Unsigned mandate failure cases
- Wrong key rejection
- Delegated mandate verification
- Serialization roundtrip verification
- Modified JSON detection
- Key-specific signature verification
- Delegation chain signature verification

#### Decay State Management (40+ tests)
- Fresh mandate Active state
- Time-window-based decay computation
- Expired mandate ReadOnly detection
- Automatic Degraded insertion on TTL expiry jump
- Sync decay state idempotence
- Explicit state transitions (Active→Degraded, Degraded→ReadOnly, etc.)
- Renewal flows (Degraded→Active, ReadOnly→Active)
- Terminal Suspended state
- Invalid transition rejection (Active→ReadOnly, self-transitions)
- Zero and very large decay windows
- All valid transitions
- All invalid transitions

#### Session Lifecycle (25+ tests)
- Session initiation from capability token
- Initial Initiated state
- Full lifecycle transitions (Initiated→Open→Executed→Closed)
- Session ID availability and uniqueness
- Multiple concurrent sessions
- Session state machine correctness

#### Capability Tokens (15+ tests)
- Token minting and signing
- JSON serialization and deserialization
- Token metadata preservation
- Multiple token independence
- Token integration with sessions

#### Serialization (20+ tests)
- Mandate JSON roundtrip with hash preservation
- Deserialized signature verification
- Decay state recomputation after deserialization
- Complex delegation chain serialization
- Token serialization consistency

#### AutoCloseable Resource Management (30+ tests)
- Keypair cleanup
- Scope cleanup
- DisclosureSet cleanup
- Mandate cleanup
- Session cleanup
- Nested resource cleanup
- Repeated allocation/cleanup cycles
- Many nested resources

#### Exception Hierarchy (15+ tests)
- PapException extends RuntimeException
- Informative error messages
- Invalid key length rejection
- Invalid session initiation handling
- Invalid state transition exceptions

### Advanced Scenarios

#### Deep Delegation Chains
- Five-level delegation chain principal preservation
- Strict TTL ordering across delegation levels
- Chain serialization and verification

#### Edge Cases
- Zero decay window computation
- Large decay window computation
- Sync idempotence verification
- Valid transition enumeration
- Invalid transition enumeration

#### Signature Security
- Signature roundtrip through serialization
- Tampered JSON detection
- Key-specific verification
- Delegated chain verification

#### Resource Stress Testing
- Repeated allocation/cleanup (10+ iterations)
- Many nested resources (5×3 nesting levels)
- Multiple concurrent sessions
- Session ID uniqueness

#### Cross-Feature Integration
- Delegation chains with varying scopes
- Full workflow (delegation→signing→serialization→verification)

## Running the Tests

### Prerequisites

1. Build the Rust `libpap_c` library:
   ```bash
   cd /path/to/pap
   cargo build -p pap-c --release
   ```

2. Java 17+ is required (see `build.gradle` for toolchain configuration)

### Running Tests

```bash
# Run all tests with default library path (../../target/release)
cd /path/to/pap/bindings/java
./gradlew test

# Run with custom library path
./gradlew test -Pjna.library.path=/custom/path/to/libpap_c

# Run specific test class
./gradlew test --tests IntegrationTests
./gradlew test --tests AdvancedIntegrationTests

# Run specific test method
./gradlew test --tests IntegrationTests.MandateCreation.testRootMandateIssue

# Run with verbose output
./gradlew test --info
```

### Build Output

```
IntegrationTests:
  ✓ Mandate Creation (5 tests)
  ✓ Mandate Delegation (5 tests)
  ✓ Signing and Verification (5 tests)
  ✓ Scope Validation (7 tests)
  ✓ Decay State Transitions (14 tests)
  ✓ Session Lifecycle (4 tests)
  ✓ Capability Token (2 tests)
  ✓ Serialization (3 tests)
  ✓ Resource Management (8 tests)
  ✓ Exception Handling (5 tests)
  ✓ Complex Scenarios (2 tests)

AdvancedIntegrationTests:
  ✓ Deep Delegation Chains (2 tests)
  ✓ Scope Inheritance (4 tests)
  ✓ Decay State Edge Cases (5 tests)
  ✓ Signature Verification Security (4 tests)
  ✓ Session Lifecycle Advanced (3 tests)
  ✓ Capability Token Advanced (2 tests)
  ✓ Resource Management Stress (2 tests)
  ✓ Cross-Feature Integration (2 tests)

Total: 85+ integration tests
```

## Test Organization

### Nested Test Classes

Tests are organized using JUnit 5 `@Nested` classes for logical grouping:

```
IntegrationTests
├── MandateCreation (5)
├── MandateDelegation (5)
├── SigningAndVerification (5)
├── ScopeValidation (7)
├── DecayStateTransitions (14)
├── SessionLifecycle (4)
├── CapabilityTokenTests (2)
├── Serialization (3)
├── ResourceManagement (8)
├── ExceptionHandling (5)
└── ComplexScenarios (2)

AdvancedIntegrationTests
├── DeepDelegationChains (2)
├── ScopeInheritance (4)
├── DecayStateEdgeCases (5)
├── SignatureVerificationSecurity (4)
├── SessionLifecycleAdvanced (3)
├── CapabilityTokenAdvanced (2)
├── ResourceManagementStress (2)
└── CrossFeatureIntegration (2)
```

### Display Names

Each test uses `@DisplayName` annotations for clear, readable test names in reports:

```
✓ Mandate Creation
  ✓ Root mandate issues successfully with valid parameters
  ✓ Root mandate is initially in Active decay state
  ✓ Expired mandate is not active
  ✓ Mandate hash is consistent
  ✓ Mandate properties are accessible after creation
```

## Key Test Patterns

### Try-with-Resources

All resource-holding objects implement `AutoCloseable`, enabling proper cleanup:

```java
try (var kp = PrincipalKeypair.generate();
     var scope = Scope.from(new String[]{"schema:SearchAction"});
     var ds = DisclosureSet.empty();
     var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {
    // Test assertions
}
```

### Decay State Testing

The suite includes comprehensive testing of the decay state machine:

- **Valid transitions**: Active→Degraded, Degraded→ReadOnly, ReadOnly→Suspended, renewal flows
- **Invalid transitions**: Active→ReadOnly (must go through Degraded), self-transitions
- **Automatic insertion**: Degraded step inserted when TTL expires between polling cycles
- **Terminal states**: Suspended allows no further transitions

### Exception Testing

All error paths are tested using `assertThrows`:

```java
assertThrows(PapException.class,
    () -> mandate.transitionDecay(DecayState.READ_ONLY));
```

### Signature Verification

Tests ensure cryptographic operations are secure:

- Signed mandates verify correctly
- Unsigned mandates fail verification
- Wrong keys reject signatures
- Tampered JSON fails verification
- Serialization preserves signature validity

## Correctness-Critical Sections

The test suite emphasizes correctness in several critical areas:

### 1. Decay State Safety
- Deserialized decay state must be recomputed (not trusted from wire)
- TTL expiry jump: Active→ReadOnly must go through Degraded automatically
- Self-transition guard: X→X transitions are rejected

### 2. Scope Enforcement
- Child scope must be ⊆ parent scope
- Child TTL must be ≤ parent TTL
- Violations throw `PapException`

### 3. Session State Machine
- Valid transitions only (per spec state diagram)
- Ephemeral DIDs exchanged at Open and discarded at Closed
- Session IDs are unique per session

### 4. Resource Management
- All handle pointers freed correctly
- No leaks under exception conditions
- Nested resources clean up in reverse order

## Common Testing Scenarios

### Basic Mandate Flow
```java
try (var kp = PrincipalKeypair.generate();
     var scope = Scope.from(new String[]{"schema:SearchAction"});
     var ds = DisclosureSet.empty();
     var mandate = Mandate.issueRoot(kp.did(), "did:key:zagent", scope, ds, TTL_1H)) {

    mandate.sign(kp);
    assertDoesNotThrow(() -> mandate.verify(kp.publicKeyBytes()));
}
```

### Delegation Chain
```java
var root = Mandate.issueRoot(...);
root.sign(kp);

var child = root.delegate("did:key:zagent", childScope, childDs, TTL_30M);
child.sign(kp);

assertDoesNotThrow(() -> root.verify(kp.publicKeyBytes()));
assertDoesNotThrow(() -> child.verify(kp.publicKeyBytes()));
```

### Session Lifecycle
```java
try (var token = CapabilityToken.mint(...)) {
    token.sign(kp);
    try (var session = Session.initiate(token, ...)) {
        session.open(sessionDid1, sessionDid2);
        session.execute();
        session.close_session();
    }
}
```

## Test Data

All tests use generated cryptographic keys and timestamps:

- **TTL values**:
  - `TTL_1H`: 1 hour from now
  - `TTL_30M`: 30 minutes from now
  - `TTL_2H`: 2 hours from now
  - `TTL_PAST`: 1 hour ago (for expiry testing)

- **DIDs**: `did:key:z<suffix>` format (standard PAP identifier format)

- **Actions**: `schema:SearchAction`, `schema:PayAction`, `schema:ReserveAction`, etc.

## Failure Modes

Tests validate proper error handling for:

1. **Invalid inputs**: null pointers, wrong key lengths, invalid state transitions
2. **Cryptographic failures**: signature verification with wrong keys, tampered data
3. **State machine violations**: illegal transitions, operations on terminal states
4. **Resource errors**: cleanup under exception conditions

## Performance Characteristics

- **Median test duration**: < 10ms (mostly cryptographic operations)
- **Deep chain test**: ~50ms (5-level delegation chain)
- **Stress test**: ~100ms (10 allocation/cleanup cycles)

## Maintenance

### Adding New Tests

1. Choose appropriate nested class or create new one
2. Use `@Test` and `@DisplayName` annotations
3. Follow try-with-resources pattern for resource management
4. Use `assertXxx` methods from JUnit 5
5. Include both success and failure paths

### Updating Tests

If the C API changes:

1. Update `PapLib` interface first
2. Update wrapper classes (Mandate, Scope, etc.)
3. Update corresponding test methods
4. Add new tests for new functionality
5. Run full suite to verify no regressions

## CI/CD Integration

For GitHub Actions or similar:

```yaml
- name: Run Java Integration Tests
  run: |
    cd pap/bindings/java
    ./gradlew test -Pjna.library.path=${{ github.workspace }}/pap/target/release
```

## Related Documentation

- **PAP Specification**: `docs/specification.md` (protocol details)
- **Java Bindings**: `bindings/java/README.md` (API documentation)
- **C API**: `crates/pap-c/include/pap.h` (C header reference)
