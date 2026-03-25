# PAP Python SDK Test Guide

## Overview

The PAP Python SDK test suite consists of comprehensive unit and integration tests covering:

1. **Session** - Protocol session lifecycle and state management
2. **CapabilityToken** - Single-use authorization tokens with scope constraints
3. **TransactionReceipt** - Co-signed transaction records with property references

Total: **90 tests** (51 existing + 39 new)

## Quick Start

### Prerequisites

```bash
# Ensure Rust toolchain is installed
rustup default stable

# Install Python development dependencies
pip install pytest pytest-cov
```

### Running Tests

```bash
cd crates/pap-python

# Build the Rust extension (required before first test run)
maturin develop

# Run all tests
pytest tests/ -v

# Run only Session/CapabilityToken/TransactionReceipt tests
pytest tests/test_session_capability_receipt.py -v

# Run with coverage report
pytest tests/ --cov=pap --cov-report=html
# Open htmlcov/index.html in browser
```

## Test Structure

### New Test File: `test_session_capability_receipt.py`

```
TestCapabilityToken (10 tests)
├── Minting and nonce generation
├── Signing (PrincipalKeypair and SessionKeypair)
├── Signature verification
├── JSON serialization
├── Timestamp validation
└── String representation

TestSessionLifecycle (12 tests)
├── Session initiation from token
├── Nonce consumption and tracking
├── State machine transitions (Initiated → Open → Executed → Closed)
├── Ephemeral DID recording
├── Key validation
└── Lifecycle management

TestTransactionReceipt (10 tests)
├── Receipt creation from executed session
├── Co-signature accumulation
├── Dual co-signature verification
├── Property reference preservation
├── JSON serialization with signatures
└── Timestamp accuracy

TestSessionCapabilityReceiptIntegration (3 tests)
├── Full end-to-end flow
├── Multiple concurrent sessions
└── Property reference privacy (refs only, not values)

TestEdgeCases (4 tests)
├── Invalid datetime handling
├── Invalid key bytes
├── Invalid JSON deserialization
└── Verification failures
```

## Key Test Scenarios

### 1. CapabilityToken Lifecycle

```python
# Mint a token
token = CapabilityToken.mint(
    target_did="did:key:zagent",
    action="schema:SearchAction",
    issuer_did=principal.did(),
    expires_at=future_ttl(hours=1)
)

# Sign with issuer's key
token.sign(principal)

# Verify signature
token.verify_signature(principal.public_key_bytes())

# Serialize/deserialize
json_str = token.to_json()
token2 = CapabilityToken.from_json(json_str)
```

### 2. Session State Machine

```python
# Initiate session from token (consumes nonce)
session = Session.initiate(
    token=token,
    receiver_did="did:key:zreceiver",
    issuer_public_key_bytes=principal.public_key_bytes()
)
# State: Initiated

# Open session (record ephemeral DIDs)
session.open(
    initiator_session_did="did:key:zinitiator_session",
    receiver_session_did="did:key:zreceiver_session"
)
# State: Open

# Execute session
session.execute()
# State: Executed

# Close session
session.close()
# State: Closed
```

### 3. TransactionReceipt Co-Signatures

```python
# Create receipt from executed session
receipt = TransactionReceipt.from_session(
    session=session,
    disclosed_by_initiator=["schema:Person.schema:name"],
    disclosed_by_receiver=["schema:WebPage.schema:url"],
    executed="schema:SearchAction",
    returned="schema:SearchResultsPage"
)

# Co-sign by initiator
receipt.co_sign(principal)

# Co-sign by receiver
receipt.co_sign_with_session_key(session_key)

# Verify both signatures
receipt.verify_both(
    principal.public_key_bytes(),
    session_key.public_key_bytes()
)

# Serialize
json_str = receipt.to_json()
receipt2 = TransactionReceipt.from_json(json_str)
```

## Test Coverage Matrix

| Feature | Unit Tests | Integration | Edge Cases | Coverage |
|---------|------------|-------------|-----------|----------|
| **CapabilityToken** | 10 | ✓ | ✓ | Complete |
| **Session Lifecycle** | 12 | ✓ | ✓ | Complete |
| **TransactionReceipt** | 10 | ✓ | ✓ | Complete |
| **Integration** | - | 3 | - | Complete |
| **Total** | 32 | 3 | 4 | ≥90% |

## Security Properties Verified

### ✅ Cryptographic Binding
- Token signatures bind to issuer's public key
- Receipt co-signatures verify against correct keypairs
- Wrong keys always fail verification

### ✅ Nonce Protection
- Each token gets unique nonce
- Consumed nonce tracked in session
- Replay with same nonce rejected

### ✅ Scope Enforcement
- Token action remains constant through session lifecycle
- Property references enforced (never actual values in receipt)

### ✅ State Transitions
- Only valid state transitions allowed
- Session DIDs recorded only in Open state
- Cannot execute without opening first

### ✅ Signature Verification
- Missing signatures raise errors
- Wrong keys raise errors
- Both co-signatures required for verification

## Running Specific Tests

```bash
# All CapabilityToken tests
pytest tests/test_session_capability_receipt.py::TestCapabilityToken -v

# All Session tests
pytest tests/test_session_capability_receipt.py::TestSessionLifecycle -v

# All TransactionReceipt tests
pytest tests/test_session_capability_receipt.py::TestTransactionReceipt -v

# All integration tests
pytest tests/test_session_capability_receipt.py::TestSessionCapabilityReceiptIntegration -v

# All edge case tests
pytest tests/test_session_capability_receipt.py::TestEdgeCases -v

# Single test
pytest tests/test_session_capability_receipt.py::TestSessionLifecycle::test_session_full_lifecycle -v
```

## Understanding Test Failures

### Signature Verification Fails

```
FAILED: test_verify_signature_fails_with_wrong_key
Expected: Exception raised
Got: No exception
```

**Check**: Token was signed with correct key? Verify key bytes are correct.

### Session State Transition Fails

```
FAILED: test_session_open_sets_session_dids
AssertionError: session.state != SessionState.Open
```

**Check**: Session must be in Initiated state before calling open(). Check previous state transitions.

### Nonce Not Consumed

```
FAILED: test_session_initiate_consumes_nonce
AssertionError: not session.is_nonce_consumed(nonce)
```

**Check**: Session.initiate() must be called with valid token. Nonce is consumed during initiation.

## Debugging Tips

### Print Test State

```python
def test_debug_session():
    session = Session.initiate(token, receiver_did, key_bytes)
    print(f"Session ID: {session.id}")
    print(f"State: {session.state}")
    print(f"Nonce consumed: {session.is_nonce_consumed(token.nonce)}")
```

### Enable Pytest Output

```bash
pytest tests/test_session_capability_receipt.py -v -s  # -s: capture output
```

### Run with Full Tracebacks

```bash
pytest tests/test_session_capability_receipt.py --tb=long
```

## Coverage Metrics

To generate a coverage report:

```bash
# Install coverage tools
pip install coverage pytest-cov

# Run tests with coverage
pytest tests/ --cov=pap --cov-report=html --cov-report=term-missing

# View report
open htmlcov/index.html  # macOS
start htmlcov/index.html  # Windows
xdg-open htmlcov/index.html  # Linux
```

Expected coverage for new tests:
- **CapabilityToken**: 100% (10 tests cover all methods)
- **Session**: 100% (12 tests cover all state transitions)
- **TransactionReceipt**: 100% (10 tests cover all co-signature paths)
- **Overall**: ≥90% (39 new + 51 existing = 90 tests)

## Continuous Integration

The test suite is designed to run in CI/CD pipelines:

```bash
# In CI environment
cd crates/pap-python
maturin develop
pytest tests/ --cov=pap --cov-report=xml
# Upload coverage.xml to coverage service (Codecov, etc.)
```

## Contributing New Tests

When adding new tests:

1. **Use descriptive names**: `test_session_open_sets_session_dids_correctly`
2. **Add docstrings**: Explain what the test verifies
3. **Isolate tests**: No shared state between tests
4. **Use helpers**: Reuse `_make_capability_token()`, `_make_completed_session()`
5. **Test both success and failure**: Include both positive and negative cases
6. **Document expectations**: Comments explaining why each assertion matters

Example:

```python
def test_my_new_feature(self):
    """My new feature should do X under condition Y."""
    # Setup
    token = CapabilityToken.mint(...)

    # Act
    session = Session.initiate(token, ...)

    # Assert
    assert session.state == SessionState.Initiated
```

## References

- [PAP Specification](../../docs/specification.md)
- [Python SDK Status](./PYTHON_SDK_STATUS.md)
- [Design System](../../DESIGN.md)

## Issues and Bug Reports

If tests fail unexpectedly:

1. Run with `-v -s --tb=long` flags
2. Check that `maturin develop` was run
3. Ensure Rust extension compiled without errors
4. Report with test name and full output

Example issue report:

```
Test: test_session_full_lifecycle
Error: PapSessionError: invalid state transition
Platform: Python 3.10, macOS 13
Extension build: maturin develop (OK)
```

## Performance Notes

- Cryptographic operations (signing, verification) dominate test runtime
- Parallel test execution not recommended (Session uses thread-local state)
- Total suite runtime: ~2-5 seconds on modern hardware

Run serially for consistency:

```bash
pytest tests/ -v -n0  # disable xdist parallelization
```
