# pap — Python SDK for the Principal Agent Protocol

`pip install pap-protocol`

Python bindings (via PyO3) for the [Principal Agent Protocol (PAP)](https://github.com/Baur-Software/pap) — a cryptographic delegation framework that gives AI agents a verifiable chain of authority back to a human principal.

## Quick start

```python
import datetime
from pap import (
    PrincipalKeypair, SessionKeypair,
    Scope, ScopeAction, DisclosureSet,
    Mandate, MandateChain,
    PapSignatureError, PapScopeError,
)

# 1. Generate the principal's root keypair (store securely — this is your identity)
principal = PrincipalKeypair.generate()
print(principal.did())  # did:key:z6Mk...

# 2. Define what the agent is allowed to do
scope = Scope([ScopeAction("schema:SearchAction")])
ds = DisclosureSet.empty()

# 3. Issue and sign a root mandate
ttl = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).isoformat()
mandate = Mandate.issue_root(principal.did(), "did:key:zagent", scope, ds, ttl)
mandate.sign(principal)

# 4. Verify (raises PapSignatureError on failure)
try:
    mandate.verify_with_keypair(principal)
    print("mandate verified ✓")
except PapSignatureError as e:
    print(f"invalid signature: {e}")

# 5. Delegate to a sub-agent (scope must be ⊆ parent)
agent_key = SessionKeypair.generate()
child = mandate.delegate(agent_key.did(), scope, ds, ttl)
child.sign_with_session_key(agent_key)

chain = MandateChain(mandate)
chain.push(child)
chain.verify_chain([principal, agent_key])  # accepts mixed keypair types
print(f"chain depth: {len(chain)}")
```

## Exception hierarchy

All PAP errors inherit from `PapError`:

| Exception | Raised when |
|---|---|
| `PapSignatureError` | Signature missing, invalid, or tampered |
| `PapScopeError` | Delegation exceeds parent scope or TTL |
| `PapSessionError` | Invalid state transition or nonce replay |
| `PapTransportError` | HTTP connection failure or bad server response |

## Installation

### From PyPI (recommended)

```bash
pip install pap-protocol
```

Pre-built wheels are available for:
- Linux x86_64 (glibc 2.28+)
- Linux x86_64 (musl, for Alpine)
- Linux aarch64 (glibc 2.28+)
- macOS (universal2: x86_64 + Apple Silicon)
- Windows x86_64

The package uses the Python Stable ABI (abi3), so a single wheel works across Python 3.8–3.13+.

### From source

```bash
cd crates/pap-python
pip install maturin
maturin develop          # development install in current Python env
maturin build --release  # produce a distributable wheel
```

Or use the build script:

```bash
./crates/pap-python/scripts/build-wheels.sh
pip install crates/pap-python/dist/*.whl
```

Requires Rust 1.75+ and Python 3.8+.

## Publishing

Releases are automated via GitHub Actions. To publish a new version:

1. Update `version` in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Commit, then tag and push:
   ```bash
   git tag python-v0.1.0
   git push origin python-v0.1.0
   ```

The workflow builds wheels for all platforms and publishes to PyPI via OIDC trusted publishing. See `.github/workflows/release-python.yml` for details.
