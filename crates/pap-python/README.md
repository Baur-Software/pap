# pap — Python SDK for the Principal Agent Protocol

`pip install pap`

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

## Building from source

```bash
cd crates/pap-python
pip install maturin
maturin develop          # development install in current Python env
maturin build --release  # produce a distributable wheel
```

Requires Rust 1.75+ and Python 3.8+.
