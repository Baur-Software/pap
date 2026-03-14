"""
pap — Python SDK for the Principal Agent Protocol
==================================================

The Principal Agent Protocol (PAP) gives AI agents a cryptographic
delegation chain: a human principal issues a signed *mandate* to an
orchestrator, which can delegate sub-mandates to specialist agents.
Every session starts with a capability token, runs a 6-phase handshake,
and closes with a co-signed transaction receipt.

Quick start
-----------

>>> from pap import PrincipalKeypair, Scope, ScopeAction, DisclosureSet, Mandate
>>> import datetime, timezone
>>>
>>> # 1. Generate principal keypair
>>> principal = PrincipalKeypair.generate()
>>>
>>> # 2. Define scope and disclosure
>>> scope = Scope([ScopeAction("schema:SearchAction")])
>>> ds = DisclosureSet.empty()
>>>
>>> # 3. Issue a root mandate
>>> ttl = (datetime.datetime.now(timezone.utc) + datetime.timedelta(hours=1)).isoformat()
>>> mandate = Mandate.issue_root(principal.did(), "did:key:zagent", scope, ds, ttl)
>>> mandate.sign(principal)
>>>
>>> # 4. Verify
>>> mandate.verify_with_keypair(principal)  # raises ValueError on failure

All classes are re-exported from the compiled Rust extension (`pap._pap`).
"""

from pap._pap import (  # noqa: F401
    # Keys
    PrincipalKeypair,
    SessionKeypair,
    # DID utilities
    public_key_to_did,
    did_to_public_key_bytes,
    # Scope / disclosure
    ScopeAction,
    Scope,
    DisclosureEntry,
    DisclosureSet,
    # Mandate / delegation
    DecayState,
    Mandate,
    MandateChain,
    # Session / token
    SessionState,
    CapabilityToken,
    Session,
    # Receipt
    TransactionReceipt,
    # Credentials
    Disclosure,
    SelectiveDisclosureJwt,
    # Marketplace
    AgentAdvertisement,
    MarketplaceRegistry,
    # Transport
    AgentClient,
)

__all__ = [
    "PrincipalKeypair",
    "SessionKeypair",
    "public_key_to_did",
    "did_to_public_key_bytes",
    "ScopeAction",
    "Scope",
    "DisclosureEntry",
    "DisclosureSet",
    "DecayState",
    "Mandate",
    "MandateChain",
    "SessionState",
    "CapabilityToken",
    "Session",
    "TransactionReceipt",
    "Disclosure",
    "SelectiveDisclosureJwt",
    "AgentAdvertisement",
    "MarketplaceRegistry",
    "AgentClient",
]
