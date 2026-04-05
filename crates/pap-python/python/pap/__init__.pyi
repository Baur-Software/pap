"""
pap — Python SDK for the Principal Agent Protocol.

Type stub for the public ``pap`` package.  All symbols are re-exported from
the compiled Rust extension ``pap._pap``.
"""

from pap._pap import (
    # Exceptions
    PapError as PapError,
    PapSignatureError as PapSignatureError,
    PapScopeError as PapScopeError,
    PapSessionError as PapSessionError,
    PapTransportError as PapTransportError,
    # Keys
    PrincipalKeypair as PrincipalKeypair,
    SessionKeypair as SessionKeypair,
    # DID utilities
    public_key_to_did as public_key_to_did,
    did_to_public_key_bytes as did_to_public_key_bytes,
    # Scope / disclosure
    ScopeAction as ScopeAction,
    Scope as Scope,
    DisclosureEntry as DisclosureEntry,
    DisclosureSet as DisclosureSet,
    # Mandate / delegation
    DecayState as DecayState,
    Mandate as Mandate,
    MandateChain as MandateChain,
    # Session / token
    SessionState as SessionState,
    CapabilityToken as CapabilityToken,
    Session as Session,
    # Receipt
    TransactionReceipt as TransactionReceipt,
    # Credentials
    Disclosure as Disclosure,
    SelectiveDisclosureJwt as SelectiveDisclosureJwt,
    # Marketplace
    AgentAdvertisement as AgentAdvertisement,
    MarketplaceRegistry as MarketplaceRegistry,
    # Transport
    AgentClient as AgentClient,
)

__all__: list[str]
