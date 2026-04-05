"""
Shared pytest fixtures for pap-python tests.

Provides reusable keypairs, tokens, sessions, and mandates
so individual test files don't duplicate setup boilerplate.
"""

import datetime

import pytest

from pap import (
    PrincipalKeypair,
    SessionKeypair,
    ScopeAction,
    Scope,
    DisclosureSet,
    Mandate,
    CapabilityToken,
    Session,
)


def future_ttl(hours: int = 1) -> str:
    """Generate a future ISO 8601 timestamp."""
    dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=hours)
    return dt.isoformat()


def past_ttl(seconds: int = 1) -> str:
    """Generate a past ISO 8601 timestamp."""
    dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=seconds)
    return dt.isoformat()


@pytest.fixture
def principal_keypair():
    """Fresh PrincipalKeypair for cryptographic isolation."""
    return PrincipalKeypair.generate()


@pytest.fixture
def session_keypair():
    """Fresh SessionKeypair (ephemeral identity)."""
    return SessionKeypair.generate()


@pytest.fixture
def signed_token(principal_keypair):
    """Minted and signed CapabilityToken. Returns (token, principal)."""
    token = CapabilityToken.mint(
        target_did="did:key:zagent",
        action="schema:SearchAction",
        issuer_did=principal_keypair.did(),
        expires_at=future_ttl(1),
    )
    token.sign(principal_keypair)
    return token, principal_keypair


@pytest.fixture
def initiated_session(signed_token):
    """Session at Initiated state. Returns (session, principal, token)."""
    token, principal = signed_token
    session = Session.initiate(
        token=token,
        receiver_did="did:key:zagent",  # must match token.target_did
        issuer_public_key_bytes=principal.public_key_bytes(),
    )
    return session, principal, token


@pytest.fixture
def open_session(initiated_session):
    """Session at Open state. Returns (session, principal)."""
    session, principal, _ = initiated_session
    session.open("did:key:zinit_session", "did:key:zrecv_session")
    return session, principal


@pytest.fixture
def executed_session(open_session):
    """Session at Executed state. Returns (session, principal)."""
    session, principal = open_session
    session.execute()
    return session, principal


@pytest.fixture
def root_mandate(principal_keypair):
    """Signed root Mandate with SearchAction scope, 1h TTL. Returns (mandate, principal)."""
    scope = Scope([ScopeAction("schema:SearchAction")])
    ds = DisclosureSet.empty()
    mandate = Mandate.issue_root(
        principal_keypair.did(), "did:key:zagent1", scope, ds, future_ttl(1)
    )
    mandate.sign(principal_keypair)
    return mandate, principal_keypair
