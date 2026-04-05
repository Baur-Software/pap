"""
CapabilityToken tamper detection, expiry handling, and Mandate
delegation constraint tests.

Covers gaps not addressed in test_session_capability_receipt.py:
  - Tampered token fields break signature verification
  - Expired tokens are rejected
  - Mandate delegation enforces scope reduction and TTL decay
"""

import datetime
import json

import pytest

from pap import (
    PapScopeError,
    PapSessionError,
    PrincipalKeypair,
    SessionKeypair,
    ScopeAction,
    Scope,
    DisclosureSet,
    Mandate,
    CapabilityToken,
    Session,
)


# ===========================================================================
# Tamper Detection
# ===========================================================================

class TestCapabilityTokenTampering:
    """Modifying any signed field and verifying must fail."""

    def _mint_and_sign(self):
        """Helper: create a signed token and return (token, principal)."""
        principal = PrincipalKeypair.generate()
        token = CapabilityToken.mint(
            target_did="did:key:zagent",
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=future_ttl(1),
        )
        token.sign(principal)
        return token, principal

    def _tamper_field(self, token, principal, field, value):
        """Helper: tamper a field in the token's JSON and verify fails."""
        data = json.loads(token.to_json())
        data[field] = value
        tampered = CapabilityToken.from_json(json.dumps(data))
        with pytest.raises(Exception):
            tampered.verify_signature(principal.public_key_bytes())

    def test_tampered_action_fails_verification(self):
        """Changing the action field breaks the signature."""
        token, principal = self._mint_and_sign()
        self._tamper_field(token, principal, "action", "schema:PayAction")

    def test_tampered_target_did_fails_verification(self):
        """Changing the target_did field breaks the signature."""
        token, principal = self._mint_and_sign()
        self._tamper_field(token, principal, "target_did", "did:key:zevil")

    def test_tampered_nonce_fails_verification(self):
        """Changing the nonce field breaks the signature."""
        token, principal = self._mint_and_sign()
        self._tamper_field(token, principal, "nonce", "tampered-nonce-value")

    def test_tampered_issuer_did_fails_verification(self):
        """Changing the issuer_did field breaks the signature."""
        token, principal = self._mint_and_sign()
        self._tamper_field(token, principal, "issuer_did", "did:key:zfake")

    def test_tampered_expires_at_fails_verification(self):
        """Extending the expiry breaks the signature."""
        token, principal = self._mint_and_sign()
        self._tamper_field(token, principal, "expires_at", future_ttl(24))


# ===========================================================================
# Token Expiry
# ===========================================================================

class TestCapabilityTokenExpiry:
    """Expired tokens must be rejected."""

    def test_mint_with_past_expiry_produces_expired_token(self):
        """A token minted with a past TTL is immediately expired."""
        principal = PrincipalKeypair.generate()
        token = CapabilityToken.mint(
            target_did="did:key:zagent",
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=past_ttl(2),
        )
        exp_dt = datetime.datetime.fromisoformat(token.expires_at)
        now = datetime.datetime.now(datetime.timezone.utc)
        assert exp_dt < now

    def test_expired_token_rejected_by_session_initiate(self):
        """Session.initiate rejects a token whose TTL is in the past."""
        principal = PrincipalKeypair.generate()
        token = CapabilityToken.mint(
            target_did="did:key:zagent",
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=past_ttl(2),
        )
        token.sign(principal)
        with pytest.raises(PapSessionError):
            Session.initiate(
                token=token,
                receiver_did="did:key:zagent",  # must match target_did
                issuer_public_key_bytes=principal.public_key_bytes(),
            )


# ===========================================================================
# Delegation Constraints (via Mandate)
# ===========================================================================

class TestDelegationConstraints:
    """Mandate delegation enforces scope reduction and TTL decay."""

    def test_delegate_child_ttl_exceeds_parent_raises(self):
        """Child mandate TTL > parent TTL → PapScopeError."""
        principal = PrincipalKeypair.generate()
        scope = Scope([ScopeAction("schema:SearchAction")])
        ds = DisclosureSet.empty()
        parent = Mandate.issue_root(principal.did(), "did:key:zagent1", scope, ds, future_ttl(1))
        parent.sign(principal)

        agent2 = SessionKeypair.generate()
        with pytest.raises(PapScopeError):
            parent.delegate(agent2.did(), scope, ds, future_ttl(2))

    def test_delegate_child_scope_exceeds_parent_raises(self):
        """Child scope with extra actions → PapScopeError."""
        principal = PrincipalKeypair.generate()
        parent_scope = Scope([ScopeAction("schema:SearchAction")])
        ds = DisclosureSet.empty()
        parent = Mandate.issue_root(principal.did(), "did:key:zagent1", parent_scope, ds, future_ttl(1))
        parent.sign(principal)

        agent2 = SessionKeypair.generate()
        child_scope = Scope([
            ScopeAction("schema:SearchAction"),
            ScopeAction("schema:PayAction"),
        ])
        with pytest.raises(PapScopeError):
            parent.delegate(agent2.did(), child_scope, ds, future_ttl(1))

    def test_delegate_within_scope_and_ttl_succeeds(self):
        """Child within parent scope and TTL succeeds."""
        principal = PrincipalKeypair.generate()
        parent_scope = Scope([
            ScopeAction("schema:SearchAction"),
            ScopeAction("schema:PayAction"),
        ])
        ds = DisclosureSet.empty()
        parent = Mandate.issue_root(principal.did(), "did:key:zagent1", parent_scope, ds, future_ttl(2))
        parent.sign(principal)

        agent2 = SessionKeypair.generate()
        child_scope = Scope([ScopeAction("schema:SearchAction")])
        child = parent.delegate(agent2.did(), child_scope, ds, future_ttl(1))
        child.sign_with_session_key(agent2)
        assert child.parent_mandate_hash == parent.hash()

    def test_delegate_equal_ttl_succeeds(self):
        """Child TTL == parent TTL is valid (boundary condition)."""
        principal = PrincipalKeypair.generate()
        scope = Scope([ScopeAction("schema:SearchAction")])
        ds = DisclosureSet.empty()
        ttl = future_ttl(1)
        parent = Mandate.issue_root(principal.did(), "did:key:zagent1", scope, ds, ttl)
        parent.sign(principal)

        agent2 = SessionKeypair.generate()
        child = parent.delegate(agent2.did(), scope, ds, ttl)
        child.sign_with_session_key(agent2)
        assert child.parent_mandate_hash == parent.hash()
