"""
Session state machine, expiry, early termination, ephemeral DID
unlinkability, and Mandate decay state tests.

Covers gaps not addressed in test_session_capability_receipt.py:
  - Invalid state transitions (raise PapSessionError)
  - Expired token rejection
  - Early termination paths (Initiated→Closed, Open→Closed)
  - Ephemeral DID unlinkability assertions
  - Mandate DecayState progression (Active → Degraded → ReadOnly → Suspended)
"""

import datetime

import pytest

from pap import (
    PapSessionError,
    PrincipalKeypair,
    SessionKeypair,
    ScopeAction,
    Scope,
    DisclosureSet,
    Mandate,
    DecayState,
    SessionState,
    CapabilityToken,
    Session,
)


def _make_session_at_closed():
    """Helper: create a session that has gone through full lifecycle to Closed."""
    principal = PrincipalKeypair.generate()
    token = CapabilityToken.mint(
        target_did="did:key:zagent",
        action="schema:SearchAction",
        issuer_did=principal.did(),
        expires_at=future_ttl(1),
    )
    token.sign(principal)
    session = Session.initiate(
        token=token,
        receiver_did="did:key:zagent",  # must match target_did
        issuer_public_key_bytes=principal.public_key_bytes(),
    )
    session.open("did:key:zinit_session", "did:key:zrecv_session")
    session.execute()
    session.close()
    return session


# ===========================================================================
# Invalid State Transitions
# ===========================================================================

class TestSessionInvalidTransitions:
    """Verify that illegal state transitions raise PapSessionError."""

    def test_initiated_to_executed_raises(self, initiated_session):
        """Cannot skip Open: Initiated → Executed is invalid."""
        session, _, _ = initiated_session
        assert session.state == SessionState.Initiated
        with pytest.raises(PapSessionError):
            session.execute()

    def test_open_to_open_raises(self, open_session):
        """Cannot open twice: Open → Open is invalid."""
        session, _ = open_session
        assert session.state == SessionState.Open
        with pytest.raises(PapSessionError):
            session.open("did:key:zother1", "did:key:zother2")

    def test_open_to_initiated_raises(self, open_session):
        """No API to revert to Initiated; verify state is Open and only
        forward transitions (execute/close) are possible."""
        session, _ = open_session
        assert session.state == SessionState.Open

    def test_executed_to_open_raises(self, executed_session):
        """Cannot go backward: Executed → Open is invalid."""
        session, _ = executed_session
        assert session.state == SessionState.Executed
        with pytest.raises(PapSessionError):
            session.open("did:key:zother1", "did:key:zother2")

    def test_executed_to_executed_raises(self, executed_session):
        """Cannot execute twice: Executed → Executed is invalid."""
        session, _ = executed_session
        assert session.state == SessionState.Executed
        with pytest.raises(PapSessionError):
            session.execute()

    def test_closed_to_open_raises(self):
        """Cannot reopen: Closed → Open is invalid."""
        session = _make_session_at_closed()
        assert session.state == SessionState.Closed
        with pytest.raises(PapSessionError):
            session.open("did:key:zother1", "did:key:zother2")

    def test_closed_to_executed_raises(self):
        """Cannot execute after close: Closed → Executed is invalid."""
        session = _make_session_at_closed()
        assert session.state == SessionState.Closed
        with pytest.raises(PapSessionError):
            session.execute()

    def test_closed_to_closed_raises(self):
        """Cannot double-close: Closed → Closed is invalid."""
        session = _make_session_at_closed()
        assert session.state == SessionState.Closed
        with pytest.raises(PapSessionError):
            session.close()


# ===========================================================================
# Session Expiry / TTL
# ===========================================================================

class TestSessionExpiry:
    """Verify expired tokens are rejected and nonce isolation works."""

    def test_expired_token_fails_initiation(self):
        """Session.initiate must reject a token whose TTL is in the past."""
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
                receiver_did="did:key:zagent",
                issuer_public_key_bytes=principal.public_key_bytes(),
            )

    def test_independent_sessions_have_independent_nonces(self):
        """Two sessions created from different tokens have independent nonce sets."""
        principal = PrincipalKeypair.generate()

        token1 = CapabilityToken.mint(
            target_did="did:key:zagent",
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=future_ttl(1),
        )
        token1.sign(principal)
        nonce1 = token1.nonce

        token2 = CapabilityToken.mint(
            target_did="did:key:zagent",
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=future_ttl(1),
        )
        token2.sign(principal)
        nonce2 = token2.nonce

        session1 = Session.initiate(
            token=token1,
            receiver_did="did:key:zagent",
            issuer_public_key_bytes=principal.public_key_bytes(),
        )
        session2 = Session.initiate(
            token=token2,
            receiver_did="did:key:zagent",
            issuer_public_key_bytes=principal.public_key_bytes(),
        )

        # Each session only knows its own nonce
        assert session1.is_nonce_consumed(nonce1)
        assert not session1.is_nonce_consumed(nonce2)
        assert session2.is_nonce_consumed(nonce2)
        assert not session2.is_nonce_consumed(nonce1)


# ===========================================================================
# Early Termination
# ===========================================================================

class TestSessionEarlyTermination:
    """Verify valid early-termination paths."""

    def test_initiated_to_closed_valid(self, initiated_session):
        """Initiated → Closed is a valid early abort."""
        session, _, _ = initiated_session
        assert session.state == SessionState.Initiated
        session.close()
        assert session.state == SessionState.Closed

    def test_open_to_closed_valid(self, open_session):
        """Open → Closed is a valid early abort."""
        session, _ = open_session
        assert session.state == SessionState.Open
        session.close()
        assert session.state == SessionState.Closed


# ===========================================================================
# Ephemeral DID Unlinkability
# ===========================================================================

class TestSessionEphemeralDidUnlinkability:
    """Verify ephemeral session DIDs are distinct from principal DIDs."""

    def test_session_dids_differ_from_principal(self):
        """Session DIDs must not equal the principal's DID."""
        principal = PrincipalKeypair.generate()
        session_key_init = SessionKeypair.generate()
        session_key_recv = SessionKeypair.generate()

        token = CapabilityToken.mint(
            target_did=session_key_recv.did(),
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=future_ttl(1),
        )
        token.sign(principal)

        session = Session.initiate(
            token=token,
            receiver_did=session_key_recv.did(),  # must match target_did
            issuer_public_key_bytes=principal.public_key_bytes(),
        )
        session.open(session_key_init.did(), session_key_recv.did())

        # Ephemeral DIDs must differ from the principal
        assert session.initiator_session_did != principal.did()
        assert session.receiver_session_did != principal.did()

    def test_session_dids_unique_across_sessions(self):
        """Two sessions should have different ephemeral DIDs."""
        principal = PrincipalKeypair.generate()

        sk1_init = SessionKeypair.generate()
        sk1_recv = SessionKeypair.generate()
        sk2_init = SessionKeypair.generate()
        sk2_recv = SessionKeypair.generate()

        token1 = CapabilityToken.mint(
            target_did=sk1_recv.did(),
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=future_ttl(1),
        )
        token1.sign(principal)

        token2 = CapabilityToken.mint(
            target_did=sk2_recv.did(),
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=future_ttl(1),
        )
        token2.sign(principal)

        s1 = Session.initiate(
            token=token1,
            receiver_did=sk1_recv.did(),
            issuer_public_key_bytes=principal.public_key_bytes(),
        )
        s1.open(sk1_init.did(), sk1_recv.did())

        s2 = Session.initiate(
            token=token2,
            receiver_did=sk2_recv.did(),
            issuer_public_key_bytes=principal.public_key_bytes(),
        )
        s2.open(sk2_init.did(), sk2_recv.did())

        # All four ephemeral DIDs must be distinct
        dids = {
            s1.initiator_session_did,
            s1.receiver_session_did,
            s2.initiator_session_did,
            s2.receiver_session_did,
        }
        assert len(dids) == 4


# ===========================================================================
# Mandate Decay States
# ===========================================================================

class TestMandateDecayStates:
    """Exercise the DecayState progression through the Python bindings.

    Maps to the spec's Active → Degraded → ReadOnly → Suspended.
    """

    def test_decay_active_within_ttl(self, root_mandate):
        """Mandate with 1h TTL and 60s window should be Active."""
        mandate, _ = root_mandate
        assert mandate.compute_decay_state(60) == DecayState.Active

    def test_decay_degraded_within_window(self):
        """Mandate whose remaining TTL is within the decay window → Degraded."""
        principal = PrincipalKeypair.generate()
        scope = Scope([ScopeAction("schema:SearchAction")])
        ds = DisclosureSet.empty()
        # TTL 5 seconds from now; decay window 10 seconds → within window
        near_ttl = (
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(seconds=5)
        ).isoformat()
        mandate = Mandate.issue_root(principal.did(), "did:key:zagent", scope, ds, near_ttl)
        mandate.sign(principal)
        assert mandate.compute_decay_state(10) == DecayState.Degraded

    def test_decay_readonly_when_expired(self):
        """Mandate with past TTL should be ReadOnly."""
        principal = PrincipalKeypair.generate()
        scope = Scope([ScopeAction("schema:SearchAction")])
        ds = DisclosureSet.empty()
        mandate = Mandate.issue_root(principal.did(), "did:key:zagent", scope, ds, past_ttl(2))
        mandate.sign(principal)
        assert mandate.compute_decay_state(60) == DecayState.ReadOnly

    def test_decay_suspended_is_terminal(self, root_mandate):
        """Once Suspended, compute_decay_state always returns Suspended."""
        mandate, _ = root_mandate
        mandate.transition_decay(DecayState.Degraded)
        mandate.transition_decay(DecayState.ReadOnly)
        mandate.transition_decay(DecayState.Suspended)
        # Even with TTL still in the future, Suspended is terminal
        assert mandate.compute_decay_state(1) == DecayState.Suspended
        assert mandate.compute_decay_state(999999) == DecayState.Suspended

    def test_transition_active_to_degraded(self, root_mandate):
        """Active → Degraded is a valid transition."""
        mandate, _ = root_mandate
        mandate.transition_decay(DecayState.Degraded)

    def test_transition_degraded_to_active_renewal(self, root_mandate):
        """Degraded → Active is valid (mandate renewal)."""
        mandate, _ = root_mandate
        mandate.transition_decay(DecayState.Degraded)
        mandate.transition_decay(DecayState.Active)

    def test_transition_readonly_to_active_renewal(self, root_mandate):
        """ReadOnly → Active is valid (mandate renewal)."""
        mandate, _ = root_mandate
        mandate.transition_decay(DecayState.Degraded)
        mandate.transition_decay(DecayState.ReadOnly)
        mandate.transition_decay(DecayState.Active)

    def test_transition_active_to_suspended_invalid(self, root_mandate):
        """Active → Suspended is invalid (must degrade first)."""
        mandate, _ = root_mandate
        with pytest.raises(ValueError):
            mandate.transition_decay(DecayState.Suspended)

    def test_transition_suspended_to_active_invalid(self, root_mandate):
        """Suspended → Active is invalid (Suspended is terminal)."""
        mandate, _ = root_mandate
        mandate.transition_decay(DecayState.Degraded)
        mandate.transition_decay(DecayState.ReadOnly)
        mandate.transition_decay(DecayState.Suspended)
        with pytest.raises(ValueError):
            mandate.transition_decay(DecayState.Active)

    def test_transition_suspended_to_degraded_invalid(self, root_mandate):
        """Suspended → Degraded is invalid (Suspended is terminal)."""
        mandate, _ = root_mandate
        mandate.transition_decay(DecayState.Degraded)
        mandate.transition_decay(DecayState.ReadOnly)
        mandate.transition_decay(DecayState.Suspended)
        with pytest.raises(ValueError):
            mandate.transition_decay(DecayState.Degraded)
