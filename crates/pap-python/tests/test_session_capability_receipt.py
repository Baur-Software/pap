"""
Comprehensive tests for Session, CapabilityToken, and TransactionReceipt.

Tests cover:
  - Session lifecycle (Initiated → Open → Executed → Closed)
  - CapabilityToken scope constraints and expiry
  - TransactionReceipt co-signature verification
  - Nonce consumption and replay protection
  - Property reference tracking

Run after `maturin develop`:
    pytest crates/pap-python/tests/test_session_capability_receipt.py
"""

import datetime
import json
import pytest

from pap import (
    # Exceptions
    PapSignatureError,
    PapSessionError,
    # Keys
    PrincipalKeypair,
    SessionKeypair,
    # Scope / disclosure
    ScopeAction,
    Scope,
    DisclosureEntry,
    DisclosureSet,
    # Mandate
    Mandate,
    # Session / token / receipt
    SessionState,
    CapabilityToken,
    Session,
    TransactionReceipt,
)


def future_ttl(hours: int = 1) -> str:
    """Generate a future ISO 8601 timestamp."""
    dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=hours)
    return dt.isoformat()


def past_ttl() -> str:
    """Generate a past ISO 8601 timestamp."""
    dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
    return dt.isoformat()


# ===========================================================================
# CapabilityToken Tests
# ===========================================================================

class TestCapabilityToken:
    """Tests for CapabilityToken minting, signing, and lifecycle."""

    def test_mint_creates_valid_token(self):
        """CapabilityToken.mint should create a token with unique nonce."""
        principal = PrincipalKeypair.generate()
        token = CapabilityToken.mint(
            target_did="did:key:zagent",
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=future_ttl(1),
        )
        assert token.id is not None
        assert len(token.id) > 0
        assert token.target_did == "did:key:zagent"
        assert token.action == "schema:SearchAction"
        assert token.issuer_did == principal.did()

    def test_mint_generates_unique_nonce(self):
        """Each minted token should have a unique nonce."""
        principal = PrincipalKeypair.generate()
        token1 = CapabilityToken.mint(
            target_did="did:key:zagent",
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=future_ttl(1),
        )
        token2 = CapabilityToken.mint(
            target_did="did:key:zagent",
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=future_ttl(1),
        )
        assert token1.nonce != token2.nonce
        assert len(token1.nonce) > 0
        assert len(token2.nonce) > 0

    def test_sign_with_principal_keypair(self):
        """CapabilityToken.sign should accept PrincipalKeypair."""
        principal = PrincipalKeypair.generate()
        token = CapabilityToken.mint(
            target_did="did:key:zagent",
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=future_ttl(1),
        )
        # Sign should mutate in place
        token.sign(principal)
        # After signing, signature should exist (verified by verify_signature not raising)
        token.verify_signature(principal.public_key_bytes())

    def test_sign_with_session_keypair(self):
        """CapabilityToken.sign_with_session_key should accept SessionKeypair."""
        session_key = SessionKeypair.generate()
        principal = PrincipalKeypair.generate()
        token = CapabilityToken.mint(
            target_did="did:key:zagent",
            action="schema:SearchAction",
            issuer_did=session_key.did(),
            expires_at=future_ttl(1),
        )
        token.sign_with_session_key(session_key)
        token.verify_signature(session_key.public_key_bytes())

    def test_verify_signature_fails_with_wrong_key(self):
        """verify_signature should fail with a different keypair."""
        principal1 = PrincipalKeypair.generate()
        principal2 = PrincipalKeypair.generate()
        token = CapabilityToken.mint(
            target_did="did:key:zagent",
            action="schema:SearchAction",
            issuer_did=principal1.did(),
            expires_at=future_ttl(1),
        )
        token.sign(principal1)
        with pytest.raises(Exception):
            token.verify_signature(principal2.public_key_bytes())

    def test_verify_signature_before_sign_fails(self):
        """verify_signature should fail if token was never signed."""
        principal = PrincipalKeypair.generate()
        token = CapabilityToken.mint(
            target_did="did:key:zagent",
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=future_ttl(1),
        )
        with pytest.raises(Exception):
            token.verify_signature(principal.public_key_bytes())

    def test_json_serialization_roundtrip(self):
        """CapabilityToken should serialize and deserialize to/from JSON."""
        principal = PrincipalKeypair.generate()
        token1 = CapabilityToken.mint(
            target_did="did:key:zagent",
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=future_ttl(1),
        )
        token1.sign(principal)

        # Serialize
        json_str = token1.to_json()
        assert isinstance(json_str, str)
        data = json.loads(json_str)
        assert data["id"] == token1.id
        assert data["target_did"] == token1.target_did
        assert data["action"] == token1.action

        # Deserialize
        token2 = CapabilityToken.from_json(json_str)
        assert token2.id == token1.id
        assert token2.target_did == token1.target_did
        assert token2.action == token1.action
        assert token2.nonce == token1.nonce

    def test_issued_at_is_set(self):
        """CapabilityToken.issued_at should be set to approximately now."""
        principal = PrincipalKeypair.generate()
        now = datetime.datetime.now(datetime.timezone.utc)
        token = CapabilityToken.mint(
            target_did="did:key:zagent",
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=future_ttl(1),
        )
        issued = datetime.datetime.fromisoformat(token.issued_at)
        # Should be within 5 seconds of now
        assert abs((issued - now).total_seconds()) < 5

    def test_expires_at_matches_input(self):
        """CapabilityToken.expires_at should match the input expiry time."""
        principal = PrincipalKeypair.generate()
        exp_time = future_ttl(2)
        token = CapabilityToken.mint(
            target_did="did:key:zagent",
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=exp_time,
        )
        # Parse both and compare (allowing for minor timestamp formatting differences)
        exp_dt = datetime.datetime.fromisoformat(exp_time)
        token_exp_dt = datetime.datetime.fromisoformat(token.expires_at)
        # Should be very close (within 1 second)
        assert abs((token_exp_dt - exp_dt).total_seconds()) < 1

    def test_repr(self):
        """CapabilityToken.__repr__ should include id, target, and action."""
        principal = PrincipalKeypair.generate()
        token = CapabilityToken.mint(
            target_did="did:key:zagent",
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=future_ttl(1),
        )
        r = repr(token)
        assert "CapabilityToken" in r
        assert token.id in r
        assert "did:key:zagent" in r
        assert "schema:SearchAction" in r


# ===========================================================================
# Session Tests (Lifecycle)
# ===========================================================================

class TestSessionLifecycle:
    """Tests for Session state transitions and lifecycle management."""

    def _make_capability_token(self, principal=None, agent_target=None):
        """Helper to create and sign a capability token."""
        if principal is None:
            principal = PrincipalKeypair.generate()
        if agent_target is None:
            agent_target = "did:key:zagent"
        token = CapabilityToken.mint(
            target_did=agent_target,
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=future_ttl(1),
        )
        token.sign(principal)
        return token, principal

    def test_session_initiate_from_valid_token(self):
        """Session.initiate should create a session from a valid token."""
        token, principal = self._make_capability_token()

        session = Session.initiate(
            token=token,
            receiver_did="did:key:zagent",  # must match token.target_did
            issuer_public_key_bytes=principal.public_key_bytes(),
        )
        assert session.state == SessionState.Initiated
        assert session.action == "schema:SearchAction"
        assert session.id is not None

    def test_session_initiate_consumes_nonce(self):
        """Session.initiate should consume the token's nonce."""
        token, principal = self._make_capability_token()
        nonce = token.nonce

        session = Session.initiate(
            token=token,
            receiver_did="did:key:zagent",  # must match token.target_did
            issuer_public_key_bytes=principal.public_key_bytes(),
        )
        assert session.is_nonce_consumed(nonce)

    def test_session_initiate_rejects_wrong_key(self):
        """Session.initiate should reject a token signed with wrong key."""
        token, _ = self._make_capability_token()
        other_principal = PrincipalKeypair.generate()

        with pytest.raises(PapSessionError):
            Session.initiate(
                token=token,
                receiver_did="did:key:zagent",  # must match token.target_did
                issuer_public_key_bytes=other_principal.public_key_bytes(),
            )

    def test_session_open_sets_session_dids(self):
        """Session.open should record both parties' ephemeral DIDs."""
        token, principal = self._make_capability_token()
        session = Session.initiate(
            token=token,
            receiver_did="did:key:zagent",  # must match token.target_did
            issuer_public_key_bytes=principal.public_key_bytes(),
        )

        # Before open, session DIDs should be None
        assert session.initiator_session_did is None
        assert session.receiver_session_did is None

        # Open the session
        initiator_session_did = "did:key:zinitiator_session"
        receiver_session_did = "did:key:zreceiver_session"
        session.open(initiator_session_did, receiver_session_did)

        # After open, session DIDs should be set
        assert session.initiator_session_did == initiator_session_did
        assert session.receiver_session_did == receiver_session_did
        assert session.state == SessionState.Open

    def test_session_execute_marks_executed(self):
        """Session.execute should mark the session as executed."""
        token, principal = self._make_capability_token()
        session = Session.initiate(
            token=token,
            receiver_did="did:key:zagent",  # must match token.target_did
            issuer_public_key_bytes=principal.public_key_bytes(),
        )
        session.open("did:key:zinitiator_session", "did:key:zreceiver_session")

        assert session.state == SessionState.Open
        session.execute()
        assert session.state == SessionState.Executed

    def test_session_close_marks_closed(self):
        """Session.close should mark the session as closed."""
        token, principal = self._make_capability_token()
        session = Session.initiate(
            token=token,
            receiver_did="did:key:zagent",  # must match token.target_did
            issuer_public_key_bytes=principal.public_key_bytes(),
        )
        session.open("did:key:zinitiator_session", "did:key:zreceiver_session")
        session.execute()

        assert session.state == SessionState.Executed
        session.close()
        assert session.state == SessionState.Closed

    def test_session_full_lifecycle(self):
        """Session should transition correctly through all states."""
        token, principal = self._make_capability_token()
        session = Session.initiate(
            token=token,
            receiver_did="did:key:zagent",  # must match token.target_did
            issuer_public_key_bytes=principal.public_key_bytes(),
        )

        assert session.state == SessionState.Initiated

        session.open("did:key:zinitiator_session", "did:key:zreceiver_session")
        assert session.state == SessionState.Open

        session.execute()
        assert session.state == SessionState.Executed

        session.close()
        assert session.state == SessionState.Closed

    def test_session_nonce_consumption(self):
        """Session should track consumed nonces."""
        token, principal = self._make_capability_token()
        nonce1 = token.nonce
        session = Session.initiate(
            token=token,
            receiver_did="did:key:zagent",  # must match token.target_did
            issuer_public_key_bytes=principal.public_key_bytes(),
        )

        assert session.is_nonce_consumed(nonce1)
        assert not session.is_nonce_consumed("some_other_nonce")

    def test_session_id_is_unique(self):
        """Each session should have a unique ID."""
        token1, principal1 = self._make_capability_token()
        token2, principal2 = self._make_capability_token()

        session1 = Session.initiate(
            token=token1,
            receiver_did="did:key:zagent",  # must match token.target_did
            issuer_public_key_bytes=principal1.public_key_bytes(),
        )
        session2 = Session.initiate(
            token=token2,
            receiver_did="did:key:zagent",  # must match token.target_did
            issuer_public_key_bytes=principal2.public_key_bytes(),
        )

        assert session1.id != session2.id

    def test_session_repr(self):
        """Session.__repr__ should include id and state."""
        token, principal = self._make_capability_token()
        session = Session.initiate(
            token=token,
            receiver_did="did:key:zagent",  # must match token.target_did
            issuer_public_key_bytes=principal.public_key_bytes(),
        )

        r = repr(session)
        assert "Session" in r
        assert session.id in r
        assert "Initiated" in r

    def test_session_action_from_token(self):
        """Session.action should reflect the token's action."""
        token, principal = self._make_capability_token()
        session = Session.initiate(
            token=token,
            receiver_did="did:key:zagent",  # must match token.target_did
            issuer_public_key_bytes=principal.public_key_bytes(),
        )
        assert session.action == token.action


# ===========================================================================
# TransactionReceipt Tests (Co-Signatures)
# ===========================================================================

class TestTransactionReceipt:
    """Tests for TransactionReceipt co-signature verification."""

    def _make_completed_session(self):
        """Helper to create a fully executed session."""
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
            receiver_did="did:key:zagent",  # must match token.target_did
            issuer_public_key_bytes=principal.public_key_bytes(),
        )
        session.open("did:key:zinitiator_session", "did:key:zreceiver_session")
        session.execute()

        return session, principal

    def test_transaction_receipt_from_session(self):
        """TransactionReceipt.from_session should create a receipt from executed session."""
        session, principal = self._make_completed_session()

        receipt = TransactionReceipt.from_session(
            session=session,
            disclosed_by_initiator=["schema:Person.schema:name"],
            disclosed_by_receiver=["schema:WebPage.schema:url"],
            executed="SELECT * FROM users",
            returned="[{...}]",
        )

        assert receipt.session_id == session.id
        assert receipt.action == session.action
        assert receipt.disclosed_by_initiator == ["schema:Person.schema:name"]
        assert receipt.disclosed_by_receiver == ["schema:WebPage.schema:url"]

    def test_transaction_receipt_properties_set(self):
        """TransactionReceipt should preserve all property references."""
        session, principal = self._make_completed_session()
        disclosed_init = ["schema:Person.schema:name", "schema:Person.schema:email"]
        disclosed_recv = ["schema:WebPage.schema:url"]
        executed_ref = "schema:SearchAction"
        returned_ref = "schema:SearchResultsPage"

        receipt = TransactionReceipt.from_session(
            session=session,
            disclosed_by_initiator=disclosed_init,
            disclosed_by_receiver=disclosed_recv,
            executed=executed_ref,
            returned=returned_ref,
        )

        assert receipt.disclosed_by_initiator == disclosed_init
        assert receipt.disclosed_by_receiver == disclosed_recv
        assert receipt.executed == executed_ref
        assert receipt.returned == returned_ref

    def test_co_sign_with_principal_keypair(self):
        """TransactionReceipt.co_sign should accept PrincipalKeypair."""
        session, principal = self._make_completed_session()
        receipt = TransactionReceipt.from_session(
            session=session,
            disclosed_by_initiator=[],
            disclosed_by_receiver=[],
            executed="schema:SearchAction",
            returned="schema:SearchResultsPage",
        )

        # Initially no signatures
        assert len(receipt.signatures) == 0

        # Co-sign with principal
        receipt.co_sign(principal)
        assert len(receipt.signatures) == 1

    def test_co_sign_with_session_keypair(self):
        """TransactionReceipt.co_sign_with_session_key should accept SessionKeypair."""
        session, principal = self._make_completed_session()
        session_key = SessionKeypair.generate()
        receipt = TransactionReceipt.from_session(
            session=session,
            disclosed_by_initiator=[],
            disclosed_by_receiver=[],
            executed="schema:SearchAction",
            returned="schema:SearchResultsPage",
        )

        receipt.co_sign_with_session_key(session_key)
        assert len(receipt.signatures) == 1

    def test_co_sign_twice_accumulates_signatures(self):
        """Co-signing twice should accumulate two signatures."""
        session, principal = self._make_completed_session()
        session_key = SessionKeypair.generate()
        receipt = TransactionReceipt.from_session(
            session=session,
            disclosed_by_initiator=[],
            disclosed_by_receiver=[],
            executed="schema:SearchAction",
            returned="schema:SearchResultsPage",
        )

        receipt.co_sign(principal)
        assert len(receipt.signatures) == 1

        receipt.co_sign_with_session_key(session_key)
        assert len(receipt.signatures) == 2

    def test_verify_both_signatures(self):
        """TransactionReceipt.verify_both should verify both co-signatures."""
        session, principal = self._make_completed_session()
        session_key = SessionKeypair.generate()
        receipt = TransactionReceipt.from_session(
            session=session,
            disclosed_by_initiator=[],
            disclosed_by_receiver=[],
            executed="schema:SearchAction",
            returned="schema:SearchResultsPage",
        )

        receipt.co_sign(principal)
        receipt.co_sign_with_session_key(session_key)

        # Should not raise
        receipt.verify_both(
            principal.public_key_bytes(),
            session_key.public_key_bytes(),
        )

    def test_verify_both_fails_with_wrong_keys(self):
        """verify_both should fail if keys don't match signatures."""
        session, principal = self._make_completed_session()
        session_key = SessionKeypair.generate()
        receipt = TransactionReceipt.from_session(
            session=session,
            disclosed_by_initiator=[],
            disclosed_by_receiver=[],
            executed="schema:SearchAction",
            returned="schema:SearchResultsPage",
        )

        receipt.co_sign(principal)
        receipt.co_sign_with_session_key(session_key)

        # Create different keys
        wrong_principal = PrincipalKeypair.generate()
        wrong_session_key = SessionKeypair.generate()

        with pytest.raises(Exception):
            receipt.verify_both(
                wrong_principal.public_key_bytes(),
                wrong_session_key.public_key_bytes(),
            )

    def test_transaction_receipt_json_serialization(self):
        """TransactionReceipt should serialize and deserialize to/from JSON."""
        session, principal = self._make_completed_session()
        receipt1 = TransactionReceipt.from_session(
            session=session,
            disclosed_by_initiator=["schema:Person.schema:name"],
            disclosed_by_receiver=["schema:WebPage.schema:url"],
            executed="schema:SearchAction",
            returned="schema:SearchResultsPage",
        )
        receipt1.co_sign(principal)

        # Serialize
        json_str = receipt1.to_json()
        assert isinstance(json_str, str)
        data = json.loads(json_str)
        assert data["session_id"] == receipt1.session_id
        assert data["action"] == receipt1.action
        assert len(data["signatures"]) == 1

        # Deserialize
        receipt2 = TransactionReceipt.from_json(json_str)
        assert receipt2.session_id == receipt1.session_id
        assert receipt2.action == receipt1.action
        assert len(receipt2.signatures) == len(receipt1.signatures)

    def test_transaction_receipt_timestamp_set(self):
        """TransactionReceipt.timestamp should be set to approximately now."""
        session, principal = self._make_completed_session()
        now = datetime.datetime.now(datetime.timezone.utc)
        receipt = TransactionReceipt.from_session(
            session=session,
            disclosed_by_initiator=[],
            disclosed_by_receiver=[],
            executed="schema:SearchAction",
            returned="schema:SearchResultsPage",
        )

        timestamp = datetime.datetime.fromisoformat(receipt.timestamp)
        # Should be within 5 seconds of now
        assert abs((timestamp - now).total_seconds()) < 5

    def test_transaction_receipt_repr(self):
        """TransactionReceipt.__repr__ should include session_id, action, and signature count."""
        session, principal = self._make_completed_session()
        receipt = TransactionReceipt.from_session(
            session=session,
            disclosed_by_initiator=[],
            disclosed_by_receiver=[],
            executed="schema:SearchAction",
            returned="schema:SearchResultsPage",
        )
        receipt.co_sign(principal)

        r = repr(receipt)
        assert "TransactionReceipt" in r
        assert session.id in r
        assert "schema:SearchAction" in r
        assert "signatures=1" in r


# ===========================================================================
# Integration Tests (Multi-Component Flows)
# ===========================================================================

class TestSessionCapabilityReceiptIntegration:
    """Integration tests combining Session, CapabilityToken, and TransactionReceipt."""

    def test_full_session_flow_with_receipt(self):
        """Full flow: mint token → initiate session → execute → receipt → verify."""
        principal = PrincipalKeypair.generate()
        session_key1 = SessionKeypair.generate()
        session_key2 = SessionKeypair.generate()

        # 1. Mint and sign capability token
        token = CapabilityToken.mint(
            target_did=session_key1.did(),
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=future_ttl(1),
        )
        token.sign(principal)

        # 2. Initiate session (receiver_did must match token.target_did)
        session = Session.initiate(
            token=token,
            receiver_did=session_key1.did(),
            issuer_public_key_bytes=principal.public_key_bytes(),
        )
        assert session.state == SessionState.Initiated

        # 3. Open session
        session.open(session_key1.did(), session_key2.did())
        assert session.state == SessionState.Open

        # 4. Execute session
        session.execute()
        assert session.state == SessionState.Executed

        # 5. Create and co-sign receipt
        receipt = TransactionReceipt.from_session(
            session=session,
            disclosed_by_initiator=["schema:Person.schema:name"],
            disclosed_by_receiver=["schema:WebPage.schema:url"],
            executed="schema:SearchAction",
            returned="schema:SearchResultsPage",
        )
        receipt.co_sign_with_session_key(session_key1)
        receipt.co_sign_with_session_key(session_key2)

        # 6. Verify receipt signatures
        receipt.verify_both(
            session_key1.public_key_bytes(),
            session_key2.public_key_bytes(),
        )

        # 7. Close session
        session.close()
        assert session.state == SessionState.Closed

    def test_multiple_sessions_independent(self):
        """Multiple concurrent sessions should maintain independent state."""
        principal1 = PrincipalKeypair.generate()
        principal2 = PrincipalKeypair.generate()

        # Create two tokens
        token1 = CapabilityToken.mint(
            target_did="did:key:zagent1",
            action="schema:SearchAction",
            issuer_did=principal1.did(),
            expires_at=future_ttl(1),
        )
        token1.sign(principal1)

        token2 = CapabilityToken.mint(
            target_did="did:key:zagent2",
            action="schema:PayAction",
            issuer_did=principal2.did(),
            expires_at=future_ttl(1),
        )
        token2.sign(principal2)

        # Create two sessions (receiver_did must match token.target_did)
        session1 = Session.initiate(
            token=token1,
            receiver_did="did:key:zagent1",
            issuer_public_key_bytes=principal1.public_key_bytes(),
        )
        session2 = Session.initiate(
            token=token2,
            receiver_did="did:key:zagent2",
            issuer_public_key_bytes=principal2.public_key_bytes(),
        )

        # Sessions should be independent
        assert session1.id != session2.id
        assert session1.action != session2.action
        assert session1.is_nonce_consumed(token1.nonce)
        assert not session1.is_nonce_consumed(token2.nonce)
        assert session2.is_nonce_consumed(token2.nonce)
        assert not session2.is_nonce_consumed(token1.nonce)

    def test_receipt_preserves_property_references_not_values(self):
        """TransactionReceipt must contain property references, never actual values."""
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
            receiver_did="did:key:zagent",  # must match token.target_did
            issuer_public_key_bytes=principal.public_key_bytes(),
        )
        session.open("did:key:zinitiator_session", "did:key:zreceiver_session")
        session.execute()

        # Property references should use schema.org qualified names
        receipt = TransactionReceipt.from_session(
            session=session,
            disclosed_by_initiator=["schema:Person.schema:name"],
            disclosed_by_receiver=["schema:WebPage.schema:url"],
            executed="schema:SearchAction",
            returned="schema:SearchResultsPage",
        )

        # Serialize and verify no actual values are present
        json_str = receipt.to_json()
        data = json.loads(json_str)

        # Properties should be references, not actual values
        assert all("schema:" in prop for prop in data["disclosed_by_initiator"])
        assert all("schema:" in prop for prop in data["disclosed_by_receiver"])
        # Executed/returned are property references
        assert "schema:" in data["executed"]
        assert "schema:" in data["returned"]


# ===========================================================================
# Edge Cases and Error Conditions
# ===========================================================================

class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_capability_token_invalid_datetime_raises(self):
        """CapabilityToken.mint should raise on invalid datetime."""
        principal = PrincipalKeypair.generate()
        with pytest.raises(Exception):
            CapabilityToken.mint(
                target_did="did:key:zagent",
                action="schema:SearchAction",
                issuer_did=principal.did(),
                expires_at="not-a-datetime",
            )

    def test_session_initiate_with_invalid_key_bytes_raises(self):
        """Session.initiate should raise on invalid public key bytes."""
        principal = PrincipalKeypair.generate()
        token = CapabilityToken.mint(
            target_did="did:key:zagent",
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=future_ttl(1),
        )
        token.sign(principal)

        with pytest.raises(Exception):
            Session.initiate(
                token=token,
                receiver_did="did:key:zagent",  # must match token.target_did
                issuer_public_key_bytes=b"not-32-bytes",
            )

    def test_transaction_receipt_verify_both_with_invalid_bytes_raises(self):
        """TransactionReceipt.verify_both should raise on invalid key bytes."""
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
            receiver_did="did:key:zagent",  # must match token.target_did
            issuer_public_key_bytes=principal.public_key_bytes(),
        )
        session.open("did:key:zinitiator_session", "did:key:zreceiver_session")
        session.execute()

        receipt = TransactionReceipt.from_session(
            session=session,
            disclosed_by_initiator=[],
            disclosed_by_receiver=[],
            executed="schema:SearchAction",
            returned="schema:SearchResultsPage",
        )
        receipt.co_sign(principal)

        with pytest.raises(Exception):
            receipt.verify_both(
                b"not-32-bytes",
                principal.public_key_bytes(),
            )

    def test_transaction_receipt_from_json_invalid_json_raises(self):
        """TransactionReceipt.from_json should raise on invalid JSON."""
        with pytest.raises(Exception):
            TransactionReceipt.from_json("not-valid-json")

    def test_capability_token_from_json_invalid_json_raises(self):
        """CapabilityToken.from_json should raise on invalid JSON."""
        with pytest.raises(Exception):
            CapabilityToken.from_json("not-valid-json")
