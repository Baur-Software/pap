"""
TransactionReceipt tamper detection, insufficient signatures,
property reference invariants, and non-executed session handling.

Covers gaps not addressed in test_session_capability_receipt.py:
  - Tampered receipt fields break co-signature verification
  - verify_both requires exactly 2 signatures
  - Property references use schema.org format, never PII
  - Receipt from non-executed session behavior
"""

import json
import re

import pytest

from pap import (
    PrincipalKeypair,
    SessionKeypair,
    CapabilityToken,
    Session,
    SessionState,
    TransactionReceipt,
)

from conftest import future_ttl


def _make_executed_session_with_keys():
    """Create an executed session with session keys. Returns (session, sk1, sk2, principal)."""
    principal = PrincipalKeypair.generate()
    sk1 = SessionKeypair.generate()
    sk2 = SessionKeypair.generate()

    # token.target_did must match receiver_did in Session.initiate
    token = CapabilityToken.mint(
        target_did=sk2.did(),
        action="schema:SearchAction",
        issuer_did=principal.did(),
        expires_at=future_ttl(1),
    )
    token.sign(principal)

    session = Session.initiate(
        token=token,
        receiver_did=sk2.did(),  # must match target_did
        issuer_public_key_bytes=principal.public_key_bytes(),
    )
    session.open(sk1.did(), sk2.did())
    session.execute()
    return session, sk1, sk2, principal


def _make_co_signed_receipt():
    """Create a fully co-signed receipt. Returns (receipt, sk1, sk2)."""
    session, sk1, sk2, _ = _make_executed_session_with_keys()

    receipt = TransactionReceipt.from_session(
        session=session,
        disclosed_by_initiator=["schema:Person.schema:name"],
        disclosed_by_receiver=["schema:WebPage.schema:url"],
        executed="schema:SearchAction",
        returned="schema:SearchResultsPage",
    )
    receipt.co_sign_with_session_key(sk1)
    receipt.co_sign_with_session_key(sk2)
    return receipt, sk1, sk2


# ===========================================================================
# Tamper Detection
# ===========================================================================

class TestTransactionReceiptTampering:
    """Modifying any co-signed field and verifying must fail."""

    def _tamper_and_verify(self, field, value):
        """Helper: tamper a field in the receipt's JSON, then verify_both fails."""
        receipt, sk1, sk2 = _make_co_signed_receipt()
        data = json.loads(receipt.to_json())
        data[field] = value
        tampered = TransactionReceipt.from_json(json.dumps(data))
        with pytest.raises(Exception):
            tampered.verify_both(
                sk1.public_key_bytes(),
                sk2.public_key_bytes(),
            )

    def test_tampered_session_id_fails_verify(self):
        """Changing session_id breaks co-signatures."""
        self._tamper_and_verify("session_id", "tampered-session-id")

    def test_tampered_action_fails_verify(self):
        """Changing action breaks co-signatures."""
        self._tamper_and_verify("action", "schema:PayAction")

    def test_tampered_disclosed_by_initiator_fails_verify(self):
        """Adding a property reference breaks co-signatures."""
        self._tamper_and_verify(
            "disclosed_by_initiator",
            ["schema:Person.schema:name", "schema:Person.schema:ssn"],
        )

    def test_tampered_executed_field_fails_verify(self):
        """Changing executed field breaks co-signatures."""
        self._tamper_and_verify("executed", "schema:PayAction")

    def test_tampered_timestamp_fails_verify(self):
        """Changing timestamp breaks co-signatures."""
        self._tamper_and_verify("timestamp", "2020-01-01T00:00:00+00:00")


# ===========================================================================
# Insufficient Signatures
# ===========================================================================

class TestTransactionReceiptInsufficientSignatures:
    """verify_both requires exactly 2 signatures."""

    def _make_unsigned_receipt(self):
        """Helper: create a receipt with 0 signatures."""
        session, sk1, sk2, _ = _make_executed_session_with_keys()

        receipt = TransactionReceipt.from_session(
            session=session,
            disclosed_by_initiator=[],
            disclosed_by_receiver=[],
            executed="schema:SearchAction",
            returned="schema:SearchResultsPage",
        )
        return receipt, sk1, sk2

    def test_verify_both_with_zero_signatures_raises(self):
        """verify_both with 0 signatures raises."""
        receipt, sk1, sk2 = self._make_unsigned_receipt()
        assert len(receipt.signatures) == 0
        with pytest.raises(Exception):
            receipt.verify_both(
                sk1.public_key_bytes(),
                sk2.public_key_bytes(),
            )

    def test_verify_both_with_one_signature_raises(self):
        """verify_both with only 1 signature raises."""
        receipt, sk1, sk2 = self._make_unsigned_receipt()
        receipt.co_sign_with_session_key(sk1)
        assert len(receipt.signatures) == 1
        with pytest.raises(Exception):
            receipt.verify_both(
                sk1.public_key_bytes(),
                sk2.public_key_bytes(),
            )

    def test_verify_both_with_three_signatures_raises(self):
        """verify_both with 3 signatures raises (exactly 2 required)."""
        receipt, sk1, sk2 = self._make_unsigned_receipt()
        sk3 = SessionKeypair.generate()
        receipt.co_sign_with_session_key(sk1)
        receipt.co_sign_with_session_key(sk2)
        receipt.co_sign_with_session_key(sk3)
        assert len(receipt.signatures) == 3
        with pytest.raises(Exception):
            receipt.verify_both(
                sk1.public_key_bytes(),
                sk2.public_key_bytes(),
            )


# ===========================================================================
# Property Reference Invariant
# ===========================================================================

class TestTransactionReceiptPropertyReferenceInvariant:
    """Receipts must contain property references, never actual values."""

    def test_no_pii_in_serialized_receipt(self):
        """Serialized receipt must not contain PII-like strings."""
        receipt, _, _ = _make_co_signed_receipt()
        json_str = receipt.to_json()

        # PII strings that must NEVER appear in a receipt
        pii_patterns = [
            "alice@example.com", "Alice", "Bob",
            "123-45-6789", "+1-555",
            "password", "secret",
        ]
        for pattern in pii_patterns:
            assert pattern not in json_str, (
                f"Receipt contains PII-like string: {pattern}"
            )

    def test_property_refs_use_schema_org_format(self):
        """All disclosed property refs must match schema:Type.schema:property format."""
        receipt, _, _ = _make_co_signed_receipt()
        json_str = receipt.to_json()
        data = json.loads(json_str)

        ref_pattern = re.compile(r"^schema:\w+\.schema:\w+$")
        for prop in data["disclosed_by_initiator"]:
            assert ref_pattern.match(prop), f"Bad property ref format: {prop}"
        for prop in data["disclosed_by_receiver"]:
            assert ref_pattern.match(prop), f"Bad property ref format: {prop}"

    def test_empty_disclosure_lists_valid(self):
        """Empty disclosure lists should roundtrip correctly."""
        session, sk1, sk2, _ = _make_executed_session_with_keys()

        receipt = TransactionReceipt.from_session(
            session=session,
            disclosed_by_initiator=[],
            disclosed_by_receiver=[],
            executed="schema:SearchAction",
            returned="schema:SearchResultsPage",
        )

        json_str = receipt.to_json()
        restored = TransactionReceipt.from_json(json_str)
        assert restored.disclosed_by_initiator == []
        assert restored.disclosed_by_receiver == []


# ===========================================================================
# Receipt from Non-Executed Session
# ===========================================================================

class TestTransactionReceiptFromNonExecutedSession:
    """Test receipt creation from sessions in various states."""

    def test_receipt_from_initiated_session_raises(self):
        """from_session on Initiated session fails (no session DIDs set)."""
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
            receiver_did="did:key:zagent",
            issuer_public_key_bytes=principal.public_key_bytes(),
        )
        assert session.state == SessionState.Initiated

        with pytest.raises(Exception):
            TransactionReceipt.from_session(
                session=session,
                disclosed_by_initiator=[],
                disclosed_by_receiver=[],
                executed="schema:SearchAction",
                returned="schema:SearchResultsPage",
            )

    def test_receipt_from_open_session_succeeds(self):
        """from_session on Open session succeeds (has session DIDs)."""
        principal = PrincipalKeypair.generate()
        sk1 = SessionKeypair.generate()
        sk2 = SessionKeypair.generate()

        token = CapabilityToken.mint(
            target_did=sk2.did(),
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=future_ttl(1),
        )
        token.sign(principal)

        session = Session.initiate(
            token=token,
            receiver_did=sk2.did(),
            issuer_public_key_bytes=principal.public_key_bytes(),
        )
        session.open(sk1.did(), sk2.did())
        assert session.state == SessionState.Open

        # Rust only checks for DID presence, not Executed state
        receipt = TransactionReceipt.from_session(
            session=session,
            disclosed_by_initiator=["schema:Person.schema:name"],
            disclosed_by_receiver=[],
            executed="schema:SearchAction",
            returned="schema:SearchResultsPage",
        )
        assert receipt.session_id == session.id
