"""
Async integration tests for the PAP Python SDK AgentClient.

Tests verify that:
  - All six async methods are awaitable (return coroutines)
  - Connection errors are raised as PapTransportError
  - Async and sync methods produce identical error behaviour
  - Methods work with asyncio.gather for concurrent execution

Run after ``maturin develop``:
    pip install pytest pytest-asyncio
    pytest tests/test_async.py
"""

import asyncio
import datetime
import inspect
import json

import pytest

from pap import (
    AgentClient,
    CapabilityToken,
    PapTransportError,
    PrincipalKeypair,
    TransactionReceipt,
)


def future_ttl(hours: int = 1) -> str:
    dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=hours)
    return dt.isoformat()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    """Client pointing at a port with nothing listening."""
    return AgentClient("http://localhost:19999")


@pytest.fixture
def signed_token():
    principal = PrincipalKeypair.generate()
    token = CapabilityToken.mint(
        target_did="did:key:zagent",
        action="schema:SearchAction",
        issuer_did=principal.did(),
        expires_at=future_ttl(1),
    )
    token.sign(principal)
    return token


@pytest.fixture
def receipt():
    """Create a TransactionReceipt via from_json (avoids Session.initiate DID mismatch)."""
    receipt_data = {
        "session_id": "test-session-001",
        "action": "schema:SearchAction",
        "initiating_agent_did": "did:key:zinitiator_session",
        "receiving_agent_did": "did:key:zreceiver_session",
        "disclosed_by_initiator": ["schema:Person.schema:name"],
        "disclosed_by_receiver": ["schema:WebPage.schema:url"],
        "executed": "schema:SearchAction",
        "returned": "schema:SearchResultsPage",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "signatures": [],
    }
    return TransactionReceipt.from_json(json.dumps(receipt_data))


# ===========================================================================
# Async methods exist and are callable
# ===========================================================================


class TestAsyncMethodsExist:
    def test_present_token_async(self):
        c = AgentClient("http://localhost:8080")
        assert hasattr(c, "present_token_async")
        assert callable(c.present_token_async)

    def test_exchange_did_async(self):
        c = AgentClient("http://localhost:8080")
        assert hasattr(c, "exchange_did_async")
        assert callable(c.exchange_did_async)

    def test_send_disclosures_async(self):
        c = AgentClient("http://localhost:8080")
        assert hasattr(c, "send_disclosures_async")
        assert callable(c.send_disclosures_async)

    def test_request_execution_async(self):
        c = AgentClient("http://localhost:8080")
        assert hasattr(c, "request_execution_async")
        assert callable(c.request_execution_async)

    def test_exchange_receipt_async(self):
        c = AgentClient("http://localhost:8080")
        assert hasattr(c, "exchange_receipt_async")
        assert callable(c.exchange_receipt_async)

    def test_close_session_async(self):
        c = AgentClient("http://localhost:8080")
        assert hasattr(c, "close_session_async")
        assert callable(c.close_session_async)


# ===========================================================================
# Async methods return awaitables
# ===========================================================================


class TestAsyncMethodsAreAwaitable:
    def test_present_token_async_returns_coroutine(self, client, signed_token):
        coro = client.present_token_async(signed_token)
        assert inspect.isawaitable(coro)
        coro.close()

    def test_exchange_did_async_returns_coroutine(self, client):
        coro = client.exchange_did_async("sess-1", "did:key:zfoo")
        assert inspect.isawaitable(coro)
        coro.close()

    def test_send_disclosures_async_returns_coroutine(self, client):
        coro = client.send_disclosures_async("sess-1", [])
        assert inspect.isawaitable(coro)
        coro.close()

    def test_request_execution_async_returns_coroutine(self, client):
        coro = client.request_execution_async("sess-1")
        assert inspect.isawaitable(coro)
        coro.close()

    def test_exchange_receipt_async_returns_coroutine(self, client, receipt):
        coro = client.exchange_receipt_async("sess-1", receipt)
        assert inspect.isawaitable(coro)
        coro.close()

    def test_close_session_async_returns_coroutine(self, client):
        coro = client.close_session_async("sess-1")
        assert inspect.isawaitable(coro)
        coro.close()


# ===========================================================================
# Connection errors produce PapTransportError (async)
# ===========================================================================


class TestAsyncConnectionErrors:
    async def test_present_token_connection_error(self, client, signed_token):
        with pytest.raises(PapTransportError):
            await client.present_token_async(signed_token)

    async def test_exchange_did_connection_error(self, client):
        with pytest.raises(PapTransportError):
            await client.exchange_did_async("sess-1", "did:key:zfoo")

    async def test_send_disclosures_connection_error(self, client):
        with pytest.raises(PapTransportError):
            await client.send_disclosures_async("sess-1", [])

    async def test_request_execution_connection_error(self, client):
        with pytest.raises(PapTransportError):
            await client.request_execution_async("sess-1")

    async def test_exchange_receipt_connection_error(self, client, receipt):
        with pytest.raises(PapTransportError):
            await client.exchange_receipt_async("sess-1", receipt)

    async def test_close_session_connection_error(self, client):
        with pytest.raises(PapTransportError):
            await client.close_session_async("sess-1")


# ===========================================================================
# Concurrent async calls via asyncio.gather
# ===========================================================================


class TestAsyncConcurrency:
    async def test_gather_multiple_connection_errors(self, client):
        """Multiple async calls can run concurrently and all raise errors."""
        coros = [
            client.exchange_did_async("s1", "did:key:z1"),
            client.exchange_did_async("s2", "did:key:z2"),
            client.exchange_did_async("s3", "did:key:z3"),
        ]
        results = await asyncio.gather(*coros, return_exceptions=True)
        assert len(results) == 3
        for r in results:
            assert isinstance(r, PapTransportError)


# ===========================================================================
# Sync methods still work (backward compatibility)
# ===========================================================================


class TestSyncBackwardCompatibility:
    def test_sync_present_token_still_works(self, client, signed_token):
        with pytest.raises(PapTransportError):
            client.present_token(signed_token)

    def test_sync_close_session_still_works(self, client):
        with pytest.raises(PapTransportError):
            client.close_session("sess-1")

    def test_repr_unchanged(self):
        c = AgentClient("http://localhost:8080")
        assert "AgentClient" in repr(c)
        assert "http://localhost:8080" in repr(c)

    def test_base_url_property_unchanged(self):
        c = AgentClient("http://localhost:9999")
        assert c.base_url == "http://localhost:9999"
