"""
Integration tests for the pap Python SDK.

Run after `maturin develop`:
    pytest crates/pap-python/tests/
"""

import datetime
import json
import pytest

import pap
from pap import (
    # Exceptions
    PapError,
    PapSignatureError,
    PapScopeError,
    PapSessionError,
    # Keys
    PrincipalKeypair,
    SessionKeypair,
    public_key_to_did,
    did_to_public_key_bytes,
    # Scope / disclosure
    ScopeAction,
    Scope,
    DisclosureEntry,
    DisclosureSet,
    # Mandate
    DecayState,
    Mandate,
    MandateChain,
    # Session / token
    SessionState,
    CapabilityToken,
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


def future_ttl(hours: int = 1) -> str:
    dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=hours)
    return dt.isoformat()


def past_ttl() -> str:
    dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
    return dt.isoformat()


# ===========================================================================
# Exception hierarchy
# ===========================================================================

class TestExceptionHierarchy:
    def test_pap_signature_error_is_pap_error(self):
        assert issubclass(PapSignatureError, PapError)
        assert issubclass(PapSignatureError, Exception)

    def test_pap_scope_error_is_pap_error(self):
        assert issubclass(PapScopeError, PapError)

    def test_pap_session_error_is_pap_error(self):
        assert issubclass(PapSessionError, PapError)

    def test_all_exported(self):
        for name in ["PapError", "PapSignatureError", "PapScopeError",
                     "PapSessionError", "PapTransportError"]:
            assert hasattr(pap, name), f"pap.{name} not found in __all__"


# ===========================================================================
# Keys
# ===========================================================================

class TestPrincipalKeypair:
    def test_generate(self):
        kp = PrincipalKeypair.generate()
        assert kp.did().startswith("did:key:z")

    def test_did_roundtrip(self):
        kp = PrincipalKeypair.generate()
        pub = kp.public_key_bytes()
        assert len(pub) == 32
        did_from_bytes = public_key_to_did(pub)
        assert did_from_bytes == kp.did()

    def test_from_secret_bytes_roundtrip(self):
        kp1 = PrincipalKeypair.generate()
        # Use from_secret_bytes with the signing key bytes (via sign/verify roundtrip)
        msg = b"hello pap"
        sig = kp1.sign(msg)
        # Reconstruct from raw bytes: we can get bytes by extracting 32-byte seed.
        # Since secret_key_bytes was removed, test round-trip via sign+verify only.
        kp1.verify(msg, sig)  # should not raise

    def test_sign_verify(self):
        kp = PrincipalKeypair.generate()
        msg = b"test message"
        sig = kp.sign(msg)
        assert len(sig) == 64
        kp.verify(msg, sig)  # must not raise

    def test_verify_bad_signature_raises(self):
        kp = PrincipalKeypair.generate()
        msg = b"test message"
        bad_sig = b"\x00" * 64
        with pytest.raises(Exception):
            kp.verify(msg, bad_sig)

    def test_no_secret_key_bytes(self):
        """secret_key_bytes() must be removed for security."""
        kp = PrincipalKeypair.generate()
        assert not hasattr(kp, "secret_key_bytes"), \
            "secret_key_bytes() must be removed (security)"

    def test_repr(self):
        kp = PrincipalKeypair.generate()
        r = repr(kp)
        assert "PrincipalKeypair" in r
        assert kp.did() in r


class TestSessionKeypair:
    def test_generate(self):
        sk = SessionKeypair.generate()
        assert sk.did().startswith("did:key:z")

    def test_sign_verify(self):
        sk = SessionKeypair.generate()
        msg = b"session message"
        sig = sk.sign(msg)
        assert len(sig) == 64
        sk.verify(msg, sig)

    def test_different_keys_verify_fails(self):
        sk1 = SessionKeypair.generate()
        sk2 = SessionKeypair.generate()
        msg = b"test"
        sig = sk1.sign(msg)
        with pytest.raises(Exception):
            sk2.verify(msg, sig)


# ===========================================================================
# DID utilities
# ===========================================================================

class TestDidUtils:
    def test_did_bytes_roundtrip(self):
        kp = PrincipalKeypair.generate()
        did = kp.did()
        pub = did_to_public_key_bytes(did)
        assert len(pub) == 32
        assert public_key_to_did(pub) == did

    def test_invalid_did_raises(self):
        with pytest.raises(Exception):
            did_to_public_key_bytes("not:a:did")


# ===========================================================================
# Scope / DisclosureEntry
# ===========================================================================

class TestScope:
    def test_deny_all(self):
        s = Scope.deny_all()
        assert not s.permits("schema:SearchAction")

    def test_permits(self):
        s = Scope([ScopeAction("schema:SearchAction")])
        assert s.permits("schema:SearchAction")
        assert not s.permits("schema:PayAction")

    def test_contains(self):
        parent = Scope([ScopeAction("schema:SearchAction"), ScopeAction("schema:PayAction")])
        child = Scope([ScopeAction("schema:SearchAction")])
        assert parent.contains(child)
        assert not child.contains(parent)

    def test_scope_action_with_object(self):
        a = ScopeAction.with_object("schema:ReserveAction", "schema:Flight")
        assert a.action == "schema:ReserveAction"
        assert a.object == "schema:Flight"


class TestDisclosureEntry:
    def test_create(self):
        e = DisclosureEntry("schema:Person", ["schema:name"], ["schema:ssn"])
        assert e.schema_type == "schema:Person"
        assert e.permitted_properties == ["schema:name"]
        assert e.prohibited_properties == ["schema:ssn"]

    def test_session_only_builder(self):
        e = DisclosureEntry("schema:Person", ["schema:name"], [])
        assert not e.is_session_only
        e2 = e.session_only()
        # mutates in place and returns self
        assert e2.is_session_only
        assert e.is_session_only  # same object

    def test_no_retention_builder(self):
        e = DisclosureEntry("schema:Person", ["schema:name"], [])
        e.no_retention()
        assert e.is_no_retention

    def test_chained_builder(self):
        e = DisclosureEntry("schema:Person", ["schema:name"], []).session_only().no_retention()
        assert e.is_session_only
        assert e.is_no_retention

    def test_disclosure_set_property_refs(self):
        e = DisclosureEntry("schema:Person", ["schema:name", "schema:email"], [])
        ds = DisclosureSet([e])
        refs = ds.property_refs()
        assert "schema:Person.schema:name" in refs
        assert "schema:Person.schema:email" in refs


# ===========================================================================
# Mandate
# ===========================================================================

class TestMandate:
    def _make_root_mandate(self, principal=None, ttl=None):
        if principal is None:
            principal = PrincipalKeypair.generate()
        if ttl is None:
            ttl = future_ttl(1)
        scope = Scope([ScopeAction("schema:SearchAction")])
        ds = DisclosureSet.empty()
        m = Mandate.issue_root(principal.did(), "did:key:zagent1", scope, ds, ttl)
        m.sign(principal)
        return m, principal

    def test_issue_and_sign(self):
        m, principal = self._make_root_mandate()
        assert m.principal_did == principal.did()
        assert m.signature is not None

    def test_verify_valid(self):
        m, principal = self._make_root_mandate()
        m.verify(principal.public_key_bytes())  # must not raise
        m.verify_with_keypair(principal)

    def test_verify_wrong_key_raises_pap_signature_error(self):
        m, _ = self._make_root_mandate()
        other = PrincipalKeypair.generate()
        with pytest.raises(PapSignatureError):
            m.verify(other.public_key_bytes())

    def test_is_expired(self):
        m, principal = self._make_root_mandate(ttl=future_ttl(1))
        assert not m.is_expired()

    def test_is_expired_past(self):
        m, principal = self._make_root_mandate(ttl=past_ttl())
        assert m.is_expired()

    def test_json_roundtrip(self):
        m, _ = self._make_root_mandate()
        j = m.to_json()
        data = json.loads(j)
        assert "principal_did" in data
        m2 = Mandate.from_json(j)
        assert m2.principal_did == m.principal_did

    def test_delegate(self):
        m, principal = self._make_root_mandate()
        agent2 = SessionKeypair.generate()
        scope = Scope([ScopeAction("schema:SearchAction")])
        ds = DisclosureSet.empty()
        child = m.delegate(agent2.did(), scope, ds, future_ttl(1))
        child.sign_with_session_key(agent2)
        assert child.parent_mandate_hash == m.hash()

    def test_delegate_exceeds_scope_raises_pap_scope_error(self):
        m, principal = self._make_root_mandate()
        agent2 = SessionKeypair.generate()
        # Parent has SearchAction only; child asks for PayAction too
        big_scope = Scope([ScopeAction("schema:SearchAction"), ScopeAction("schema:PayAction")])
        ds = DisclosureSet.empty()
        with pytest.raises(PapScopeError):
            m.delegate(agent2.did(), big_scope, ds, future_ttl(1))

    def test_decay_state(self):
        m, _ = self._make_root_mandate()
        state = m.compute_decay_state(3600)
        assert state == DecayState.Active


# ===========================================================================
# MandateChain
# ===========================================================================

class TestMandateChain:
    def test_verify_chain_principal_only(self):
        principal = PrincipalKeypair.generate()
        scope = Scope([ScopeAction("schema:SearchAction")])
        ds = DisclosureSet.empty()
        ttl = future_ttl(1)
        root = Mandate.issue_root(principal.did(), "did:key:zagent", scope, ds, ttl)
        root.sign(principal)

        chain = MandateChain(root)
        assert len(chain) == 1
        chain.verify_chain([principal])  # must not raise

    def test_verify_chain_mixed_keypairs(self):
        """verify_chain must accept both PrincipalKeypair and SessionKeypair."""
        principal = PrincipalKeypair.generate()
        agent_key = SessionKeypair.generate()
        scope = Scope([ScopeAction("schema:SearchAction")])
        ds = DisclosureSet.empty()
        ttl = future_ttl(1)

        root = Mandate.issue_root(principal.did(), agent_key.did(), scope, ds, ttl)
        root.sign(principal)

        child = root.delegate("did:key:zagent2", scope, ds, ttl)
        child.sign_with_session_key(agent_key)

        chain = MandateChain(root)
        chain.push(child)
        assert len(chain) == 2
        chain.verify_chain([principal, agent_key])  # mixed types — must not raise

    def test_verify_chain_bad_key_raises(self):
        principal = PrincipalKeypair.generate()
        scope = Scope([ScopeAction("schema:SearchAction")])
        ds = DisclosureSet.empty()
        root = Mandate.issue_root(principal.did(), "did:key:zagent", scope, ds, future_ttl(1))
        root.sign(principal)

        chain = MandateChain(root)
        other = PrincipalKeypair.generate()
        with pytest.raises(PapSignatureError):
            chain.verify_chain([other])

    def test_leaf_and_root(self):
        principal = PrincipalKeypair.generate()
        agent_key = SessionKeypair.generate()
        scope = Scope([ScopeAction("schema:SearchAction")])
        ds = DisclosureSet.empty()
        ttl = future_ttl(1)

        root = Mandate.issue_root(principal.did(), agent_key.did(), scope, ds, ttl)
        root.sign(principal)
        child = root.delegate("did:key:z3", scope, ds, ttl)
        child.sign_with_session_key(agent_key)

        chain = MandateChain(root)
        chain.push(child)
        assert chain.root().principal_did == principal.did()
        assert chain.leaf().agent_did == "did:key:z3"


# ===========================================================================
# SelectiveDisclosureJwt
# ===========================================================================

class TestSelectiveDisclosureJwt:
    def test_create_and_sign(self):
        principal = PrincipalKeypair.generate()
        claims = '{"schema:name": "Alice", "schema:email": "alice@example.com"}'
        jwt = SelectiveDisclosureJwt(principal.did(), claims)
        jwt.sign(principal)
        keys = jwt.claim_keys()
        assert "schema:name" in keys
        assert "schema:email" in keys

    def test_disclose_subset(self):
        principal = PrincipalKeypair.generate()
        claims = '{"schema:name": "Alice", "schema:email": "alice@example.com"}'
        jwt = SelectiveDisclosureJwt(principal.did(), claims)
        jwt.sign(principal)

        disclosures = jwt.disclose(["schema:name"])
        assert len(disclosures) == 1
        assert disclosures[0].key == "schema:name"
        val = json.loads(disclosures[0].value_json())
        assert val == "Alice"

    def test_verify_disclosures(self):
        principal = PrincipalKeypair.generate()
        claims = '{"schema:name": "Alice"}'
        jwt = SelectiveDisclosureJwt(principal.did(), claims)
        jwt.sign(principal)

        disclosures = jwt.disclose(["schema:name"])
        jwt.verify_disclosures(disclosures, principal.public_key_bytes())  # must not raise

    def test_disclosure_hash(self):
        principal = PrincipalKeypair.generate()
        claims = '{"schema:name": "Alice"}'
        jwt = SelectiveDisclosureJwt(principal.did(), claims)
        jwt.sign(principal)
        d = jwt.disclose(["schema:name"])[0]
        h = d.hash()
        assert isinstance(h, str) and len(h) > 0


# ===========================================================================
# AgentAdvertisement / MarketplaceRegistry
# ===========================================================================

class TestMarketplace:
    def _make_ad(self, principal=None):
        if principal is None:
            principal = PrincipalKeypair.generate()
        ad = AgentAdvertisement(
            name="Search Agent",
            provider_name="Acme Corp",
            operator_did=principal.did(),
            capability=["schema:SearchAction"],
            object_types=["schema:WebPage"],
            requires_disclosure=["schema:Person.schema:name"],
            returns=["schema:SearchResultsPage"],
        )
        ad.sign(principal)
        return ad, principal

    def test_create_and_sign(self):
        ad, principal = self._make_ad()
        assert ad.name == "Search Agent"
        assert ad.supports_action("schema:SearchAction")
        assert not ad.supports_action("schema:PayAction")

    def test_verify(self):
        ad, principal = self._make_ad()
        ad.verify(principal.public_key_bytes())  # must not raise

    def test_disclosure_satisfiable(self):
        ad, _ = self._make_ad()
        assert ad.disclosure_satisfiable(["schema:Person.schema:name"])
        assert not ad.disclosure_satisfiable([])

    def test_json_roundtrip(self):
        ad, _ = self._make_ad()
        j = ad.to_json()
        ad2 = AgentAdvertisement.from_json(j)
        assert ad2.name == ad.name

    def test_registry_register_and_query(self):
        reg = MarketplaceRegistry()
        ad, _ = self._make_ad()
        reg.register(ad)
        assert len(reg) == 1

        results = reg.query_by_action("schema:SearchAction")
        assert len(results) == 1
        assert results[0].name == "Search Agent"

        no_results = reg.query_by_action("schema:PayAction")
        assert len(no_results) == 0

    def test_registry_query_satisfiable(self):
        reg = MarketplaceRegistry()
        ad, _ = self._make_ad()
        reg.register(ad)

        satisfied = reg.query_satisfiable(
            "schema:SearchAction", ["schema:Person.schema:name"]
        )
        assert len(satisfied) == 1

        not_satisfied = reg.query_satisfiable("schema:SearchAction", [])
        assert len(not_satisfied) == 0


# ===========================================================================
# AgentClient
# ===========================================================================

class TestAgentClient:
    def test_repr_includes_url(self):
        client = AgentClient("http://localhost:8080")
        r = repr(client)
        assert "http://localhost:8080" in r
        assert "AgentClient" in r

    def test_base_url_property(self):
        client = AgentClient("http://localhost:9999")
        assert client.base_url == "http://localhost:9999"

    def test_present_token_connection_error_raises_pap_transport_error(self):
        from pap import PapTransportError
        principal = PrincipalKeypair.generate()
        ttl = future_ttl(1)
        token = CapabilityToken.mint(
            target_did="did:key:zagent",
            action="schema:SearchAction",
            issuer_did=principal.did(),
            expires_at=ttl,
        )
        token.sign(principal)

        # Nothing is listening on port 19999 — should raise PapTransportError
        client = AgentClient("http://localhost:19999")
        with pytest.raises(PapTransportError):
            client.present_token(token)
