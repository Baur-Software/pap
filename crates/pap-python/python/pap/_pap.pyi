"""
Type stubs for pap._pap (compiled Rust extension via PyO3).

These stubs provide IDE auto-complete and static type checking for the
Principal Agent Protocol Python SDK.
"""

from __future__ import annotations
from enum import IntEnum
from typing import Optional, Union

# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

class PapError(Exception):
    """Base exception for all PAP protocol errors.

    All PAP-specific exceptions inherit from this class, so you can catch
    the base to handle any protocol error::

        try:
            mandate.verify(public_key_bytes)
        except PapError as exc:
            print(f"PAP error: {exc}")
    """

class PapSignatureError(PapError):
    """Raised when a signature is missing, invalid, or verification fails.

    Thrown by: ``Mandate.verify()``, ``Mandate.verify_with_keypair()``,
    ``MandateChain.verify_chain()``, ``CapabilityToken.verify_signature()``,
    ``SelectiveDisclosureJwt.verify_signature()``,
    ``SelectiveDisclosureJwt.verify_disclosures()``,
    ``TransactionReceipt.verify_both()``.
    """

class PapScopeError(PapError):
    """Raised when a delegation would exceed the parent scope or TTL.

    Thrown by: ``Mandate.delegate()``.
    """

class PapSessionError(PapError):
    """Raised on invalid session state transitions or nonce replay.

    Thrown by: ``Session.initiate()``, ``Session.open()``,
    ``Session.execute()``, ``Session.close()``.
    """

class PapTransportError(PapError):
    """Raised on HTTP transport failures or unexpected server responses.

    Thrown by all ``AgentClient`` phase methods (``present_token``,
    ``exchange_did``, ``send_disclosures``, ``request_execution``,
    ``exchange_receipt``, ``close_session``).
    """


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

class PrincipalKeypair:
    """Root Ed25519 keypair bound to a human principal.

    In production this wraps a WebAuthn / platform authenticator credential.
    For development, keys are generated in software.
    """

    @staticmethod
    def generate() -> PrincipalKeypair:
        """Generate a fresh Ed25519 principal keypair."""
        ...

    @staticmethod
    def from_secret_bytes(bytes: bytes) -> PrincipalKeypair:
        """Reconstruct a keypair from 32 raw secret key bytes.

        Raises:
            ValueError: if the bytes are not 32 bytes or are invalid.
        """
        ...

    def did(self) -> str:
        """Return the `did:key:z…` identifier derived from this keypair."""
        ...

    def public_key_bytes(self) -> bytes:
        """Return the raw 32-byte public key."""
        ...

    def sign(self, message: bytes) -> bytes:
        """Sign arbitrary bytes. Returns a 64-byte Ed25519 signature."""
        ...

    def verify(self, message: bytes, signature: bytes) -> None:
        """Verify a 64-byte Ed25519 signature.

        Raises:
            ValueError: if the signature is invalid.
        """
        ...


class SessionKeypair:
    """Ephemeral Ed25519 keypair for a single protocol session.

    Generated fresh for each session and discarded at session close.
    Not linked to any persistent identity.
    """

    @staticmethod
    def generate() -> SessionKeypair:
        """Generate a fresh ephemeral session keypair."""
        ...

    def did(self) -> str:
        """Return the ephemeral `did:key:z…` identifier."""
        ...

    def public_key_bytes(self) -> bytes:
        """Return the raw 32-byte public key."""
        ...

    def sign(self, message: bytes) -> bytes:
        """Sign arbitrary bytes. Returns a 64-byte Ed25519 signature."""
        ...

    def verify(self, message: bytes, signature: bytes) -> None:
        """Verify a 64-byte Ed25519 signature.

        Raises:
            ValueError: if the signature is invalid.
        """
        ...


# ---------------------------------------------------------------------------
# DID utilities
# ---------------------------------------------------------------------------

def public_key_to_did(public_key_bytes: bytes) -> str:
    """Convert 32-byte Ed25519 public key bytes to a `did:key:z…` identifier.

    Raises:
        ValueError: if the bytes are not a valid Ed25519 public key.
    """
    ...


def did_to_public_key_bytes(did: str) -> bytes:
    """Extract 32-byte public key bytes from a `did:key:z…` identifier.

    Raises:
        ValueError: if the DID is invalid or not a did:key.
    """
    ...


# ---------------------------------------------------------------------------
# Scope / Disclosure
# ---------------------------------------------------------------------------

class ScopeAction:
    """A single permitted action in a mandate scope.

    Expressed as a Schema.org action reference (e.g. ``"schema:SearchAction"``)
    with an optional object-type constraint.
    """

    def __init__(self, action: str) -> None:
        """Create a scope action with no object constraint."""
        ...

    @staticmethod
    def with_object(action: str, object: str) -> ScopeAction:
        """Create a scope action constrained to a specific object type."""
        ...

    @property
    def action(self) -> str:
        """Schema.org action string, e.g. ``"schema:SearchAction"``."""
        ...

    @property
    def object(self) -> Optional[str]:
        """Optional Schema.org object type constraint."""
        ...


class Scope:
    """Deny-by-default set of permitted actions for a mandate."""

    def __init__(self, actions: list[ScopeAction]) -> None:
        """Create a scope permitting the given actions."""
        ...

    @staticmethod
    def deny_all() -> Scope:
        """Create an empty scope that denies everything."""
        ...

    def permits(self, action: str) -> bool:
        """Return True if this scope permits the given Schema.org action string."""
        ...

    def contains(self, child: Scope) -> bool:
        """Return True if ``child`` is a strict subset of this scope."""
        ...

    @property
    def actions(self) -> list[ScopeAction]:
        """List of permitted scope actions."""
        ...


class DisclosureEntry:
    """A single entry in a DisclosureSet.

    Specifies which properties of a Schema.org type an agent holds and
    under what retention constraints they may be shared.

    Supports builder-style chaining::

        entry = DisclosureEntry("schema:Person", ["schema:name"], [])
        entry = entry.session_only().no_retention()
    """

    def __init__(
        self,
        schema_type: str,
        permitted: list[str],
        prohibited: list[str],
    ) -> None:
        """Create a disclosure entry.

        Args:
            schema_type: Schema.org type, e.g. ``"schema:Person"``
            permitted: property names that may be disclosed
            prohibited: property names that must never be disclosed
        """
        ...

    def session_only(self) -> DisclosureEntry:
        """Mark this entry as session-only (data valid only during session).

        Mutates and returns ``self`` for builder-style chaining.
        """
        ...

    def no_retention(self) -> DisclosureEntry:
        """Mark this entry as no-retention (receiver must not store data).

        Mutates and returns ``self`` for builder-style chaining.
        """
        ...

    @property
    def schema_type(self) -> str:
        """Schema.org type string."""
        ...

    @property
    def permitted_properties(self) -> list[str]:
        """Properties that may be disclosed."""
        ...

    @property
    def prohibited_properties(self) -> list[str]:
        """Properties that must never be disclosed."""
        ...

    @property
    def is_session_only(self) -> bool:
        """True if data is valid only during the session."""
        ...

    @property
    def is_no_retention(self) -> bool:
        """True if the receiver must not retain this data."""
        ...


class DisclosureSet:
    """The set of context classes an agent holds and conditions for sharing."""

    def __init__(self, entries: list[DisclosureEntry]) -> None:
        """Create a disclosure set from entries."""
        ...

    @staticmethod
    def empty() -> DisclosureSet:
        """Create an empty disclosure set (disclose nothing)."""
        ...

    def property_refs(self) -> list[str]:
        """Return property references in ``Type.property`` format (no values).

        Used in transaction receipts — refs only, never actual values.
        """
        ...


# ---------------------------------------------------------------------------
# Mandate / Delegation
# ---------------------------------------------------------------------------

class DecayState(IntEnum):
    """Mandate decay state as TTL approaches expiry without renewal.

    Progression: ``Active → Degraded → ReadOnly → Suspended``
    """

    Active = 0
    """Full scope, within TTL."""

    Degraded = 1
    """Reduced scope, TTL within decay window, renewal pending."""

    ReadOnly = 2
    """No execution, observation only, TTL expired."""

    Suspended = 3
    """No activity, awaiting principal review."""


class Mandate:
    """The core delegation primitive.

    Signed by the issuing agent, verifiable back to the root principal key.
    Encodes permitted scope, disclosure policy, TTL, and decay state.
    """

    @staticmethod
    def issue_root(
        principal_did: str,
        agent_did: str,
        scope: Scope,
        disclosure_set: DisclosureSet,
        ttl: str,
    ) -> Mandate:
        """Issue a root mandate directly from a principal to an agent.

        Args:
            principal_did: DID of the human principal (root of trust)
            agent_did: DID of the agent receiving the mandate
            scope: permitted actions
            disclosure_set: context the agent may share
            ttl: expiry timestamp as ISO 8601 string (e.g. ``"2025-01-01T00:00:00Z"``)

        Returns:
            Unsigned root mandate. Call ``sign()`` before use.
        """
        ...

    def delegate(
        self,
        agent_did: str,
        scope: Scope,
        disclosure_set: DisclosureSet,
        ttl: str,
    ) -> Mandate:
        """Delegate a child mandate from this mandate.

        Enforces: ``child.scope ⊆ self.scope`` and ``child.ttl ≤ self.ttl``.

        Raises:
            PapScopeError: if scope or TTL would exceed parent.
        """
        ...

    def sign(self, keypair: PrincipalKeypair) -> None:
        """Sign this mandate with the issuer's principal keypair."""
        ...

    def sign_with_session_key(self, keypair: SessionKeypair) -> None:
        """Sign this mandate with an ephemeral session keypair."""
        ...

    def verify(self, public_key_bytes: bytes) -> None:
        """Verify this mandate's signature using 32-byte public key bytes.

        Raises:
            PapSignatureError: if the signature is invalid.
        """
        ...

    def verify_with_keypair(self, keypair: PrincipalKeypair) -> None:
        """Verify this mandate's signature using a PrincipalKeypair.

        Raises:
            PapSignatureError: if the signature is invalid.
        """
        ...

    def hash(self) -> str:
        """SHA-256 hash of the canonical mandate form (base64url, no padding)."""
        ...

    def is_expired(self) -> bool:
        """Return True if this mandate's TTL has passed."""
        ...

    def compute_decay_state(self, decay_window_secs: int) -> DecayState:
        """Compute the current decay state given a decay window in seconds."""
        ...

    def transition_decay(self, next: DecayState) -> None:
        """Transition the decay state.

        Raises:
            ValueError: if the transition is invalid.
        """
        ...

    def to_json(self) -> str:
        """Serialize to pretty JSON string."""
        ...

    @staticmethod
    def from_json(json: str) -> Mandate:
        """Deserialize from JSON string.

        Raises:
            ValueError: if the JSON is invalid.
        """
        ...

    @property
    def principal_did(self) -> str:
        """DID of the human principal (root of trust)."""
        ...

    @property
    def agent_did(self) -> str:
        """DID of the agent receiving this mandate."""
        ...

    @property
    def issuer_did(self) -> str:
        """DID of the agent that issued (signed) this mandate."""
        ...

    @property
    def parent_mandate_hash(self) -> Optional[str]:
        """Hash of the parent mandate, or None for root mandates."""
        ...

    @property
    def scope(self) -> Scope:
        """Permitted actions for this mandate."""
        ...

    @property
    def disclosure_set(self) -> DisclosureSet:
        """Shareable context for this mandate."""
        ...

    @property
    def ttl(self) -> str:
        """Expiry timestamp as ISO 8601 string."""
        ...

    @property
    def issued_at(self) -> str:
        """Issuance timestamp as ISO 8601 string."""
        ...

    @property
    def decay_state(self) -> DecayState:
        """Current decay state."""
        ...

    @property
    def signature(self) -> Optional[str]:
        """Base64url-encoded Ed25519 signature, or None if unsigned."""
        ...


class MandateChain:
    """A chain of mandates from root to leaf, each signed by the previous issuer."""

    def __init__(self, root: Mandate) -> None:
        """Create a mandate chain starting with a root mandate."""
        ...

    def push(self, mandate: Mandate) -> None:
        """Append a delegated mandate to the chain."""
        ...

    def leaf(self) -> Mandate:
        """Return the most-recently delegated mandate in the chain."""
        ...

    def root(self) -> Mandate:
        """Return the root mandate in the chain."""
        ...

    def verify_chain(
        self, keypairs: list[Union[PrincipalKeypair, SessionKeypair]]
    ) -> None:
        """Verify the entire chain. Pass one keypair per mandate (root first).

        Each element may be a ``PrincipalKeypair`` (root / long-term key) or a
        ``SessionKeypair`` (ephemeral key used for sub-delegations).

        Verifies: parent hashes, scope containment, TTL ordering, and signatures.

        Raises:
            PapSignatureError: if any link in the chain is invalid.
            ValueError: if a keypair has an unexpected type.
        """
        ...

    def __len__(self) -> int:
        """Number of mandates in the chain."""
        ...


# ---------------------------------------------------------------------------
# Session / Capability Token
# ---------------------------------------------------------------------------

class SessionState(IntEnum):
    """Protocol session state machine."""

    Initiated = 0
    """Token presented, awaiting verification."""

    Open = 1
    """Handshake complete, session DIDs exchanged."""

    Executed = 2
    """Transaction executed within session."""

    Closed = 3
    """Session closed, ephemeral keys discarded."""


class CapabilityToken:
    """Single-use proof of authorization.

    Bound to a specific target DID, action, and nonce. Consumed when the
    session opens to prevent replay attacks.
    """

    @staticmethod
    def mint(
        target_did: str,
        action: str,
        issuer_did: str,
        expires_at: str,
    ) -> CapabilityToken:
        """Mint a new capability token.

        Args:
            target_did: DID of the agent this token is valid for
            action: Schema.org action reference
            issuer_did: DID of the orchestrator issuing the token
            expires_at: expiry timestamp as ISO 8601 string
        """
        ...

    def sign(self, keypair: PrincipalKeypair) -> None:
        """Sign the token with the issuer's principal keypair."""
        ...

    def sign_with_session_key(self, keypair: SessionKeypair) -> None:
        """Sign the token with an ephemeral session keypair."""
        ...

    def verify_signature(self, public_key_bytes: bytes) -> None:
        """Verify the token's signature using 32-byte public key bytes.

        Raises:
            ValueError: if the signature is invalid.
        """
        ...

    def to_json(self) -> str:
        """Serialize to pretty JSON string."""
        ...

    @staticmethod
    def from_json(json: str) -> CapabilityToken:
        """Deserialize from JSON string."""
        ...

    @property
    def id(self) -> str:
        """Unique token identifier (UUID)."""
        ...

    @property
    def target_did(self) -> str:
        """DID of the target agent."""
        ...

    @property
    def action(self) -> str:
        """Schema.org action reference."""
        ...

    @property
    def nonce(self) -> str:
        """Single-use nonce (UUID)."""
        ...

    @property
    def issuer_did(self) -> str:
        """DID of the issuing orchestrator."""
        ...

    @property
    def issued_at(self) -> str:
        """Issuance timestamp as ISO 8601 string."""
        ...

    @property
    def expires_at(self) -> str:
        """Expiry timestamp as ISO 8601 string."""
        ...


class Session:
    """A protocol session between two agents.

    Tracks state transitions (Initiated → Open → Executed → Closed)
    and prevents nonce replay.

    Note:
        ``Session`` is **not thread-safe** — use it from a single Python thread.
    """

    @staticmethod
    def initiate(
        token: CapabilityToken,
        receiver_did: str,
        issuer_public_key_bytes: bytes,
    ) -> Session:
        """Initiate a session from a capability token.

        Verifies the token, consumes the nonce, and sets state to Initiated.

        Args:
            token: signed capability token
            receiver_did: DID of the receiving agent (must match token.target_did)
            issuer_public_key_bytes: 32-byte public key of the token issuer

        Raises:
            PapSessionError: if the token is invalid, expired, or nonce replayed.
        """
        ...

    def open(self, initiator_session_did: str, receiver_session_did: str) -> None:
        """Open the session by recording both parties' ephemeral DIDs.

        Raises:
            PapSessionError: if the session is not in Initiated state.
        """
        ...

    def execute(self) -> None:
        """Mark the session as executed.

        Raises:
            PapSessionError: if the session is not in Open state.
        """
        ...

    def close(self) -> None:
        """Close the session.

        Raises:
            PapSessionError: if the session is already Closed.
        """
        ...

    def is_nonce_consumed(self, nonce: str) -> bool:
        """Return True if the given nonce has been consumed in this session."""
        ...

    @property
    def id(self) -> str:
        """Unique session identifier (UUID)."""
        ...

    @property
    def state(self) -> SessionState:
        """Current session state."""
        ...

    @property
    def action(self) -> str:
        """Schema.org action this session is executing."""
        ...

    @property
    def initiator_session_did(self) -> Optional[str]:
        """Ephemeral DID of the initiating agent (set after open)."""
        ...

    @property
    def receiver_session_did(self) -> Optional[str]:
        """Ephemeral DID of the receiving agent (set after open)."""
        ...


# ---------------------------------------------------------------------------
# Transaction Receipt
# ---------------------------------------------------------------------------

class TransactionReceipt:
    """Co-signed transaction record.

    Contains property references only — never actual values.
    Auditable by both principals. Not stored by any platform.
    """

    @staticmethod
    def from_session(
        session: Session,
        disclosed_by_initiator: list[str],
        disclosed_by_receiver: list[str],
        executed: str,
        returned: str,
    ) -> TransactionReceipt:
        """Build a receipt from a completed (Executed) session.

        Raises:
            ValueError: if the session is missing ephemeral DIDs.
        """
        ...

    @staticmethod
    def from_json(json: str) -> TransactionReceipt:
        """Deserialize from JSON string."""
        ...

    def co_sign(self, keypair: PrincipalKeypair) -> None:
        """Co-sign the receipt with a principal keypair. Call once per party."""
        ...

    def co_sign_with_session_key(self, keypair: SessionKeypair) -> None:
        """Co-sign the receipt with an ephemeral session keypair."""
        ...

    def verify_both(
        self,
        initiator_public_key_bytes: bytes,
        receiver_public_key_bytes: bytes,
    ) -> None:
        """Verify both co-signatures.

        Raises:
            ValueError: if either signature is missing or invalid.
        """
        ...

    def to_json(self) -> str:
        """Serialize to pretty JSON string."""
        ...

    @property
    def session_id(self) -> str:
        """Ephemeral session ID (not linked to principal)."""
        ...

    @property
    def action(self) -> str:
        """Schema.org action that was executed."""
        ...

    @property
    def initiating_agent_did(self) -> str:
        """Ephemeral session DID of the initiating agent."""
        ...

    @property
    def receiving_agent_did(self) -> str:
        """Ephemeral session DID of the receiving agent."""
        ...

    @property
    def disclosed_by_initiator(self) -> list[str]:
        """Property references disclosed by the initiator (refs only)."""
        ...

    @property
    def disclosed_by_receiver(self) -> list[str]:
        """Property references / operator statements from the receiver."""
        ...

    @property
    def executed(self) -> str:
        """Description of what was executed."""
        ...

    @property
    def returned(self) -> str:
        """Description of what was returned."""
        ...

    @property
    def timestamp(self) -> str:
        """Receipt timestamp as ISO 8601 string."""
        ...

    @property
    def signatures(self) -> list[str]:
        """List of base64url-encoded co-signatures."""
        ...


# ---------------------------------------------------------------------------
# Selective Disclosure JWT
# ---------------------------------------------------------------------------

class Disclosure:
    """A single disclosed claim (salt + key + value).

    Produced by ``SelectiveDisclosureJwt.disclose()``.
    """

    @property
    def salt(self) -> str:
        """Random salt for this disclosure."""
        ...

    @property
    def key(self) -> str:
        """Claim key, e.g. ``"schema:name"``."""
        ...

    def value_json(self) -> str:
        """The claim value as a JSON string."""
        ...

    def hash(self) -> str:
        """SHA-256 hash of this disclosure (base64url, no padding)."""
        ...


class SelectiveDisclosureJwt:
    """Selective Disclosure JWT (SD-JWT).

    Sign a set of claims once and later reveal only the subset that the
    mandate permits. Based on draft-ietf-oauth-selective-disclosure-jwt.
    """

    def __init__(self, issuer: str, claims_json: str) -> None:
        """Create a new SD-JWT.

        Args:
            issuer: DID of the issuer
            claims_json: JSON object mapping string keys to JSON-serializable values.
                         Example: ``'{"schema:name": "Alice", "schema:email": "alice@example.com"}'``
        """
        ...

    def sign(self, keypair: PrincipalKeypair) -> None:
        """Sign the SD-JWT with the issuer's keypair."""
        ...

    def verify_signature(self, public_key_bytes: bytes) -> None:
        """Verify the SD-JWT signature.

        Raises:
            ValueError: if the signature is invalid.
        """
        ...

    def disclose(self, keys: list[str]) -> list[Disclosure]:
        """Produce disclosures for only the specified claim keys.

        The holder reveals only what the mandate permits.

        Raises:
            ValueError: if a requested key does not exist in the SD-JWT.
        """
        ...

    def verify_disclosures(
        self, disclosures: list[Disclosure], public_key_bytes: bytes
    ) -> None:
        """Verify that the given disclosures match the signed commitments.

        Raises:
            ValueError: if any disclosure is tampered or the signature is invalid.
        """
        ...

    def claim_keys(self) -> list[str]:
        """List all claim keys in this SD-JWT."""
        ...

    @property
    def issuer(self) -> str:
        """DID of the issuer."""
        ...


# ---------------------------------------------------------------------------
# Marketplace
# ---------------------------------------------------------------------------

class AgentAdvertisement:
    """Signed JSON-LD agent capability advertisement.

    Published by an operator to describe what the agent can do, what context
    it requires, and what it returns.
    """

    def __init__(
        self,
        name: str,
        provider_name: str,
        operator_did: str,
        capability: list[str],
        object_types: list[str],
        requires_disclosure: list[str],
        returns: list[str],
    ) -> None:
        """Create a new advertisement.

        Args:
            name: human-readable agent name
            provider_name: name of the operator organization
            operator_did: DID of the operator who will sign
            capability: Schema.org action types, e.g. ``["schema:SearchAction"]``
            object_types: Schema.org object types operated on
            requires_disclosure: property refs the agent requires from the principal
            returns: Schema.org return types
        """
        ...

    def sign(self, keypair: PrincipalKeypair) -> None:
        """Sign the advertisement with the operator's keypair."""
        ...

    def verify(self, public_key_bytes: bytes) -> None:
        """Verify the advertisement's signature.

        Raises:
            ValueError: if the signature is invalid.
        """
        ...

    def supports_action(self, action: str) -> bool:
        """Return True if this agent supports the given Schema.org action."""
        ...

    def disclosure_satisfiable(self, available: list[str]) -> bool:
        """Return True if the given available properties satisfy disclosure requirements."""
        ...

    def hash(self) -> str:
        """SHA-256 hash of the advertisement (base64url, no padding)."""
        ...

    def to_json(self) -> str:
        """Serialize to pretty JSON-LD string."""
        ...

    @staticmethod
    def from_json(json: str) -> AgentAdvertisement:
        """Deserialize from JSON string."""
        ...

    @property
    def name(self) -> str:
        """Human-readable agent name."""
        ...

    @property
    def capability(self) -> list[str]:
        """Schema.org action types this agent supports."""
        ...

    @property
    def object_types(self) -> list[str]:
        """Schema.org object types operated on."""
        ...

    @property
    def requires_disclosure(self) -> list[str]:
        """Property references the agent requires from the principal."""
        ...

    @property
    def returns(self) -> list[str]:
        """Schema.org return types."""
        ...

    @property
    def signed_by(self) -> str:
        """DID of the operator who signed this advertisement."""
        ...


class MarketplaceRegistry:
    """In-memory agent advertisement registry.

    Supports discovery by action and disclosure satisfiability.
    """

    def __init__(self) -> None:
        """Create an empty registry."""
        ...

    def register(self, ad: AgentAdvertisement) -> None:
        """Register a signed advertisement.

        Raises:
            ValueError: if the advertisement is unsigned.
        """
        ...

    def query_by_action(self, action: str) -> list[AgentAdvertisement]:
        """Return all agents that support the given Schema.org action."""
        ...

    def query_satisfiable(
        self,
        action: str,
        available_properties: list[str],
    ) -> list[AgentAdvertisement]:
        """Return agents that support ``action`` and whose disclosure requirements
        are satisfied by ``available_properties``."""
        ...

    def __len__(self) -> int:
        """Number of registered advertisements."""
        ...


# ---------------------------------------------------------------------------
# HTTP Transport
# ---------------------------------------------------------------------------

class AgentClient:
    """HTTP client for an initiating PAP agent.

    Drives the six-phase handshake by posting protocol messages to a
    receiving agent's HTTP server. All methods are synchronous in Python.

    Example::

        client = AgentClient("http://localhost:8080")
        response = client.present_token(token)  # returns JSON string
        data = json.loads(response)
        session_id = data["session_id"]
    """

    def __init__(self, base_url: str) -> None:
        """Create a client.

        Args:
            base_url: base URL of the receiving agent, e.g. ``"http://localhost:8080"``
        """
        ...

    @property
    def base_url(self) -> str:
        """The base URL this client connects to."""
        ...

    def present_token(self, token: CapabilityToken) -> str:
        """Phase 1 — Present a capability token.

        Returns:
            JSON string. On success: ``{"type": "TokenAccepted",
            "session_id": "...", "receiver_session_did": "..."}``

        Raises:
            PapTransportError: on connection failure or invalid response.
        """
        ...

    def exchange_did(self, session_id: str, initiator_session_did: str) -> str:
        """Phase 2 — Send the initiator's ephemeral session DID.

        Returns:
            JSON string acknowledgement.

        Raises:
            PapTransportError: on connection failure or invalid response.
        """
        ...

    def send_disclosures(
        self, session_id: str, disclosures: list[Disclosure]
    ) -> str:
        """Phase 3 — Send selective disclosures.

        Args:
            session_id: session identifier from phase 1
            disclosures: list of ``Disclosure`` objects, or ``[]`` for zero-disclosure

        Returns:
            JSON string acknowledgement.

        Raises:
            PapTransportError: on connection failure or invalid response.
        """
        ...

    def request_execution(self, session_id: str) -> str:
        """Phase 4 — Request execution.

        Returns:
            JSON string with execution result.

        Raises:
            PapTransportError: on connection failure or invalid response.
        """
        ...

    def exchange_receipt(self, session_id: str, receipt: TransactionReceipt) -> str:
        """Phase 5 — Send receipt for co-signing.

        Returns:
            JSON string with co-signed receipt.

        Raises:
            PapTransportError: on connection failure or invalid response.
        """
        ...

    def close_session(self, session_id: str) -> str:
        """Phase 6 — Close the session.

        Returns:
            JSON string confirmation.

        Raises:
            PapTransportError: on connection failure or invalid response.
        """
        ...
