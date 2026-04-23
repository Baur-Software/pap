# Integrating PAP with LangChain, CrewAI, and MCP

This guide shows how to use the PAP Python SDK (`pip install pap-protocol`) to add
cryptographic mandate enforcement to the three most common AI orchestration
stacks: LangChain, CrewAI, and the Model Context Protocol (MCP).

PAP does not replace these frameworks — it sits in the authorization layer,
ensuring every agent action is bound to a human-signed mandate with a
verifiable scope, TTL, and selective-disclosure policy.

## Prerequisites

```bash
pip install pap-protocol langchain langchain-core langchain-openai crewai mcp
```

PAP requires Python 3.8+. Pre-built wheels are available for Linux x86_64/aarch64, macOS universal2, and Windows x64 — no Rust toolchain required.

If you are building from source (contributors or unreleased branches):

```bash
cd crates/pap-python
pip install maturin
maturin develop --release
```

---

## Core concepts

Before diving into framework-specific code, understand the four primitives you
will use in every integration.

### Keypairs

```python
from pap import PrincipalKeypair, SessionKeypair

# The human principal's long-lived identity keypair.
# Store the secret in a hardware token or encrypted vault.
principal = PrincipalKeypair.generate()
print(principal.did())  # did:key:z6Mk...

# An ephemeral keypair generated per agent or per session.
# Never persisted to disk; destroyed after the session closes.
agent_key = SessionKeypair.generate()
```

### Mandates and delegation

```python
import datetime
from pap import Scope, ScopeAction, DisclosureSet, Mandate, MandateChain

# A scope is a set of allowed schema.org actions.
scope = Scope([ScopeAction("schema:SearchAction")])
ds    = DisclosureSet.empty()  # no data disclosure required

ttl = (
    datetime.datetime.now(datetime.timezone.utc)
    + datetime.timedelta(hours=1)
).isoformat()

# Issue a root mandate — principal authorizes agent_key for one hour.
mandate = Mandate.issue_root(
    principal.did(), agent_key.did(), scope, ds, ttl
)
mandate.sign(principal)  # Ed25519 signature over canonical JSON

# Verify before use (raises PapSignatureError on failure).
mandate.verify_with_keypair(principal)
```

### Scope enforcement

```python
from pap import PapScopeError

# Attempting to delegate a broader scope than the parent raises PapScopeError.
big_scope = Scope([
    ScopeAction("schema:SearchAction"),
    ScopeAction("schema:PayAction"),  # not in parent
])
try:
    mandate.delegate(agent_key.did(), big_scope, ds, ttl)
except PapScopeError as e:
    print(f"Scope violation blocked: {e}")
```

### Decay states

Mandates progress through a decay lifecycle. Check the current state before
issuing capability tokens:

```python
from pap import DecayState

state = mandate.compute_decay_state(decay_window_secs=3600)
# DecayState.Active | Degraded | ReadOnly | Suspended

if state == DecayState.Suspended:
    raise RuntimeError("Mandate is suspended; re-authorize the principal.")
if mandate.is_expired():
    raise RuntimeError("Mandate has expired.")
```

---

## 1. LangChain integration

LangChain tools are Python callables wrapped in a `BaseTool` subclass. The PAP
mandate lives on the tool instance, providing per-tool scope enforcement without
any global mutable state.

### 1.1 Wrapping a PAP-scoped tool

```python
import datetime
from typing import Optional, Type

from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from pap import (
    PrincipalKeypair,
    SessionKeypair,
    Scope,
    ScopeAction,
    DisclosureSet,
    Mandate,
    CapabilityToken,
    PapSignatureError,
    PapScopeError,
    DecayState,
)


def _future_ttl(hours: int = 1) -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(hours=hours)
    ).isoformat()


class PapToolInput(BaseModel):
    query: str = Field(description="The search query to execute")


class PapSearchTool(BaseTool):
    """A LangChain tool whose execution is gated behind a PAP mandate.

    Only schema:SearchAction is permitted. Any attempt to call this tool
    with an expired or out-of-scope mandate raises an exception before the
    underlying search function is invoked.
    """

    name: str = "pap_search"
    description: str = (
        "Search the web. Requires an active PAP mandate for schema:SearchAction."
    )
    args_schema: Type[BaseModel] = PapToolInput

    # PAP fields — stored on the tool, not in global state.
    mandate: object        # pap.Mandate (use Any if Pydantic complains)
    principal: object      # pap.PrincipalKeypair
    agent_key: object      # pap.SessionKeypair

    class Config:
        arbitrary_types_allowed = True

    def _run(self, query: str) -> str:
        # 1. Check TTL and decay state before every call.
        if self.mandate.is_expired():
            raise RuntimeError(
                "PAP mandate has expired. Re-issue before making further calls."
            )
        state = self.mandate.compute_decay_state(decay_window_secs=1800)
        if state == DecayState.Suspended:
            raise RuntimeError("Mandate is in Suspended state.")

        # 2. Verify scope allows this action.
        scope = self.mandate.scope()
        if not scope.permits("schema:SearchAction"):
            raise PapScopeError(
                "Mandate does not permit schema:SearchAction"
            )

        # 3. Mint a single-use capability token for this invocation.
        token = CapabilityToken.mint(
            target_did=self.agent_key.did(),
            action="schema:SearchAction",
            issuer_did=self.principal.did(),
            expires_at=_future_ttl(hours=0),   # expires in < 1 minute
        )
        token.sign(self.principal)

        # 4. Execute the actual search (replace with your real search backend).
        result = f"[PAP-verified search result for: {query!r}]"
        return result

    async def _arun(self, query: str) -> str:
        # Async path: same PAP checks, then delegate to async backend.
        return self._run(query)
```

### 1.2 Building an agent with a PAP-scoped tool

```python
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate

# --- Principal setup (do this once at application startup) ---
principal = PrincipalKeypair.generate()
agent_key = SessionKeypair.generate()

scope = Scope([ScopeAction("schema:SearchAction")])
ds    = DisclosureSet.empty()
ttl   = _future_ttl(hours=1)

mandate = Mandate.issue_root(principal.did(), agent_key.did(), scope, ds, ttl)
mandate.sign(principal)
mandate.verify_with_keypair(principal)  # guard

# --- Tool instantiation ---
search_tool = PapSearchTool(
    mandate=mandate,
    principal=principal,
    agent_key=agent_key,
)

# --- LangChain agent ---
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a research assistant. Use the pap_search tool to answer questions."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])

tools = [search_tool]
agent = create_tool_calling_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

response = executor.invoke({"input": "What is the Principal Agent Protocol?"})
print(response["output"])
```

### 1.3 Restricting to a single schema.org action

The PAP scope model maps naturally to LangChain's tool registry. Issue a
separate mandate per tool and per schema.org action. If you want an agent that
can only search, issue a mandate with `Scope([ScopeAction("schema:SearchAction")])`.
The framework never sees the principal's identity or broader scope.

```python
# Attempting to call a PayAction tool with a SearchAction-only mandate
# will fail at the PAP layer before any LLM call goes through.
pay_scope = Scope([ScopeAction("schema:PayAction")])
try:
    sub_mandate = mandate.delegate(agent_key.did(), pay_scope, ds, ttl)
except PapScopeError:
    print("Blocked: principal only authorized SearchAction.")
```

### 1.4 Error handling in LangChain agents

```python
from pap import PapError, PapSignatureError, PapScopeError

def safe_invoke(executor: AgentExecutor, input_text: str) -> str:
    try:
        result = executor.invoke({"input": input_text})
        return result["output"]
    except PapSignatureError as e:
        # Mandate signature is invalid or has been tampered with.
        return f"Authorization error (signature): {e}"
    except PapScopeError as e:
        # Agent attempted an action outside its granted scope.
        return f"Authorization error (scope): {e}"
    except PapError as e:
        # Catch-all for other PAP protocol errors.
        return f"PAP protocol error: {e}"
```

---

## 2. CrewAI integration

CrewAI models multi-agent pipelines as Crews with Agents and Tasks. PAP fits
naturally at the orchestrator/worker boundary: the principal issues a root
mandate to an orchestrator agent, which re-delegates narrower mandates to
worker agents before dispatching tasks.

### 2.1 PAP-scoped CrewAI tool

```python
from crewai_tools import BaseTool as CrewBaseTool
from pap import (
    PrincipalKeypair,
    SessionKeypair,
    Scope,
    ScopeAction,
    DisclosureEntry,
    DisclosureSet,
    Mandate,
    MandateChain,
    CapabilityToken,
    PapScopeError,
    DecayState,
)


class PapCrewTool(CrewBaseTool):
    """CrewAI tool wrapper that verifies a PAP mandate before execution."""

    name: str = "pap_web_search"
    description: str = (
        "Search the web for information. "
        "Requires a valid PAP mandate for schema:SearchAction."
    )

    # Injected at construction time.
    mandate: object
    issuer_key: object       # PrincipalKeypair or SessionKeypair of the issuing layer
    agent_key: object        # SessionKeypair of this worker

    class Config:
        arbitrary_types_allowed = True

    def _run(self, query: str) -> str:
        if self.mandate.is_expired():
            raise RuntimeError("Worker mandate has expired.")

        state = self.mandate.compute_decay_state(decay_window_secs=900)
        if state in (DecayState.ReadOnly, DecayState.Suspended):
            raise RuntimeError(f"Mandate in {state} state; cannot execute.")

        if not self.mandate.scope().permits("schema:SearchAction"):
            raise PapScopeError("Worker mandate does not permit schema:SearchAction.")

        # Real search logic goes here.
        return f"[Search results for: {query!r}]"
```

### 2.2 Multi-agent pipeline with delegation chain

This example shows the full delegation chain:

```
Human Principal
  └── Orchestrator (root mandate: SearchAction + ReserveAction)
        └── Search Worker (delegated: SearchAction only)
        └── Booking Worker (delegated: ReserveAction(Flight) only)
```

```python
import datetime
from crewai import Agent, Task, Crew, Process


def future_ttl(hours: int) -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(hours=hours)
    ).isoformat()


# ---------------------------------------------------------------------------
# Step 1 — Human principal issues root mandate to orchestrator
# ---------------------------------------------------------------------------

principal        = PrincipalKeypair.generate()
orchestrator_key = SessionKeypair.generate()
search_key       = SessionKeypair.generate()
booking_key      = SessionKeypair.generate()

root_scope = Scope([
    ScopeAction("schema:SearchAction"),
    ScopeAction.with_object("schema:ReserveAction", "schema:Flight"),
])

root_disclosure = DisclosureSet([
    DisclosureEntry(
        "schema:Person",
        ["schema:name", "schema:nationality"],
        ["schema:email", "schema:telephone"],
    ).session_only().no_retention()
])

root_mandate = Mandate.issue_root(
    principal.did(),
    orchestrator_key.did(),
    root_scope,
    root_disclosure,
    future_ttl(hours=4),
)
root_mandate.sign(principal)
root_mandate.verify_with_keypair(principal)

# ---------------------------------------------------------------------------
# Step 2 — Orchestrator re-delegates to worker agents (scope must be subset)
# ---------------------------------------------------------------------------

search_scope = Scope([ScopeAction("schema:SearchAction")])
search_ds    = DisclosureSet.empty()

search_mandate = root_mandate.delegate(
    search_key.did(),
    search_scope,
    search_ds,
    future_ttl(hours=2),          # shorter TTL than root
)
search_mandate.sign_with_session_key(orchestrator_key)

booking_scope = Scope([
    ScopeAction.with_object("schema:ReserveAction", "schema:Flight"),
])
booking_disclosure = DisclosureSet([
    DisclosureEntry(
        "schema:Person",
        ["schema:name", "schema:nationality"],
        ["schema:email"],          # email now prohibited
    ).session_only().no_retention()
])

booking_mandate = root_mandate.delegate(
    booking_key.did(),
    booking_scope,
    booking_disclosure,
    future_ttl(hours=2),
)
booking_mandate.sign_with_session_key(orchestrator_key)

# ---------------------------------------------------------------------------
# Step 3 — Verify delegation chains before starting the crew
# ---------------------------------------------------------------------------

search_chain = MandateChain(root_mandate)
search_chain.push(search_mandate)
search_chain.verify_chain([principal, orchestrator_key])

booking_chain = MandateChain(root_mandate)
booking_chain.push(booking_mandate)
booking_chain.verify_chain([principal, orchestrator_key])

# ---------------------------------------------------------------------------
# Step 4 — Construct PAP-scoped CrewAI tools
# ---------------------------------------------------------------------------

search_tool = PapCrewTool(
    mandate=search_mandate,
    issuer_key=orchestrator_key,
    agent_key=search_key,
)

booking_tool = PapCrewTool(
    name="pap_flight_booking",
    description=(
        "Book a flight. "
        "Requires a valid PAP mandate for schema:ReserveAction(schema:Flight)."
    ),
    mandate=booking_mandate,
    issuer_key=orchestrator_key,
    agent_key=booking_key,
)

# ---------------------------------------------------------------------------
# Step 5 — Define CrewAI agents and tasks
# ---------------------------------------------------------------------------

search_agent = Agent(
    role="Flight Researcher",
    goal="Find the best available flights for the requested route and dates.",
    backstory="You search flight databases and return structured options.",
    tools=[search_tool],
    verbose=True,
)

booking_agent = Agent(
    role="Flight Booker",
    goal="Reserve the flight selected by the researcher.",
    backstory="You complete flight reservations on behalf of the principal.",
    tools=[booking_tool],
    verbose=True,
)

research_task = Task(
    description="Find round-trip flights from London to Tokyo for 2026-06-01 to 2026-06-15.",
    expected_output="A list of at least three flight options with prices.",
    agent=search_agent,
)

booking_task = Task(
    description="Book the cheapest flight identified by the researcher.",
    expected_output="A booking confirmation reference number.",
    agent=booking_agent,
    context=[research_task],   # depends on search output
)

crew = Crew(
    agents=[search_agent, booking_agent],
    tasks=[research_task, booking_task],
    process=Process.sequential,
    verbose=True,
)

result = crew.kickoff()
print(result)
```

### 2.3 Mandate TTL management in long-running crews

CrewAI crews can run for minutes. Check TTL before each task dispatch and
refresh mandates proactively:

```python
def refresh_mandate_if_needed(
    parent_mandate: "Mandate",
    parent_key: "SessionKeypair",
    agent_did: str,
    scope: "Scope",
    ds: "DisclosureSet",
    ttl_hours: int = 2,
) -> "Mandate":
    """Re-issue a child mandate if it is degraded or about to expire."""
    state = parent_mandate.compute_decay_state(decay_window_secs=1800)
    if state in (DecayState.Degraded, DecayState.ReadOnly, DecayState.Suspended):
        new_mandate = parent_mandate.delegate(
            agent_did, scope, ds, future_ttl(hours=ttl_hours)
        )
        new_mandate.sign_with_session_key(parent_key)
        return new_mandate
    return parent_mandate
```

### 2.4 Error handling in CrewAI tasks

```python
from pap import PapError, PapSignatureError, PapScopeError

# Wrap the crew kickoff to surface PAP errors clearly.
try:
    result = crew.kickoff()
except PapSignatureError as e:
    print(f"Signature verification failed — mandate may be tampered: {e}")
except PapScopeError as e:
    print(f"Scope violation — worker tried to exceed granted authority: {e}")
except PapError as e:
    print(f"PAP protocol error: {e}")
```

---

## 3. MCP (Model Context Protocol) integration

The Model Context Protocol defines a standard for tool-calling between LLM
hosts and external servers. PAP slots into MCP as the authorization layer:
before any MCP tool is executed, the server verifies that the caller holds a
valid PAP CapabilityToken scoped to that tool's schema.org action.

### 3.1 PAP as MCP authorization middleware

The pattern is:

1. The MCP client (LLM host) presents a signed PAP CapabilityToken in a
   custom HTTP header (`X-PAP-Capability-Token`).
2. The MCP server verifies the token before dispatching to the tool.
3. If verification fails, the server returns a 403 with a structured error.

```python
import json
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.types import Tool, TextContent, CallToolResult
import mcp.server.stdio

from pap import (
    CapabilityToken,
    PrincipalKeypair,
    PapSignatureError,
    PapScopeError,
)


# ---------------------------------------------------------------------------
# Shared principal registry — in production, load from a trusted store.
# Maps principal DID -> public key bytes.
# ---------------------------------------------------------------------------

TRUSTED_PRINCIPALS: dict[str, bytes] = {}


def register_principal(keypair: PrincipalKeypair) -> None:
    TRUSTED_PRINCIPALS[keypair.did()] = keypair.public_key_bytes()


def verify_capability_token(token_json: str, required_action: str) -> None:
    """Verify a serialized CapabilityToken against the trusted principal registry.

    Raises:
        PapSignatureError: Token signature is invalid or issuer is unknown.
        PapScopeError:     Token action does not match the required action.
        ValueError:        Token is malformed or expired.
    """
    token = CapabilityToken.from_json(token_json)

    # Check that the issuer is a trusted principal.
    issuer_did = token.issuer_did
    if issuer_did not in TRUSTED_PRINCIPALS:
        raise PapSignatureError(f"Unknown issuer DID: {issuer_did}")

    # Verify the Ed25519 signature.
    token.verify_signature(TRUSTED_PRINCIPALS[issuer_did])

    # Verify that the token grants the correct action.
    if token.action != required_action:
        raise PapScopeError(
            f"Token grants {token.action!r}, but {required_action!r} is required."
        )

    # Check expiry (the token's expires_at field is authoritative).
    import datetime
    expires = datetime.datetime.fromisoformat(token.expires_at)
    now = datetime.datetime.now(datetime.timezone.utc)
    if expires <= now:
        raise ValueError(f"CapabilityToken expired at {token.expires_at}")


# ---------------------------------------------------------------------------
# MCP server with PAP-guarded tools
# ---------------------------------------------------------------------------

server = Server("pap-mcp-server")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="web_search",
            description=(
                "Search the web. Caller must present a PAP CapabilityToken "
                "for schema:SearchAction in the X-PAP-Capability-Token header."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "capability_token": {
                        "type": "string",
                        "description": "Serialized PAP CapabilityToken JSON",
                    },
                },
                "required": ["query", "capability_token"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "web_search":
        token_json = arguments.get("capability_token", "")

        try:
            verify_capability_token(token_json, required_action="schema:SearchAction")
        except PapSignatureError as e:
            return [TextContent(
                type="text",
                text=json.dumps({"error": "invalid_token", "detail": str(e)}),
            )]
        except PapScopeError as e:
            return [TextContent(
                type="text",
                text=json.dumps({"error": "scope_violation", "detail": str(e)}),
            )]
        except (ValueError, Exception) as e:
            return [TextContent(
                type="text",
                text=json.dumps({"error": "token_rejected", "detail": str(e)}),
            )]

        # Token verified — proceed with the actual search.
        query = arguments["query"]
        result = f"[Verified MCP search result for: {query!r}]"
        return [TextContent(type="text", text=result)]

    return [TextContent(type="text", text=json.dumps({"error": "unknown_tool"}))]


async def run_server():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="pap-mcp-server",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=None,
                    experimental_capabilities=None,
                ),
            ),
        )
```

### 3.2 MCP client: issuing tokens before tool calls

On the client side, the LLM host mints a CapabilityToken and includes it in
each tool call:

```python
import asyncio
import datetime
import json

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from pap import (
    PrincipalKeypair,
    SessionKeypair,
    Scope,
    ScopeAction,
    DisclosureSet,
    Mandate,
    CapabilityToken,
)


def future_ttl(minutes: int = 5) -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(minutes=minutes)
    ).isoformat()


async def run_pap_mcp_client():
    # Principal setup (done once; reuse across sessions).
    principal = PrincipalKeypair.generate()
    agent_key = SessionKeypair.generate()

    scope    = Scope([ScopeAction("schema:SearchAction")])
    ds       = DisclosureSet.empty()
    mandate  = Mandate.issue_root(principal.did(), agent_key.did(), scope, ds, future_ttl(60))
    mandate.sign(principal)
    mandate.verify_with_keypair(principal)

    # Mint a single-use token immediately before the tool call.
    token = CapabilityToken.mint(
        target_did=agent_key.did(),
        action="schema:SearchAction",
        issuer_did=principal.did(),
        expires_at=future_ttl(minutes=5),
    )
    token.sign(principal)
    token_json = token.to_json()

    server_params = StdioServerParameters(
        command="python",
        args=["pap_mcp_server.py"],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            result = await session.call_tool(
                "web_search",
                arguments={
                    "query": "Principal Agent Protocol specification",
                    "capability_token": token_json,
                },
            )
            print(result.content[0].text)


asyncio.run(run_pap_mcp_client())
```

### 3.3 Integrating PAP with existing MCP middleware

If you have existing MCP middleware, inject PAP verification as a decorator:

```python
from functools import wraps
from typing import Callable, Awaitable
from pap import PapError


def require_pap_token(action: str):
    """Decorator that enforces a PAP CapabilityToken for the given action.

    The decorated MCP tool handler must accept `capability_token` as a keyword
    argument in its `arguments` dict.
    """
    def decorator(handler: Callable[..., Awaitable]) -> Callable[..., Awaitable]:
        @wraps(handler)
        async def wrapper(name: str, arguments: dict) -> list:
            token_json = arguments.get("capability_token")
            if not token_json:
                return [TextContent(
                    type="text",
                    text=json.dumps({"error": "missing_capability_token"}),
                )]
            try:
                verify_capability_token(token_json, required_action=action)
            except PapError as e:
                return [TextContent(
                    type="text",
                    text=json.dumps({"error": "pap_auth_failed", "detail": str(e)}),
                )]
            return await handler(name, arguments)
        return wrapper
    return decorator


@require_pap_token("schema:SearchAction")
async def handle_web_search(name: str, arguments: dict) -> list:
    query = arguments["query"]
    return [TextContent(type="text", text=f"Results for {query!r}")]
```

---

## 4. Common patterns

### 4.1 Issuing and verifying mandates

```python
import datetime
from pap import (
    PrincipalKeypair,
    SessionKeypair,
    Scope,
    ScopeAction,
    DisclosureEntry,
    DisclosureSet,
    Mandate,
    PapSignatureError,
    PapScopeError,
)


def issue_mandate(
    principal: PrincipalKeypair,
    agent_did: str,
    actions: list[str],
    ttl_hours: int = 1,
    require_disclosure: list[tuple[str, list[str], list[str]]] | None = None,
) -> Mandate:
    """Issue a root mandate from a human principal to an agent DID.

    Args:
        principal:          The human's PrincipalKeypair.
        agent_did:          DID of the authorized agent.
        actions:            List of schema.org action strings.
        ttl_hours:          Validity period in hours.
        require_disclosure: Optional list of (schema_type, permitted, prohibited).

    Returns:
        A signed Mandate ready to be handed to the agent.

    Raises:
        PapSignatureError:  If signing fails (should not happen with a valid keypair).
    """
    scope = Scope([ScopeAction(a) for a in actions])

    if require_disclosure:
        entries = [
            DisclosureEntry(stype, permitted, prohibited).session_only().no_retention()
            for stype, permitted, prohibited in require_disclosure
        ]
        ds = DisclosureSet(entries)
    else:
        ds = DisclosureSet.empty()

    ttl = (
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(hours=ttl_hours)
    ).isoformat()

    mandate = Mandate.issue_root(principal.did(), agent_did, scope, ds, ttl)
    mandate.sign(principal)
    return mandate


def verify_mandate(mandate: Mandate, principal: PrincipalKeypair) -> None:
    """Verify a mandate's signature and freshness.

    Raises:
        PapSignatureError:  Signature is invalid.
        RuntimeError:       Mandate is expired or suspended.
    """
    mandate.verify_with_keypair(principal)

    if mandate.is_expired():
        raise RuntimeError("Mandate has expired.")

    state = mandate.compute_decay_state(decay_window_secs=1800)
    if state == "Suspended":
        raise RuntimeError("Mandate is suspended.")
```

### 4.2 Selective disclosure in tool calls

Use `SelectiveDisclosureJwt` when a tool needs to prove specific claims about
the principal without revealing the full credential:

```python
import json
from pap import PrincipalKeypair, SelectiveDisclosureJwt


def disclose_name_only(principal: PrincipalKeypair, name: str, email: str) -> dict:
    """Return an SD-JWT that proves schema:name but withholds schema:email."""
    claims = json.dumps({"schema:name": name, "schema:email": email})
    jwt = SelectiveDisclosureJwt(principal.did(), claims)
    jwt.sign(principal)

    # Selectively disclose only the name claim.
    disclosures = jwt.disclose(["schema:name"])

    # Verify before sending (proves the disclosure is well-formed).
    jwt.verify_disclosures(disclosures, principal.public_key_bytes())

    return {
        "disclosed_key": disclosures[0].key,
        "disclosed_value": json.loads(disclosures[0].value_json()),
        "disclosure_hash": disclosures[0].hash(),
    }


# Usage: attach the disclosed hash to a TransactionReceipt, not the value.
result = disclose_name_only(
    PrincipalKeypair.generate(), "Alice", "alice@example.com"
)
print(result["disclosed_key"])    # schema:name
print(result["disclosed_value"])  # Alice
# The hash goes in the receipt; the value never leaves the session.
```

### 4.3 Transaction receipts

Every executed session should produce a co-signed receipt. The receipt
contains only schema.org property references — never actual values.

```python
from pap import (
    PrincipalKeypair,
    SessionKeypair,
    CapabilityToken,
    Session,
    TransactionReceipt,
)


def run_session_with_receipt(
    principal: PrincipalKeypair,
    agent_key: SessionKeypair,
) -> TransactionReceipt:
    """Demonstrate the full session lifecycle and co-signed receipt."""
    import datetime

    ttl = (
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(minutes=5)
    ).isoformat()

    # 1. Mint and sign a capability token.
    token = CapabilityToken.mint(
        target_did=agent_key.did(),
        action="schema:SearchAction",
        issuer_did=principal.did(),
        expires_at=ttl,
    )
    token.sign(principal)

    # 2. Open a session.
    receiver_key = SessionKeypair.generate()
    session = Session.initiate(
        token=token,
        receiver_did=receiver_key.did(),
        issuer_public_key_bytes=principal.public_key_bytes(),
    )
    session.open(agent_key.did(), receiver_key.did())

    # 3. Execute the action.
    session.execute()

    # 4. Build a co-signed receipt with property references only.
    receipt = TransactionReceipt.from_session(
        session=session,
        disclosed_by_initiator=["schema:Person.schema:name"],  # reference, not value
        disclosed_by_receiver=["schema:WebPage.schema:url"],   # reference, not value
        executed="schema:SearchAction",
        returned="schema:SearchResultsPage",
    )
    receipt.co_sign_with_session_key(agent_key)
    receipt.co_sign_with_session_key(receiver_key)

    # 5. Verify both co-signatures.
    receipt.verify_both(
        agent_key.public_key_bytes(),
        receiver_key.public_key_bytes(),
    )

    # 6. Close the session.
    session.close()

    return receipt
```

### 4.4 Scope enforcement patterns

```python
from pap import Scope, ScopeAction, PapScopeError


ALLOWED_ACTIONS = {
    "search_only":  ["schema:SearchAction"],
    "travel":       ["schema:SearchAction", "schema:ReserveAction"],
    "full_booking": ["schema:SearchAction", "schema:ReserveAction", "schema:PayAction"],
}


def build_scope(profile: str) -> Scope:
    """Return a PAP Scope for the named profile."""
    actions = ALLOWED_ACTIONS.get(profile)
    if actions is None:
        raise ValueError(f"Unknown scope profile: {profile!r}")
    return Scope([ScopeAction(a) for a in actions])


def enforce_action(mandate: "Mandate", action: str) -> None:
    """Raise PapScopeError if the mandate does not permit the given action.

    Call this at the top of every tool's _run method.
    """
    if not mandate.scope().permits(action):
        raise PapScopeError(
            f"Mandate (agent={mandate.agent_did}) does not permit {action!r}. "
            f"Permitted actions: {[a.action() for a in mandate.scope().actions()]}"
        )
```

### 4.5 TTL management helpers

```python
import datetime
from pap import Mandate, DecayState


def mandate_health(mandate: Mandate) -> dict:
    """Return a structured health report for a mandate."""
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = datetime.datetime.fromisoformat(mandate.ttl())
    remaining = (expires - now).total_seconds()
    state = mandate.compute_decay_state(decay_window_secs=1800)

    return {
        "expired":       mandate.is_expired(),
        "seconds_left":  max(0, int(remaining)),
        "decay_state":   state.name if hasattr(state, "name") else str(state),
        "is_usable":     (
            not mandate.is_expired()
            and state not in (DecayState.Suspended,)
        ),
    }


def assert_mandate_usable(mandate: Mandate, action: str) -> None:
    """Raise a descriptive error if the mandate cannot authorize the action."""
    health = mandate_health(mandate)

    if health["expired"]:
        raise RuntimeError(
            f"Mandate for {mandate.agent_did} expired. "
            "Re-issue from the principal before continuing."
        )

    if not health["is_usable"]:
        raise RuntimeError(
            f"Mandate is in {health['decay_state']} state and cannot authorize {action!r}."
        )

    if not mandate.scope().permits(action):
        from pap import PapScopeError
        raise PapScopeError(
            f"Mandate does not permit {action!r}. "
            f"Remaining TTL: {health['seconds_left']}s."
        )
```

---

## 5. Security checklist

Before deploying any PAP-integrated agent:

- **Store principal keypairs in a hardware token or OS keychain.** Never write
  raw secret bytes to disk. The `PrincipalKeypair` object holds the secret in
  memory only; serialize only the DID (`principal.did()`) for storage.

- **Verify every mandate before use.** Call `mandate.verify_with_keypair(principal)`
  at startup and after deserialization. Do not trust a mandate received over an
  untrusted channel without re-verification.

- **Use short TTLs for capability tokens.** A `CapabilityToken` is single-use.
  Issue it immediately before the call and set `expires_at` to no more than
  five minutes in the future.

- **Never widen scope during re-delegation.** The PAP runtime raises
  `PapScopeError` on scope escalation, but defensive code should verify parent
  scope with `parent_scope.contains(child_scope)` before calling `.delegate()`.

- **Transaction receipts must contain property references, not values.** Use
  `schema:Person.schema:name` (the reference), not the actual name string.

- **Do not deserialize JSON-LD via `innerHTML` or `eval`.** All PAP JSON-LD
  content must be rendered as text only (see DESIGN.md). The `Mandate.from_json`
  and `CapabilityToken.from_json` methods are safe; do not bypass them.

- **Rotate session keypairs per session.** `SessionKeypair.generate()` is
  cheap. Never reuse a `SessionKeypair` across sessions; doing so breaks
  ephemerality guarantees.

---

## 6. Complete working example

The snippet below is a self-contained script that exercises all three
integration patterns without any external AI API calls. Run it after
`pip install pap` and `maturin develop`:

```python
"""
pap_integration_demo.py — exercises LangChain, CrewAI, and MCP patterns
without live AI backends.
"""

import datetime
import json

from pap import (
    PrincipalKeypair,
    SessionKeypair,
    Scope,
    ScopeAction,
    DisclosureEntry,
    DisclosureSet,
    Mandate,
    MandateChain,
    CapabilityToken,
    Session,
    TransactionReceipt,
    SelectiveDisclosureJwt,
    PapSignatureError,
    PapScopeError,
    DecayState,
)


def future_ttl(hours: int = 1) -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(hours=hours)
    ).isoformat()


# ---------------------------------------------------------------------------
# 1. Principal setup
# ---------------------------------------------------------------------------

print("=== PAP Integration Demo ===\n")

principal       = PrincipalKeypair.generate()
orchestrator    = SessionKeypair.generate()
search_worker   = SessionKeypair.generate()

print(f"Principal DID:    {principal.did()}")
print(f"Orchestrator DID: {orchestrator.did()}")
print(f"Search worker DID:{search_worker.did()}")
print()

# ---------------------------------------------------------------------------
# 2. Root mandate: principal → orchestrator
# ---------------------------------------------------------------------------

root_scope = Scope([
    ScopeAction("schema:SearchAction"),
    ScopeAction.with_object("schema:ReserveAction", "schema:Flight"),
])

root_mandate = Mandate.issue_root(
    principal.did(), orchestrator.did(), root_scope, DisclosureSet.empty(), future_ttl(4)
)
root_mandate.sign(principal)
root_mandate.verify_with_keypair(principal)
print(f"Root mandate hash: {root_mandate.hash()}")

# ---------------------------------------------------------------------------
# 3. Delegation: orchestrator → search worker (narrowed scope)
# ---------------------------------------------------------------------------

search_scope   = Scope([ScopeAction("schema:SearchAction")])
search_mandate = root_mandate.delegate(
    search_worker.did(), search_scope, DisclosureSet.empty(), future_ttl(2)
)
search_mandate.sign_with_session_key(orchestrator)

chain = MandateChain(root_mandate)
chain.push(search_mandate)
chain.verify_chain([principal, orchestrator])
print(f"Delegation chain depth: {len(chain)} — verified OK")

# ---------------------------------------------------------------------------
# 4. Scope violation is blocked
# ---------------------------------------------------------------------------

try:
    root_mandate.delegate(
        search_worker.did(),
        Scope([ScopeAction("schema:PayAction")]),  # not in root scope
        DisclosureSet.empty(),
        future_ttl(1),
    )
    print("ERROR: scope escalation should have been blocked!")
except PapScopeError as e:
    print(f"Scope escalation correctly blocked: {e}")

# ---------------------------------------------------------------------------
# 5. Session lifecycle and receipt
# ---------------------------------------------------------------------------

token = CapabilityToken.mint(
    target_did=search_worker.did(),
    action="schema:SearchAction",
    issuer_did=principal.did(),
    expires_at=future_ttl(hours=0),
)
token.sign(principal)

receiver = SessionKeypair.generate()
session  = Session.initiate(
    token=token,
    receiver_did=receiver.did(),
    issuer_public_key_bytes=principal.public_key_bytes(),
)
session.open(search_worker.did(), receiver.did())
session.execute()

receipt = TransactionReceipt.from_session(
    session=session,
    disclosed_by_initiator=["schema:Person.schema:name"],
    disclosed_by_receiver=["schema:WebPage.schema:url"],
    executed="schema:SearchAction",
    returned="schema:SearchResultsPage",
)
receipt.co_sign_with_session_key(search_worker)
receipt.co_sign_with_session_key(receiver)
receipt.verify_both(search_worker.public_key_bytes(), receiver.public_key_bytes())
session.close()

print(f"Transaction receipt session_id: {receipt.session_id}")
print(f"Co-signatures: {len(receipt.signatures)}")

# ---------------------------------------------------------------------------
# 6. Selective disclosure
# ---------------------------------------------------------------------------

claims = '{"schema:name": "Alice", "schema:email": "alice@example.com"}'
jwt = SelectiveDisclosureJwt(principal.did(), claims)
jwt.sign(principal)

disclosures = jwt.disclose(["schema:name"])
jwt.verify_disclosures(disclosures, principal.public_key_bytes())
print(f"Disclosed key: {disclosures[0].key} = {json.loads(disclosures[0].value_json())!r}")
print(f"Disclosure hash: {disclosures[0].hash()}")

print("\n=== All checks passed ===")
```

---

## References

- [PAP Specification](../specification.md) — authoritative protocol definition
- [pap Python SDK README](../../crates/pap-python/README.md) — quick start and build instructions
- [LangChain Tools documentation](https://python.langchain.com/docs/modules/agents/tools/)
- [CrewAI documentation](https://docs.crewai.com/)
- [Model Context Protocol specification](https://spec.modelcontextprotocol.io/)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
- [SD-JWT specification (IETF draft)](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
