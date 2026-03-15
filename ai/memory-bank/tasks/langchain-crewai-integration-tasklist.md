# LangChain / CrewAI Integration Examples — Development Tasks

## Specification Summary

**Original Requirements** (verbatim):
> Developers using LangChain or CrewAI want to add privacy to their existing stack, not replace it. Show PAP composing with popular frameworks.
>
> Build two examples:
> 1. LangChain: A PAP-aware tool that wraps an existing LangChain tool with mandate enforcement and SD-JWT disclosure
> 2. CrewAI: A PAP-aware agent that uses PAP for inter-agent communication while running inside a CrewAI crew
>
> Each example should include:
> - Before: standard LangChain/CrewAI tool call (showing what leaks)
> - After: PAP-wrapped version (showing what's protected)
> - Receipt output proving the disclosure difference
>
> Estimated effort: ~3 days.
> Depends on: Python SDK via PyO3.

**Technical Stack**:
- Python 3.8+ (SDK constraint from `pap-python` PyO3 bindings: `abi3-py38`)
- `pap` Python SDK — built locally via `maturin develop` in `crates/pap-python/`
- LangChain (`langchain`, `langchain-core`) — no live LLM required (use stubs)
- CrewAI (`crewai`) — no live LLM required (use stubs / `FakeListLLM`)
- No network calls in examples — all data is synthetic/stubbed

**Key SDK types already available** (from `crates/pap-python/python/pap/_pap.pyi`):
- `PrincipalKeypair`, `SessionKeypair` — Ed25519 keys
- `Mandate`, `MandateChain` — hierarchical delegation
- `Scope`, `ScopeAction`, `DisclosureSet`, `DisclosureEntry` — deny-by-default permissions
- `CapabilityToken`, `Session` — single-use session handshake
- `TransactionReceipt` — co-signed, property-refs only (no values)
- `SelectiveDisclosureJwt`, `Disclosure` — SD-JWT selective claim reveal
- `AgentAdvertisement`, `MarketplaceRegistry` — agent discovery

**Prior art in this repo** to model after:
- `examples/travel-booking/` — SD-JWT selective disclosure pattern in Rust
- `examples/search/` — zero-disclosure pattern with 12 protocol steps
- `crates/pap-python/tests/test_basic.py` — Python SDK usage patterns

---

## Target File Structure

```
examples/
  langchain-integration/
    README.md
    requirements.txt
    before.py               ← vanilla LangChain, leaks all fields
    after.py                ← PAP-wrapped, shows protected output + receipt
    pap_langchain/
      __init__.py
      tool.py               ← PapAwareTool(BaseTool) wrapper class
  crewai-integration/
    README.md
    requirements.txt
    before.py               ← vanilla CrewAI crew, data leaks through scratchpad
    after.py                ← PAP-wrapped crew, receipt shows what each agent saw
    pap_crewai/
      __init__.py
      agent.py              ← PapAwareAgent wrapper
      crew.py               ← PapCrew that wires mandates between agents
```

---

## Development Tasks

### [ ] Task 1: Project Scaffolding
**Description**: Create both example directories with `requirements.txt` and package skeletons (`__init__.py` files). No implementation yet — just the file/directory structure with correct Python packaging.

**Acceptance Criteria**:
- `examples/langchain-integration/` and `examples/crewai-integration/` directories exist
- `requirements.txt` in each lists correct dependencies (see below)
- `pap_langchain/__init__.py` and `pap_crewai/__init__.py` exist (can be empty)
- Both directories have a top-level comment in `requirements.txt` explaining how to install the local `pap` wheel via `maturin develop`

**Files to Create**:
- `examples/langchain-integration/requirements.txt`
- `examples/langchain-integration/pap_langchain/__init__.py`
- `examples/crewai-integration/requirements.txt`
- `examples/crewai-integration/pap_crewai/__init__.py`

**LangChain `requirements.txt` contents**:
```
# Install the local pap wheel first:
#   cd ../../crates/pap-python && maturin develop && cd -
langchain-core>=0.1
# No live LLM needed — examples use stub tools only
```

**CrewAI `requirements.txt` contents**:
```
# Install the local pap wheel first:
#   cd ../../crates/pap-python && maturin develop && cd -
crewai>=0.1
# No live LLM needed — examples use FakeListLLM / stub agents
```

**Reference**: Python SDK README in `crates/pap-python/README.md`

---

### [ ] Task 2: LangChain `before.py` — Vanilla Tool Call (What Leaks)
**Description**: Implement a standalone, runnable `before.py` that demonstrates the disclosure problem with a plain LangChain tool. Use a fake `CustomerProfileTool` that receives a full customer dict (name, email, nationality, SSN, phone) and logs exactly what it receives. No LLM call needed — just direct `tool.run()` invocation.

**Acceptance Criteria**:
- Runs with `python before.py` (no network, no API keys)
- Clearly prints a `=== WHAT WAS DISCLOSED ===` section showing all 5 fields leaked
- Uses `langchain_core.tools.BaseTool` as the base class for the example tool
- Output is readable and self-explanatory — a developer skimming it instantly sees the problem

**Sample Output Pattern**:
```
=== BEFORE: Standard LangChain Tool Call ===

Tool: CustomerProfileLookup
Input received by tool:
  schema:name        → "Alice Baur"
  schema:email       → "alice@example.com"
  schema:nationality → "US"
  schema:ssn         → "123-45-6789"       ← leaked
  schema:telephone   → "+1-555-0100"        ← leaked

Result: Flight booked for Alice Baur
```

**Files to Create**:
- `examples/langchain-integration/before.py`

**Reference**: `examples/travel-booking/src/main.rs` (step 1–2 for disclosure context)

---

### [ ] Task 3: `PapAwareTool` Class — Core LangChain Wrapper
**Description**: Implement `pap_langchain/tool.py` containing `PapAwareTool`, a `BaseTool` subclass that wraps any existing LangChain tool with PAP mandate enforcement and SD-JWT selective disclosure. This is the core reusable component.

**Acceptance Criteria**:
- `PapAwareTool` accepts `tool: BaseTool`, `mandate: Mandate`, `principal: PrincipalKeypair`, `sd_jwt: SelectiveDisclosureJwt`, and `permitted_keys: list[str]` in its constructor
- `_run(tool_input: dict) -> str` method:
  1. Checks `mandate.scope.permits(action)` — raises `PapScopeError` if not permitted
  2. Creates an ephemeral `SessionKeypair` for this invocation
  3. Calls `sd_jwt.disclose(permitted_keys)` to get only the allowed disclosures
  4. Builds a filtered `tool_input_sanitized` dict containing only permitted keys
  5. Calls the wrapped `tool.run(tool_input_sanitized)`
  6. Creates a `TransactionReceipt` with `disclosed_by_initiator = sd_jwt.property_refs_for_disclosed` (property refs only, no values)
  7. Returns the result AND stores the receipt as `self.last_receipt`
- `last_receipt: Optional[TransactionReceipt]` property accessible after `_run()`
- Raises `PapScopeError` if mandate doesn't cover the action — doesn't fall through to the underlying tool

**Files to Create**:
- `examples/langchain-integration/pap_langchain/tool.py`

**Key SDK usage**:
```python
from pap import (
    Mandate, PrincipalKeypair, SessionKeypair,
    SelectiveDisclosureJwt, TransactionReceipt, Session,
    CapabilityToken, PapScopeError
)
from langchain_core.tools import BaseTool
```

**Reference**:
- `crates/pap-python/tests/test_basic.py` — `TestSelectiveDisclosureJwt.test_disclose_subset`
- `crates/pap-python/python/pap/_pap.pyi` — `SelectiveDisclosureJwt.disclose()`, `TransactionReceipt.from_session()`

---

### [ ] Task 4: LangChain `after.py` — PAP-Wrapped Version with Receipt
**Description**: Implement `after.py` that runs the same scenario as `before.py` but wrapped with `PapAwareTool`. Must show a side-by-side Before/After comparison in output, then print the full `TransactionReceipt` JSON proving what was disclosed.

**Acceptance Criteria**:
- Runs with `python after.py` after `maturin develop` has been run
- Sets up the same customer profile scenario as `before.py`
- Instantiates `PapAwareTool` with a mandate scoped to `schema:ReserveAction` and disclosure set permitting only `schema:name` + `schema:nationality`
- Calls `tool.run(full_customer_dict)` — the wrapper filters it
- Prints a `=== WHAT WAS DISCLOSED ===` section showing only 2 fields
- Prints `=== WHAT WAS WITHHELD ===` showing the 3 suppressed fields
- Prints `=== TRANSACTION RECEIPT ===` containing the PAP receipt JSON (property refs only — no "Alice Baur", no email, no SSN)
- Receipt `disclosed_by_initiator` contains only `["schema:Person.schema:name", "schema:Person.schema:nationality"]`

**Sample Output Pattern**:
```
=== AFTER: PAP-Wrapped LangChain Tool Call ===

Mandate scope:  [schema:ReserveAction]
Permitted disclosure: [schema:name, schema:nationality]
Prohibited:     [schema:email, schema:ssn, schema:telephone]

Tool executed with sanitized input:
  schema:name        → disclosed (permitted)
  schema:nationality → disclosed (permitted)
  schema:email       → WITHHELD  (not in disclosure set)
  schema:ssn         → WITHHELD  (not in disclosure set)
  schema:telephone   → WITHHELD  (not in disclosure set)

Result: Flight booked for [disclosed: schema:name]

=== TRANSACTION RECEIPT ===
{
  "session_id": "...",
  "action": "schema:ReserveAction",
  "disclosed_by_initiator": [
    "schema:Person.schema:name",
    "schema:Person.schema:nationality"
  ],
  ...
}
```

**Files to Create**:
- `examples/langchain-integration/after.py`

---

### [ ] Task 5: LangChain `README.md`
**Description**: Write a clear, developer-facing README for the LangChain example. Follow the same "Before / After / Why it matters" structure used in the existing Rust examples. Include copy-pasteable setup commands.

**Acceptance Criteria**:
- Has a "Quick Start" section with exact commands (maturin develop + python after.py)
- Has a "Before" section quoting the key output lines showing leakage
- Has an "After" section quoting the key output lines showing protection
- Explains what `PapAwareTool` does in 3-4 sentences (not a protocol specification)
- Has a "How it works" section referencing the 3 PAP primitives used: `Mandate`, `SelectiveDisclosureJwt`, `TransactionReceipt`
- Does not require an LLM API key — calls this out explicitly

**Files to Create**:
- `examples/langchain-integration/README.md`

---

### [ ] Task 6: CrewAI `before.py` — Vanilla Crew (What Leaks Through Scratchpad)
**Description**: Implement `before.py` for the CrewAI example. Show two agents (ResearchAgent + BookingAgent) in a crew where the ResearchAgent collects a full customer profile and passes it to the BookingAgent via the shared task output. Use `FakeListLLM` or a simple string stub so no API key is needed.

**Acceptance Criteria**:
- Runs with `python before.py` (no API keys, no network)
- Uses `crewai.Agent`, `crewai.Task`, `crewai.Crew` directly (no PAP)
- ResearchAgent "researches" the customer and returns a full context dict (name, email, nationality, SSN, phone)
- BookingAgent receives the full dict and logs what it sees
- A `=== SHARED SCRATCHPAD CONTENTS ===` print block shows the raw data that flowed between agents
- Uses a stub / mock LLM (e.g., the agent's `step_callback` or a `FakeListLLM`) — do NOT require an OpenAI key

**Implementation Note**: CrewAI's default `verbose=True` and agent scratchpad dump can be redirected. The key is that the print output must clearly show a student the data leakage. If CrewAI requires an LLM instance, use `langchain_community.llms.FakeListLLM` or monkey-patch the agent's `_execute_task` to return a canned response.

**Files to Create**:
- `examples/crewai-integration/before.py`

---

### [ ] Task 7: `PapAwareAgent` Class — CrewAI Agent Wrapper
**Description**: Implement `pap_crewai/agent.py` containing `PapAwareAgent`. This class composes with a `crewai.Agent` and intercepts task execution to enforce PAP mandate scope and produce selective disclosures when passing context to the next agent.

**Acceptance Criteria**:
- `PapAwareAgent(agent: crewai.Agent, mandate: Mandate, session_key: SessionKeypair)` constructor
- `execute_task(task, context: dict) -> tuple[str, TransactionReceipt]` method that:
  1. Verifies `mandate` is not expired and scope permits the task's action
  2. Builds an SD-JWT from the full `context` dict
  3. Discloses only the fields permitted by `mandate.disclosure_set`
  4. Passes the sanitized context (disclosed fields only) to the underlying `agent` for execution
  5. Generates and returns a `TransactionReceipt` containing only property references
- `mandate` and `last_receipt` are accessible as properties
- Does not break CrewAI's agent interface — a `PapAwareAgent` can be used anywhere a `crewai.Agent` is used for task execution

**Files to Create**:
- `examples/crewai-integration/pap_crewai/agent.py`

---

### [ ] Task 8: `PapCrew` Class — Crew-Level Mandate Wiring
**Description**: Implement `pap_crewai/crew.py` containing `PapCrew`. This class mirrors `crewai.Crew` but issues a root mandate to the orchestrator agent and delegates child mandates to each specialist agent with narrowed scope.

**Acceptance Criteria**:
- `PapCrew(principal: PrincipalKeypair, agents: list[PapAwareAgent], tasks: list[crewai.Task])` constructor
- `kickoff(inputs: dict) -> PapCrewResult` method that:
  1. Issues a root mandate to the first (orchestrator) agent
  2. For each subsequent agent, delegates a child mandate with scope narrowed to that agent's permitted actions
  3. Passes context between agents via `PapAwareAgent.execute_task()` (never the raw full dict)
  4. Collects all `TransactionReceipt` objects from each agent handoff
  5. Returns a `PapCrewResult` (simple dataclass) containing `final_output: str` and `receipts: list[TransactionReceipt]`
- Mandate delegation chain is verifiable: `MandateChain([root, child]).verify_chain([principal, orchestrator_key])`

**Files to Create**:
- `examples/crewai-integration/pap_crewai/crew.py`

**Reference**:
- `examples/delegation-chain/src/main.rs` — pattern for 3-level mandate hierarchy
- `crates/pap-python/tests/test_basic.py` — `TestMandateChain.test_verify_chain_mixed_keypairs`

---

### [ ] Task 9: CrewAI `after.py` — PAP-Wrapped Crew with Receipt Per Handoff
**Description**: Implement `after.py` for the CrewAI example. Run the same ResearchAgent + BookingAgent scenario using `PapCrew`, showing what each agent actually received vs. what was in the original context. Print all receipts.

**Acceptance Criteria**:
- Runs with `python after.py` after `maturin develop`
- Sets up the same crew scenario as `before.py`
- Uses `PapCrew` with two `PapAwareAgent` instances
- ResearchAgent has scope `[schema:SearchAction]` and no disclosure permitted (it's collecting)
- BookingAgent has scope `[schema:ReserveAction]` and disclosure set permitting only `schema:name + schema:nationality`
- Output shows two handoffs with receipts:
  - Handoff 1 (Principal → Orchestrator/ResearchAgent): root mandate, scope shown
  - Handoff 2 (ResearchAgent → BookingAgent): delegated mandate, SD-JWT disclosures shown
- `=== RECEIPT: RESEARCH → BOOKING HANDOFF ===` section with receipt JSON
- Receipt `disclosed_by_initiator` shows `["schema:Person.schema:name", "schema:Person.schema:nationality"]` — NOT the SSN, NOT the email

**Sample Output Pattern**:
```
=== AFTER: PAP-Wrapped CrewAI Crew ===

[ResearchAgent] Scope: schema:SearchAction | Collecting customer data...
[ResearchAgent] Task complete. Full context held locally.

[Mandate Delegation]
  Root mandate:  Principal → ResearchAgent  (scope: SearchAction)
  Child mandate: ResearchAgent → BookingAgent (scope: ReserveAction)
  Permitted disclosure to BookingAgent: [schema:name, schema:nationality]

[BookingAgent] Received sanitized context:
  schema:name        → "Alice Baur"    (disclosed)
  schema:nationality → "US"            (disclosed)
  schema:email       → [WITHHELD]
  schema:ssn         → [WITHHELD]
  schema:telephone   → [WITHHELD]

=== RECEIPT: RESEARCH → BOOKING HANDOFF ===
{
  "action": "schema:ReserveAction",
  "disclosed_by_initiator": [
    "schema:Person.schema:name",
    "schema:Person.schema:nationality"
  ],
  ...
}
```

**Files to Create**:
- `examples/crewai-integration/after.py`

---

### [ ] Task 10: CrewAI `README.md`
**Description**: Write the developer-facing README for the CrewAI example. Same structure as the LangChain README.

**Acceptance Criteria**:
- "Quick Start" section with exact commands
- "Before" section showing the scratchpad dump from `before.py`
- "After" section showing the sanitized handoff from `after.py`
- Explains what `PapCrew` and `PapAwareAgent` do in plain terms
- "Architecture" diagram (ASCII) showing data flow:
  ```
  Principal
    └─ root mandate → ResearchAgent (SearchAction)
         └─ child mandate → BookingAgent (ReserveAction, name+nationality only)
  ```
- Does not require LLM API key — calls this out explicitly

**Files to Create**:
- `examples/crewai-integration/README.md`

---

### [ ] Task 11: Update Repo Root README
**Description**: Add a "Python Framework Integrations" section to the main `README.md` linking to both new examples. Keep it to 4–6 lines.

**Acceptance Criteria**:
- New section titled `## Python Framework Integrations` (or added to existing `## Examples` table)
- Links to `examples/langchain-integration/README.md` and `examples/crewai-integration/README.md`
- One-sentence description per example
- Does not rewrite any existing content

**Files to Edit**:
- `README.md`

---

### [ ] Task 12: Smoke-Test Both Examples End-to-End
**Description**: After all code is written, do a manual smoke-test run of both `before.py` and `after.py` in each integration to verify clean output. Fix any import errors, missing dependencies, or SDK usage mistakes.

**Acceptance Criteria**:
- `python examples/langchain-integration/before.py` exits 0 with expected output
- `python examples/langchain-integration/after.py` exits 0 with receipt JSON containing property refs (not values)
- `python examples/crewai-integration/before.py` exits 0 with expected scratchpad dump
- `python examples/crewai-integration/after.py` exits 0 with two receipts in output
- No `ImportError`, no `PapSignatureError`, no `PapScopeError` from correct usage
- Confirmed that `maturin develop` completes without error in `crates/pap-python/`

**Test commands**:
```bash
# Build the Python SDK first
cd crates/pap-python && maturin develop && cd ../..

# LangChain examples
pip install -r examples/langchain-integration/requirements.txt
python examples/langchain-integration/before.py
python examples/langchain-integration/after.py

# CrewAI examples
pip install -r examples/crewai-integration/requirements.txt
python examples/crewai-integration/before.py
python examples/crewai-integration/after.py
```

---

## Quality Requirements

- [ ] No live LLM API calls — all examples run offline
- [ ] No network calls in examples (PAP sessions are in-process only)
- [ ] `maturin develop` is the only build step required before running examples
- [ ] Receipt JSON must contain only property references — never actual values ("Alice Baur" must not appear in any receipt)
- [ ] All PAP signature operations must pass (`verify_with_keypair`, `verify_chain`) — examples prove correctness, not just happy-path printing
- [ ] Each `before.py` must make the leakage *obvious* from the printed output — a developer skimming it for 10 seconds should say "oh, that's bad"
- [ ] Each `after.py` must make the protection *obvious* from the printed output — same 10-second test

---

## Technical Notes

**Python SDK install path**:
```bash
cd crates/pap-python
pip install maturin
maturin develop   # installs pap into current Python env
```
No wheel upload required. The SDK compiles against the local Rust workspace.

**Stub LLM for CrewAI** (avoids requiring an OpenAI key):
```python
from langchain_community.llms.fake import FakeListLLM
llm = FakeListLLM(responses=["Flight booked for Alice Baur."])
```
Or, if CrewAI's agent execution can be bypassed more cleanly via `step_callback`, prefer that — keep the example simple.

**SD-JWT pattern from existing tests**:
```python
jwt = SelectiveDisclosureJwt(principal.did(), json.dumps({
    "schema:name": "Alice Baur",
    "schema:email": "alice@example.com",
    "schema:nationality": "US",
    "schema:ssn": "123-45-6789",
}))
jwt.sign(principal)
disclosures = jwt.disclose(["schema:name", "schema:nationality"])  # 2 of 4
```

**Receipt with no values**:
```python
receipt = TransactionReceipt.from_session(
    session,
    disclosed_by_initiator=["schema:Person.schema:name", "schema:Person.schema:nationality"],
    disclosed_by_receiver=["schema:ReserveAction.result"],
    executed="schema:ReserveAction",
    returned="schema:ReservationConfirmation",
)
```
The receipt proves what *types* of data were shared. "Alice Baur" never appears in it.

**Timeline**: ~3 days total
- Day 1: Tasks 1–5 (LangChain integration complete)
- Day 2: Tasks 6–10 (CrewAI integration complete)
- Day 3: Tasks 11–12 + polish, edge-case fixes, and README review
