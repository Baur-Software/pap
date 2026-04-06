# The Semantic Rendering Engine

PAP Renderer Specification
Working Draft — April 2026
Principal Agent Protocol Working Group

---

## Abstract

This document specifies the PAP rendering engine, a deterministic system that maps structured Schema.org vocabulary encoded as JSON-LD directly to visual output — without per-feature HTML, CSS, or JavaScript.

The central thesis: **when the data is semantically typed, the renderer is a pure function.** The same JSON-LD input produces the same visual output. There is no layout logic to write, no CSS to debug, no component lifecycle to manage. The vocabulary *is* the interface.

This is a meaningful departure from the document-centric model of the web, where rendering knowledge is scattered across HTML structure, CSS rules, and JavaScript behavior — and must be reimplemented for every application and every feature.

---

## 1. Motivation

### 1.1 The Problem with HTML/CSS/JS

The standard web rendering model requires developers to:

1. Receive data (as JSON or a custom type)
2. Write HTML expressing the structure of that specific data shape
3. Write CSS expressing the visual treatment of that structure
4. Write JavaScript expressing any behavior or interactivity

This must be repeated for every new data type. A `FlightReservation` needs its own template. A `WeatherForecast` needs its own template. The surface area compounds. Each template introduces new CSS selectors, new JavaScript event handlers, new accessibility considerations, new failure modes. The coupling between data shape and presentation logic is total.

### 1.2 The Insight

Schema.org defines approximately 900 types covering commerce, travel, health, science, news, events, creative works, organizations, people, and more. These types carry **semantic precision**: a `FlightReservation` always has a `departureAirport`, an `arrivalAirport`, a `departureDate`. A `JobPosting` always has a `title`, a `hiringOrganization`, a `baseSalary`.

The vocabulary is stable, published, and machine-readable. Every Schema.org property has a declared range type — `departureDate` has range `Date | DateTime`, `totalPrice` has range `Number | Text`, `url` has range `URL`. These types are not inferred; they are specified.

JSON-LD encodes this vocabulary in a standard wire format. Every JSON-LD object with an `@type` field is self-describing.

**The shift:** instead of writing rendering logic per data shape, write it per semantic type — once — and it applies universally. An agent anywhere can return a `FlightReservation` and the renderer handles it without any coordination with the agent author.

### 1.3 Agents Are Contract, Not Transport

An agent is anything that:

1. Accepts a mandate (authorization scope)
2. Executes an action
3. Returns a JSON-LD payload

Nothing in this definition requires a network call, an LLM, or a specific runtime. A UI component widget is an agent — it accepts a mandate authorizing it to see certain data, the user interacts with it, it returns a typed JSON-LD result. A date picker, a map, a form — all agents. The renderer doesn't care how the payload was produced; it cares about the schema type.

Transport is an implementation detail already encoded in `endpoint`:

- `endpoint: None` — local agent (embedded component, on-device synthesizer)
- `endpoint: Some("https://...")` — remote HTTP agent
- `endpoint: Some("wss://...")` — remote WebSocket agent

No separate type enum is required. The protocol does not distinguish between these at the rendering layer.

---

## 2. Architecture

### 2.1 Overview

The renderer is a three-layer dispatch pipeline:

```
JSON-LD Input
      │
      ▼
 Type Detection ──── Two-Tier Registry ──► Renderer Selected
      │
      ▼                    Tier 1: agent_did + schema_type  (highest priority)
 Composite Types           Tier 2: schema_type only         (fallback)
 (Vec<String>)
      │
      ├─── Tier 1 hit → Agent-scoped renderer (agent owns its visual output)
      ├─── Tier 2 hit → Shipped or user-defined template
      └─── No hit    → Generic stream renderer (universal fallback)
                               │
                               ▼
                      Receipt Wrapper
                               │
                               ▼
                         Visual Output
```

Every path terminates at receipt-wrapped visual output. The dispatch question is which renderer handles it.

### 2.2 The Two-Tier Registry

The `RendererRegistry` maintains two maps:

**Tier 1 — Agent-scoped:** keyed by `(agent_did, schema_type)`. A renderer registered here owns the rendering of a specific agent's output for that type, independent of the global schema vocabulary mapping. This is how a component agent or a specialized remote agent asserts full control over how its payload looks.

**Tier 2 — Type-global:** keyed by `schema_type` alone. The 25+ shipped templates live here. User-authored declarative templates also register here (or in Tier 1 if the template has an `agent_did`).

Lookup order is strict: Tier 1 → Tier 2 → generic stream renderer. A Tier 1 hit short-circuits everything below it.

```rust
pub trait BlockRenderer: Send + Sync {
    fn render(&self, content: &Value) -> AnyView;
    fn schema_types(&self) -> Vec<&'static str>;

    // Optional: when Some, registered in Tier 1 under (agent_id, schema_type).
    // Default None → registered in Tier 2 by schema type only.
    fn agent_id(&self) -> Option<&str> { None }
}
```

### 2.3 Composite Type Dispatch

JSON-LD allows `@type` to be an array: `["FlightReservation", "Reservation"]`. This declares that the object is simultaneously both types — most-specific first.

The renderer preserves the full type list through the entire pipeline:

```rust
FieldKind::TypedObject { schema_types: Vec<String> }
EntryKind::TypedObjectHeader { schema_types: Vec<String>, template_hit: bool, content: Option<Value> }
```

Registry dispatch iterates the list in order. `FlightReservation` wins if registered. If not, `Reservation` is tried. If not, `Intangible`, and so on. The most-specific available renderer is always selected.

This is the abstract composite interface: given any set of Schema.org types, the renderer selects the best available handler without any author coordination. A component agent that returns `["BookingForm", "LodgingReservation"]` gets its specific renderer if one is registered; otherwise it falls back to `LodgingReservation`'s shipped template.

### 2.4 Vocabulary-Driven Field Classification

The generic stream renderer classifies every field value before rendering it. Classification is **vocabulary-driven first, heuristic second.**

Schema.org specifies the range type of each property. `departureDate` has range `Date | DateTime`. `totalPrice` has range `Number | Text` (in a monetary context). `url` has range `URL`. These are facts about the vocabulary, not guesses from key names.

The `schema_property` catalog encodes this:

```rust
pub fn classify_by_property(property_name: &str) -> Option<FieldKind> {
    match property_name {
        "startDate" | "endDate" | "departureDate" | "arrivalDate" |
        "checkinDate" | "checkoutDate" | "datePublished" | ... => Some(FieldKind::DateTime),

        "price" | "totalPrice" | "baseSalary" | "amount" | ... => Some(FieldKind::Price),

        "url" | "sameAs" | "thumbnailUrl" | "contentUrl" | ... => Some(FieldKind::ExternalUrl),

        _ => None,
    }
}
```

Classification priority in `classify_field`:

1. **PAP scheme URIs** — `pap://`, `pap+https://`, `pap+wss://` are classified before everything else to prevent misclassification of intent URIs stored under date-keyed fields
2. **Vocabulary catalog** — property name maps to known range type
3. **Value-shape heuristics** — ISO 8601 date detection, `http://` prefix, `did:` prefix
4. **Key-name heuristics** — fallback for unknown properties (contains "date", "price", etc.)

The result: `departureDate` is `DateTime` because the vocabulary says so, not because the key contains "date". An agent returning a custom property `scheduledExecution` would fall through to heuristics only if it isn't in the catalog.

```rust
pub enum FieldKind {
    Scalar,
    DateTime,
    Price,
    ExternalUrl,
    PapLink,      // PAP intent URI — requires principal confirmation
    Did,          // Decentralized identifier
    TypedObject { schema_types: Vec<String> },
    List,
    Object,
    Empty,
}
```

### 2.5 The Generic Stream Renderer

When no registered template handles a type, the generic renderer provides a deterministic universal fallback. It operates in three phases:

**Flatten.** The nested JSON-LD tree is traversed depth-first using an explicit stack (no recursion) and converted to a linear sequence of `StreamEntry` values:

```
TypedObjectHeader { schema_types, template_hit, content }
TypedObjectFooter { schema_type }
ObjectHeader { key }
ObjectFooter
ListHeader { key, total_items, rendered_items }
ListFooter
Field { key, value, field_kind, parent_css }
ListOverflow { remaining }
```

Limits: 2,000 max entries total, 50 items per list. Both are DoS bounds, not quality limits.

**Classify.** Each `Field` entry receives a `FieldKind` via the vocabulary catalog (see §2.4).

**Render.** The flat entry sequence is consumed to build the view tree. Header/footer pairs establish nesting. Fields are rendered with type-appropriate visual treatment per their `FieldKind`.

### 2.6 The Handshake Envelope

Agent responses arrive wrapped in a handshake envelope:

```json
{
  "@type": "FlightReservation",
  "agent": "Amadeus Flight Search",
  "query": "JFK to LAX",
  "result": {
    "@type": ["FlightReservation", "Reservation"],
    "departureAirport": "JFK",
    "arrivalAirport": "LAX",
    "departureDate": "2026-04-15",
    "totalPrice": "299",
    "airline": "American Airlines"
  },
  "receipt": {
    "session_id": "sess_...",
    "co_signatures": 3,
    "action": "SearchAction"
  }
}
```

The renderer unwraps `result`, which contains the semantically typed payload. The `@type` on the envelope drives registry dispatch. The `receipt` is passed separately to the receipt wrapper. The `result` payload may itself declare multiple types — these are preserved as `Vec<String>` through the pipeline.

### 2.7 Declarative Templates

Users may define custom renderers without writing code. A declarative template is a JSON configuration specifying:

- Which `@type` it handles (`schema_type`)
- Optional `agent_did` — when set, registered in Tier 1 (agent-scoped)
- Which fields to extract (dot-path notation: `offers.price`)
- Conditional display rules (`exists`, `equals`, `contains`)
- Display type per field (`title`, `text`, `price`, `date`, `url`)

A declarative template with `agent_did` set gives a specific agent permanent control over how its output renders, expressed as configuration rather than code.

---

## 3. Determinism

The renderer is a pure function:

```
render(json_ld, registry) → AnyView
```

Given the same input and the same registry state, the output is identical. Properties:

- **Testability.** Any renderer output is a pure snapshot. No mocking, no state.
- **Reproducibility.** A stored receipt replayed later renders identically.
- **Auditability.** The rendering path is determined entirely by schema type and field values, never by runtime context. It is inspectable and verifiable.
- **Security.** All values are rendered as `.textContent`, never `.innerHTML`. No injection surface exists.

Specified invariants:
- PAP scheme URI classification precedes all other checks — reordering is a breaking change
- Composite type dispatch iterates in declaration order — first declared type is most specific
- Entry limit (2,000) and list cap (50) bound rendering cost — changing them is a breaking change
- Tier 1 always takes priority over Tier 2 — this ordering is guaranteed

---

## 4. Block Lifecycle

Rendered content exists within a block lifecycle state machine:

```
Ghost → Resolving → Resolved
                  → Failed
                  → Outcome
```

**Ghost** is the pre-execution state. The block shows what the agent *will* see (its mandate scope) and what it *will* return (its declared schema type). For component agents with no endpoint, Ghost may show an interactive input UI rather than static scope badges — the component itself is the agent's interface.

**Resolving** tracks handshake phases. Six phase indicators show progress for remote agents. Local component agents may transition Ghost → Resolved directly upon user submission, bypassing Resolving.

**Resolved** is the terminal success state. The typed content card is rendered from the agent's JSON-LD payload via the dispatch pipeline.

**Failed** shows the phase at which failure occurred.

**Outcome** is a synthesized block produced by on-device reasoning across multiple Resolved blocks. It renders identically to a Resolved block, with an expandable provenance layer.

### 4.1 Agent DID on the Block

`CanvasBlock.agent_did` carries the DID of the agent that produced the block's payload. This enables Tier 1 dispatch: the renderer checks `(agent_did, schema_type)` first, before the global schema-type registry.

---

## 5. Provenance

Every rendered block carries a provenance layer showing, for each contributing agent:

- Agent name and decay state (Active, Degraded, ReadOnly, Suspended)
- Agent DID and principal DID
- Mandate scope (what the agent was authorized to see)
- Return value declaration (what type the agent committed to returning)
- Receipt link (the co-signed transaction record)

Provenance is collapsed by default. It is the mechanism by which the user can verify, after the fact, exactly which agents participated in producing what they see, under what authorization, with what cryptographic attestation.

---

## 6. Relationship to HTML/CSS/JS

The claim is narrow: **for data-driven content whose type is known at schema time, HTML/CSS/JS is unnecessary overhead.** When you know you have a `FlightReservation`, you already know what fields it has, what they mean, and how they should be presented. Writing a bespoke template in HTML repeats work that the schema already encodes.

The PAP renderer exploits this. Every Schema.org type is handled once. Every new agent that adopts an existing Schema.org type gets rendering for free, with no coordination required between the agent author and the renderer author.

The complexity budget shifts. Instead of N templates × M agents worth of authoring, there is one renderer and one shared vocabulary. The interface is the schema. The schema is already written.

---

## 7. Security Considerations

- All rendered values are `.textContent`. `innerHTML` is not used anywhere in the rendering pipeline.
- PAP intent URIs require explicit principal confirmation before execution. They cannot be triggered by rendering alone.
- The entry limit (2,000 entries) and list cap (50 items) bound the computational cost of rendering any single JSON-LD object.
- The PAP-before-vocabulary classification ordering is a specified invariant. Reorderings are breaking changes.
- Tier 1 agent-scoped renderers cannot execute arbitrary code at the protocol level — they are still `BlockRenderer` implementations subject to the same text-only output guarantee.

---

## 8. Extensibility

The registry is designed for extension at three levels:

1. **Compiled templates** — shipped in the binary, covering the core Schema.org vocabulary. Implement `BlockRenderer`, optionally implement `agent_id()` for Tier 1 registration.
2. **Declarative templates** — user-defined JSON configurations, loaded at runtime. Set `agent_did` to register in Tier 1.
3. **Generic stream renderer** — handles any type not covered by (1) or (2) using the vocabulary catalog for field classification. No author intervention required.

New Schema.org types, proprietary types, and composite types all render. The question is only whether they render with a curated visual treatment or with the universal fallback.

---

## 9. Summary

The PAP rendering engine is a system in which the vocabulary does the work.

- Schema.org property names are the field type specification
- Schema.org type strings are the dispatch key
- JSON-LD field values are the content
- The renderer is a pure function
- The output is deterministic

The dispatch has two tiers — agent-scoped (Tier 1) and type-global (Tier 2) — so specific agents can own their visual output while the shared vocabulary remains the universal fallback. Composite `@type` arrays are preserved through the pipeline so inheritance chains resolve automatically.

Against the standard model — where every new data shape requires new HTML, new CSS, new JavaScript — this is a compression. The implementation surface is bounded by the vocabulary, not by the number of agents or use cases.

The vocabulary is the interface. The schema is already written.

---

*End of specification.*
