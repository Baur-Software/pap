# Design: Agent Designer WYSIWYG Editor for Chrysalis Registry

**Generated:** 2026-03-23
**Branch:** vk/c893-registry-visual
**Repo:** anthropics/pap
**Status:** APPROVED (Ready for Implementation)
**Mode:** Builder (side project exploratory)

---

## Context

Chrysalis is a self-hosted, federated PAP agent registry. Currently, developers register agents by pasting pre-signed JSON-LD directly into a textarea modal. This works but has friction:

1. **Schema.org vocab mapping** — Developers must manually map their agent capabilities to schema.org action types and object types
2. **Property/disclosure requirements** — Specifying which `schema:*` properties their agent needs requires knowing the vocab hierarchy and syntax
3. **No visual feedback** — No preview of the final JSON-LD before signing and registering
4. **Version iteration** — Each new agent release requires editing JSON from scratch or duplicating+editing old advertisements

The goal: **Build a WYSIWYG visual designer** that lets developers design agent advertisements declaratively — defining capabilities, required disclosure properties, and return types through forms and pickers — then generates the JSON-LD they register.

Key constraint: **Export produces JSON-LD only.** This is not a runtime executor or simulator. It's a form-based generator for the advertisement metadata.

---

## Problem Statement

A developer wants to register a new agent service. They have:
- A deployed API service (e.g., flight search agent)
- An understanding of what it does (searches flights, returns results)
- A desire to register it in the Chrysalis registry

Today they must:
1. Manually construct JSON-LD with schema.org vocab
2. Ensure all required fields are present and valid
3. Sign the advertisement with their key
4. Paste it into the registry UI

The visual designer should eliminate steps 1-2, making the process:
1. **Click "New Agent Design"**
2. **Fill out a visual form** (agent name, capabilities, required properties, returns)
3. **Preview the generated JSON-LD**
4. **Sign and register**

---

## Success Criteria

1. **Developers can design an agent without writing JSON** — all core fields (name, capabilities, requires_disclosure, returns) filled via UI
2. **Schema.org vocab is discoverable** — pickers/autocomplete for capabilities, object_types, properties
3. **Versioning works smoothly** — design v1, publish; later edit and publish v2 with visual diff
4. **JSON-LD output is spec-compliant** — generated advertisements validate against existing PAP registry schema
5. **Visual preview shows the final output** — developers see exactly what will be registered before signing

---

## Core Design

### Data Flow Diagram

```
┌─────────────────────────────────────────────────────────┐
│  AGENT DESIGNER PAGE (/agents/design)                   │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  Left Column: Form                Right Column: Preview  │
│  ┌──────────────────────────┐    ┌──────────────────┐   │
│  │ MetadataSection          │    │  PreviewPane     │   │
│  │ ├─ name                  │    │  ┌────────────┐  │   │
│  │ ├─ provider_name         │───→│  │ JSON-LD    │  │   │
│  │ └─ provider_did (validate)    │  │ (real-time)│  │   │
│  │                          │    │  │ [Copy JSON]│  │   │
│  │ <Picker "Capabilities">  │    │  └────────────┘  │   │
│  │ (autocomplete + tags)    │    │                   │   │
│  │                          │    │                   │   │
│  │ <Picker "Disclosure">    │    │                   │   │
│  │                          │    │                   │   │
│  │ <Picker "Returns">       │    │                   │   │
│  │                          │    │                   │   │
│  │ <Picker "ObjectTypes">   │    │                   │   │
│  │                          │    │                   │   │
│  │ TTL input                │    │                   │   │
│  │                          │    │                   │   │
│  │ [Sign & Register]        │    │                   │   │
│  └──────────────────────────┘    └──────────────────┘   │
│         ↓ (on click)                                      │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ SigningFlow (Phase 4)                               │ │
│  │ ├─ WebAuthn/Passkey prompt                          │ │
│  │ ├─ Client-side Ed25519 signing                      │ │
│  │ └─ POST /api/agents (signed JSON-LD)                │ │
│  └─────────────────────────────────────────────────────┘ │
│         ↓ (success)                                       │
│  Redirect to /agents, show success toast                  │
│                                                           │
└─────────────────────────────────────────────────────────┘

STATE MANAGEMENT:
  AgentFormState (RwSignal)
    ├─ name: String
    ├─ provider_name: String
    ├─ provider_did: String (with validation status)
    ├─ capabilities: Vec<String>
    ├─ object_types: Vec<String>
    ├─ requires_disclosure: Vec<String>
    ├─ returns: Vec<String>
    ├─ ttl_min: u64
    └─ errors: HashMap<String, String>

  preview_json = Memo::new(|| state.to_advertisement())
  (updates when state changes)
```

### User Flow

1. Developer clicks "+ Design New Agent" button (in Agents page header)
2. Agent Designer opens (modal or dedicated page)
3. Choose starting point:
   - Blank canvas (new agent design)
   - From template (pre-filled capability/return templates)
   - From existing agent (duplicate + edit prior version)
4. Fill in form sections:
   - Agent metadata (name, provider DID, provider name)
   - Capabilities (pick schema.org actions: SearchAction, BookAction, etc.)
   - Required disclosure properties (autocomplete: Person.name, PostalAddress, etc.)
   - Return types (schema.org types: SearchResult, Reservation, etc.)
   - Object types (what entities this agent works with)
   - Min TTL for mandate
5. JSON-LD preview pane updates in real-time
6. "Sign & Register" button triggers signing flow
7. On success, redirect to agents list, show success toast

### UI Architecture

**Location:** `/pap/apps/registry/src/ui/pages/agent_designer.rs` (new file)

**Components:**
- `AgentDesignerPage` — top-level page, routing + layout
- `DesignerForm` — form state + submission
- `MetadataSection` — agent name, provider fields
- `CapabilitiesSection` — searchable picker for schema.org actions
- `DisclosureSection` — multi-select for required properties
- `ReturnsSection` — picker for return types
- `PreviewPane` — JSON-LD viewer
- `DesignerModal` — if modal experience preferred (can be decision point)

**Key Pattern:** Split into sections, each with its own RwSignal state that contributes to a root `agent_form: AgentForm` signal. The form updates the preview in real-time via a derived signal.

### Data Model

**New Leptos component state:**

```rust
#[derive(Clone, Debug)]
pub struct AgentFormState {
    pub name: String,
    pub provider_name: String,
    pub provider_did: String,
    pub capabilities: Vec<String>,  // ["schema:SearchAction", "schema:BookAction"]
    pub object_types: Vec<String>,  // ["schema:Flight", "schema:Hotel"]
    pub requires_disclosure: Vec<String>,  // ["schema:Person.name", "schema:PostalAddress"]
    pub returns: Vec<String>,  // ["schema:SearchResult"]
    pub ttl_min: u64,  // seconds
    pub errors: HashMap<String, String>,  // field -> error message
}

impl AgentFormState {
    fn to_advertisement(&self) -> AgentAdvertisement {
        AgentAdvertisement {
            context: "https://schema.org".to_string(),
            schema_type: "schema:Service".to_string(),
            name: self.name.clone(),
            provider: Provider {
                schema_type: "schema:Organization".to_string(),
                name: self.provider_name.clone(),
                did: self.provider_did.clone(),
            },
            capability: self.capabilities.clone(),
            object_types: self.object_types.clone(),
            requires_disclosure: self.requires_disclosure.clone(),
            returns: self.returns.clone(),
            ttl_min: self.ttl_min,
            signed_by: String::new(),  // filled at sign time
            signature: None,
        }
    }

    fn validate(&mut self) -> bool {
        self.errors.clear();
        let mut valid = true;

        if self.name.trim().is_empty() {
            self.errors.insert("name".to_string(), "Agent name required".to_string());
            valid = false;
        }
        if self.provider_did.trim().is_empty() {
            self.errors.insert("provider_did".to_string(), "Provider DID required".to_string());
            valid = false;
        }
        if self.capabilities.is_empty() {
            self.errors.insert("capabilities".to_string(), "At least one capability required".to_string());
            valid = false;
        }
        if self.requires_disclosure.is_empty() {
            self.errors.insert("requires_disclosure".to_string(), "Specify what properties you need".to_string());
            valid = false;
        }
        if self.returns.is_empty() {
            self.errors.insert("returns".to_string(), "Specify what types you return".to_string());
            valid = false;
        }

        valid
    }
}
```

### Schema.org Vocab Picker

**Approach:**

1. **Hardcoded high-value sets** for common agent use cases:
   - **Capabilities (Actions):** SearchAction, BookAction, ReserveAction, PayAction, OrderAction, ViewAction, BuyAction, RentAction, ScheduleAction, ReplyAction, SendAction, etc. (~30 most common PAP agent scenarios)
   - **Object types:** Person, PostalAddress, PaymentMethod, Hotel, Flight, Restaurant, Reservation, Booking, Event, etc.
   - **Return types:** SearchResult, Thing, Reservation, Order, BookingConfirmation, etc.
   - **Properties (disclosure):** Person.{name, email, telephone, birthDate}, PostalAddress.{streetAddress, city, state, postalCode, country}, PaymentMethod.{cardNumber, expirationDate}, etc.

2. **Autocomplete UI:**
   - Text input with dropdown matching
   - Show full `schema:Type` or `schema:Type.property` syntax in display
   - Filter by typing (case-insensitive prefix match)
   - Tags for already-selected items with X to remove

3. **Storage location:**
   - New file: `/pap/apps/registry/src/ui/schema_org_vocab.rs`
   - Constants for action types, object types, properties
   - Helper function `schema_org_completions(search_term: &str, context: &str) -> Vec<String>`

### Signing Architecture (Zero Trust)

**Model:** User signs on their device, registry validates. Registry never holds keys.

**Spec Reference:** PAP Section 9.4 (Advertisement Signing) + Section 4.3 (Principal Keypair)

**Flow:**
1. Designer generates `AgentAdvertisement` struct (unsigned, all fields except `signature`)
2. Serialize to canonical JSON-LD in spec-defined order:
   - @context, @type, name, provider, capability, object_types, requires_disclosure, returns, ttl_min, signed_by
3. User clicks "Sign & Register"
4. Client-side WebAuthn/Passkey prompt (biometric or PIN)
5. User approves → client-side Ed25519 signs canonical JSON bytes
6. Base64url-no-pad encode signature → fill `signature` field
7. POST complete `AgentAdvertisement` (with signature) to `register_agent_json()` API
8. Server validates Ed25519 signature against public key extracted from provider DID
9. Agent registered

**Implementation (Phase 4):**
- Add WASM Ed25519 library (`ed25519-dalek` compiled to WASM)
- New component: `SigningFlow` — handles WebAuthn prompt + client-side signing
- Serialize form state to canonical JSON (field order per spec)
- Sign canonical bytes, base64url-no-pad encode signature
- Reuse existing `register_agent_json()` API call

### Versioning & Iteration

**Scenario:** Developer published agent v1. Now designing v2 with new capabilities.

**Flow:**
1. On agent card, add "Edit/Redesign" button alongside "View"
2. Clicking opens designer with pre-filled form fields from existing advertisement
3. Developer modifies fields (adds new capabilities, etc.)
4. New JSON-LD is generated
5. "Sign & Register" creates a new entry in registry (same agent name, but new hash, new timestamp)

---

## Implementation Plan

### Phase 1: Setup & Scaffolding
- Create `/pap/apps/registry/src/ui/pages/agent_designer.rs`
- Create `/pap/apps/registry/src/ui/schema_org_vocab.rs` with hardcoded vocab sets
- Update `pages/mod.rs` to export new page
- Add route in app.rs for designer page

### Phase 2: Form Components
- Extract reusable `Picker` component (autocomplete + multi-select)
- Implement `MetadataSection` with DID validation
- Implement capability/disclosure/returns/object-types pickers
- Add real-time error display and field validation

### Phase 3: Preview & JSON Export
- Implement `PreviewPane` showing JSON-LD
- Add real-time preview update on form changes
- Implement copy-to-clipboard helper for JSON

### Phase 4: Integration with Existing Registry
- Update `agents.rs` page to add "+ Design New Agent" button
- Implement "Load from existing" dropdown for versioning
- Integrate client-side Ed25519 WASM signing
- Connect to existing `register_agent_json()` API
- Add signing success/failure/cancellation error handling

### Phase 5: Polish & Validation
- Error messages and inline validation
- Keyboard shortcuts (Enter to submit, Esc to close)
- Accessibility (labels, ARIA attributes)
- Responsive design (mobile-friendly pickers)

---

## Critical Files to Create/Modify

**New Files:**
- `/pap/apps/registry/src/ui/pages/agent_designer.rs`
- `/pap/apps/registry/src/ui/schema_org_vocab.rs`

**Modified Files:**
- `/pap/apps/registry/src/ui/pages/mod.rs` — Export agent_designer module
- `/pap/apps/registry/src/ui/app.rs` — Add route for designer
- `/pap/apps/registry/src/ui/pages/agents.rs` — Add "+ Design New Agent" button, edit workflow
- `/pap/apps/registry/src/ui/api.rs` — (Optional) if DID validation server function needed

---

## Design Decisions (Finalized)

✅ **Signing Flow:** WebAuthn prompt (zero-trust client-side signing)
✅ **Edit Flow:** Single entry point via "Load from Existing" dropdown
✅ **Page Route:** Dedicated page at `/agents/design` (full-screen, not modal)
✅ **Hardcoded Vocab:** ~100 curated schema.org items for PAP use cases
✅ **Preview Rendering:** Plain JSON for MVP (developers are technical, want raw output)

---

## Review Status

| Review | Status | Findings |
|--------|--------|----------|
| CEO Review | ✅ APPROVED | All premises verified, scope in blast radius, no new infra |
| Design Review | ✅ APPROVED | Two-column layout, reuses design system, all interactions covered |
| Eng Review | ✅ APPROVED | Architecture clean, DRY extraction done, 40+ codepaths mapped |

**VERDICT:** APPROVED — Ready for Phase 1 implementation. All reviews passed. 0 unresolved decisions.

---

## What This Solves

- **Schema.org vocab is friction:** Hardcoded sets + autocomplete make discovery seamless
- **No visual feedback:** Real-time JSON-LD preview keeps abstraction transparent
- **Version iteration:** "Load from existing" + edit + register v2 enables smooth developer workflow
- **JSON-LD complexity:** Form-based generation eliminates manual JSON construction
