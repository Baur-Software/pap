# Test Plan: Agent Designer WYSIWYG Editor

**Generated:** 2026-03-23
**Branch:** vk/c893-registry-visual
**Repo:** anthropics/pap
**Status:** Comprehensive coverage mapped, ready for Phase 1 implementation

---

## Affected Pages/Routes

- **`/agents/design`** — New designer page (full-screen form + preview)
- **`GET /api/agents`** — Existing (used to load prior agents for "Load from existing")
- **`POST /api/agents`** — Existing (used to register signed JSON-LD)

---

## Key Interactions to Verify

### 1. Form Submission Flow
- **Happy path:** Fill all fields → Preview updates live → Sign & Register → WebAuthn prompt → Success
- **Validation failure:** Try to submit with invalid data → Error inline → Cannot submit
- **Network failure:** Registration fails → Error banner with retry → Can recover

### 2. DID Validation
- Enter valid `did:key:...` → Green checkmark appears
- Enter invalid DID (wrong format, bad multibase) → Red error shown
- Error prevents signing/registration attempt

### 3. Autocomplete Pickers
- Type "sea" in Capabilities → Filters to SearchAction, ReserveAction, etc.
- Click item → Added to selected tags
- Click X on tag → Removed from selected
- Multiple selections work correctly
- No duplicates in selection

### 4. Real-time Preview
- Fill form field → JSON preview updates immediately
- Change capabilities → @type array in preview updates
- All 6 required fields reflected in preview before signing

### 5. Versioning (Load from Existing)
- Click "+ Design New Agent"
- Choose "Load from existing" → Dropdown shows prior agents
- Select agent → Form pre-fills with all v1 fields
- Modify capabilities (add new one)
- Register → Creates new version (different hash, same name)
- Both v1 and v2 visible in agents list

### 6. Copy JSON to Clipboard
- Click "Copy JSON" → JSON copied
- Paste into text editor → Valid, parseable JSON-LD
- No missing or malformed fields

---

## Edge Cases

| Case | Expected Behavior | Test Type |
|------|-------------------|-----------|
| Agent name > 128 chars | Validation error | Unit + Component |
| Unicode in name | Preserved in JSON-LD | Unit |
| Empty object_types | Handled appropriately | Unit |
| Rapid "Sign & Register" clicks | Single submission only | Component + E2E |
| Form open 30 minutes | Still submittable | E2E |
| Browser back after registration | Agents list shown | E2E |
| Paste into autocomplete field | Search works normally | Component |
| Select same item twice | Deduplicated or rejected | Component |
| No internet during signing | Clear error, can retry | E2E |

---

## Critical Paths

1. **New agent registration end-to-end:** Click "+ Design New Agent" → blank canvas → fill form → sign → register → see in agents list
2. **Agent versioning end-to-end:** Register v1 → click "+ Design New Agent" → load from existing → modify → register v2 → both visible in registry
3. **Error recovery end-to-end:** Try invalid input → error shown → fix → resubmit → succeeds

---

## Test Breakdown by Phase

### Phase 2 (Form Components) — Unit + Component Tests
- `AgentFormState::validate()` — all validation paths
- `AgentFormState::to_advertisement()` — JSON-LD generation
- DID validation logic — parsing, format checking
- `Picker` component — autocomplete, filtering, add/remove, deduplication
- `PreviewPane` — rendering, updates on state change, copy-to-clipboard

### Phase 3 (Preview & JSON Export) — Component Tests
- Preview pane updates in real-time
- Copy JSON produces valid JSON-LD
- JSON structure matches spec

### Phase 4 (Integration) — E2E Tests
- Full form submission flow
- WebAuthn/Passkey integration
- API call success/failure handling
- Network error recovery
- "Load from existing" agent pre-fill
- Success toast and redirect

### Phase 5 (Polish) — Component Tests
- Error message clarity
- Keyboard shortcuts (Esc, Enter)
- Accessibility (labels, ARIA)
- Responsive layout (mobile)

---

## Test Framework & Setup

**Framework:** Leptos testing (component tests) + Playwright (E2E)

**Server:**
- Existing `POST /api/agents` endpoint
- Test with mocked WebAuthn/signing (for unit/component tests)
- Real signing flow for E2E tests

**Fixtures:**
- Sample `AgentAdvertisement` (valid + invalid variants)
- Sample schema.org vocab lists
- Pre-registered DIDs for testing (in test database)

---

## Testing Philosophy

100% test coverage is the goal — every untested path is a path where bugs hide and vibe coding becomes yolo coding. With AI assistance, the cost of complete test coverage is near-zero compared to human team effort. Tests make shipping fast and confident.

---

## What Gets Tested When

| Phase | Focus | Type |
|-------|-------|------|
| Phase 1 | Scaffolding compiles cleanly | Compile check |
| Phase 2 | Form logic, validation, DID parsing | Unit + Component |
| Phase 3 | Preview updates, JSON export | Component + Manual |
| Phase 4 | Full flows, WebAuthn, API, versioning | E2E |
| Phase 5 | Accessibility, responsiveness, UX | Component + Manual |
