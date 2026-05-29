# PAP Infrastructure Assessment Tool — Design Specification

**Date:** 2026-05-22  
**Status:** Design approved, ready for implementation planning  
**Owner:** Baur Software / PAP project  
**File:** `docs/assess.html`

---

## 1. Purpose

A single-page, self-contained assessment tool that evaluates an organization's infrastructure and security posture for deploying the Principal Agent Protocol (PAP). It produces a dual output:

1. A **plaintext summary** embedded in a `mailto:` body for immediate submission to Baur Software.
2. A **self-contained HTML report** the user downloads and attaches for full detail.

The tool lives on the static docs site and requires no backend, no build step, and no external dependencies.

---

## 2. Architecture

### 2.1 Page Structure

- **One HTML file:** `docs/assess.html`
- **Design system:** Uses the same CSS tokens as the existing docs site (Satoshi, DM Sans, JetBrains Mono, purple `#6c5ce7`, wing spectrum colors). CSS is **inlined** so the report requires no external stylesheet.
- **No framework:** Vanilla JavaScript only. No Webpack, Vite, Leptos, or Yew. The existing docs site is static HTML and this file must follow that pattern.

### 2.2 Two Views in One Page

| View | Description | Persistence |
|------|-------------|-------------|
| **Wizard** | Multi-step questionnaire. One section visible at a time. | `sessionStorage` saves answers after every section change. |
| **Report** | Self-contained HTML string generated client-side. Rendered via `document.open()` / `document.write()` into the **same tab**. | Not persisted; re-generated from `sessionStorage` on demand. |

### 2.3 State Management

- All answers stored in `sessionStorage` under key `pap_assessment_state`.
- State is a JSON object: `{ role, answers: { sectionId: { questionId: value } }, contact }`.
- On page load: if `sessionStorage` has state, offer "Resume assessment" or "Start over".
- On report generation: state is read but **not** cleared. The "Back to Assessment" button restores the wizard DOM from the saved state.

### 2.4 Report Generation

The report HTML string is assembled in-memory with all CSS inlined via a `<style>` block. It is:
1. Rendered in-place with `document.open()` / `document.write()` / `document.close()`.
2. Offered as a Blob download via `<a download="pap-assessment-[company]-YYYY-MM-DD.html">`.

This avoids `window.open()` issues when the page is served via `file://`.

---

## 3. Questionnaire Flow

### 3.1 Entry Gate

Before the first section, a single screen asks:

> **"What best describes your role?"**
> - Technical / Architect
> - Security / Compliance
> - Product / Engineering Lead

This sets a `role` flag in state. It does **not** hide sections entirely; it **reorders and highlights** questions within sections.

### 3.2 Sections

| # | Section | Audience Emphasis | Approx. Questions |
|---|---------|-------------------|-------------------|
| 1 | Org Context | Universal | 4–5 |
| 2 | Identity & Trust | Security heavy | 5–6 |
| 3 | Agent Infrastructure | Technical heavy | 5–6 |
| 4 | Data & Disclosure | Security heavy | 5–6 |
| 5 | Integration Surface | Technical heavy | 4–5 |
| 6 | Goals & Contact | Universal | 3–4 |

**Total: 25–35 questions.**

### 3.3 Adaptive Behavior

- If a user answers **"No existing agents"** in section 3, deep framework questions are skipped and a `greenfield` flag is set in state.
- If a user selects **"HIPAA"** in section 4, a `healthcare_compliance` flag is set and surfaced in the report narrative.
- If a user answers **"No key management"** in section 2, a `critical_gap: identity` flag is set.
- Skipped questions record `"unknown"` as the value and appear as `"Unknown — follow-up needed"` in the report.

### 3.4 Input Types

- **Radio** (single choice)
- **Multi-select** (checkbox group)
- **Short text** (one-line input)
- **Long text** (textarea, only in section 6)

### 3.5 Navigation

- **Next / Previous** buttons per section.
- **Progress indicator:** horizontal dots or bar showing `section / total`.
- **Skip section** allowed — marks all questions in that section as `"unknown"`.
- **Progress bar at top:** labeled steps `○ ○ ○ ○ ○ ○` with section names.

---

## 4. Scoring Model

### 4.1 Pillars & Weights

| Pillar | Weight | Rationale |
|--------|--------|-----------|
| Identity & Trust | 30 | PAP is built on DID keypairs, mandate scoping, and principal verification. |
| Data Stewardship | 25 | Selective disclosure and privacy-preserving disclosure are core PAP features. |
| Governance & Compliance | 20 | Mandate TTL, approval workflows, and audit receipts require policy maturity. |
| Agent Infrastructure | 15 | PAP wraps existing frameworks; agents matter but are not the hard part. |
| Integration Surface | 10 | API auth and SDKs are important but fixable; least specific to PAP readiness. |

**Total: 100 points.**

### 4.2 Scoring Rules

Each question maps to one or more pillars. Answers are weighted:

| Answer Level | Points | Example |
|--------------|--------|---------|
| Production-grade / Yes | Full | "We use a production HSM for key custody" |
| Partial / In progress | Half | "Key management is planned for Q3" |
| No / Not present | Zero | "We have no key management" |
| Unknown / Skipped | Zero | Skipped or not answered |

Per-question scoring logic is hardcoded in the JS (not data-driven), since the tool is a single file.

### 4.3 Maturity Tiers

| Range | Tier | Description |
|-------|------|-------------|
| 0–39 | Nascent | Significant gaps in trust infrastructure. PAP would be a foundational layer. |
| 40–59 | Developing | Some trust mechanisms exist but are not unified or agent-aware. |
| 60–79 | Maturing | Good foundation; PAP adds selective disclosure and mandate scoping. |
| 80–100 | Production-Ready | Strong posture; PAP enhances verifiability and federation. |

### 4.4 Critical Gaps

Certain answers trigger red flags regardless of total score:

| Gap | Trigger | Severity |
|-----|---------|----------|
| No key management | Section 2: "No" to key custody | Blocker |
| No API authentication | Section 5: "No" to auth on APIs | Blocker |
| No audit logging | Section 2: "No" to audit history | Warning |
| No data classification | Section 4: "No" to PII classification | Warning |
| Agents with no governance | Section 3: "Yes" agents + "No" governance | Blocker |

Critical gaps appear prominently in the report and influence the recommended scope text.

### 4.5 Qualitative Narrative

The report auto-generates 3–5 plain-language paragraphs:

1. **Posture summary** — "Your identity infrastructure is [strong / partial / not yet established]..."
2. **Biggest gap** — "The biggest gap we see is..."
3. **PAP focus** — "A PAP deployment would likely focus first on..."
4. **Engagement complexity** — "Estimated engagement complexity: [Light / Standard / Complex]"

---

## 5. Report Layout

The generated report is a single self-contained HTML file with inlined CSS. It uses the PAP design system but works standalone.

### 5.1 Sections (top to bottom)

1. **Header** — Baur Software logo (SVG inlined), report title, generation date
2. **Executive Summary** — 3–4 sentences synthesizing role, score, tier, and primary gap
3. **Readiness Score** — Large number (`72 / 100`), color-coded by tier:
   - 0–39: coral
   - 40–59: gold
   - 60–79: teal
   - 80–100: violet
4. **Score Breakdown** — Horizontal Unicode bar chart per pillar, with score and one-line interpretation
5. **Critical Gaps** — Red-flagged items with severity (Blocker / Warning / Advisory) and one-sentence mitigation
6. **Infrastructure Snapshot** — Clean table of answers grouped by section. Skipped questions show "Unknown — follow-up needed"
7. **Recommended Engagement Scope** — Auto-text based on score:
   - 0–39: "Foundational Trust Layer Build"
   - 40–59: "Phased Integration with Trust Retrofit"
   - 60–79: "Selective Disclosure & Federation Enablement"
   - 80–100: "PAP Hardening & Multi-Principal Expansion"
8. **Next Steps** — Bulleted action items derived from gaps
9. **Contact & Notes** — Submitted contact info and free-form notes, verbatim
10. **Footer** — "Generated by the PAP Infrastructure Assessment Tool", link to `get-pap.html`

### 5.2 Print Styles

- `@media print` hides the action bar buttons.
- `page-break-before` on Critical Gaps and Next Steps.

---

## 6. Email Handoff

### 6.1 Report Action Bar

Sticky bar at the bottom of the report (hidden on print):

| Button | Action |
|--------|--------|
| **Download Report (.html)** | Blob download of the self-contained report |
| **Send to Baur Software** | Opens `mailto:contact@baursoftware.com` |
| **Back to Assessment** | Restores wizard from `sessionStorage` |

### 6.2 Mailto Body (Plaintext Summary)

The `mailto:` body is a Unicode-formatted plaintext summary. It is **not** HTML — email clients render `mailto` bodies as plain text.

Example:

```
PAP Infrastructure Assessment Summary
=====================================

Organization: Acme Corp
Role: Technical / Architect
Readiness Score: 72 / 100
Maturity Tier: Maturing

Pillar Breakdown:
• Identity & Trust      24 / 30
• Data Stewardship      22 / 25
• Governance            14 / 20
• Agent Infrastructure   8 / 15
• Integration Surface    4 / 10

Critical Gaps:
⚠ No Ed25519 key management detected (Blocker)
⚠ Agent API surface lacks mandate scoping (Warning)

Recommended Scope:
Selective Disclosure & Federation Enablement

Contact: alice@acme.com
Notes: (free-form notes, truncated to ~500 chars if needed)

Please attach the downloaded .html report for full details.
```

### 6.3 Mailto Length Guard

If the body exceeds ~1800 characters (safe across email clients), truncate free-form notes and append `"(full details in attached report)"`.

---

## 7. Files & Integration

### 7.1 New File

- `docs/assess.html` — the assessment tool

### 7.2 Modified Files

- `docs/get-pap.html` — add a link to `assess.html` from the "Start a Conversation" CTA section, e.g.:
  > "Not sure where to start? [Take the 5-minute PAP Infrastructure Assessment →](assess.html)"

### 7.3 No New Dependencies

The tool uses vanilla JavaScript and CSS. No npm packages, no build step, no framework.

---

## 8. Accessibility & Responsive

- All form inputs have associated `<label>` elements.
- Wizard sections use `aria-live="polite"` for step transitions.
- Progress indicator uses `role="progressbar"`.
- Color is never the sole indicator of status (icons + text accompany the score color).
- Mobile-first layout: sections stack vertically, inputs are full-width on narrow viewports.

---

## 9. Edge Cases

| Case | Behavior |
|------|----------|
| User refreshes mid-wizard | Restore from `sessionStorage`; show toast "Resumed from previous session" |
| User opens report, then goes back | Wizard state intact; they land on the section they left |
| All questions skipped | Score = 0, tier = Nascent, narrative says "Assessment incomplete — follow-up required" |
| `sessionStorage` unavailable | Tool still works; warn user that progress won't survive refresh |
| `mailto:` fails (no email client) | Show a copy-to-clipboard button with the plaintext summary |
| Page opened on `file://` | Fully supported; Blob download and `document.write()` work correctly |

---

## 10. Open Questions (for implementation)

The following will be resolved during the implementation planning phase:

1. **Exact question list** — The 25–35 specific questions and their answer options will be defined in the implementation plan.
2. **Scoring logic per question** — Point assignments and pillar mappings per answer will be codified in a lookup table during implementation.
3. **Narrative template strings** — The exact sentence templates for the qualitative paragraphs will be drafted during implementation.
4. **Contact email address** — Confirm whether `contact@baursoftware.com` is the correct `mailto:` target.

---

## 11. Approval

This specification has been reviewed and approved for implementation planning.
