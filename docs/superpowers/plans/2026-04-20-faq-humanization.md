# FAQ Humanization + Accuracy Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite all 13 FAQ question titles to plain language, add a human-first opening paragraph to each answer, and fix two accuracy bugs (Q13 SD-JWT claim, SD-JWT glossary entry).

**Architecture:** Single file edit — `docs/faq.html`. No new files, no new UI, no structural changes to the page. Each question gets its title text node replaced and a new `<p>` block prepended inside `.faq-body`. Two accuracy fixes are surgical replacements.

**Tech Stack:** HTML, hand-edited with exact string matching. No build step. Verify by opening in a browser.

---

## File Map

| File | Changes |
|------|---------|
| `docs/faq.html` | 13 × title rewrite, 13 × lead paragraph insert, 1 × Q13 SD-JWT sentence removal, 1 × glossary entry rewrite |

---

### Task 1: Rewrite Q1 title and add lead paragraph

**Files:**
- Modify: `docs/faq.html` (around line 403)

- [ ] **Step 1: Replace Q1 title text**

Find exactly:
```
              What is the enterprise identity story — RBAC, SAML, OIDC integration?
```
Replace with:
```
              Does PAP work with our company's existing identity system — SSO, Active Directory, SAML?
```

- [ ] **Step 2: Insert Q1 lead paragraph**

Find exactly:
```html
        <div class="faq-body">
          <p>
            PAP v0.x is <strong>explicitly consumer-first</strong>.
```
Replace with:
```html
        <div class="faq-body">
          <p>
            PAP doesn't plug into Okta or Active Directory — and that's intentional. Instead of a central hub that decides who has access, every agent session runs under a time-limited permission signed by the principal's own device key. When someone leaves your org, their access doesn't need to be revoked. It decays automatically — Active → Degraded → ReadOnly → Suspended — and stops working on its own. For key recovery, you split your identity into shards using Shamir Secret Sharing (the same math behind AES) and give them to trustees you choose. Any M shards reconstruct your key; fewer than M reveals nothing. Threshold and total are yours to configure.
          </p>
          <p>
            PAP v0.x is <strong>explicitly consumer-first</strong>.
```

- [ ] **Step 3: Verify in browser**

Open `docs/faq.html` in a browser, expand Q1, confirm the plain-language paragraph appears above the existing content. No layout breaks.

- [ ] **Step 4: Commit**

```bash
git add docs/faq.html
git commit -m "docs(faq): humanize Q1 title and add plain-language lead"
```

---

### Task 2: Rewrite Q2 title and add lead paragraph

**Files:**
- Modify: `docs/faq.html` (around line 454)

- [ ] **Step 1: Replace Q2 title text**

Find exactly:
```
              Do property reference patterns constitute quasi-identifiers even when values are hidden?
```
Replace with:
```
              Could an agent build a profile of me just from seeing which data fields were requested, even without the actual values?
```

- [ ] **Step 2: Insert Q2 lead paragraph**

Find exactly:
```html
          <p>
            <strong>Yes — scoped to the recipient agent and cross-session receipt patterns.</strong>
```
Replace with:
```html
          <p>
            Yes, and we document it honestly. Even if an agent never sees your actual data, it still learns which fields you shared. Receipts store strings like <code>"schema:Person.name"</code> — property references, never values. But across enough sessions, the pattern of which properties you share with a given agent becomes a fingerprint on its own. A healthcare provider never reads your records but still knows you asked about the same condition three times this month. The mitigation today is OHTTP — when enabled, even the field pattern is invisible to network observers. Without it, transport is encrypted but the query structure is visible at the relay hop.
          </p>
          <p>
            <strong>Yes — scoped to the recipient agent and cross-session receipt patterns.</strong>
```

- [ ] **Step 3: Commit**

```bash
git add docs/faq.html
git commit -m "docs(faq): humanize Q2 title and add plain-language lead"
```

---

### Task 3: Rewrite Q3 title and add lead paragraph

**Files:**
- Modify: `docs/faq.html` (around line 511)

- [ ] **Step 1: Replace Q3 title text**

Find exactly:
```
              Who operates OHTTP relays, and is there a recentralization risk?
```
Replace with:
```
              Who runs the privacy relay, and could it become a new central chokepoint?
```

- [ ] **Step 2: Insert Q3 lead paragraph**

Find exactly:
```html
          <p>
            <strong><a href="#gloss-ohttp" class="gloss">OHTTP</a> relay capability is built into
```
Replace with:
```html
          <p>
            The relay runs wherever you deploy it — colocated with your own node, not on Baur Software infrastructure. If you don't configure one, the protocol falls back to a direct connection: <code>relay_url</code> is optional, and when it's absent, the handshake continues without it. Privacy degrades — query structure becomes visible at the relay hop — but the session never breaks, and scope enforcement, expiring mandates, and co-signed receipts all work exactly the same.
          </p>
          <p>
            <strong><a href="#gloss-ohttp" class="gloss">OHTTP</a> relay capability is built into
```

- [ ] **Step 3: Commit**

```bash
git add docs/faq.html
git commit -m "docs(faq): humanize Q3 title and add plain-language lead"
```

---

### Task 4: Rewrite Q4 title and add lead paragraph

**Files:**
- Modify: `docs/faq.html` (around line 549)

- [ ] **Step 1: Replace Q4 title text**

Find exactly:
```
              What stops a Sybil flood of signed agent advertisements in Chrysalis?
```
Replace with:
```
              What stops someone from flooding the network with fake agents?
```

- [ ] **Step 2: Insert Q4 lead paragraph**

Find exactly:
```html
          <p>
            <strong>Vouch-based peer admission.</strong> Joining the Chrysalis mesh is not free —
```
Replace with:
```html
          <p>
            Getting a fake agent into the Chrysalis mesh takes real calendar time, not just compute. A new peer needs three vouches from existing members, each of whom can only vouch for three peers per year — and must themselves have been active for at least 90 days before they can vouch for anyone. New peers spend 60 days in a probationary state. The trust graph also checks path diversity: if your three vouchers all trace back through the same cluster of ancestors, the registration is rejected. You can't manufacture trust quickly; you have to earn it slowly.
          </p>
          <p>
            <strong>Vouch-based peer admission.</strong> Joining the Chrysalis mesh is not free —
```

- [ ] **Step 3: Commit**

```bash
git add docs/faq.html
git commit -m "docs(faq): humanize Q4 title and add plain-language lead"
```

---

### Task 5: Rewrite Q5 title and add lead paragraph

**Files:**
- Modify: `docs/faq.html` (around line 587)

- [ ] **Step 1: Replace Q5 title text**

Find exactly:
```
              Doesn't PAP's dependency on Schema.org create a governance capture risk?
```
Replace with:
```
              Google basically co-created Schema.org. Doesn't that give them leverage over PAP?
```

- [ ] **Step 2: Insert Q5 lead paragraph**

Find exactly:
```html
          <p>
            Schema.org is a <strong>collaborative, open-community project</strong> founded by Google,
```
Replace with:
```html
          <p>
            The protocol doesn't depend on Schema.org being controlled by anyone in particular. The action field in a mandate is a plain string — any namespace-prefixed identifier is valid. Schema.org is the default because it's widely understood and makes agents discoverable to everyone, but a financial compliance action, a FHIR operation, or a lab protocol step can be expressed as <code>operator:FhirReadAction</code> without touching Schema.org at all. The governance capture risk is real for the interoperability layer — agents that want to be universally discoverable benefit from Schema.org alignment. Agents targeting a specific vertical can use the <code>operator:</code> namespace freely.
          </p>
          <p>
            Schema.org is a <strong>collaborative, open-community project</strong> founded by Google,
```

- [ ] **Step 3: Commit**

```bash
git add docs/faq.html
git commit -m "docs(faq): humanize Q5 title and add plain-language lead"
```

---

### Task 6: Rewrite Q6 title and add lead paragraph

**Files:**
- Modify: `docs/faq.html` (around line 636)

- [ ] **Step 1: Replace Q6 title text**

Find exactly:
```
              Can an adversarial agent decompose a prohibited action into auto-approvable micro-actions?
```
Replace with:
```
              Could a malicious agent sneak around your restrictions by breaking one big ask into many small ones?
```

- [ ] **Step 2: Insert Q6 lead paragraph**

Find exactly:
```html
          <p>
            <a href="#gloss-scope" class="gloss">Scope containment</a> is <strong>cryptographically enforced at every delegation step</strong>.
```
Replace with:
```html
          <p>
            The mandate chain enforces scope cryptographically at every delegation step. Each child's scope must be a strict subset of its parent's, its TTL can't exceed its parent's, and the whole chain is hash-linked so nothing can be forged or reordered. An agent cannot ask for more than it was granted, regardless of how the request is phrased. The narrower residual risk: a sequence of zero-disclosure micro-actions — each individually below the approval threshold — could collectively achieve something a single equivalent request would have surfaced for review. The cryptographic bounds still hold at each step. The gap is at the semantic layer, not the authorization layer.
          </p>
          <p>
            <a href="#gloss-scope" class="gloss">Scope containment</a> is <strong>cryptographically enforced at every delegation step</strong>.
```

- [ ] **Step 3: Commit**

```bash
git add docs/faq.html
git commit -m "docs(faq): humanize Q6 title and add plain-language lead"
```

---

### Task 7: Rewrite Q7 title and add lead paragraph

**Files:**
- Modify: `docs/faq.html` (around line 672)

- [ ] **Step 1: Replace Q7 title text**

Find exactly:
```
              Doesn't prompt injection bypass all your cryptographic controls?
```
Replace with:
```
              Can't someone trick PAP with a prompt injection attack?
```

- [ ] **Step 2: Insert Q7 lead paragraph**

Find exactly:
```html
          <p>
            <strong>The premise needs clarifying.</strong> Papillon's intent router is a
```
Replace with:
```html
          <p>
            The parts of PAP that enforce what an agent can do are cryptographic, not textual. Your device-signed key authorizes scope — no injected text can change that. The routing step has three layers: direct URL detection (deterministic), BM25 scoring (pure math — k1=1.5, b=0.75, no model), and on-device LLM fallback only when confidence drops below 0.35. Even at the LLM layer, the output must match one of a fixed list of permitted action strings from the agent catalog — a hallucinated action that isn't on the list is discarded. The model receives your query text and the list of allowed action types. It cannot see your mandate, your session keys, or any prior disclosed values.
          </p>
          <p>
            <strong>The premise needs clarifying.</strong> Papillon's intent router is a
```

- [ ] **Step 3: Commit**

```bash
git add docs/faq.html
git commit -m "docs(faq): humanize Q7 title and add plain-language lead"
```

---

### Task 8: Rewrite Q8 title and add lead paragraph

**Files:**
- Modify: `docs/faq.html` (around line 730)

- [ ] **Step 1: Replace Q8 title text**

Find exactly:
```
              What are real-world p99 latencies in a 3-hop production chain?
```
Replace with:
```
              How fast is PAP in the real world — what are the actual latency numbers?
```

- [ ] **Step 2: Insert Q8 lead paragraph**

Find exactly:
```html
          <p>
            Measured loopback numbers from CI (<code>benches/baseline.json</code>):
```
Replace with:
```html
          <p>
            The loopback benchmarks — 2,000 runs each, 200 warmup — show full session lifecycle at 130 µs p50 / 500 µs p99, and a three-level mandate chain verification at 138.5 µs p50 / 480 µs p99. Those are on a single machine with no network hop, so they're best-case numbers. Real latency adds network RTT at each of the six protocol phases. One detail worth understanding: the HTTP path treats each phase as an independent POST and can be retried per-phase if a connection drops. The WebSocket path shares one persistent connection across all six phases — a drop requires starting a new session. Neither path is fail-open; errors propagate immediately to the caller.
          </p>
          <p>
            Measured loopback numbers from CI (<code>benches/baseline.json</code>):
```

- [ ] **Step 3: Commit**

```bash
git add docs/faq.html
git commit -m "docs(faq): humanize Q8 title and add plain-language lead"
```

---

### Task 9: Rewrite Q9 title and add lead paragraph

**Files:**
- Modify: `docs/faq.html` (around line 778)

- [ ] **Step 1: Replace Q9 title text**

Find exactly:
```
              How does PAP handle GDPR Article 17, HIPAA, and MiFID II?
```
Replace with:
```
              Does PAP satisfy GDPR, HIPAA, and financial regulations out of the box?
```

- [ ] **Step 2: Insert Q9 lead paragraph**

Find exactly:
```html
          <p>
            Receipts contain <strong>property references only, never values</strong>
```
Replace with:
```html
          <p>
            The hard parts are protocol invariants, not configuration. There's no central PAP server — nothing to breach at the platform level. Every session runs under a time-limited permission that decays on its own (Active → Degraded → ReadOnly → Suspended). Receipts store which <em>types</em> of data were accessed — <code>"schema:Person.dateOfBirth"</code> — never actual values. The episode store is local SQLite under your control. For stricter requirements — HIPAA no-retention policies, MiFID audit windows — those are configurable at deployment. Set <code>no_retention: true</code> on a disclosure entry and the protocol requires the receiving agent to run in a TEE, making the retention constraint cryptographically auditable rather than contractual.
          </p>
          <p>
            Receipts contain <strong>property references only, never values</strong>
```

- [ ] **Step 3: Commit**

```bash
git add docs/faq.html
git commit -m "docs(faq): humanize Q9 title and add plain-language lead"
```

---

### Task 10: Rewrite Q10 title and add lead paragraph

**Files:**
- Modify: `docs/faq.html` (around line 825)

- [ ] **Step 1: Replace Q10 title text**

Find exactly:
```
              What is the Python integration story for LangChain and CrewAI?
```
Replace with:
```
              How do I use PAP with Python, LangChain, or CrewAI?
```

- [ ] **Step 2: Insert Q10 lead paragraph**

Find exactly:
```html
          <p>
            <strong>Full PyO3 bindings ship today.</strong> <code>crates/pap-python/src/lib.rs</code>
```
Replace with:
```html
          <p>
            Full PyO3 bindings ship today. Async works correctly — the GIL is released during await, so concurrent handshakes don't block each other in asyncio pipelines. There's an integration guide covering LangChain, CrewAI, and MCP. The main friction right now: the package isn't on PyPI yet, so you build from source with <code>maturin develop --release</code>. For a team at the evaluation stage, that's a real speed bump. A zero-build-step <code>pip install pap</code> is on the roadmap.
          </p>
          <p>
            <strong>Full PyO3 bindings ship today.</strong> <code>crates/pap-python/src/lib.rs</code>
```

- [ ] **Step 3: Commit**

```bash
git add docs/faq.html
git commit -m "docs(faq): humanize Q10 title and add plain-language lead"
```

---

### Task 11: Rewrite Q11 title and add lead paragraph

**Files:**
- Modify: `docs/faq.html` (around line 867)

- [ ] **Step 1: Replace Q11 title text**

Find exactly:
```
              You've cryptographically secured the disclosure layer. How do you prevent the model itself from being the attack surface?
```
Replace with:
```
              If the AI model gets compromised, does your whole security model fall apart?
```

- [ ] **Step 2: Insert Q11 lead paragraph**

Find exactly:
```html
          <p>
            <strong>The LLM touches exactly one function in the PAP stack.</strong>
```
Replace with:
```html
          <p>
            No — and the reason is that the model is structurally isolated from anything security-critical. It has one job: pick one of the action strings you handed it. It receives your query text and a list of permitted action types from the agent catalog. It cannot see your mandate, your session keys, your principal identity, or any previously disclosed values. Its output must match one of the strings it was given — a hallucinated action is discarded. What the model controls is routing: which catalog agent handles your query. What it cannot touch is the mandate that governs what that agent is allowed to do. Those are signed by your device-bound key, which the model never sees. If you prefer no model at all, <code>LlmProvider::None</code> gives you the full protocol running deterministically.
          </p>
          <p>
            <strong>The LLM touches exactly one function in the PAP stack.</strong>
```

- [ ] **Step 3: Commit**

```bash
git add docs/faq.html
git commit -m "docs(faq): humanize Q11 title and add plain-language lead"
```

---

### Task 12: Rewrite Q12 title and add lead paragraph

**Files:**
- Modify: `docs/faq.html` (around line 926)

- [ ] **Step 1: Replace Q12 title text**

Find exactly:
```
              Our CISO won't deploy an agent framework without Okta / Azure AD integration. Does PAP have a SAML bridge?
```
Replace with:
```
              Our security team requires Okta or Azure AD. Is there an integration path?
```

- [ ] **Step 2: Insert Q12 lead paragraph**

Find exactly:
```html
          <p>
            <strong>The IdP question carries a centralized assumption PAP is designed to make
            unnecessary.</strong>
```
Replace with:
```html
          <p>
            The SAML bridge question assumes a hub-and-spoke model PAP is designed to make unnecessary. Instead of a central authority managing who has access, each agent protects itself — it declares what it requires, your orchestrator presents a cryptographically scoped mandate, and access is enforced at the edge with no IdP involved. When a mandate expires (default 8 hours), access stops without a deprovisioning call or a session token to revoke. For access tied to value exchange, the ecash layer issues blind-signed tokens using RFC 9474 RSABSSA-SHA384-PSS — the agent validates the token without learning who holds it, and receipts store only a commitment hash, never amounts or identities. What your security team actually needs maps to protocol mechanisms: access policy in mandate scope, audit trail in co-signed receipts (property type references, held locally by both parties), revocation through TTL decay.
          </p>
          <p>
            <strong>The IdP question carries a centralized assumption PAP is designed to make
            unnecessary.</strong>
```

- [ ] **Step 3: Commit**

```bash
git add docs/faq.html
git commit -m "docs(faq): humanize Q12 title and add plain-language lead"
```

---

### Task 13: Rewrite Q13 title, add lead paragraph, and fix SD-JWT accuracy bug

**Files:**
- Modify: `docs/faq.html` (around line 984)

- [ ] **Step 1: Replace Q13 title text**

Find exactly:
```
              We're a regulated financial institution / healthcare system. Walk me through how PAP operates inside our compliance framework.
```
Replace with:
```
              We're in healthcare or financial services. How does PAP fit our compliance requirements?
```

- [ ] **Step 2: Insert Q13 lead paragraph**

Find exactly:
```html
          <p>
            <strong>Most enterprise software achieves compliance by adding controls on top of a
            general-purpose system.</strong> PAP's compliance properties are protocol invariants —
            they hold because of cryptographic enforcement, not configuration. Here is what that
            means per framework.
          </p>
```
Replace with:
```html
          <p>
            Most enterprise software achieves compliance by adding controls on top of a general-purpose system. PAP's compliance properties are protocol invariants — they hold because of how the cryptography works, not because someone configured them correctly. No central server. Receipts store property type references like <code>"schema:Person.dateOfBirth"</code>, never the values. Every session runs under a mandate your device signed, specifying the exact agent, actions, data types, and duration. Access decays automatically without a deprovisioning step. For no-retention requirements, set <code>no_retention: true</code> on disclosure entries and the protocol requires the receiving agent to run in a TEE, making retention constraints auditable and binding. The 34 pre-built health and finance catalog agents (15 health, 19 finance) all require zero personal disclosure — public data sources only — giving you a no-PHI baseline to build from before you add anything sensitive.
          </p>
          <p>
            <strong>Most enterprise software achieves compliance by adding controls on top of a
            general-purpose system.</strong> PAP's compliance properties are protocol invariants —
            they hold because of cryptographic enforcement, not configuration. Here is what that
            means per framework.
          </p>
```

- [ ] **Step 3: Fix SD-JWT accuracy bug in Q13 body**

Find exactly:
```html
            <strong>HIPAA — Minimum Necessary Rule:</strong> Every agent session uses
            <a href="#gloss-sd-jwt" class="gloss">Selective Disclosure JWT</a>
            (<code>crates/pap-credential/src/sd_jwt.rs</code>) for claim-level
            cryptographic hiding. The mandate's <code>DisclosureSet</code>
```
Replace with:
```html
            <strong>HIPAA — Minimum Necessary Rule:</strong> The mandate's <code>DisclosureSet</code>
```

- [ ] **Step 4: Commit**

```bash
git add docs/faq.html
git commit -m "docs(faq): humanize Q13 title and lead, fix SD-JWT accuracy bug in HIPAA section"
```

---

### Task 14: Fix SD-JWT glossary entry

**Files:**
- Modify: `docs/faq.html` (around line 1078)

- [ ] **Step 1: Replace the inaccurate SD-JWT glossary description**

Find exactly:
```html
        <dd>A credential format that hides individual claim <em>values</em> via per-claim salted hashes. The orchestrator reveals only the property slots required by each agent — no more. Defined in <code>crates/pap-credential/src/sd_jwt.rs</code>.</dd>
```
Replace with:
```html
        <dd>A credential format that hides individual claim <em>values</em> via per-claim salted hashes. Available as an optional enhancement for credential-bearing payloads; not used in the current query handshake path — scope is instead bounded by the Mandate's <code>DisclosureSet</code> during Phase 2. Defined in <code>crates/pap-credential/src/sd_jwt.rs</code>.</dd>
```

- [ ] **Step 2: Verify accuracy fixes**

```bash
grep -n "Selective Disclosure JWT.*for claim-level" docs/faq.html
# Expected: no output (sentence removed from Q13)

grep -n "orchestrator reveals only the property slots" docs/faq.html
# Expected: no output (glossary fixed)
```

- [ ] **Step 3: Commit**

```bash
git add docs/faq.html
git commit -m "docs(faq): fix SD-JWT glossary entry — remove inaccurate orchestrator claim"
```

---

### Task 15: Final verification

**Files:**
- Read: `docs/faq.html`

- [ ] **Step 1: Verify all 13 titles changed**

```bash
grep -n "What is the enterprise identity story\|Do property reference patterns\|Who operates OHTTP\|What stops a Sybil\|Doesn't PAP's dependency\|Can an adversarial agent\|Doesn't prompt injection\|What are real-world p99\|How does PAP handle GDPR\|What is the Python integration\|You've cryptographically secured\|Our CISO won't deploy\|Walk me through how PAP" docs/faq.html
# Expected: no output — all old titles gone
```

- [ ] **Step 2: Verify all 13 leads present**

```bash
grep -c "faq-body" docs/faq.html
# Expected: 13 (one per question)

grep -n "PAP doesn't plug into Okta\|Yes, and we document it honestly\|The relay runs wherever you deploy\|Getting a fake agent\|The protocol doesn't depend on Schema.org\|The mandate chain enforces scope\|The parts of PAP that enforce\|The loopback benchmarks\|The hard parts are protocol invariants\|Full PyO3 bindings ship today\|No — and the reason is that the model\|The SAML bridge question\|Most enterprise software achieves compliance" docs/faq.html
# Expected: 13 lines — one match per lead
```

- [ ] **Step 3: Open in browser and spot-check**

Open `docs/faq.html` in a browser:
- Expand Q2 — plain-language lead appears, then "Yes — scoped to..." technical content follows
- Expand Q7 — plain-language lead appears, then "The premise needs clarifying" technical content follows
- Expand Q13 — plain-language lead appears, HIPAA section no longer opens with SD-JWT claim
- Check SD-JWT glossary entry reads correctly
- Click all 7 category filter pills — confirm filtering still works
- Confirm no layout breaks or double-spacing

- [ ] **Step 4: Final commit if any fixes needed**

```bash
git add docs/faq.html
git commit -m "docs(faq): final touchups from browser verification"
```
