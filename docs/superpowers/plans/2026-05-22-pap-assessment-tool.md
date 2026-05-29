# PAP Infrastructure Assessment Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single-file vanilla-JS assessment tool at `docs/assess.html` that collects infrastructure/security posture via a multi-step wizard, scores answers across five pillars, and produces a self-contained HTML report plus a plaintext summary for a `mailto:` handoff.

**Architecture:** One HTML file with an inline `<script>` organized in sections (config, state, questions, wizard rendering, scoring, report generation, report actions). The wizard view uses the site's shared CSS; the generated report embeds all CSS directly so it works standalone. No framework, no backend, no build step.

**Tech Stack:** HTML5, vanilla ES6 JavaScript, CSS3 (design tokens from `docs/assets/css/shared.css`).

---

## Files Overview

| File | Action | Purpose |
|------|--------|---------|
| `docs/assess.html` | **Create** | The assessment tool — wizard, scoring, report generation, and actions in one file |
| `docs/get-pap.html` | **Modify** | Add a link to `assess.html` from the "Start a Conversation" CTA section |

---

### Task 1: Create docs/assess.html — HTML Skeleton

**Files:**
- Create: `docs/assess.html`

This task establishes the page structure, loads shared assets, adds assessment-specific layout CSS, includes the site nav and footer, and creates the JavaScript module shell with named marker comments that later tasks will replace.

- [ ] **Step 1: Create the file with HTML skeleton, CSS, nav, and footer**

Create `docs/assess.html` with the following exact content. The JavaScript block contains unique marker comments (`// === MARKER ===`) that later tasks will match and replace with real code.

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <script>!function(){var t=localStorage.getItem('pap-theme');if(t)document.documentElement.dataset.theme=t}()</script>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PAP Infrastructure Assessment — Baur Software</title>
  <meta name="description" content="Evaluate your organization's infrastructure and security posture for deploying the Principal Agent Protocol.">
  <link rel="icon" type="image/x-icon" href="./favicon.ico">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;1,9..40,400&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <link href="https://api.fontshare.com/v2/css?f[]=satoshi@400,500,700,900&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="assets/css/shared.css">
  <style>
    /* Assessment-specific styles */
    main { padding-top: 64px; min-height: 100vh; }
    .assess-container { max-width: 720px; margin: 0 auto; padding: 48px 24px; }
    .assess-header { text-align: center; margin-bottom: 48px; }
    .assess-header h1 {
      font-family: var(--font-display); font-size: 2rem; font-weight: 700;
      letter-spacing: -.02em; margin-bottom: 12px;
    }
    .assess-header p { color: var(--muted); font-size: 1.05rem; }
    .progress-bar {
      display: flex; align-items: center; gap: 8px; margin-bottom: 32px;
      justify-content: center; flex-wrap: wrap;
    }
    .progress-step {
      display: flex; align-items: center; gap: 8px; font-size: .75rem;
      color: var(--faint); font-weight: 500; text-transform: uppercase;
      letter-spacing: .04em;
    }
    .progress-step.active { color: var(--indigo); }
    .progress-step.completed { color: var(--teal); }
    .progress-dot {
      width: 10px; height: 10px; border-radius: 50%; background: var(--border2);
      transition: background .2s ease;
    }
    .progress-step.active .progress-dot { background: var(--indigo); }
    .progress-step.completed .progress-dot { background: var(--teal); }
    .card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: var(--radius-lg); padding: 32px; margin-bottom: 24px;
    }
    .card h2 {
      font-family: var(--font-display); font-size: 1.3rem; font-weight: 700;
      margin-bottom: 8px;
    }
    .card .subtitle { color: var(--muted); font-size: .9rem; margin-bottom: 24px; }
    .question { margin-bottom: 28px; }
    .question-label {
      display: block; font-weight: 600; font-size: .95rem; margin-bottom: 12px;
      color: var(--text);
    }
    .question-required { color: var(--coral); margin-left: 4px; }
    .options { display: flex; flex-direction: column; gap: 10px; }
    .option-label {
      display: flex; align-items: flex-start; gap: 10px;
      padding: 10px 14px; border-radius: var(--radius);
      border: 1px solid var(--border); cursor: pointer; transition: all .15s ease;
      font-size: .9rem; color: var(--text);
    }
    .option-label:hover { border-color: var(--indigo); background: rgba(108,92,231,.06); }
    .option-label input { margin-top: 2px; accent-color: var(--indigo); }
    .option-label.selected { border-color: var(--indigo); background: rgba(108,92,231,.1); }
    .text-input, .textarea-input {
      width: 100%; padding: 12px 14px; border-radius: var(--radius);
      border: 1px solid var(--border); background: var(--surface2);
      color: var(--text); font-family: var(--font-body); font-size: .95rem;
      outline: none; transition: border-color .15s ease;
    }
    .text-input:focus, .textarea-input:focus { border-color: var(--indigo); }
    .textarea-input { min-height: 100px; resize: vertical; }
    .nav-buttons {
      display: flex; justify-content: space-between; align-items: center;
      margin-top: 32px;
    }
    .nav-buttons .btn { min-width: 120px; justify-content: center; }
    .skip-link {
      font-size: .85rem; color: var(--faint); cursor: pointer;
      background: none; border: none; text-decoration: underline;
    }
    .skip-link:hover { color: var(--muted); }
    .toast {
      position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%);
      background: var(--surface2); color: var(--text); padding: 12px 24px;
      border-radius: var(--radius); border: 1px solid var(--border);
      font-size: .9rem; z-index: 200; opacity: 0; transition: opacity .3s ease;
      pointer-events: none;
    }
    .toast.show { opacity: 1; }
    #report-view { display: none; }
    .report-actions {
      position: sticky; bottom: 0; left: 0; right: 0;
      background: var(--surface); border-top: 1px solid var(--border);
      padding: 16px 24px; display: flex; gap: 12px;
      justify-content: center; flex-wrap: wrap; z-index: 50;
    }
    @media (max-width: 600px) {
      .assess-header h1 { font-size: 1.5rem; }
      .card { padding: 20px; }
      .nav-buttons { flex-direction: column; gap: 12px; }
      .nav-buttons .btn { width: 100%; }
    }
    @media print {
      .report-actions, nav, footer, .progress-bar { display: none !important; }
    }
  </style>
</head>
<body>

<nav aria-label="Main navigation">
  <div class="nav-inner">
    <a href="index.html" class="nav-logo" aria-label="Baur Software">
      <img src="https://www.baursoftware.com/static/images/logo.png" alt="Baur Software logo">
      <span class="nav-wordmark">Baur Software</span>
    </a>
    <ul class="nav-links" role="list">
      <li><a href="pap/"><span class="nav-link-icon">pap://</span> PAP</a></li>
      <li><a href="papillon/"><img src="assets/images/papillon-icon.png" alt="" class="nav-link-icon-img"> Papillon</a></li>
      <li><a href="chrysalis.html"><img src="assets/images/chrysalis-icon.svg" alt="" class="nav-link-icon-img"> Chrysalis</a></li>
      <li><a href="extension/">Extension</a></li>
      <li><a href="faq.html">FAQ</a></li>
      <li><a href="get-pap.html">Work With Us</a></li>
    </ul>
    <div class="nav-cta">
      <button class="nav-theme-toggle" aria-label="Toggle light/dark mode" onclick="toggleTheme()">
        <svg class="icon-sun" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 18a6 6 0 1 1 0-12 6 6 0 0 1 0 12zm0-2a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM11 1h2v3h-2V1zm0 19h2v3h-2v-3zM3.515 4.929l1.414-1.414L7.05 5.636 5.636 7.05 3.515 4.93zM16.95 18.364l1.414-1.414 2.121 2.121-1.414 1.414-2.121-2.121zm2.121-14.85 1.414 1.415-2.121 2.121-1.414-1.414 2.121-2.121zM5.636 16.95l1.414 1.414-2.121 2.121-1.414-1.414 2.121-2.121zM23 11v2h-3v-2h3zM4 11v2H1v-2h3z"/></svg>
        <svg class="icon-moon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3a9 9 0 1 0 9 9c0-.46-.04-.92-.1-1.36a5.389 5.389 0 0 1-4.4 2.26 5.403 5.403 0 0 1-3.14-9.8c-.44-.06-.9-.1-1.36-.1z"/></svg>
      </button>
      <a href="get-pap.html" class="btn btn-work-with-us">Work With Us</a>
    </div>
  </div>
</nav>

<main>
  <div id="wizard-view" class="assess-container">
    <div class="assess-header">
      <h1>PAP Infrastructure Assessment</h1>
      <p>Evaluate your organization's readiness for trust-first agentic infrastructure.</p>
    </div>
    <div class="progress-bar" id="progress-bar" role="progressbar" aria-label="Assessment progress"></div>
    <div id="wizard-content"></div>
    <div class="nav-buttons" id="wizard-nav">
      <button class="btn btn-outline" id="btn-prev" style="visibility:hidden">Previous</button>
      <div style="display:flex;gap:12px;align-items:center">
        <button class="skip-link" id="btn-skip" style="display:none">Skip section</button>
        <button class="btn btn-primary" id="btn-next">Get Started</button>
      </div>
    </div>
  </div>
  <div id="report-view"></div>
</main>

<div class="toast" id="toast"></div>

<footer aria-label="Site footer" style="border-top:1px solid var(--border);padding:32px 0">
  <div class="container">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px;font-size:.85rem;color:var(--muted)">
      <div>&#169; 2026 Baur Software. Licensed MIT OR Apache-2.0.</div>
      <div style="display:flex;gap:16px">
        <a href="https://github.com/Baur-Software/pap" target="_blank" rel="noopener" style="color:var(--muted)">GitHub</a>
        <a href="https://github.com/Baur-Software/pap/blob/main/CONTRIBUTING.md" target="_blank" rel="noopener" style="color:var(--muted)">Contributing</a>
        <a href="https://baursoftware.com/contact" target="_blank" rel="noopener" style="color:var(--muted)">Contact</a>
      </div>
    </div>
  </div>
</footer>

<script>
(function() {
  'use strict';

  // === CONFIG ===

  // === STATE MANAGEMENT ===

  // === QUESTION DEFINITIONS ===

  // === WIZARD RENDERING ===

  // === SCORING LOGIC ===

  // === REPORT GENERATION ===

  // === REPORT ACTIONS ===

  // === EDGE CASES ===

  // === INIT ===

})();
</script>
<script src="assets/js/theme.js"></script>
</body>
</html>
```

- [ ] **Step 2: Verify file opens in browser**

Open `docs/assess.html` in a browser (can be via `file://` or a local server). Verify:
1. The page renders with the Baur Software nav and footer.
2. The heading "PAP Infrastructure Assessment" is visible.
3. The "Get Started" button is visible.
4. No console errors from `theme.js`.

- [ ] **Step 3: Commit**

```bash
git add docs/assess.html
git commit -m "feat(assessment): create assessment tool HTML skeleton"
```

---

### Task 2: Add Configuration, State Management, and Question Definitions

**Files:**
- Modify: `docs/assess.html` (script block)

Replace the three marker comments `// === CONFIG ===`, `// === STATE MANAGEMENT ===`, and `// === QUESTION DEFINITIONS ===` with real code.

- [ ] **Step 1: Read assess.html to confirm marker comments exist**

Run a quick grep to verify the three markers are present:
```bash
grep -n "=== CONFIG ===\|=== STATE MANAGEMENT ===\|=== QUESTION DEFINITIONS ===" docs/assess.html
```
Expected output: three lines with line numbers.

- [ ] **Step 2: Replace `// === CONFIG ===` with configuration constants**

```javascript
  const CONTACT_EMAIL = 'contact@baursoftware.com';
  const STORAGE_KEY = 'pap_assessment_state';
  const MAX_MAILTO_CHARS = 1800;

  // Maturity tier thresholds and labels
  const TIERS = [
    { max: 39,  label: 'Nascent',           desc: 'Significant gaps in trust infrastructure. PAP would be a foundational layer.', scope: 'Foundational Trust Layer Build' },
    { max: 59,  label: 'Developing',        desc: 'Some trust mechanisms exist but are not unified or agent-aware.', scope: 'Phased Integration with Trust Retrofit' },
    { max: 79,  label: 'Maturing',          desc: 'Good foundation; PAP adds selective disclosure and mandate scoping.', scope: 'Selective Disclosure & Federation Enablement' },
    { max: 100, label: 'Production-Ready',  desc: 'Strong posture; PAP enhances verifiability and federation.', scope: 'PAP Hardening & Multi-Principal Expansion' }
  ];
```

- [ ] **Step 3: Replace `// === STATE MANAGEMENT ===` with state logic**

```javascript
  let state = {
    role: null,
    currentSection: 0,
    answers: {},
    contact: { name: '', email: '', notes: '' }
  };

  function loadState() {
    try {
      const raw = sessionStorage.getItem(STORAGE_KEY);
      if (raw) {
        const saved = JSON.parse(raw);
        state = { ...state, ...saved };
        return true;
      }
    } catch (e) {
      console.warn('Failed to load assessment state:', e);
    }
    return false;
  }

  function saveState() {
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch (e) {
      console.warn('Failed to save assessment state:', e);
      showToast('Progress will not survive page refresh (storage unavailable)');
    }
  }

  function clearState() {
    try { sessionStorage.removeItem(STORAGE_KEY); } catch (e) {}
    state = { role: null, currentSection: 0, answers: {}, contact: { name: '', email: '', notes: '' } };
  }

  function setAnswer(qid, value) {
    state.answers[qid] = value;
    saveState();
  }

  function getAnswer(qid) {
    return state.answers[qid] ?? null;
  }

  function showToast(msg) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 3000);
  }
```

- [ ] **Step 4: Replace `// === QUESTION DEFINITIONS ===` with all question data**

```javascript
  // Sections and questions
  const SECTIONS = [
    {
      id: 'org',
      title: 'Organization Context',
      subtitle: 'Basic context about your organization and goals.',
      questions: [
        { id: 'q1_org', type: 'text', text: 'Organization name', required: true },
        { id: 'q1_size', type: 'radio', text: 'Approximate team size', required: true,
          options: [
            { value: '1-10', label: '1–10' },
            { value: '11-50', label: '11–50' },
            { value: '51-200', label: '51–200' },
            { value: '201-1000', label: '201–1000' },
            { value: '1000+', label: '1000+' }
          ] },
        { id: 'q1_industry', type: 'radio', text: 'Industry', required: true,
          options: [
            { value: 'technology', label: 'Technology' },
            { value: 'finance', label: 'Finance' },
            { value: 'healthcare', label: 'Healthcare' },
            { value: 'government', label: 'Government' },
            { value: 'energy', label: 'Energy' },
            { value: 'other', label: 'Other' }
          ] },
        { id: 'q1_agents', type: 'radio', text: 'Are you currently using AI agents in production?', required: true,
          options: [
            { value: 'extensive', label: 'Yes — extensively in production' },
            { value: 'pilot', label: 'Yes — pilot or limited production' },
            { value: 'evaluating', label: 'Evaluating — not yet deployed' },
            { value: 'no', label: 'No — not using AI agents today' }
          ] },
        { id: 'q1_timeline', type: 'radio', text: 'Desired timeline to evaluate or deploy PAP?', required: true,
          options: [
            { value: 'asap', label: 'ASAP' },
            { value: '3mo', label: 'Within 3 months' },
            { value: '6mo', label: 'Within 6 months' },
            { value: '12mo', label: 'Within 12 months' },
            { value: 'exploring', label: 'Just exploring — no fixed timeline' }
          ] }
      ]
    },
    {
      id: 'identity',
      title: 'Identity & Trust',
      subtitle: 'How your organization handles identity, keys, and trust boundaries.',
      questions: [
        { id: 'q2_idp', type: 'radio', text: 'Do you have a central identity provider (IdP) in production?', required: true,
          options: [
            { value: 'production', label: 'Yes — production IdP' },
            { value: 'evaluating', label: 'Yes — evaluating or partial deployment' },
            { value: 'no', label: 'No' }
          ] },
        { id: 'q2_keys', type: 'radio', text: 'How do you manage cryptographic keys for services?', required: true,
          options: [
            { value: 'hsm', label: 'Hardware Security Module (HSM) or Cloud KMS' },
            { value: 'software', label: 'Software key management with access controls' },
            { value: 'manual', label: 'Manual / secrets manager (no rotation)' },
            { value: 'no', label: 'No key management in place' }
          ] },
        { id: 'q2_audit', type: 'radio', text: 'Do you have audit logging for all API and agent actions?', required: true,
          options: [
            { value: 'full', label: 'Yes — comprehensive audit logging' },
            { value: 'partial', label: 'Partial — some systems covered' },
            { value: 'no', label: 'No' }
          ] },
        { id: 'q2_did', type: 'radio', text: 'Have you implemented or evaluated decentralized identifiers (DIDs)?', required: true,
          options: [
            { value: 'production', label: 'Yes — in production' },
            { value: 'evaluated', label: 'Yes — evaluated, not deployed' },
            { value: 'aware', label: 'Aware but not evaluated' },
            { value: 'no', label: 'No' }
          ] },
        { id: 'q2_mfa', type: 'radio', text: 'Is multi-factor authentication enforced for all administrative access?', required: true,
          options: [
            { value: 'enforced', label: 'Yes — enforced for all admin access' },
            { value: 'partial', label: 'Partial — some systems only' },
            { value: 'no', label: 'No' }
          ] },
        { id: 'q2_trust', type: 'radio', text: 'Is there a formal trust-boundary model for your agent systems?', required: true,
          options: [
            { value: 'documented', label: 'Yes — documented and maintained' },
            { value: 'informal', label: 'Informal — understood by team but not documented' },
            { value: 'no', label: 'No' }
          ] }
      ]
    },
    {
      id: 'agents',
      title: 'Agent Infrastructure',
      subtitle: 'Your current agent frameworks, orchestration, and observability.',
      questions: [
        { id: 'q3_frameworks', type: 'multi', text: 'What agent frameworks do you use? (Select all that apply)', required: false,
          options: [
            { value: 'langchain', label: 'LangChain' },
            { value: 'crewai', label: 'CrewAI' },
            { value: 'autogen', label: 'AutoGen' },
            { value: 'custom', label: 'Custom / in-house' },
            { value: 'none', label: 'None yet' }
          ] },
        { id: 'q3_orchestration', type: 'radio', text: 'How are your agents orchestrated?', required: true,
          options: [
            { value: 'central', label: 'Central orchestrator' },
            { value: 'distributed', label: 'Distributed / event-driven' },
            { value: 'adhoc', label: 'Ad-hoc / manual triggering' },
            { value: 'none', label: 'No orchestration' }
          ] },
        { id: 'q3_prod_data', type: 'radio', text: 'Do your agents access production data?', required: true,
          options: [
            { value: 'full', label: 'Yes — full production data access' },
            { value: 'restricted', label: 'Yes — with restrictions' },
            { value: 'sandbox', label: 'Sandbox / synthetic data only' },
            { value: 'no', label: 'No' }
          ] },
        { id: 'q3_observability', type: 'radio', text: 'Is there observability (logging, metrics, tracing) across all agent executions?', required: true,
          options: [
            { value: 'full', label: 'Yes — full observability' },
            { value: 'partial', label: 'Partial — some systems covered' },
            { value: 'no', label: 'No' }
          ] },
        { id: 'q3_registry', type: 'radio', text: 'Do you have a registry or catalog of agents and their capabilities?', required: true,
          options: [
            { value: 'yes', label: 'Yes' },
            { value: 'partial', label: 'Partial — informal list' },
            { value: 'no', label: 'No' }
          ] },
        { id: 'q3_workflows', type: 'radio', text: 'How many distinct agent workflows exist?', required: true,
          options: [
            { value: '1-5', label: '1–5' },
            { value: '6-20', label: '6–20' },
            { value: '21-100', label: '21–100' },
            { value: '100+', label: '100+' }
          ] }
      ]
    },
    {
      id: 'data',
      title: 'Data & Disclosure',
      subtitle: 'How you classify, steward, and disclose data in agent workflows.',
      questions: [
        { id: 'q4_classification', type: 'radio', text: 'Do you have a data classification policy (Public / Internal / Confidential / Restricted)?', required: true,
          options: [
            { value: 'enforced', label: 'Yes — enforced across all systems' },
            { value: 'documented', label: 'Yes — documented, partially enforced' },
            { value: 'informal', label: 'Informal — understood but not enforced' },
            { value: 'no', label: 'No' }
          ] },
        { id: 'q4_pii', type: 'radio', text: 'How is PII handled in agent workflows?', required: true,
          options: [
            { value: 'tokenized', label: 'Tokenized or anonymized before agent access' },
            { value: 'masked', label: 'Masked or redacted' },
            { value: 'raw_controls', label: 'Raw data with access controls only' },
            { value: 'no', label: 'No specific PII handling' }
          ] },
        { id: 'q4_regulations', type: 'multi', text: 'What regulations apply to your data? (Select all that apply)', required: false,
          options: [
            { value: 'gdpr', label: 'GDPR' },
            { value: 'hipaa', label: 'HIPAA' },
            { value: 'sox', label: 'SOX' },
            { value: 'ccpa', label: 'CCPA / CPRA' },
            { value: 'soc2', label: 'SOC 2' },
            { value: 'none', label: 'None of the above' }
          ] },
        { id: 'q4_residency', type: 'radio', text: 'Is there a data residency requirement?', required: true,
          options: [
            { value: 'single', label: 'Yes — single region / jurisdiction' },
            { value: 'multi', label: 'Yes — multi-region with constraints' },
            { value: 'none', label: 'No specific requirement' }
          ] },
        { id: 'q4_disclosure', type: 'radio', text: 'Do you implement selective disclosure today (only sharing minimum required data)?', required: true,
          options: [
            { value: 'systematic', label: 'Yes — systematic across workflows' },
            { value: 'partial', label: 'Partial — some workflows only' },
            { value: 'no', label: 'No' }
          ] },
        { id: 'q4_retention', type: 'radio', text: 'How long do you retain agent interaction logs?', required: true,
          options: [
            { value: '30d', label: 'Less than 30 days' },
            { value: '90d', label: '30–90 days' },
            { value: '1y', label: '90 days to 1 year' },
            { value: '1y+', label: 'More than 1 year' },
            { value: 'indefinite', label: 'Indefinite / no policy' }
          ] }
      ]
    },
    {
      id: 'integration',
      title: 'Integration Surface',
      subtitle: 'Your API surface, authentication patterns, and target SDKs.',
      questions: [
        { id: 'q5_protocols', type: 'multi', text: 'What API protocols do your agents use? (Select all that apply)', required: false,
          options: [
            { value: 'rest', label: 'REST' },
            { value: 'graphql', label: 'GraphQL' },
            { value: 'grpc', label: 'gRPC' },
            { value: 'websocket', label: 'WebSocket' },
            { value: 'other', label: 'Other' }
          ] },
        { id: 'q5_auth', type: 'multi', text: 'How are your APIs authenticated? (Select all that apply)', required: true,
          options: [
            { value: 'oauth', label: 'OAuth 2.0' },
            { value: 'mtls', label: 'mTLS' },
            { value: 'apikeys', label: 'API keys' },
            { value: 'jwt', label: 'JWT / custom tokens' },
            { value: 'none', label: 'No authentication' }
          ] },
        { id: 'q5_gateway', type: 'radio', text: 'Do you use an API gateway or service mesh?', required: true,
          options: [
            { value: 'production', label: 'Yes — in production' },
            { value: 'evaluating', label: 'Yes — evaluating' },
            { value: 'no', label: 'No' }
          ] },
        { id: 'q5_sdks', type: 'multi', text: 'Which SDK languages are most important for PAP integration? (Select all that apply)', required: false,
          options: [
            { value: 'rust', label: 'Rust' },
            { value: 'ts', label: 'TypeScript / JavaScript' },
            { value: 'python', label: 'Python' },
            { value: 'java', label: 'Java' },
            { value: 'cpp', label: 'C / C++' },
            { value: 'csharp', label: 'C#' },
            { value: 'go', label: 'Go' },
            { value: 'other', label: 'Other' }
          ] },
        { id: 'q5_ratelimit', type: 'radio', text: 'Do your APIs support rate limiting and throttling?', required: true,
          options: [
            { value: 'yes', label: 'Yes — all APIs' },
            { value: 'partial', label: 'Partial — some APIs only' },
            { value: 'no', label: 'No' }
          ] }
      ]
    },
    {
      id: 'goals',
      title: 'Goals & Contact',
      subtitle: 'What you want to achieve and how to reach you.',
      questions: [
        { id: 'q6_goals', type: 'multi', text: 'Primary goal for PAP (Select all that apply)', required: false,
          options: [
            { value: 'trust', label: 'Agent trust / attestation' },
            { value: 'disclosure', label: 'Selective disclosure' },
            { value: 'mandates', label: 'Mandate scoping' },
            { value: 'federation', label: 'Cross-organization federation' },
            { value: 'compliance', label: 'Audit / compliance' },
            { value: 'other', label: 'Other' }
          ] },
        { id: 'q6_concerns', type: 'textarea', text: 'What is your biggest concern about deploying PAP?', required: false },
        { id: 'q6_name', type: 'text', text: 'Your name', required: true },
        { id: 'q6_email', type: 'text', text: 'Your email address', required: true },
        { id: 'q6_notes', type: 'textarea', text: 'Additional notes', required: false }
      ]
    }
  ];

  // Role gate is a pseudo-section before SECTIONS[0]
  const ROLE_GATE = {
    id: 'role',
    title: 'Welcome',
    subtitle: 'What best describes your role? This helps us tailor the assessment.',
    questions: [
      { id: 'role', type: 'radio', text: 'Select your role', required: true,
        options: [
          { value: 'technical', label: 'Technical / Architect' },
          { value: 'security', label: 'Security / Compliance' },
          { value: 'product', label: 'Product / Engineering Lead' }
        ] }
    ]
  };
```

- [ ] **Step 5: Verify the file has no syntax errors**

Open `docs/assess.html` in a browser. Verify:
1. The page still renders without console errors.
2. In DevTools console, `SECTIONS` and `ROLE_GATE` are defined (type `SECTIONS.length` → expected `6`).

- [ ] **Step 6: Commit**

```bash
git add docs/assess.html
git commit -m "feat(assessment): add state management and question definitions"
```

---

### Task 3: Add Wizard Rendering Engine

**Files:**
- Modify: `docs/assess.html` (script block)

Replace `// === WIZARD RENDERING ===` with the full wizard rendering logic, including the entry gate, section rendering, question rendering, input handling, navigation, and progress bar.

- [ ] **Step 1: Read assess.html to confirm the `// === WIZARD RENDERING ===` marker exists**

```bash
grep -n "=== WIZARD RENDERING ===" docs/assess.html
```

- [ ] **Step 2: Replace the marker with wizard rendering functions**

```javascript
  const wizardContent = document.getElementById('wizard-content');
  const progressBar = document.getElementById('progress-bar');
  const btnPrev = document.getElementById('btn-prev');
  const btnNext = document.getElementById('btn-next');
  const btnSkip = document.getElementById('btn-skip');
  const wizardView = document.getElementById('wizard-view');

  function isRoleGate() {
    return state.role === null;
  }

  function currentSectionObj() {
    if (isRoleGate()) return ROLE_GATE;
    return SECTIONS[state.currentSection] || null;
  }

  function isLastSection() {
    return state.currentSection === SECTIONS.length - 1;
  }

  function renderProgress() {
    if (isRoleGate()) {
      progressBar.innerHTML = '<span style="color:var(--faint);font-size:.8rem">Role selection</span>';
      progressBar.setAttribute('aria-valuenow', '0');
      return;
    }
    const total = SECTIONS.length;
    const current = state.currentSection;
    let html = '';
    for (let i = 0; i < total; i++) {
      const stepClass = i < current ? 'completed' : i === current ? 'active' : '';
      html += `<div class="progress-step ${stepClass}"><span class="progress-dot"></span>${SECTIONS[i].title}</div>`;
      if (i < total - 1) html += '<span style="color:var(--border2)">→</span>';
    }
    progressBar.innerHTML = html;
    progressBar.setAttribute('aria-valuenow', String(current + 1));
    progressBar.setAttribute('aria-valuemax', String(total));
  }

  function renderQuestion(q) {
    const val = getAnswer(q.id);
    const requiredMark = q.required ? '<span class="question-required">*</span>' : '';
    let inputHtml = '';

    if (q.type === 'radio') {
      inputHtml = '<div class="options">' + q.options.map(opt => {
        const checked = val === opt.value ? 'checked' : '';
        const selectedClass = val === opt.value ? 'selected' : '';
        return `<label class="option-label ${selectedClass}" onclick="this.querySelector('input').click()">
          <input type="radio" name="${q.id}" value="${opt.value}" ${checked} onchange="window._papOnChange('${q.id}',this.value)">
          <span>${escapeHtml(opt.label)}</span>
        </label>`;
      }).join('') + '</div>';
    } else if (q.type === 'multi') {
      const arr = Array.isArray(val) ? val : [];
      inputHtml = '<div class="options">' + q.options.map(opt => {
        const checked = arr.includes(opt.value) ? 'checked' : '';
        const selectedClass = arr.includes(opt.value) ? 'selected' : '';
        return `<label class="option-label ${selectedClass}" onclick="event.preventDefault();window._papOnMultiToggle('${q.id}','${opt.value}')">
          <input type="checkbox" name="${q.id}" value="${opt.value}" ${checked}>
          <span>${escapeHtml(opt.label)}</span>
        </label>`;
      }).join('') + '</div>';
    } else if (q.type === 'text') {
      inputHtml = `<input type="text" class="text-input" value="${escapeHtml(val || '')}" oninput="window._papOnInput('${q.id}',this.value)">`;
    } else if (q.type === 'textarea') {
      inputHtml = `<textarea class="textarea-input" oninput="window._papOnInput('${q.id}',this.value)">${escapeHtml(val || '')}</textarea>`;
    }

    return `<div class="question" id="qwrap-${q.id}">
      <label class="question-label">${escapeHtml(q.text)}${requiredMark}</label>
      ${inputHtml}
    </div>`;
  }

  function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str.replace(/[&<>"']/g, m => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[m]));
  }

  // Expose handlers to window for inline event attributes
  window._papOnChange = (qid, value) => {
    setAnswer(qid, value);
    // Re-render to update selected styling
    renderSection();
  };
  window._papOnMultiToggle = (qid, value) => {
    let arr = Array.isArray(getAnswer(qid)) ? [...getAnswer(qid)] : [];
    if (arr.includes(value)) arr = arr.filter(v => v !== value);
    else arr.push(value);
    setAnswer(qid, arr);
    renderSection();
  };
  window._papOnInput = (qid, value) => {
    setAnswer(qid, value);
  };

  function renderSection() {
    const sec = currentSectionObj();
    if (!sec) {
      generateReport();
      return;
    }

    let html = `<div class="card">
      <h2>${escapeHtml(sec.title)}</h2>
      <p class="subtitle">${escapeHtml(sec.subtitle)}</p>`;

    for (const q of sec.questions) {
      html += renderQuestion(q);
    }

    html += '</div>';
    wizardContent.innerHTML = html;
    renderProgress();
    updateNavButtons();
  }

  function updateNavButtons() {
    if (isRoleGate()) {
      btnPrev.style.visibility = 'hidden';
      btnSkip.style.display = 'none';
      btnNext.textContent = 'Continue';
      return;
    }

    btnPrev.style.visibility = state.currentSection > 0 ? 'visible' : 'hidden';
    btnSkip.style.display = 'inline-block';
    btnNext.textContent = isLastSection() ? 'Generate Report' : 'Next';
  }

  function validateCurrentSection() {
    const sec = currentSectionObj();
    if (!sec) return true;
    for (const q of sec.questions) {
      if (!q.required) continue;
      const val = getAnswer(q.id);
      const isEmpty = val === null || val === '' || (Array.isArray(val) && val.length === 0);
      if (isEmpty) {
        showToast('Please answer all required questions before continuing.');
        const el = document.getElementById('qwrap-' + q.id);
        if (el) {
          el.style.borderLeft = '3px solid var(--coral)';
          el.style.paddingLeft = '12px';
          el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
        return false;
      }
    }
    return true;
  }

  function handleNext() {
    if (!validateCurrentSection()) return;

    if (isRoleGate()) {
      const roleVal = getAnswer('role');
      if (!roleVal) { showToast('Please select a role.'); return; }
      state.role = roleVal;
      state.currentSection = 0;
      saveState();
      renderSection();
      return;
    }

    if (isLastSection()) {
      // Save contact info from answers
      state.contact.name = getAnswer('q6_name') || '';
      state.contact.email = getAnswer('q6_email') || '';
      state.contact.notes = getAnswer('q6_notes') || '';
      saveState();
      generateReport();
      return;
    }

    state.currentSection += 1;
    saveState();
    renderSection();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function handlePrev() {
    if (isRoleGate()) return;
    if (state.currentSection > 0) {
      state.currentSection -= 1;
      saveState();
      renderSection();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } else {
      // Go back to role gate
      state.role = null;
      state.currentSection = 0;
      saveState();
      renderSection();
    }
  }

  function handleSkip() {
    const sec = currentSectionObj();
    if (!sec || isRoleGate()) return;
    for (const q of sec.questions) {
      if (getAnswer(q.id) === null) setAnswer(q.id, 'unknown');
    }
    showToast('Section skipped — marked as unknown.');
    handleNext();
  }

  function initWizard() {
    btnNext.addEventListener('click', handleNext);
    btnPrev.addEventListener('click', handlePrev);
    btnSkip.addEventListener('click', handleSkip);

    const hadState = loadState();
    renderSection();
    if (hadState && state.role !== null) {
      showToast('Resumed from previous session');
    }
  }
```

- [ ] **Step 3: Update the `// === INIT ===` marker to call `initWizard()`**

Replace `// === INIT ===` with:

```javascript
  initWizard();
```

- [ ] **Step 4: Add the `toggleTheme` helper**

Since the nav references `toggleTheme()`, add this before the IIFE or just before the closing `</script>` tag:

Replace `</script>` (the first closing script tag before `</script>
<script src="assets/js/theme.js"></script>`) with:

```javascript
  // Theme toggle is handled by theme.js; this stub prevents errors if called before load
  window.toggleTheme = window.toggleTheme || function() {
    const html = document.documentElement;
    const current = html.dataset.theme;
    const next = current === 'light' ? 'dark' : 'light';
    html.dataset.theme = next;
    localStorage.setItem('pap-theme', next);
  };
})();
</script>
<script src="assets/js/theme.js"></script>
```

- [ ] **Step 5: Verify wizard works in browser**

Open `docs/assess.html` in a browser and verify:
1. The role selection screen appears with three options.
2. Selecting a role and clicking "Continue" advances to Section 1 (Organization Context).
3. The progress bar shows "Organization Context → Identity & Trust → ...".
4. Filling out required questions and clicking "Next" advances through sections.
5. "Previous" goes back.
6. "Skip section" marks questions unknown and advances.
7. Refreshing mid-wizard restores progress (sessionStorage).
8. The "Generate Report" button appears on the last section.

- [ ] **Step 6: Commit**

```bash
git add docs/assess.html
git commit -m "feat(assessment): add wizard rendering engine with role gate and navigation"
```

---

### Task 4: Add Scoring Logic and Critical Gap Detection

**Files:**
- Modify: `docs/assess.html` (script block)

Replace `// === SCORING LOGIC ===` with the scoring implementation. This includes per-pillar raw score calculation, normalization to 100, tier determination, and critical gap detection.

- [ ] **Step 1: Read assess.html to confirm the `// === SCORING LOGIC ===` marker exists**

```bash
grep -n "=== SCORING LOGIC ===" docs/assess.html
```

- [ ] **Step 2: Replace the marker with scoring and gap functions**

```javascript
  function scoreIdentity(a) {
    let s = 0;
    if (a.q2_idp === 'production') s += 5;
    else if (a.q2_idp === 'evaluating') s += 3;
    if (a.q2_keys === 'hsm') s += 5;
    else if (a.q2_keys === 'software') s += 3;
    else if (a.q2_keys === 'manual') s += 1;
    if (a.q2_audit === 'full') s += 5;
    else if (a.q2_audit === 'partial') s += 3;
    if (a.q2_did === 'production') s += 5;
    else if (a.q2_did === 'evaluated') s += 3;
    else if (a.q2_did === 'aware') s += 1;
    if (a.q2_mfa === 'enforced') s += 5;
    else if (a.q2_mfa === 'partial') s += 3;
    if (a.q2_trust === 'documented') s += 5;
    else if (a.q2_trust === 'informal') s += 3;
    return Math.min(s, 30);
  }

  function scoreData(a) {
    let s = 0;
    if (a.q4_classification === 'enforced') s += 5;
    else if (a.q4_classification === 'documented') s += 3;
    else if (a.q4_classification === 'informal') s += 2;
    if (a.q4_pii === 'tokenized') s += 5;
    else if (a.q4_pii === 'masked') s += 3;
    else if (a.q4_pii === 'raw_controls') s += 2;
    // Regulations: count selected (excluding 'none')
    const regs = Array.isArray(a.q4_regulations) ? a.q4_regulations.filter(v => v !== 'none') : [];
    if (regs.length >= 4) s += 5;
    else if (regs.length >= 3) s += 4;
    else if (regs.length >= 2) s += 3;
    else if (regs.length >= 1) s += 2;
    if (a.q4_residency === 'single' || a.q4_residency === 'multi') s += 5;
    else if (a.q4_residency === 'none') s += 2;
    if (a.q4_disclosure === 'systematic') s += 5;
    else if (a.q4_disclosure === 'partial') s += 3;
    return Math.min(s, 25);
  }

  function scoreGovernance(a) {
    let s = 0;
    if (a.q1_agents === 'extensive') s += 5;
    else if (a.q1_agents === 'pilot') s += 4;
    else if (a.q1_agents === 'evaluating') s += 2;
    // API auth: count selected (excluding 'none')
    const auth = Array.isArray(a.q5_auth) ? a.q5_auth.filter(v => v !== 'none') : [];
    if (auth.length >= 2) s += 5;
    else if (auth.length === 1) s += 3;
    if (a.q5_ratelimit === 'yes') s += 5;
    else if (a.q5_ratelimit === 'partial') s += 3;
    if (a.q3_prod_data === 'restricted') s += 3;
    else if (a.q3_prod_data === 'sandbox') s += 4;
    else if (a.q3_prod_data === 'no') s += 2;
    return Math.min(s, 20);
  }

  function scoreAgents(a) {
    let s = 0;
    // Frameworks: any selected (excluding 'none')
    const fw = Array.isArray(a.q3_frameworks) ? a.q3_frameworks.filter(v => v !== 'none') : [];
    if (fw.length >= 2) s += 5;
    else if (fw.length === 1) s += 3;
    if (a.q3_orchestration === 'central') s += 5;
    else if (a.q3_orchestration === 'distributed') s += 4;
    else if (a.q3_orchestration === 'adhoc') s += 2;
    if (a.q3_observability === 'full') s += 5;
    else if (a.q3_observability === 'partial') s += 3;
    return Math.min(s, 15);
  }

  function scoreIntegration(a) {
    let s = 0;
    const protos = Array.isArray(a.q5_protocols) ? a.q5_protocols : [];
    if (protos.length >= 2) s += 3;
    else if (protos.length === 1) s += 2;
    if (a.q5_gateway === 'production') s += 3;
    else if (a.q5_gateway === 'evaluating') s += 2;
    const sdks = Array.isArray(a.q5_sdks) ? a.q5_sdks : [];
    if (sdks.length >= 2) s += 2;
    else if (sdks.length === 1) s += 1;
    if (a.q3_registry === 'yes') s += 2;
    else if (a.q3_registry === 'partial') s += 1;
    return Math.min(s, 10);
  }

  function calculateScores(answers) {
    const a = answers || {};
    const identity = scoreIdentity(a);
    const data = scoreData(a);
    const governance = scoreGovernance(a);
    const agents = scoreAgents(a);
    const integration = scoreIntegration(a);
    const rawTotal = identity + data + governance + agents + integration;
    const maxTotal = 30 + 25 + 20 + 15 + 10;
    const normalized = Math.round((rawTotal / maxTotal) * 100);
    return { identity, data, governance, agents, integration, total: normalized };
  }

  function getTier(total) {
    for (const t of TIERS) {
      if (total <= t.max) return t;
    }
    return TIERS[TIERS.length - 1];
  }

  function detectGaps(answers) {
    const a = answers || {};
    const gaps = [];
    if (a.q2_keys === 'no') {
      gaps.push({ text: 'No cryptographic key management detected', severity: 'Blocker', mitigation: 'Deploy an HSM, cloud KMS, or software key management system before PAP mandate signing.' });
    }
    const auth = Array.isArray(a.q5_auth) ? a.q5_auth : [];
    if (auth.length === 0 || (auth.length === 1 && auth[0] === 'none')) {
      gaps.push({ text: 'API surface lacks authentication', severity: 'Blocker', mitigation: 'Implement OAuth 2.0 or mTLS on all agent-facing APIs before adding PAP trust boundaries.' });
    }
    if (a.q2_audit === 'no') {
      gaps.push({ text: 'No audit logging for agent or API actions', severity: 'Warning', mitigation: 'Add structured audit logging to all agent execution paths.' });
    }
    if (a.q4_classification === 'no') {
      gaps.push({ text: 'No data classification policy', severity: 'Warning', mitigation: 'Establish a four-tier classification (Public / Internal / Confidential / Restricted) before selective disclosure design.' });
    }
    if ((a.q1_agents === 'extensive' || a.q1_agents === 'pilot') && a.q3_prod_data === 'full') {
      gaps.push({ text: 'Agents have unrestricted production data access', severity: 'Warning', mitigation: 'Scope agent data access to sandbox or tokenized pipelines before PAP mandate scoping.' });
    }
    if ((a.q1_agents === 'extensive' || a.q1_agents === 'pilot') && a.q3_observability === 'no') {
      gaps.push({ text: 'Agent executions lack observability', severity: 'Warning', mitigation: 'Add logging, metrics, or tracing to all agent workflows before trust attestation.' });
    }
    return gaps;
  }

  function getComplexity(gaps, total) {
    const blockers = gaps.filter(g => g.severity === 'Blocker').length;
    if (blockers >= 2 || total < 30) return 'Complex';
    if (blockers === 1 || total < 60) return 'Standard';
    return 'Light';
  }
```

- [ ] **Step 3: Verify scoring in browser console**

Open `docs/assess.html`, fill out all sections, then before clicking "Generate Report", open DevTools console and run:

```javascript
const s = calculateScores(state.answers);
console.log(s);
```

Expected: an object with `identity`, `data`, `governance`, `agents`, `integration`, and `total` (0–100).

Also test `detectGaps(state.answers)` and verify it returns an array of gap objects with `text`, `severity`, and `mitigation`.

- [ ] **Step 4: Commit**

```bash
git add docs/assess.html
git commit -m "feat(assessment): add scoring logic and critical gap detection"
```

---

### Task 5: Add Report Generation

**Files:**
- Modify: `docs/assess.html` (script block)

Replace `// === REPORT GENERATION ===` with the `generateReport()` function and the `generateReportHTML(state)` helper. The generated report is a complete, self-contained HTML document string with inlined CSS.

- [ ] **Step 1: Read assess.html to confirm the `// === REPORT GENERATION ===` marker exists**

```bash
grep -n "=== REPORT GENERATION ===" docs/assess.html
```

- [ ] **Step 2: Replace the marker with report generation functions**

```javascript
  function generateReport() {
    const reportHtml = generateReportHTML(state);
    const reportView = document.getElementById('report-view');
    const wizardView = document.getElementById('wizard-view');

    // Hide wizard, show report
    wizardView.style.display = 'none';
    reportView.style.display = 'block';
    reportView.innerHTML = reportHtml;

    // Scroll to top
    window.scrollTo(0, 0);
  }

  function generateReportHTML(st) {
    const scores = calculateScores(st.answers);
    const tier = getTier(scores.total);
    const gaps = detectGaps(st.answers);
    const complexity = getComplexity(gaps, scores.total);
    const orgName = escapeHtml(st.answers.q1_org || 'Unnamed Organization');
    const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

    // Color by tier
    let scoreColor = '#e8706a'; // coral
    if (scores.total >= 80) scoreColor = '#6c5ce7';
    else if (scores.total >= 60) scoreColor = '#2ec4a0';
    else if (scores.total >= 40) scoreColor = '#f0a030';

    // Build snapshot rows
    let snapshotRows = '';
    for (const sec of SECTIONS) {
      for (const q of sec.questions) {
        const val = st.answers[q.id];
        let display = 'Unknown — follow-up needed';
        if (val !== null && val !== undefined && val !== '') {
          if (Array.isArray(val)) {
            if (val.length === 0) display = 'None selected';
            else {
              const labels = val.map(v => {
                const opt = q.options ? q.options.find(o => o.value === v) : null;
                return opt ? opt.label : v;
              });
              display = labels.join(', ');
            }
          } else {
            const opt = q.options ? q.options.find(o => o.value === val) : null;
            display = opt ? opt.label : val;
          }
        }
        snapshotRows += `<tr><td style="padding:10px 12px;border-bottom:1px solid #e6e5ee;color:#5c5b70;font-size:.85rem;width:35%"><strong>${escapeHtml(q.text)}</strong></td><td style="padding:10px 12px;border-bottom:1px solid #e6e5ee;color:#1a1928;font-size:.85rem">${escapeHtml(display)}</td></tr>`;
      }
    }

    // Build gaps HTML
    let gapsHtml = '';
    if (gaps.length === 0) {
      gapsHtml = '<p style="color:#2ec4a0;font-weight:600">No critical gaps detected. Strong foundation for PAP deployment.</p>';
    } else {
      gapsHtml = '<ul style="list-style:none;padding:0;margin:0">' + gaps.map(g => {
        const icon = g.severity === 'Blocker' ? '&#10060;' : '&#9888;&#65039;';
        const color = g.severity === 'Blocker' ? '#e8706a' : '#f0a030';
        return `<li style="margin-bottom:14px;padding:12px;border-radius:8px;background:#faf9fc;border-left:4px solid ${color}">
          <div style="font-weight:700;color:${color};margin-bottom:4px">${icon} ${escapeHtml(g.text)} (${g.severity})</div>
          <div style="color:#5c5b70;font-size:.9rem">${escapeHtml(g.mitigation)}</div>
        </li>`;
      }).join('') + '</ul>';
    }

    // Narrative
    const roleLabels = { technical: 'Technical / Architect', security: 'Security / Compliance', product: 'Product / Engineering Lead' };
    const roleText = roleLabels[st.role] || 'Mixed';
    const narrative = `
      <p style="margin-bottom:12px">Based on the <strong>${roleText}</strong> perspective provided, your organization's overall trust posture scores <strong>${scores.total} / 100</strong>, placing it in the <strong style="color:${scoreColor}">${tier.label}</strong> tier. This means ${tier.desc}</p>
      <p style="margin-bottom:12px">The biggest gap${gaps.length === 1 ? ' we see is' : 's we see are'} ${gaps.length > 0 ? gaps.slice(0, 2).map(g => g.text.toLowerCase()).join(' and ') + '.' : 'minimal — your foundation is solid.'}</p>
      <p style="margin-bottom:12px">A PAP deployment would likely focus first on ${gaps.length > 0 ? gaps[0].mitigation.split('before')[0].toLowerCase() + '.' : 'extending existing trust boundaries with mandate scoping and selective disclosure.'}</p>
      <p>Estimated engagement complexity: <strong>${complexity}</strong>.</p>
    `;

    // Bar chart helper
    function bar(score, max) {
      const pct = Math.round((score / max) * 100);
      const filled = Math.round(pct / 10);
      const empty = 10 - filled;
      return `<span style="font-family:'SF Mono',monospace;font-size:.85rem;color:#1a1928">${String(score).padStart(2,' ')} / ${max}</span> <span style="color:#6c5ce7">${'█'.repeat(filled)}</span><span style="color:#d0cfdc">${'█'.repeat(empty)}</span>`;
    }

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PAP Assessment Report — ${orgName}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;1,9..40,400&family=JetBrains+Mono:wght@400;500;600&display=swap');
  @import url('https://api.fontshare.com/v2/css?f[]=satoshi@400,500,700,900&display=swap');
  body { font-family:'DM Sans',-apple-system,sans-serif; background:#faf9fc; color:#1a1928; line-height:1.6; margin:0; padding:0; -webkit-font-smoothing:antialiased; }
  .container { max-width:800px; margin:0 auto; padding:48px 24px; }
  h1,h2,h3 { font-family:'Satoshi',-apple-system,sans-serif; font-weight:700; letter-spacing:-.02em; }
  h1 { font-size:1.8rem; margin-bottom:8px; }
  h2 { font-size:1.3rem; margin-top:40px; margin-bottom:16px; padding-bottom:8px; border-bottom:2px solid #6c5ce7; }
  .header { text-align:center; margin-bottom:40px; }
  .header .logo { font-family:'Satoshi'; font-weight:900; font-size:1.1rem; color:#6c5ce7; margin-bottom:8px; }
  .header .date { color:#8888a0; font-size:.85rem; }
  .score-box { text-align:center; padding:32px; background:#f0eff5; border-radius:12px; margin-bottom:32px; }
  .score-number { font-family:'Satoshi'; font-size:3.5rem; font-weight:900; line-height:1; }
  .score-label { font-size:1rem; font-weight:600; margin-top:8px; }
  .score-desc { color:#5c5b70; font-size:.9rem; margin-top:4px; }
  .pillar { display:flex; align-items:center; justify-content:space-between; padding:10px 0; border-bottom:1px solid #e6e5ee; }
  .pillar-name { font-weight:600; font-size:.9rem; }
  .pillar-bar { font-family:'JetBrains Mono','SF Mono',monospace; font-size:.85rem; }
  table { width:100%; border-collapse:collapse; margin-top:12px; }
  th { text-align:left; padding:10px 12px; background:#f0eff5; font-size:.8rem; text-transform:uppercase; letter-spacing:.04em; color:#5c5b70; }
  .footer { text-align:center; margin-top:48px; padding-top:24px; border-top:1px solid #d0cfdc; color:#8888a0; font-size:.8rem; }
  @media print { body { background:#fff; } .container { padding:24px; } }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="logo">Baur Software</div>
    <h1>PAP Infrastructure Assessment Report</h1>
    <div class="date">${dateStr}</div>
  </div>

  <div class="score-box">
    <div class="score-number" style="color:${scoreColor}">${scores.total}</div>
    <div style="color:#8888a0;font-size:.9rem;margin-bottom:8px">/ 100</div>
    <div class="score-label" style="color:${scoreColor}">${tier.label}</div>
    <div class="score-desc">${tier.desc}</div>
  </div>

  <h2>Executive Summary</h2>
  <div style="font-size:.95rem;color:#1a1928">${narrative}</div>

  <h2>Score Breakdown</h2>
  <div class="pillar"><span class="pillar-name">Identity &amp; Trust</span><span class="pillar-bar">${bar(scores.identity, 30)}</span></div>
  <div class="pillar"><span class="pillar-name">Data Stewardship</span><span class="pillar-bar">${bar(scores.data, 25)}</span></div>
  <div class="pillar"><span class="pillar-name">Governance &amp; Compliance</span><span class="pillar-bar">${bar(scores.governance, 20)}</span></div>
  <div class="pillar"><span class="pillar-name">Agent Infrastructure</span><span class="pillar-bar">${bar(scores.agents, 15)}</span></div>
  <div class="pillar"><span class="pillar-name">Integration Surface</span><span class="pillar-bar">${bar(scores.integration, 10)}</span></div>

  <h2>Critical Gaps</h2>
  ${gapsHtml}

  <h2>Infrastructure Snapshot</h2>
  <table>
    <thead><tr><th>Question</th><th>Response</th></tr></thead>
    <tbody>${snapshotRows}</tbody>
  </table>

  <h2>Recommended Engagement Scope</h2>
  <p style="font-weight:600;font-size:1.05rem;color:#6c5ce7">${tier.scope}</p>

  <h2>Next Steps</h2>
  <ul style="padding-left:20px;color:#1a1928;font-size:.95rem">
    ${gaps.length > 0 ? gaps.map(g => `<li>${escapeHtml(g.mitigation)}</li>`).join('') : '<li>Schedule a PAP architecture review to extend your strong foundation with mandate scoping and selective disclosure.</li>'}
  </ul>

  <h2>Contact &amp; Notes</h2>
  <table>
    <tbody>
      <tr><td style="padding:10px 12px;border-bottom:1px solid #e6e5ee;color:#5c5b70;font-size:.85rem;width:35%"><strong>Name</strong></td><td style="padding:10px 12px;border-bottom:1px solid #e6e5ee;color:#1a1928;font-size:.85rem">${escapeHtml(st.contact.name || '—')}</td></tr>
      <tr><td style="padding:10px 12px;border-bottom:1px solid #e6e5ee;color:#5c5b70;font-size:.85rem"><strong>Email</strong></td><td style="padding:10px 12px;border-bottom:1px solid #e6e5ee;color:#1a1928;font-size:.85rem">${escapeHtml(st.contact.email || '—')}</td></tr>
      <tr><td style="padding:10px 12px;border-bottom:1px solid #e6e5ee;color:#5c5b70;font-size:.85rem"><strong>Notes</strong></td><td style="padding:10px 12px;border-bottom:1px solid #e6e5ee;color:#1a1928;font-size:.85rem;white-space:pre-wrap">${escapeHtml(st.contact.notes || '—')}</td></tr>
    </tbody>
  </table>

  <div class="footer">
    Generated by the PAP Infrastructure Assessment Tool &middot; <a href="https://baur-software.github.io/pap/get-pap.html" style="color:#8888a0">Work With Us</a>
  </div>
</div>
</body>
</html>`;
  }
```

- [ ] **Step 3: Verify report generation in browser**

Open `docs/assess.html`, fill out all sections, and click "Generate Report". Verify:
1. The wizard disappears and a styled report appears in the same page.
2. The report shows the organization name, date, large score number, tier label, narrative, pillar bars, critical gaps, snapshot table, engagement scope, next steps, and contact info.
3. The report uses the correct colors (coral for low, gold, teal, violet for high).
4. The score math is reasonable (0–100).
5. Gaps appear with correct severity icons.

- [ ] **Step 4: Commit**

```bash
git add docs/assess.html
git commit -m "feat(assessment): add report generation with self-contained HTML output"
```

---

### Task 6: Add Report Actions, Edge Cases, and Polish

**Files:**
- Modify: `docs/assess.html` (script block)

Replace `// === REPORT ACTIONS ===` and `// === EDGE CASES ===` with the action bar, download/mailto/clipboard logic, back-button handling, and edge-case guards.

- [ ] **Step 1: Read assess.html to confirm the two markers exist**

```bash
grep -n "=== REPORT ACTIONS ===\|=== EDGE CASES ===" docs/assess.html
```

- [ ] **Step 2: Replace `// === REPORT ACTIONS ===` with action functions**

```javascript
  function setupReportActions() {
    const reportView = document.getElementById('report-view');
    // Create action bar if not present
    let bar = document.getElementById('report-action-bar');
    if (!bar) {
      bar = document.createElement('div');
      bar.id = 'report-action-bar';
      bar.className = 'report-actions';
      bar.innerHTML = `
        <button class="btn btn-outline" onclick="window._papDownloadReport()">Download Report (.html)</button>
        <button class="btn btn-primary" onclick="window._papSendEmail()">Send to Baur Software</button>
        <button class="btn btn-outline" onclick="window._papCopySummary()">Copy Summary</button>
        <button class="btn btn-outline" onclick="window._papBackToWizard()">Back to Assessment</button>
      `;
      document.body.appendChild(bar);
    }
  }

  window._papDownloadReport = () => {
    const html = generateReportHTML(state);
    const org = (state.answers.q1_org || 'assessment').replace(/[^a-z0-9]/gi, '-').toLowerCase();
    const date = new Date().toISOString().slice(0, 10);
    const filename = `pap-assessment-${org}-${date}.html`;
    const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Report downloaded');
  };

  function generateMailtoSummary(st) {
    const scores = calculateScores(st.answers);
    const tier = getTier(scores.total);
    const gaps = detectGaps(st.answers);
    const org = st.answers.q1_org || 'Unnamed Organization';
    let body = `PAP Infrastructure Assessment Summary
=====================================

Organization: ${org}
Role: ${st.role || 'Unknown'}
Readiness Score: ${scores.total} / 100
Maturity Tier: ${tier.label}

Pillar Breakdown:
• Identity & Trust            ${String(scores.identity).padStart(2, ' ')} / 30
• Data Stewardship            ${String(scores.data).padStart(2, ' ')} / 25
• Governance & Compliance     ${String(scores.governance).padStart(2, ' ')} / 20
• Agent Infrastructure        ${String(scores.agents).padStart(2, ' ')} / 15
• Integration Surface         ${String(scores.integration).padStart(2, ' ')} / 10

Critical Gaps:
`;
    if (gaps.length === 0) {
      body += '• None detected\n';
    } else {
      for (const g of gaps) {
        body += `• ${g.text} (${g.severity})\n`;
      }
    }
    body += `
Recommended Scope:
${tier.scope}

Contact: ${st.contact.email || 'Not provided'}
Notes: ${(st.contact.notes || '').slice(0, 400)}

Please attach the downloaded .html report for full details.
`;
    // Truncate if too long
    if (body.length > MAX_MAILTO_CHARS) {
      const truncated = body.slice(0, MAX_MAILTO_CHARS - 50);
      body = truncated + '\n\n(full details in attached report)';
    }
    return body;
  }

  window._papSendEmail = () => {
    const subject = `PAP Infrastructure Assessment — ${state.answers.q1_org || 'Unknown Organization'}`;
    const body = generateMailtoSummary(state);
    const url = `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
    window.location.href = url;
  };

  window._papCopySummary = () => {
    const text = generateMailtoSummary(state);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => showToast('Summary copied to clipboard'));
    } else {
      // Fallback
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showToast('Summary copied to clipboard');
    }
  };

  window._papBackToWizard = () => {
    const reportView = document.getElementById('report-view');
    const wizardView = document.getElementById('wizard-view');
    reportView.style.display = 'none';
    reportView.innerHTML = '';
    wizardView.style.display = 'block';
    // Hide action bar
    const bar = document.getElementById('report-action-bar');
    if (bar) bar.style.display = 'none';
    renderSection();
    window.scrollTo(0, 0);
  };

  // Hook report generation to also set up actions
  const _originalGenerateReport = generateReport;
  generateReport = function() {
    _originalGenerateReport();
    setupReportActions();
  };
```

- [ ] **Step 3: Replace `// === EDGE CASES ===` with edge-case guards**

```javascript
  // Edge case: if all questions are skipped/unknown, override narrative
  function sanitizeState() {
    if (!state.answers) state.answers = {};
    // Ensure contact fields exist
    if (!state.contact) state.contact = { name: '', email: '', notes: '' };
  }

  // Wrap initWizard to sanitize first
  const _origInitWizard = initWizard;
  initWizard = function() {
    sanitizeState();
    // Detect if user is returning from a completed report
    const reportView = document.getElementById('report-view');
    if (reportView && reportView.style.display === 'block') {
      reportView.style.display = 'none';
      document.getElementById('wizard-view').style.display = 'block';
    }
    _origInitWizard();
  };
```

- [ ] **Step 4: Verify all actions in browser**

Open `docs/assess.html`, complete the wizard, and verify:
1. **Download Report** — triggers a file download of `.html`. Open the downloaded file: it should render identically to the in-page report, with no external dependencies.
2. **Send to Baur Software** — opens the system email client with a pre-filled subject and plaintext summary body. Check that body length is reasonable and not truncated unless answers are very long.
3. **Copy Summary** — copies plaintext summary to clipboard; verify by pasting into a text editor.
4. **Back to Assessment** — returns to the wizard on the last section, with all answers preserved.
5. Refresh while on the report: you return to the wizard (not a blank report).

- [ ] **Step 5: Commit**

```bash
git add docs/assess.html
git commit -m "feat(assessment): add report actions, email handoff, and edge-case guards"
```

---

### Task 7: Link from get-pap.html

**Files:**
- Modify: `docs/get-pap.html`

- [ ] **Step 1: Read get-pap.html around the CTA section**

Find the CTA section in `docs/get-pap.html` (around line 242–267). The target is the paragraph inside `#cta` that says:
> "Tell us about your current stack and where you want to go. We'll put together a scoped engagement proposal within a few business days."

- [ ] **Step 2: Insert assessment link before the CTA buttons**

Edit `docs/get-pap.html`. Find this exact HTML block:

```html
      <p class="reveal reveal-delay-2">
        Tell us about your current stack and where you want to go. We'll put together
        a scoped engagement proposal within a few business days.
      </p>
      <div class="cta-buttons reveal reveal-delay-3">
```

Replace it with:

```html
      <p class="reveal reveal-delay-2">
        Tell us about your current stack and where you want to go. We'll put together
        a scoped engagement proposal within a few business days.
      </p>
      <p class="reveal reveal-delay-2" style="margin-top:16px">
        <a href="assess.html" style="color:var(--indigo);font-weight:600">Not sure where to start? Take the 5-minute PAP Infrastructure Assessment &#8594;</a>
      </p>
      <div class="cta-buttons reveal reveal-delay-3">
```

- [ ] **Step 3: Verify the link renders correctly**

Open `docs/get-pap.html` in a browser, scroll to the CTA section, and verify:
1. The new link "Not sure where to start? Take the 5-minute PAP Infrastructure Assessment →" appears above the "Start a Conversation" button.
2. Clicking it navigates to `assess.html`.

- [ ] **Step 4: Commit**

```bash
git add docs/get-pap.html
git commit -m "feat(assessment): add link to assessment tool from get-pap page"
```

---

## Self-Review Checklist

- [ ] **Spec coverage:** Every requirement from `docs/superpowers/specs/2026-05-22-pap-assessment-tool-design.md` is covered by at least one task.
  - Single-file tool at `docs/assess.html` — **Task 1**
  - Role gate with three tracks — **Task 3**
  - Six sections, ~25–35 questions — **Task 2**
  - Trust-first scoring (30/25/20/15/10) — **Task 4**
  - Maturity tiers (Nascent / Developing / Maturing / Production-Ready) — **Task 4**
  - Critical gap detection — **Task 4**
  - Self-contained HTML report with inlined CSS — **Task 5**
  - Plaintext summary for mailto — **Task 6**
  - Blob download of `.html` — **Task 6**
  - `sessionStorage` persistence — **Task 2, 3**
  - `file://` compatibility — **Task 5, 6**
  - Print styles — **Task 1** (CSS `@media print`)
  - Accessibility (labels, aria-live, progressbar) — **Task 1, 3**
  - Link from `get-pap.html` — **Task 7**

- [ ] **Placeholder scan:** No TBD, TODO, or vague steps remain. Every step contains exact code, file paths, or verification commands.

- [ ] **Type consistency:** `state.answers`, `calculateScores`, `detectGaps`, `generateReportHTML`, and `generateMailtoSummary` use consistent property names (`q1_org`, `q2_keys`, etc.) across all tasks.

- [ ] **No gaps:** The plan produces a fully working single-file assessment tool. All 7 tasks are necessary and ordered correctly (wizard → scoring → report → actions → link).
