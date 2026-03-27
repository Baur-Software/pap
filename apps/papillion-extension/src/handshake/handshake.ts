/**
 * Handshake page — 6-phase PAP handshake UI.
 *
 * Reads ?uri= from URL params, shows a setup form, starts the handshake
 * on button click, and displays real-time phase progress + results.
 *
 * All JSON-LD content is rendered as text only — never innerHTML.
 */

import type { ExtensionMessage } from "../lib/types.js";

// ── Phase definitions ──────────────────────────────────────────────────

const PHASES = [
  { num: 1, name: "Token Presentation", icon: "1" },
  { num: 2, name: "DID Exchange", icon: "2" },
  { num: 3, name: "Selective Disclosure", icon: "3" },
  { num: 4, name: "Execution", icon: "4" },
  { num: 5, name: "Receipt Co-signing", icon: "5" },
  { num: 6, name: "Close Session", icon: "6" },
] as const;

// ── DOM References ─────────────────────────────────────────────────────

const $ = (id: string) => document.getElementById(id)!;
const uriEl = $("uri");
const setupSection = $("setup-section");
const phasesSection = $("phases-section");
const resultSection = $("result-section");
const receiptSection = $("receipt-section");
const errorSection = $("error-section");
const pipeline = $("pipeline");
const resultContainer = $("result-container");
const receiptContainer = $("receipt-container");
const errorMessage = $("error-message");
const startBtn = $("start-btn") as HTMLButtonElement;
const retryBtn = $("retry-btn");
const actionInput = $("action-input") as HTMLInputElement;
const queryInput = $("query-input") as HTMLInputElement;

// ── State ──────────────────────────────────────────────────────────────

const params = new URLSearchParams(window.location.search);
const uri = params.get("uri") || "";
let currentPhase = 0;
let activeSessionId: string | null = null;

// ── Initialize ─────────────────────────────────────────────────────────

uriEl.textContent = uri;
document.title = `PAP — ${uri}`;

if (params.has("action")) {
  actionInput.value = params.get("action")!;
}
if (params.has("query")) {
  queryInput.value = params.get("query")!;
}

renderPipeline();

// ── Pipeline Rendering ─────────────────────────────────────────────────

function renderPipeline() {
  pipeline.innerHTML = "";
  for (const phase of PHASES) {
    const el = document.createElement("div");
    el.className = "hs-phase pending";
    el.dataset.phase = String(phase.num);

    const dot = document.createElement("div");
    dot.className = "hs-phase-dot";
    dot.textContent = phase.icon;

    const info = document.createElement("div");
    info.className = "hs-phase-info";

    const name = document.createElement("div");
    name.className = "hs-phase-name";
    name.textContent = phase.name;

    const label = document.createElement("div");
    label.className = "hs-phase-label";
    label.textContent = "";

    info.appendChild(name);
    info.appendChild(label);
    el.appendChild(dot);
    el.appendChild(info);
    pipeline.appendChild(el);
  }
}

function updatePhaseUI(phase: number, label: string) {
  currentPhase = phase;
  const phaseEls = pipeline.querySelectorAll<HTMLElement>(".hs-phase");

  phaseEls.forEach((el) => {
    const num = parseInt(el.dataset.phase!, 10);
    const labelEl = el.querySelector<HTMLElement>(".hs-phase-label");
    const dotEl = el.querySelector<HTMLElement>(".hs-phase-dot");

    if (num < phase) {
      el.className = "hs-phase complete";
      if (dotEl) dotEl.textContent = "\u2713"; // checkmark
      if (labelEl) labelEl.textContent = "Done";
    } else if (num === phase) {
      el.className = "hs-phase active";
      if (labelEl) labelEl.textContent = label;
    } else {
      el.className = "hs-phase pending";
      if (labelEl) labelEl.textContent = "";
    }
  });
}

function markAllComplete() {
  const phaseEls = pipeline.querySelectorAll<HTMLElement>(".hs-phase");
  phaseEls.forEach((el) => {
    el.className = "hs-phase complete";
    const dotEl = el.querySelector<HTMLElement>(".hs-phase-dot");
    if (dotEl) dotEl.textContent = "\u2713";
    const labelEl = el.querySelector<HTMLElement>(".hs-phase-label");
    if (labelEl) labelEl.textContent = "Done";
  });
}

function markPhaseFailed(phase: number, error: string) {
  const phaseEls = pipeline.querySelectorAll<HTMLElement>(".hs-phase");
  phaseEls.forEach((el) => {
    const num = parseInt(el.dataset.phase!, 10);
    if (num === phase || (phase === 0 && num === currentPhase)) {
      el.className = "hs-phase failed";
      const labelEl = el.querySelector<HTMLElement>(".hs-phase-label");
      if (labelEl) labelEl.textContent = error;
    }
  });
}

// ── Schema.org JSON-LD Renderer ────────────────────────────────────────
// Text only — never innerHTML. Per DESIGN.md security spec.

function renderSchemaOrg(data: unknown, container: HTMLElement, depth = 0) {
  if (depth > 4) {
    const truncated = document.createElement("div");
    truncated.className = "typed-truncated";
    truncated.textContent = "(nested content omitted)";
    container.appendChild(truncated);
    return;
  }

  if (data === null || data === undefined) {
    container.textContent = "(empty)";
    return;
  }

  if (typeof data !== "object") {
    container.textContent = String(data);
    return;
  }

  if (Array.isArray(data)) {
    renderArray(data, container, depth);
    return;
  }

  const obj = data as Record<string, unknown>;
  const type = obj["@type"] as string | undefined;

  // Type badge
  if (type) {
    const badge = document.createElement("span");
    badge.className = "result-type";
    badge.textContent = type;
    container.appendChild(badge);
  }

  // Check for blessed renderers
  if (type === "SearchResultsPage" || type === "SearchAction") {
    renderSearchResults(obj, container);
    return;
  }

  if (type === "FlightReservation") {
    renderFlight(obj, container);
    return;
  }

  if (type === "LodgingReservation") {
    renderHotel(obj, container);
    return;
  }

  if (type === "Answer") {
    renderAnswer(obj, container);
    return;
  }

  // Generic renderer
  renderGeneric(obj, container, depth);
}

function renderGeneric(
  obj: Record<string, unknown>,
  container: HTMLElement,
  depth: number
) {
  const wrapper = document.createElement("div");
  wrapper.className = "typed-generic";

  const entries = Object.entries(obj).filter(
    ([k]) => k !== "@type" && k !== "@context"
  );

  for (const [key, value] of entries) {
    const field = document.createElement("div");
    field.className = "typed-field";

    const keyEl = document.createElement("span");
    keyEl.className = "typed-key";
    keyEl.textContent = key;

    const valEl = document.createElement("span");
    valEl.className = classifyFieldClass(key, value);

    if (typeof value === "object" && value !== null) {
      if (Array.isArray(value)) {
        renderArray(value, valEl, depth + 1);
      } else {
        const nested = document.createElement("div");
        nested.className = "typed-nested";
        renderSchemaOrg(value, nested, depth + 1);
        valEl.appendChild(nested);
      }
    } else {
      valEl.textContent = String(value ?? "");
    }

    field.appendChild(keyEl);
    field.appendChild(valEl);
    wrapper.appendChild(field);
  }

  container.appendChild(wrapper);
}

function renderArray(
  arr: unknown[],
  container: HTMLElement,
  depth: number
) {
  const list = document.createElement("div");
  list.className = "typed-list";

  const max = Math.min(arr.length, 50);
  for (let i = 0; i < max; i++) {
    const item = document.createElement("div");
    renderSchemaOrg(arr[i], item, depth + 1);
    list.appendChild(item);
  }

  if (arr.length > 50) {
    const truncated = document.createElement("div");
    truncated.className = "typed-truncated";
    truncated.textContent = `(${arr.length - 50} more items)`;
    list.appendChild(truncated);
  }

  container.appendChild(list);
}

function classifyFieldClass(key: string, value: unknown): string {
  const k = key.toLowerCase();
  if (k.includes("date") || k.includes("time")) return "typed-val typed-field-date";
  if (k.includes("price") || k.includes("cost") || k.includes("amount"))
    return "typed-val typed-field-price";
  if (k.includes("url") || k.includes("href") || k.includes("link"))
    return "typed-val typed-field-url";
  if (
    typeof value === "string" &&
    (value.startsWith("did:key:") || value.startsWith("did:web:"))
  )
    return "typed-val typed-field-did";
  return "typed-val";
}

function renderSearchResults(obj: Record<string, unknown>, container: HTMLElement) {
  const results = (obj.results || obj.result) as unknown[];
  if (!Array.isArray(results)) {
    renderGeneric(obj, container, 0);
    return;
  }

  const wrapper = document.createElement("div");
  wrapper.className = "typed-search-results";

  for (const item of results.slice(0, 50)) {
    const r = item as Record<string, unknown>;
    const el = document.createElement("div");
    el.className = "typed-search-item";

    const title = document.createElement("div");
    title.className = "typed-search-title";
    title.textContent = String(r.title || r.name || "");

    const url = document.createElement("div");
    url.className = "typed-search-url";
    url.textContent = String(r.url || "");

    const snippet = document.createElement("div");
    snippet.className = "typed-search-snippet";
    snippet.textContent = String(r.snippet || r.description || "");

    el.appendChild(title);
    el.appendChild(url);
    el.appendChild(snippet);
    wrapper.appendChild(el);
  }

  container.appendChild(wrapper);
}

function renderFlight(obj: Record<string, unknown>, container: HTMLElement) {
  const wrapper = document.createElement("div");
  wrapper.className = "typed-flight";

  const route = document.createElement("div");
  route.className = "typed-flight-route";
  route.textContent = `${obj.departureAirport || "?"} → ${obj.arrivalAirport || "?"}`;

  const date = document.createElement("div");
  date.className = "typed-flight-date";
  date.textContent = String(obj.departureDate || "");

  const price = document.createElement("div");
  price.className = "typed-flight-price";
  price.textContent = obj.totalPrice ? `$${obj.totalPrice}` : "";

  const carrier = document.createElement("div");
  carrier.className = "typed-flight-carrier";
  carrier.textContent = String(obj.airline || "");

  wrapper.appendChild(route);
  wrapper.appendChild(date);
  if (obj.totalPrice) wrapper.appendChild(price);
  if (obj.airline) wrapper.appendChild(carrier);
  container.appendChild(wrapper);
}

function renderHotel(obj: Record<string, unknown>, container: HTMLElement) {
  const wrapper = document.createElement("div");
  wrapper.className = "typed-hotel";

  const name = document.createElement("div");
  name.className = "typed-hotel-name";
  name.textContent = String(obj.name || "");

  const dates = document.createElement("div");
  dates.className = "typed-hotel-dates";
  dates.textContent = `${obj.checkinDate || "?"} → ${obj.checkoutDate || "?"}`;

  const price = document.createElement("div");
  price.className = "typed-hotel-price";
  price.textContent = obj.totalPrice ? `$${obj.totalPrice}` : "";

  wrapper.appendChild(name);
  wrapper.appendChild(dates);
  if (obj.totalPrice) wrapper.appendChild(price);
  container.appendChild(wrapper);
}

function renderAnswer(obj: Record<string, unknown>, container: HTMLElement) {
  const wrapper = document.createElement("div");
  wrapper.className = "typed-answer";

  const text = document.createElement("div");
  text.className = "typed-answer-text";
  text.textContent = String(obj.text || obj.content || JSON.stringify(obj));

  wrapper.appendChild(text);
  container.appendChild(wrapper);
}

// ── Receipt Renderer ───────────────────────────────────────────────────

function renderReceipt(receipt: {
  session_id: string;
  co_signatures: number;
  action: string;
}) {
  receiptContainer.innerHTML = "";

  const fields: [string, string, string?][] = [
    ["Session", receipt.session_id],
    ["Action", receipt.action],
    ["Co-signatures", String(receipt.co_signatures), "teal"],
    ["Timestamp", new Date().toISOString()],
  ];

  for (const [key, value, cls] of fields) {
    const keyEl = document.createElement("div");
    keyEl.className = "receipt-key";
    keyEl.textContent = key;

    const valEl = document.createElement("div");
    valEl.className = `receipt-val${cls ? " " + cls : ""}`;
    valEl.textContent = value;

    receiptContainer.appendChild(keyEl);
    receiptContainer.appendChild(valEl);
  }
}

// ── Event Handlers ─────────────────────────────────────────────────────

startBtn.addEventListener("click", () => {
  if (!uri) return;

  const action = actionInput.value.trim() || "SearchAction";
  const query = queryInput.value.trim();

  setupSection.hidden = true;
  phasesSection.hidden = false;
  errorSection.hidden = true;
  resultSection.hidden = true;
  receiptSection.hidden = true;

  renderPipeline();
  updatePhaseUI(1, "Starting...");

  chrome.runtime.sendMessage({
    type: "START_HANDSHAKE",
    uri,
    action,
    query,
  });
});

retryBtn.addEventListener("click", () => {
  errorSection.hidden = true;
  setupSection.hidden = false;
  phasesSection.hidden = true;
  resultSection.hidden = true;
  receiptSection.hidden = true;
});

// ── Message Listener ───────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((msg: ExtensionMessage) => {
  switch (msg.type) {
    case "PHASE_UPDATE":
      updatePhaseUI(msg.phase, msg.label);
      break;

    case "HANDSHAKE_COMPLETE":
      markAllComplete();

      // Show result
      resultContainer.innerHTML = "";
      const resultContent = document.createElement("div");
      resultContent.className = "result-content";
      renderSchemaOrg(msg.result, resultContent);
      resultContainer.appendChild(resultContent);
      resultSection.hidden = false;

      // Show receipt
      renderReceipt(msg.receipt);
      receiptSection.hidden = false;
      break;

    case "HANDSHAKE_FAILED":
      markPhaseFailed(msg.phase, msg.error);
      errorMessage.textContent = msg.error;
      errorSection.hidden = false;
      break;
  }
});
