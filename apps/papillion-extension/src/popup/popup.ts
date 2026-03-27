/**
 * Popup — identity status, active sessions, quick actions.
 */

import type { StateResponse } from "../lib/types.js";

const principalDidEl = document.getElementById("principal-did")!;
const sessionCountEl = document.getElementById("session-count")!;
const nativeStatusEl = document.getElementById("native-status")!;
const openHandshakeBtn = document.getElementById("open-handshake")!;
const openSettingsBtn = document.getElementById("open-settings")!;

// ── Load State ─────────────────────────────────────────────────────────

chrome.runtime.sendMessage({ type: "GET_STATE" }, (resp: StateResponse) => {
  if (chrome.runtime.lastError || !resp) {
    principalDidEl.textContent = "Extension not ready";
    return;
  }

  // Principal DID
  if (resp.principalDid) {
    principalDidEl.textContent = resp.principalDid;
  } else {
    principalDidEl.textContent = "No identity — click New Handshake to generate";
    principalDidEl.style.color = "var(--text-3)";
  }

  // Session count
  const numEl = sessionCountEl.querySelector<HTMLElement>(".pop-stat-num")!;
  numEl.textContent = String(resp.activeSessions);
  if (resp.activeSessions === 0) {
    numEl.classList.add("zero");
  }

  // Native app status
  const dotEl = nativeStatusEl.querySelector<HTMLElement>(".pop-status-dot")!;
  const textEl = nativeStatusEl.querySelector<HTMLElement>(".pop-status-text")!;

  if (resp.nativeAppConnected) {
    dotEl.className = "pop-status-dot connected";
    textEl.textContent = "Connected";
  } else {
    dotEl.className = "pop-status-dot disconnected";
    textEl.textContent = "Not running";
  }
});

// ── Actions ────────────────────────────────────────────────────────────

openHandshakeBtn.addEventListener("click", () => {
  chrome.tabs.create({
    url: chrome.runtime.getURL("handshake/handshake.html?uri=pap://localhost:7890"),
  });
  window.close();
});

openSettingsBtn.addEventListener("click", () => {
  // Future: dedicated settings page. For now, open chrome extension settings.
  chrome.runtime.openOptionsPage?.() ??
    chrome.tabs.create({
      url: `chrome://extensions/?id=${chrome.runtime.id}`,
    });
  window.close();
});
