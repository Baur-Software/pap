/**
 * Popup — identity status, active sessions, quick actions.
 */

import type { StateResponse, PapSiteResponse } from "../lib/types.js";

const principalDidEl = document.getElementById("principal-did")!;
const sessionCountEl = document.getElementById("session-count")!;
const nativeStatusEl = document.getElementById("native-status")!;
const papSiteSectionEl = document.getElementById("pap-site-section")!;
const papSiteNameEl = document.getElementById("pap-site-name")!;
const openHandshakeBtn = document.getElementById("open-handshake")!;
const openSettingsBtn = document.getElementById("open-settings")!;
const interceptToggleBtn = document.getElementById("intercept-toggle") as HTMLButtonElement;
const domainToggleBtn = document.getElementById("domain-toggle") as HTMLButtonElement;

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

// ── PAP Site Discovery ────────────────────────────────────────────────

chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  if (!tab?.id) return;
  chrome.runtime.sendMessage(
    { type: "GET_PAP_SITE", tabId: tab.id },
    (resp: PapSiteResponse) => {
      if (chrome.runtime.lastError || !resp?.manifest) return;
      papSiteSectionEl.hidden = false;
      papSiteNameEl.textContent = resp.manifest.name;
    }
  );
});

// ── Auto-intercept controls ────────────────────────────────────────────

const STORAGE_AUTO_INTERCEPT = "autoInterceptHttps";
const STORAGE_EXCLUDED_DOMAINS = "excludedDomains";

let currentHostname: string | null = null;

function updateDomainButton(excluded: boolean): void {
  domainToggleBtn.textContent = excluded
    ? "Enable on this site"
    : "Disable on this site";
  if (excluded) {
    domainToggleBtn.classList.add("excluded");
  } else {
    domainToggleBtn.classList.remove("excluded");
  }
}

chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  if (!tab?.url) return;
  try {
    currentHostname = new URL(tab.url).hostname;
  } catch {
    return;
  }

  chrome.storage.sync.get(
    [STORAGE_AUTO_INTERCEPT, STORAGE_EXCLUDED_DOMAINS],
    (result) => {
      // Global toggle — default on
      const autoOn =
        typeof result[STORAGE_AUTO_INTERCEPT] === "boolean"
          ? (result[STORAGE_AUTO_INTERCEPT] as boolean)
          : true;
      interceptToggleBtn.setAttribute("aria-checked", String(autoOn));

      // Per-domain exclusion
      const domains: string[] = Array.isArray(result[STORAGE_EXCLUDED_DOMAINS])
        ? (result[STORAGE_EXCLUDED_DOMAINS] as string[])
        : [];
      updateDomainButton(
        currentHostname !== null && domains.includes(currentHostname)
      );
    }
  );
});

interceptToggleBtn.addEventListener("click", () => {
  const next = interceptToggleBtn.getAttribute("aria-checked") !== "true";
  interceptToggleBtn.setAttribute("aria-checked", String(next));
  chrome.storage.sync.set({ [STORAGE_AUTO_INTERCEPT]: next });
});

domainToggleBtn.addEventListener("click", () => {
  if (!currentHostname) return;
  chrome.storage.sync.get([STORAGE_EXCLUDED_DOMAINS], (result) => {
    const domains: string[] = Array.isArray(result[STORAGE_EXCLUDED_DOMAINS])
      ? [...(result[STORAGE_EXCLUDED_DOMAINS] as string[])]
      : [];
    const idx = domains.indexOf(currentHostname!);
    if (idx === -1) {
      domains.push(currentHostname!);
      updateDomainButton(true);
    } else {
      domains.splice(idx, 1);
      updateDomainButton(false);
    }
    chrome.storage.sync.set({ [STORAGE_EXCLUDED_DOMAINS]: domains });
  });
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
