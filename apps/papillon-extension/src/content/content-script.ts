/**
 * Content script — PAP link interceptor and site discovery.
 *
 * Scans pages for <a href="pap://..."> and <a href="pap+https://..."> links,
 * marks them with a visual badge, and intercepts clicks to route through
 * the extension's handshake flow.
 *
 * Also probes the current site for PAP support via:
 * - Layer 0: <link rel="pap-manifest"> in document head (zero cost)
 * - Layer 1: Same-origin fetch of /.well-known/pap-manifest (one fetch)
 */

import { fetchManifest } from "../lib/discovery.js";
import { resolveInterceptUrl } from "./intercept-logic.js";
import { STORAGE_AUTO_INTERCEPT, STORAGE_EXCLUDED_DOMAINS } from "../lib/constants.js";

const PAP_SCHEMES = ["pap://", "pap+https://", "pap+wss://"];

// ── Auto-intercept HTTPS links ──────────────────────────────────────────

/** Live-updated from chrome.storage.sync. Default: on. */
let autoInterceptEnabled = true;

/** Live-updated from chrome.storage.sync. Hostname strings only. */
let excludedDomains = new Set<string>();

// Load initial values from storage before any click can arrive.
chrome.storage.sync.get(
  [STORAGE_AUTO_INTERCEPT, STORAGE_EXCLUDED_DOMAINS],
  (result) => {
    if (typeof result[STORAGE_AUTO_INTERCEPT] === "boolean") {
      autoInterceptEnabled = result[STORAGE_AUTO_INTERCEPT] as boolean;
    }
    if (Array.isArray(result[STORAGE_EXCLUDED_DOMAINS])) {
      excludedDomains = new Set<string>(
        (result[STORAGE_EXCLUDED_DOMAINS] as unknown[]).filter(
          (d): d is string => typeof d === "string"
        )
      );
    }
  }
);

// Keep in-memory state in sync when the user changes settings in the popup.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "sync") return;
  if (STORAGE_AUTO_INTERCEPT in changes) {
    const next = changes[STORAGE_AUTO_INTERCEPT].newValue;
    if (typeof next === "boolean") autoInterceptEnabled = next;
  }
  if (STORAGE_EXCLUDED_DOMAINS in changes) {
    const next = changes[STORAGE_EXCLUDED_DOMAINS].newValue;
    if (Array.isArray(next)) {
      excludedDomains = new Set<string>(
        (next as unknown[]).filter((d): d is string => typeof d === "string")
      );
    }
  }
});

function isPapLink(el: HTMLAnchorElement): boolean {
  const href = el.getAttribute("href");
  if (!href) return false;
  return PAP_SCHEMES.some((scheme) => href.startsWith(scheme));
}

function markLink(el: HTMLAnchorElement) {
  if (el.dataset.papMarked) return;
  el.dataset.papMarked = "true";
  el.classList.add("pap-link");

  // Add butterfly indicator
  const badge = document.createElement("span");
  badge.className = "pap-link-badge";
  badge.textContent = "\u{1F98B}"; // butterfly emoji as fallback; CSS replaces with icon
  badge.title = "PAP Protocol Link — click to open agent handshake";
  el.style.position = "relative";
  el.appendChild(badge);
}

function interceptClick(e: MouseEvent) {
  const target = e.target as HTMLElement;
  const link = target.closest("a") as HTMLAnchorElement | null;
  if (!link || !isPapLink(link)) return;

  e.preventDefault();
  e.stopPropagation();

  const href = link.getAttribute("href")!;
  chrome.runtime.sendMessage({
    type: "PAP_LINK_CLICKED",
    uri: href,
    pageTitle: document.title,
    pageUrl: window.location.href,
  });
}

/**
 * Auto-intercept plain left-clicks on https:// links and route through PAP.
 * Guard logic is in resolveInterceptUrl (intercept-logic.ts) for testability.
 */
function interceptHttpsClick(e: MouseEvent): void {
  const link = (e.target as HTMLElement).closest("a") as HTMLAnchorElement | null;
  const rawHref = link?.getAttribute("href") ?? null;
  const hasDownload = link?.hasAttribute("download") ?? false;

  const url = resolveInterceptUrl(
    e,
    rawHref,
    hasDownload,
    document.baseURI,
    autoInterceptEnabled,
    excludedDomains
  );
  if (!url) return;

  e.preventDefault();
  e.stopPropagation();

  chrome.runtime.sendMessage({
    type: "HTTPS_LINK_CLICKED",
    httpsUrl: url,
    pageTitle: document.title,
    pageUrl: window.location.href,
  });
}

function scanLinks(root: ParentNode = document) {
  const links = root.querySelectorAll<HTMLAnchorElement>("a[href]");
  for (const link of links) {
    if (isPapLink(link)) {
      markLink(link);
    }
  }
}

// ── Initial scan ───────────────────────────────────────────────────────

scanLinks();

// ── Mutation observer for dynamic content ──────────────────────────────

const observer = new MutationObserver((mutations) => {
  for (const mutation of mutations) {
    for (const node of mutation.addedNodes) {
      if (node instanceof HTMLElement) {
        if (node.tagName === "A" && isPapLink(node as HTMLAnchorElement)) {
          markLink(node as HTMLAnchorElement);
        } else {
          scanLinks(node);
        }
      }
    }
  }
});

observer.observe(document.body, {
  childList: true,
  subtree: true,
});

// ── Click handlers ─────────────────────────────────────────────────────

document.addEventListener("click", interceptClick, true);
document.addEventListener("click", interceptHttpsClick, true);

// ── Layer 0+1: PAP site discovery ─────────────────────────────────────

/**
 * Layer 0: Check <link rel="pap-manifest"> or equivalent in document head.
 * Zero network cost — reads existing DOM only.
 * Returns null if the link points to a different origin (enforces same-origin).
 */
function checkLinkRelPap(): string | null {
  const link = document.querySelector<HTMLLinkElement>(
    'link[rel="pap-manifest"], link[rel="alternate"][type="application/pap+json"]'
  );
  if (!link?.href) return null;

  // Enforce same-origin: the manifest URL must be on the same host/port/scheme
  try {
    const manifestUrl = new URL(link.href);
    const pageUrl = new URL(window.location.href);
    if (
      manifestUrl.origin !== pageUrl.origin
    ) {
      console.warn(
        "[PAP] Cross-origin link-rel detected, rejecting:",
        link.href
      );
      return null;
    }
    return link.href;
  } catch {
    // Invalid URL
    return null;
  }
}

/**
 * Layer 1: Same-origin probe for /.well-known/pap-manifest.
 * Uses link-rel href if present (must pass same-origin check), else the well-known path.
 * Reports result to service worker for icon badge.
 */
async function probeSameOrigin() {
  const linkRelHref = checkLinkRelPap();
  const url =
    linkRelHref || `${window.location.origin}/.well-known/pap-manifest`;

  const manifest = await fetchManifest(url);
  if (manifest) {
    chrome.runtime.sendMessage({
      type: "SITE_HAS_PAP",
      manifest,
      source: linkRelHref ? "link-rel" : "well-known",
    });
  }
}

// Run discovery once after initial scan, non-blocking.
// Guard: only probe on HTTP(S) pages — skip chrome-extension://, about:blank, etc.
const proto = window.location.protocol;
if (proto === "https:" || proto === "http:") {
  probeSameOrigin();
}

// ── Cleanup on page unload ─────────────────────────────────────────────

window.addEventListener("pagehide", () => {
  observer.disconnect();
  document.removeEventListener("click", interceptClick, true);
  document.removeEventListener("click", interceptHttpsClick, true);
});
