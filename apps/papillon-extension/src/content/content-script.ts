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

const PAP_SCHEMES = ["pap://", "pap+https://", "pap+wss://"];

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

// ── Click handler ──────────────────────────────────────────────────────

document.addEventListener("click", interceptClick, true);

// ── Layer 0+1: PAP site discovery ─────────────────────────────────────

/**
 * Layer 0: Check <link rel="pap-manifest"> or equivalent in document head.
 * Zero network cost — reads existing DOM only.
 */
function checkLinkRelPap(): string | null {
  const link = document.querySelector<HTMLLinkElement>(
    'link[rel="pap-manifest"], link[rel="alternate"][type="application/pap+json"]'
  );
  return link?.href ?? null;
}

/**
 * Layer 1: Same-origin probe for /.well-known/pap-manifest.
 * Uses link-rel href if present, else the well-known path.
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
      tabId: 0, // service worker uses sender.tab.id
      manifest,
      source: linkRelHref ? "link-rel" : "well-known",
    });
  }
}

// Run discovery once after initial scan, non-blocking
probeSameOrigin();

// ── Cleanup on page unload ─────────────────────────────────────────────

window.addEventListener("pagehide", () => {
  observer.disconnect();
  document.removeEventListener("click", interceptClick, true);
});
