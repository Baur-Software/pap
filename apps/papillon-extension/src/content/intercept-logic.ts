/**
 * Pure interception logic — no DOM, no Chrome APIs.
 *
 * Extracted from content-script.ts so this decision function can be
 * unit-tested in Node without jsdom or a browser runtime.
 *
 * content-script.ts calls resolveInterceptUrl() and, when it returns a URL,
 * preventDefault/stopPropagation and sends HTTPS_LINK_CLICKED.
 */

/**
 * Determines whether a link click should be routed through PAP.
 *
 * @param e         MouseEvent-compatible subset (no DOM type dependency)
 * @param rawHref   The raw `href` attribute value from the anchor element
 * @param hasDownload Whether the anchor has a `download` attribute
 * @param baseURI   Document base URI used to resolve relative hrefs
 * @param autoInterceptEnabled Global toggle from chrome.storage.sync
 * @param excludedDomains Per-domain exclusion set from chrome.storage.sync
 *
 * @returns The resolved absolute https:// URL to intercept, or null to pass through.
 */
export function resolveInterceptUrl(
  e: {
    button: number;
    ctrlKey: boolean;
    metaKey: boolean;
    shiftKey: boolean;
    altKey: boolean;
    isTrusted: boolean;
  },
  rawHref: string | null,
  hasDownload: boolean,
  baseURI: string,
  autoInterceptEnabled: boolean,
  excludedDomains: Set<string>
): string | null {
  // Only plain left-clicks
  if (e.button !== 0) return null;
  // Modifier keys: Ctrl/Meta = open in new tab, Shift = new window, Alt = opt-out
  if (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return null;
  // Synthetic/programmatic clicks are not user-initiated navigation
  if (!e.isTrusted) return null;
  // Download links are not navigations
  if (hasDownload) return null;
  // No href at all
  if (!rawHref) return null;

  let resolved: URL;
  try {
    resolved = new URL(rawHref, baseURI);
  } catch {
    return null; // Malformed href — pass through
  }

  // Only intercept https:// — pap://, pap+https://, http://, mailto:, etc. excluded
  if (resolved.protocol !== "https:") return null;

  // Check global auto-intercept toggle
  if (!autoInterceptEnabled) return null;

  // Check per-domain exclusion list
  if (excludedDomains.has(resolved.hostname)) return null;

  return resolved.href;
}
