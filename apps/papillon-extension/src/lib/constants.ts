/**
 * Shared chrome.storage.sync key constants.
 *
 * Imported by both content-script.ts and popup.ts.
 * Any key rename only needs to happen here.
 */

/** Storage key for the global auto-intercept toggle (boolean, default true). */
export const STORAGE_AUTO_INTERCEPT = "autoInterceptHttps" as const;

/** Storage key for the per-domain exclusion list (string[], default []). */
export const STORAGE_EXCLUDED_DOMAINS = "excludedDomains" as const;
