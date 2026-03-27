/**
 * Service Worker — central message router and extension coordinator.
 *
 * Responsibilities:
 * - Route messages between content scripts, offscreen document, and UI pages
 * - Handle omnibox input (pap keyword → handshake tab)
 * - Manage offscreen document lifecycle
 * - Track active sessions for badge count
 * - Native messaging bridge to Papillion desktop
 */

import { parsePapUri } from "../lib/uri.js";
import type {
  ExtensionMessage,
  ActiveSession,
  StateResponse,
} from "../lib/types.js";

// ── State ──────────────────────────────────────────────────────────────

const activeSessions = new Map<string, ActiveSession>();
let principalDid: string | null = null;
let offscreenReady = false;
let nativePort: chrome.runtime.Port | null = null;

// ── Offscreen Document Lifecycle ───────────────────────────────────────

async function ensureOffscreen(): Promise<void> {
  if (offscreenReady) return;

  // Check if already exists
  const contexts = await chrome.runtime.getContexts({
    contextTypes: [chrome.runtime.ContextType.OFFSCREEN_DOCUMENT],
  });

  if (contexts.length > 0) {
    offscreenReady = true;
    return;
  }

  await chrome.offscreen.createDocument({
    url: "offscreen/offscreen.html",
    reasons: [chrome.offscreen.Reason.WORKERS],
    justification: "Host PAP WASM module for cryptographic operations",
  });

  offscreenReady = true;
}

// ── Handshake Tab Management ───────────────────────────────────────────

function openHandshakeTab(uri: string, action?: string, query?: string) {
  const params = new URLSearchParams({ uri });
  if (action) params.set("action", action);
  if (query) params.set("query", query);

  chrome.tabs.create({
    url: chrome.runtime.getURL(
      `handshake/handshake.html?${params.toString()}`
    ),
  });
}

// ── Badge Update ───────────────────────────────────────────────────────

function updateBadge() {
  const count = activeSessions.size;
  if (count > 0) {
    chrome.action.setBadgeText({ text: String(count) });
    chrome.action.setBadgeBackgroundColor({ color: "#f0a030" }); // --gold
  } else {
    chrome.action.setBadgeText({ text: "" });
  }
}

// ── Native Messaging ───────────────────────────────────────────────────

const NATIVE_APP_ID = "com.baur_software.papillion";

function connectNative(): chrome.runtime.Port | null {
  try {
    const port = chrome.runtime.connectNative(NATIVE_APP_ID);
    port.onDisconnect.addListener(() => {
      nativePort = null;
    });
    port.onMessage.addListener((msg) => {
      // Forward native app responses to the requesting context
      if (msg.type === "NATIVE_RESPONSE") {
        chrome.runtime.sendMessage(msg);
      }
    });
    return port;
  } catch {
    return null;
  }
}

function isNativeConnected(): boolean {
  return nativePort !== null;
}

// ── Message Router ─────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener(
  (msg: ExtensionMessage, sender, sendResponse) => {
    switch (msg.type) {
      // Content script: user clicked a pap:// link
      case "PAP_LINK_CLICKED":
        openHandshakeTab(msg.uri);
        break;

      // Handshake page: start the protocol
      case "START_HANDSHAKE":
        ensureOffscreen().then(() => {
          const session: ActiveSession = {
            id: crypto.randomUUID(),
            uri: msg.uri,
            agentHost: parsePapUri(msg.uri).host,
            phase: 0,
            phaseLabel: "Initializing...",
            startedAt: Date.now(),
            tabId: sender.tab?.id,
          };
          activeSessions.set(session.id, session);
          updateBadge();

          // Forward to offscreen with session ID
          chrome.runtime.sendMessage({
            ...msg,
            sessionId: session.id,
          });
        });
        break;

      // Offscreen: phase progress
      case "PHASE_UPDATE": {
        const session = activeSessions.get(msg.sessionId);
        if (session) {
          session.phase = msg.phase;
          session.phaseLabel = msg.label;
        }
        // Forward to all extension pages (handshake tabs)
        broadcastToTabs(msg);
        break;
      }

      // Offscreen: handshake complete
      case "HANDSHAKE_COMPLETE":
        activeSessions.delete(msg.sessionId);
        updateBadge();
        broadcastToTabs(msg);
        break;

      // Offscreen: handshake failed
      case "HANDSHAKE_FAILED":
        activeSessions.delete(msg.sessionId);
        updateBadge();
        broadcastToTabs(msg);
        break;

      // Popup / page: get current state
      case "GET_STATE":
        ensureOffscreen()
          .then(() =>
            chrome.runtime.sendMessage({ type: "ENSURE_IDENTITY" })
          )
          .then((resp: { did: string | null }) => {
            principalDid = resp?.did ?? principalDid;
            const state: StateResponse = {
              type: "STATE_RESPONSE",
              principalDid,
              activeSessions: activeSessions.size,
              nativeAppConnected: isNativeConnected(),
            };
            sendResponse(state);
          })
          .catch(() => {
            sendResponse({
              type: "STATE_RESPONSE",
              principalDid,
              activeSessions: activeSessions.size,
              nativeAppConnected: false,
            } satisfies StateResponse);
          });
        return true; // async

      // Native messaging bridge
      case "NATIVE_REQUEST":
        if (!nativePort) {
          nativePort = connectNative();
        }
        if (nativePort) {
          nativePort.postMessage(msg);
        } else {
          sendResponse({ type: "NATIVE_RESPONSE", error: "Native app not available" });
        }
        return true;

      // WASM requests pass through to offscreen
      case "WASM_REQUEST":
        ensureOffscreen().then(() => {
          chrome.runtime.sendMessage(msg, sendResponse);
        });
        return true;

      // Identity ready from offscreen
      case "IDENTITY_READY":
        principalDid = msg.did;
        break;
    }
  }
);

function broadcastToTabs(msg: ExtensionMessage) {
  chrome.runtime.sendMessage(msg).catch(() => {
    // No listeners — that's fine
  });
}

// ── Omnibox ────────────────────────────────────────────────────────────

chrome.omnibox.onInputStarted.addListener(() => {
  chrome.omnibox.setDefaultSuggestion({
    description: "Navigate to a PAP agent (e.g., pap://agent.example.com/search)",
  });
});

chrome.omnibox.onInputChanged.addListener((text, suggest) => {
  const trimmed = text.trim();
  if (!trimmed) return;

  // Try to parse as a PAP URI (with or without scheme prefix)
  const suggestions: chrome.omnibox.SuggestResult[] = [];

  // If they typed a bare host, suggest scheme variants
  if (!trimmed.includes("://")) {
    suggestions.push({
      content: `pap://${trimmed}`,
      description: `pap://${trimmed} — native transport`,
    });
    suggestions.push({
      content: `pap+https://${trimmed}`,
      description: `pap+https://${trimmed} — HTTPS transport`,
    });
    suggestions.push({
      content: `pap+wss://${trimmed}`,
      description: `pap+wss://${trimmed} — WebSocket transport`,
    });
  }

  suggest(suggestions);
});

chrome.omnibox.onInputEntered.addListener((text, disposition) => {
  let uri = text.trim();

  // If no scheme, default to pap://
  if (!uri.includes("://")) {
    uri = `pap://${uri}`;
  }

  try {
    parsePapUri(uri); // Validate
    openHandshakeTab(uri);
  } catch {
    // Invalid URI — open anyway, let the handshake page show the error
    openHandshakeTab(uri);
  }
});

// ── Startup ────────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(async () => {
  // Pre-warm the offscreen document and ensure identity exists
  await ensureOffscreen();
  chrome.runtime.sendMessage({ type: "ENSURE_IDENTITY" });

  // Try to connect to native app
  nativePort = connectNative();
});

console.log("[PAP Service Worker] Ready");
