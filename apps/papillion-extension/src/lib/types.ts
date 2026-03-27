/**
 * Shared types for the PAP browser extension.
 *
 * Protocol message types mirror crates/pap-proto/src/message.rs.
 * Internal message types define the extension's IPC contract.
 */

// ── Protocol Messages (wire format) ────────────────────────────────────

export interface TokenPresentation {
  type: "TokenPresentation";
  token: unknown; // CapabilityToken JSON
}

export interface TokenAccepted {
  type: "TokenAccepted";
  session_id: string;
  receiver_session_did: string;
  attestation?: unknown;
}

export interface TokenRejected {
  type: "TokenRejected";
  reason: string;
}

export interface SessionDidExchange {
  type: "SessionDidExchange";
  initiator_session_did: string;
}

export interface SessionDidAck {
  type: "SessionDidAck";
}

export interface DisclosureOffer {
  type: "DisclosureOffer";
  disclosures: unknown[];
}

export interface DisclosureAccepted {
  type: "DisclosureAccepted";
}

export interface ExecutionResult {
  type: "ExecutionResult";
  result: unknown;
}

export interface ReceiptForCoSign {
  type: "ReceiptForCoSign";
  receipt: unknown;
}

export interface ReceiptCoSigned {
  type: "ReceiptCoSigned";
  receipt: unknown;
}

export interface SessionClose {
  type: "SessionClose";
  session_id: string;
}

export interface SessionClosed {
  type: "SessionClosed";
}

export interface ProtocolError {
  type: "Error";
  code: string;
  message: string;
}

export type ProtocolMessage =
  | TokenPresentation
  | TokenAccepted
  | TokenRejected
  | SessionDidExchange
  | SessionDidAck
  | DisclosureOffer
  | DisclosureAccepted
  | ExecutionResult
  | ReceiptForCoSign
  | ReceiptCoSigned
  | SessionClose
  | SessionClosed
  | ProtocolError;

// ── Extension Internal Messages ────────────────────────────────────────

/** Content script → Service worker: user clicked a pap:// link */
export interface PapLinkClicked {
  type: "PAP_LINK_CLICKED";
  uri: string;
  pageTitle: string;
  pageUrl: string;
}

/** Handshake page → Service worker → Offscreen: start a handshake */
export interface StartHandshake {
  type: "START_HANDSHAKE";
  uri: string;
  action: string;
  query: string;
}

/** Service worker → Offscreen: perform a WASM operation */
export interface WasmRequest {
  type: "WASM_REQUEST";
  id: string;
  method: string;
  args: unknown[];
}

/** Offscreen → Service worker: WASM operation result */
export interface WasmResponse {
  type: "WASM_RESPONSE";
  id: string;
  result?: unknown;
  error?: string;
}

/** Offscreen → Service worker → Handshake page: phase progress */
export interface PhaseUpdate {
  type: "PHASE_UPDATE";
  sessionId: string;
  phase: number;
  label: string;
}

/** Offscreen → Service worker → Handshake page: handshake complete */
export interface HandshakeComplete {
  type: "HANDSHAKE_COMPLETE";
  sessionId: string;
  result: unknown;
  receipt: {
    session_id: string;
    co_signatures: number;
    action: string;
  };
}

/** Offscreen → Service worker → Handshake page: handshake failed */
export interface HandshakeFailed {
  type: "HANDSHAKE_FAILED";
  sessionId: string;
  phase: number;
  error: string;
}

/** Popup / Handshake page → Service worker: get current state */
export interface GetState {
  type: "GET_STATE";
}

export interface StateResponse {
  type: "STATE_RESPONSE";
  principalDid: string | null;
  activeSessions: number;
  nativeAppConnected: boolean;
}

/** Service worker → Offscreen: ensure identity exists */
export interface EnsureIdentity {
  type: "ENSURE_IDENTITY";
}

export interface IdentityReady {
  type: "IDENTITY_READY";
  did: string;
}

/** Native messaging bridge messages */
export interface NativeRequest {
  type: "NATIVE_REQUEST";
  method: string;
  args: unknown[];
}

export interface NativeResponse {
  type: "NATIVE_RESPONSE";
  result?: unknown;
  error?: string;
}

export type ExtensionMessage =
  | PapLinkClicked
  | StartHandshake
  | WasmRequest
  | WasmResponse
  | PhaseUpdate
  | HandshakeComplete
  | HandshakeFailed
  | GetState
  | StateResponse
  | EnsureIdentity
  | IdentityReady
  | NativeRequest
  | NativeResponse;

// ── Session tracking ───────────────────────────────────────────────────

export interface ActiveSession {
  id: string;
  uri: string;
  agentHost: string;
  phase: number;
  phaseLabel: string;
  startedAt: number;
  tabId?: number;
}

// ── Key storage ────────────────────────────────────────────────────────

export interface EncryptedKeyData {
  ciphertext: number[];
  salt: number[];
  iv: number[];
}
