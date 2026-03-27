/**
 * WebSocket transport for pap+wss:// connections.
 *
 * Implements the PAP WebSocket binding (spec section 14.7):
 * - WSS-only (no unencrypted ws://)
 * - Each text frame = one JSON Envelope
 * - Full-duplex federation streams
 *
 * Falls back to HTTPS transport if WSS connection fails.
 */

import type { ProtocolMessage } from "./types.js";

export interface WssConnection {
  readonly connected: boolean;
  send(msg: ProtocolMessage): void;
  receive(): Promise<ProtocolMessage>;
  close(): void;
}

export function connectWss(endpoint: string): Promise<WssConnection> {
  return new Promise((resolve, reject) => {
    if (!endpoint.startsWith("wss://")) {
      reject(new Error(`WSS transport requires wss:// URL, got: ${endpoint}`));
      return;
    }

    const ws = new WebSocket(endpoint);
    const messageQueue: ProtocolMessage[] = [];
    let waitingResolve: ((msg: ProtocolMessage) => void) | null = null;
    let connected = false;

    ws.onopen = () => {
      connected = true;
      resolve({
        get connected() {
          return connected;
        },

        send(msg: ProtocolMessage) {
          if (!connected) throw new Error("WebSocket not connected");
          ws.send(JSON.stringify(msg));
        },

        receive(): Promise<ProtocolMessage> {
          // If there's a queued message, return it immediately
          const queued = messageQueue.shift();
          if (queued) return Promise.resolve(queued);

          // Otherwise, wait for the next message
          return new Promise((res) => {
            waitingResolve = res;
          });
        },

        close() {
          connected = false;
          ws.close(1000, "Session complete");
        },
      });
    };

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data as string) as ProtocolMessage;
      if (waitingResolve) {
        const resolve = waitingResolve;
        waitingResolve = null;
        resolve(msg);
      } else {
        messageQueue.push(msg);
      }
    };

    ws.onerror = () => {
      connected = false;
      reject(new Error(`WebSocket connection failed: ${endpoint}`));
    };

    ws.onclose = () => {
      connected = false;
    };

    // Timeout after 10s
    setTimeout(() => {
      if (!connected) {
        ws.close();
        reject(new Error(`WebSocket connection timed out: ${endpoint}`));
      }
    }, 10_000);
  });
}

/**
 * Execute the 6-phase handshake over WebSocket.
 *
 * Unlike HTTP transport (request-response per phase), WSS sends all
 * messages over a single persistent connection. The protocol still
 * follows the same phase ordering — just over a different wire.
 */
export async function handshakeOverWss(
  conn: WssConnection,
  tokenMsg: ProtocolMessage,
  didMsg: ProtocolMessage,
  disclosureMsg: ProtocolMessage,
  receiptMsg: ProtocolMessage,
  closeMsg: ProtocolMessage
): Promise<{
  tokenResp: ProtocolMessage;
  didResp: ProtocolMessage;
  disclosureResp: ProtocolMessage;
  executionResp: ProtocolMessage;
  receiptResp: ProtocolMessage;
  closeResp: ProtocolMessage;
}> {
  // Phase 1: Token
  conn.send(tokenMsg);
  const tokenResp = await conn.receive();

  // Phase 2: DID Exchange
  conn.send(didMsg);
  const didResp = await conn.receive();

  // Phase 3: Disclosure
  conn.send(disclosureMsg);
  const disclosureResp = await conn.receive();

  // Phase 4: Execution (agent sends result without us requesting)
  const executionResp = await conn.receive();

  // Phase 5: Receipt
  conn.send(receiptMsg);
  const receiptResp = await conn.receive();

  // Phase 6: Close
  conn.send(closeMsg);
  const closeResp = await conn.receive();

  return { tokenResp, didResp, disclosureResp, executionResp, receiptResp, closeResp };
}
