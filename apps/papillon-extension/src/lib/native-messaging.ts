/**
 * Native messaging bridge to Papillon desktop app.
 *
 * When Papillon is installed and the native messaging host is registered,
 * the extension can delegate WASM operations to the desktop app. This provides:
 * - Access to the full Rust crate ecosystem (receipts, credentials, federation)
 * - Hardware-backed WebAuthn for principal key operations
 * - Local LLM inference via the desktop's Candle runtime
 *
 * Fallback: If the native app is unavailable, operations run in the
 * offscreen document via @pap/sdk WASM.
 */

const NATIVE_APP_ID = "com.baur_software.papillon";

export interface NativeHost {
  readonly connected: boolean;
  send(method: string, args: unknown[]): Promise<unknown>;
  disconnect(): void;
}

export function connectNativeHost(): NativeHost {
  let port: chrome.runtime.Port | null = null;
  let connected = false;
  const pending = new Map<
    string,
    { resolve: (v: unknown) => void; reject: (e: Error) => void }
  >();

  try {
    port = chrome.runtime.connectNative(NATIVE_APP_ID);
    connected = true;

    port.onMessage.addListener((msg: { id: string; result?: unknown; error?: string }) => {
      const p = pending.get(msg.id);
      if (!p) return;
      pending.delete(msg.id);

      if (msg.error) {
        p.reject(new Error(msg.error));
      } else {
        p.resolve(msg.result);
      }
    });

    port.onDisconnect.addListener(() => {
      connected = false;
      port = null;
      // Reject all pending requests
      for (const [, p] of pending) {
        p.reject(new Error("Native app disconnected"));
      }
      pending.clear();
    });
  } catch {
    connected = false;
  }

  return {
    get connected() {
      return connected;
    },

    send(method: string, args: unknown[]): Promise<unknown> {
      return new Promise((resolve, reject) => {
        if (!port || !connected) {
          reject(new Error("Native app not connected"));
          return;
        }

        const id = crypto.randomUUID();
        pending.set(id, { resolve, reject });
        port.postMessage({ id, method, args });

        // Timeout after 30s
        setTimeout(() => {
          if (pending.has(id)) {
            pending.delete(id);
            reject(new Error("Native app request timed out"));
          }
        }, 30_000);
      });
    },

    disconnect() {
      port?.disconnect();
      port = null;
      connected = false;
    },
  };
}

/**
 * Native messaging host manifest for Papillon.
 *
 * Install locations:
 * - Windows: HKCU\Software\Google\Chrome\NativeMessagingHosts\com.baur_software.papillon
 * - macOS:   ~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.baur_software.papillon.json
 * - Linux:   ~/.config/google-chrome/NativeMessagingHosts/com.baur_software.papillon.json
 */
export const NATIVE_HOST_MANIFEST = {
  name: NATIVE_APP_ID,
  description: "Papillon PAP desktop application",
  path: "", // Set during Papillon installation
  type: "stdio" as const,
  allowed_origins: [] as string[], // Set to chrome-extension://<id>/
};
