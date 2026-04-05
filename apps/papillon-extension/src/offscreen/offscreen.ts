/**
 * Offscreen document — WASM host and handshake executor.
 *
 * Loads @pap/sdk WASM and provides:
 * 1. Crypto operations (keypair generation, signing, DID resolution)
 * 2. Full 6-phase PAP handshake execution over fetch()
 *
 * Mirrors the security model from apps/papillon/src/handshake.rs:
 * - Principal key only signs in phases 1-2, then reference is dropped
 * - Session key only signs in phase 5, then dropped
 * - All agent communication goes through the protocol REST surface
 *
 * ISS-840: When SubtleCrypto Ed25519 is available, signing uses browser-native
 * crypto with non-exportable keys. Falls back to WASM (ed25519-dalek) on older
 * browsers. Key material never enters JS or WASM memory in the SubtleCrypto path.
 */

import { parsePapUri, toEndpoint } from "../lib/uri.js";
import { loadPrincipalKey, storePrincipalKey, deletePrincipalKey } from "../lib/storage.js";
import {
  supportsEd25519,
  generateKeypair,
  importSeed,
  exportPublicKeyRaw,
  sign as subtleCryptoSign,
} from "../lib/webcrypto.js";
import {
  storePrincipalKeypair,
  loadPrincipalKeypair,
} from "../lib/idb-storage.js";
import type {
  ExtensionMessage,
  TokenAccepted,
  ProtocolMessage,
} from "../lib/types.js";

// ── Crypto Backend Selection ──────────────────────────────────────────

let useSubtleCrypto = false;

async function initCryptoBackend(): Promise<void> {
  useSubtleCrypto = await supportsEd25519();
  if (useSubtleCrypto) {
    await maybeMigrateLegacyKey();
  }
}

/**
 * Migrate a legacy AES-256-GCM encrypted seed from chrome.storage.local
 * into a SubtleCrypto CryptoKey stored in IndexedDB.
 *
 * After migration the raw seed is zeroed out in memory (best-effort)
 * and the legacy entry is deleted from chrome.storage.local.
 */
async function maybeMigrateLegacyKey(): Promise<void> {
  // Already migrated?
  const existing = await loadPrincipalKeypair();
  if (existing) return;

  // Legacy key present?
  const legacySeed = await loadPrincipalKey();
  if (!legacySeed) return;

  // Derive the public key bytes from the seed via WASM *before* importing into
  // SubtleCrypto. This avoids importing the private key as extractable and
  // exporting it as JWK — which would materialise private key material in the
  // JS heap. The WASM keypair is freed immediately after public key extraction.
  const sdk = await loadWasm();
  const wasmKp = sdk.PrincipalKeypair.fromSecretBytes(legacySeed);
  const rawPub = wasmKp.publicKeyBytes();
  wasmKp.free();

  // Import into SubtleCrypto: private key is non-extractable, public key is
  // constructed from the raw bytes derived above — no JWK round-trip needed.
  const keypair = await importSeed(legacySeed, rawPub);
  const did = sdk.publicKeyBytesToDid(rawPub);

  // Store in IndexedDB
  await storePrincipalKeypair(
    keypair.privateKey,
    keypair.publicKey,
    rawPub,
    did,
    "aes-gcm"
  );

  // Clean up legacy storage
  await deletePrincipalKey();
  legacySeed.fill(0); // best-effort zeroing
}

// ── WASM Module Loading ────────────────────────────────────────────────

type PapWasm = typeof import("pap-wasm");
let wasm: PapWasm | null = null;

async function loadWasm(): Promise<PapWasm> {
  if (wasm) return wasm;
  // @pap/sdk built with --target web produces an init() default export.
  // Dynamic import with a runtime URL bypasses TS module resolution —
  // the type safety comes from src/wasm.d.ts.
  const wasmJsUrl = chrome.runtime.getURL("wasm/pap_wasm.js");
  const mod = await (Function("url", "return import(url)")(wasmJsUrl) as Promise<PapWasm>);
  await mod.default(chrome.runtime.getURL("wasm/pap_wasm_bg.wasm"));
  wasm = mod;
  return mod;
}

// ── Identity Management ────────────────────────────────────────────────

async function ensureIdentity(): Promise<string> {
  if (useSubtleCrypto) {
    return ensureIdentitySubtleCrypto();
  }
  return ensureIdentityWasm();
}

/** SubtleCrypto path: keys stored as opaque CryptoKey objects in IndexedDB. */
async function ensureIdentitySubtleCrypto(): Promise<string> {
  const stored = await loadPrincipalKeypair();
  if (stored) return stored.did;

  // First run: generate new keypair
  const keypair = await generateKeypair();
  const sdk = await loadWasm();
  const rawPub = await exportPublicKeyRaw(keypair.publicKey);
  const did = sdk.publicKeyBytesToDid(rawPub);

  await storePrincipalKeypair(keypair.privateKey, keypair.publicKey, rawPub, did);
  return did;
}

/** WASM fallback: keys stored as AES-256-GCM encrypted seeds. */
async function ensureIdentityWasm(): Promise<string> {
  const sdk = await loadWasm();
  const stored = await loadPrincipalKey();

  if (stored) {
    const kp = sdk.PrincipalKeypair.fromSecretBytes(stored);
    const did = kp.did();
    kp.free();
    return did;
  }

  const seed = crypto.getRandomValues(new Uint8Array(32));
  const kp = sdk.PrincipalKeypair.fromSecretBytes(seed);
  const did = kp.did();
  await storePrincipalKey(seed);
  kp.free();
  return did;
}

/** Load the WASM principal keypair from legacy storage. Caller must free(). */
async function loadKeypairWasm() {
  const sdk = await loadWasm();
  const secret = await loadPrincipalKey();
  if (!secret) throw new Error("No principal key stored");
  return sdk.PrincipalKeypair.fromSecretBytes(secret);
}

// ── SubtleCrypto Signing Helper ────────────────────────────────────────

/**
 * Sign a WASM object's canonical bytes with SubtleCrypto and embed the
 * signature back into the object. The "sign externally" pattern:
 * WASM exposes signableBytes(), JS signs, JS calls setSignatureBytes().
 */
async function signWithSubtleCrypto(
  signable: { signableBytes(): Uint8Array; setSignatureBytes(sig: Uint8Array): void },
  privateKey: CryptoKey
): Promise<void> {
  const bytes = signable.signableBytes();
  const sig = await subtleCryptoSign(privateKey, bytes);
  signable.setSignatureBytes(sig);
}

// ── Protocol Transport (fetch-based) ───────────────────────────────────

async function protocolPost(
  endpoint: string,
  path: string,
  body?: unknown
): Promise<ProtocolMessage> {
  const url = `${endpoint}${path}`;
  const resp = await fetch(url, {
    method: "POST",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => resp.statusText);
    throw new Error(`${resp.status} ${path}: ${text}`);
  }

  return resp.json();
}

// ── 6-Phase Handshake ──────────────────────────────────────────────────

interface HandshakeParams {
  uri: string;
  action: string;
  query: string;
  sessionId: string;
}

function sendPhase(sessionId: string, phase: number, label: string) {
  chrome.runtime.sendMessage({
    type: "PHASE_UPDATE",
    sessionId,
    phase,
    label,
  });
}

async function executeHandshake(params: HandshakeParams): Promise<void> {
  const { uri, action, query, sessionId } = params;
  const sdk = await loadWasm();
  const papUrl = parsePapUri(uri);
  const endpoint = toEndpoint(papUrl);

  const ttl = new Date(Date.now() + 3600_000).toISOString(); // 1 hour

  try {
    // ── Phase 1: Token Presentation ──────────────────────────
    sendPhase(sessionId, 1, "Presenting capability token...");

    // Resolve principal identity and signing material
    const principalDid = await ensureIdentity();

    // We need the agent's DID. For now, use a well-known discovery endpoint.
    let agentDid: string;
    try {
      const didResp = await fetch(`${endpoint}/did`);
      const didData = await didResp.json();
      agentDid = didData.did || didData.id;
    } catch {
      agentDid = `did:key:z6Mk${papUrl.host}`;
    }

    const token = sdk.CapabilityToken.mint(agentDid, action, principalDid, ttl);

    // Sign the token: SubtleCrypto or WASM
    let principalKp: InstanceType<typeof sdk.PrincipalKeypair> | null = null;
    let principalPublicKey: Uint8Array;

    if (useSubtleCrypto) {
      const stored = await loadPrincipalKeypair();
      if (!stored) throw new Error("No principal key in IndexedDB");
      await signWithSubtleCrypto(token, stored.privateKey);
      principalPublicKey = stored.publicKeyRaw;
    } else {
      principalKp = await loadKeypairWasm();
      token.sign(principalKp);
      principalPublicKey = principalKp.publicKeyBytes();
    }

    const tokenJson = JSON.parse(token.toJson());

    const phase1Resp = await protocolPost(endpoint, "/session", {
      type: "TokenPresentation",
      token: tokenJson,
    });

    if (phase1Resp.type === "TokenRejected") {
      throw new Error(`Token rejected: ${phase1Resp.reason}`);
    }
    if (phase1Resp.type === "Error") {
      throw new Error(`Protocol error: ${phase1Resp.message}`);
    }
    if (phase1Resp.type !== "TokenAccepted") {
      throw new Error(`Unexpected response: ${phase1Resp.type}`);
    }

    const agentSessionId = phase1Resp.session_id;
    const receiverSessionDid = phase1Resp.receiver_session_did;

    // ── Phase 2: Ephemeral DID Exchange ──────────────────────
    sendPhase(sessionId, 2, "Exchanging session DIDs...");

    // Generate ephemeral session keypair
    let initiatorDid: string;
    let sessionKp: InstanceType<typeof sdk.SessionKeypair> | null = null;

    if (useSubtleCrypto) {
      const ephemeralKp = await generateKeypair();
      const ephemeralPub = await exportPublicKeyRaw(ephemeralKp.publicKey);
      initiatorDid = sdk.publicKeyBytesToDid(ephemeralPub);
    } else {
      sessionKp = sdk.SessionKeypair.generate();
      initiatorDid = sessionKp.did();
    }

    // Issue mandate
    const scopeAction = sdk.ScopeAction.new(action);
    const scope = sdk.Scope.new([scopeAction]);
    const disclosure = sdk.DisclosureSet.empty();
    const mandate = sdk.Mandate.issueRoot(
      principalDid,
      agentDid,
      scope,
      disclosure,
      ttl
    );

    // Sign the mandate: SubtleCrypto or WASM
    if (useSubtleCrypto) {
      const stored = await loadPrincipalKeypair();
      if (!stored) throw new Error("No principal key in IndexedDB");
      await signWithSubtleCrypto(mandate, stored.privateKey);
    } else {
      mandate.sign(principalKp!);
    }

    // DID exchange
    await protocolPost(endpoint, `/session/${agentSessionId}/did`, {
      type: "SessionDidExchange",
      initiator_session_did: initiatorDid,
    });

    // Principal keypair is no longer needed after phase 2.
    if (principalKp) {
      principalKp.free();
      principalKp = null;
    }

    // ── Phase 3: Selective Disclosure ────────────────────────
    sendPhase(sessionId, 3, "Sending disclosures...");

    const disclosures = [{ "@type": action, query }];

    await protocolPost(endpoint, `/session/${agentSessionId}/disclosure`, {
      type: "DisclosureOffer",
      disclosures,
    });

    // ── Phase 4: Execution ───────────────────────────────────
    sendPhase(sessionId, 4, "Agent working...");

    const phase4Resp = await protocolPost(
      endpoint,
      `/session/${agentSessionId}/execute`
    );

    let executionResult: unknown;
    if (phase4Resp.type === "ExecutionResult") {
      executionResult = phase4Resp.result;
    } else if (phase4Resp.type === "Error") {
      throw new Error(`Execution error: ${phase4Resp.message}`);
    } else {
      executionResult = phase4Resp;
    }

    // ── Phase 5: Receipt Co-signing ──────────────────────────
    sendPhase(sessionId, 5, "Co-signing receipt...");

    // Build receipt token for session bookkeeping
    const receiptToken = sdk.CapabilityToken.mint(
      agentDid,
      action,
      principalDid,
      ttl
    );

    // Sign receipt with an ephemeral key
    if (useSubtleCrypto) {
      const ephemeralReceipt = await generateKeypair();
      await signWithSubtleCrypto(receiptToken, ephemeralReceipt.privateKey);
      // ephemeralReceipt goes out of scope — GC'd, key material never in JS
    } else {
      const receiptSigner = sdk.SessionKeypair.generate();
      receiptToken.sign(receiptSigner);
      receiptSigner.free();
    }

    const session = sdk.Session.initiate(receiptToken, agentDid, principalPublicKey);
    session.open(initiatorDid, receiverSessionDid);
    session.execute();

    const receipt = {
      session_id: session.id(),
      initiator_did: initiatorDid,
      receiver_did: receiverSessionDid,
      action,
      timestamp: new Date().toISOString(),
      disclosed_properties: ["query"],
      result_properties: [],
    };

    let coSignatures = 1;
    try {
      const phase5Resp = await protocolPost(
        endpoint,
        `/session/${agentSessionId}/receipt`,
        { type: "ReceiptForCoSign", receipt }
      );
      if (phase5Resp.type === "ReceiptCoSigned") {
        coSignatures = 2;
      }
    } catch {
      // Agent refused to co-sign — non-fatal, receipt has 1 signature
    }

    session.close();
    if (sessionKp) sessionKp.free();
    session.free();

    // ── Phase 6: Close Session ───────────────────────────────
    sendPhase(sessionId, 6, "Closing session...");

    await protocolPost(endpoint, `/session/${agentSessionId}/close`, {
      type: "SessionClose",
      session_id: agentSessionId,
    });

    // ── Done ─────────────────────────────────────────────────
    chrome.runtime.sendMessage({
      type: "HANDSHAKE_COMPLETE",
      sessionId,
      result: executionResult,
      receipt: {
        session_id: agentSessionId,
        co_signatures: coSignatures,
        action,
      },
    });

    // Free remaining WASM objects
    token.free();
    mandate.free();
    scopeAction.free();
    scope.free();
    disclosure.free();
    receiptToken.free();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    chrome.runtime.sendMessage({
      type: "HANDSHAKE_FAILED",
      sessionId,
      phase: 0, // Will be overridden by last known phase in UI
      error: message,
    });
  }
}

// ── Message Handler ────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener(
  (msg: ExtensionMessage, _sender, sendResponse) => {
    switch (msg.type) {
      case "ENSURE_IDENTITY":
        ensureIdentity()
          .then((did) => sendResponse({ type: "IDENTITY_READY", did }))
          .catch((err) =>
            sendResponse({ type: "IDENTITY_READY", did: null, error: err.message })
          );
        return true; // async response

      case "START_HANDSHAKE":
        executeHandshake({
          uri: msg.uri,
          action: msg.action,
          query: msg.query,
          sessionId: crypto.randomUUID(),
        });
        sendResponse({ ok: true });
        return false;

      case "WASM_REQUEST":
        handleWasmRequest(msg)
          .then((result) =>
            sendResponse({ type: "WASM_RESPONSE", id: msg.id, result })
          )
          .catch((err) =>
            sendResponse({
              type: "WASM_RESPONSE",
              id: msg.id,
              error: err.message,
            })
          );
        return true; // async response
    }
  }
);

async function handleWasmRequest(msg: {
  method: string;
  args: unknown[];
}): Promise<unknown> {
  const sdk = await loadWasm();

  switch (msg.method) {
    case "generateKeypair": {
      if (useSubtleCrypto) {
        const did = await ensureIdentitySubtleCrypto();
        return { did };
      }
      const seed = crypto.getRandomValues(new Uint8Array(32));
      const kp = sdk.PrincipalKeypair.fromSecretBytes(seed);
      const did = kp.did();
      await storePrincipalKey(seed);
      kp.free();
      return { did };
    }

    case "getDid": {
      if (useSubtleCrypto) {
        const stored = await loadPrincipalKeypair();
        return { did: stored?.did ?? null };
      }
      const secret = await loadPrincipalKey();
      if (!secret) return { did: null };
      const kp = sdk.PrincipalKeypair.fromSecretBytes(secret);
      const did = kp.did();
      kp.free();
      return { did };
    }

    case "didToPublicKey": {
      const bytes = sdk.didToPublicKeyBytes(msg.args[0] as string);
      return { publicKey: Array.from(bytes) };
    }

    case "publicKeyToDid": {
      const did = sdk.publicKeyBytesToDid(
        new Uint8Array(msg.args[0] as number[])
      );
      return { did };
    }

    default:
      throw new Error(`Unknown WASM method: ${msg.method}`);
  }
}

// ── Init ──────────────────────────────────────────────────────────────

initCryptoBackend().then(() => {
  console.log(
    `[PAP Offscreen] Ready (crypto: ${useSubtleCrypto ? "SubtleCrypto Ed25519" : "WASM ed25519-dalek"})`
  );
});
