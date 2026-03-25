# WASM Security Considerations

This document covers security implications of running Ed25519 key material
in WebAssembly (WASM) linear memory, as used by `pap-did` in the browser
build of Papillion.

## Memory Zeroization

The `pap-did` crate uses `ed25519-dalek` with the `zeroize` feature on native
targets. When compiled to WebAssembly, **zeroization guarantees are weakened**:

1. **WASM linear memory is a flat byte array** managed by the JavaScript
   runtime. The `zeroize` crate's `Drop` implementation writes zeros to the
   memory location, but the WASM engine may have already copied the bytes
   elsewhere (e.g., during memory growth or GC compaction).

2. **JavaScript JIT engines** may create intermediate copies of WASM memory
   pages for optimization purposes. These copies are outside Rust's control
   and are not zeroed.

3. **Browser developer tools** can inspect WASM linear memory at any point,
   potentially exposing key material to a user with devtools access.

## Storage Security: IndexedDB vs localStorage

Private key seeds are stored in **IndexedDB**, not localStorage, for several
reasons:

| Property | IndexedDB | localStorage |
|----------|-----------|--------------|
| Same-origin isolation | Yes | Yes |
| Storage format | Structured clone (binary-safe) | String-only |
| XSS exfiltration surface | Lower (async API, no `document.cookie` path) | Higher (sync string access) |
| Storage limits | Large (GB-scale) | Small (~5-10 MB) |
| Transaction support | Yes (ACID within a transaction) | No |

IndexedDB's async, structured-clone API makes it harder for injected scripts
to silently exfiltrate data compared to the synchronous string-based
`localStorage` API.

## Mitigations

- **IndexedDB for secrets**: Ed25519 seeds are stored as base64url-encoded
  values in IndexedDB under a reserved key (`__profiles__`), isolated per
  origin.

- **No key material in return types**: `IdentityInfo` contains only the DID
  (public) and base64url-encoded public key. Seeds never leave the
  `WebIdentityService` module except through internal keypair reconstruction.

- **Session keys are ephemeral**: `SessionKeypair` instances are generated
  per-session and never persisted to storage. Their exposure window is limited
  to the session lifetime.

- **Minimal memory residence**: Seeds are loaded from IndexedDB, used for
  signing, and the `PrincipalKeypair` is dropped as soon as possible. While
  zeroization is best-effort in WASM, minimizing the lifetime reduces the
  exposure window.

## Recommendations for Production

- **Use WebAuthn / platform authenticators** for principal key operations
  where available. The PAP specification designates `PrincipalKeypair` as a
  software fallback; production deployments should prefer hardware-backed
  keys via the WebAuthn API.

- **Consider Web Crypto API** (`SubtleCrypto`) for key generation and
  signing. Web Crypto stores keys in opaque, non-extractable objects that
  cannot be read from WASM linear memory. This would require an alternative
  signing abstraction (not `ed25519-dalek`). Note: Web Crypto does not
  natively support Ed25519 in all browsers as of 2026.

- **Content Security Policy**: Deploy with a strict CSP to reduce XSS
  injection vectors that could access IndexedDB.

- **Do not log or serialize seeds**: Avoid `Debug` or `Display` output that
  includes seed material. The `PrincipalKeypair` struct intentionally does
  not implement `Debug`.
