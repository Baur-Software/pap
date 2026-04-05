import { sha256 as nobleSha256 } from '@noble/hashes/sha256';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** RFC 4648 §5 base64url encoding without padding. */
export function base64urlEncode(bytes: Uint8Array): string {
  // Build base64 from bytes, then convert to url-safe
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const b64 = btoa(binary);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decode a base64url-no-pad string to bytes. */
export function base64urlDecode(str: string): Uint8Array {
  // Restore standard base64
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding
  while (b64.length % 4 !== 0) {
    b64 += '=';
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** SHA-256 hash returning raw bytes. */
export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

/** SHA-256 hash returning base64url-no-pad encoded string. */
export function sha256Hash(data: Uint8Array): string {
  return base64urlEncode(sha256(data));
}

/** Serialize an object to canonical JSON bytes (compact, insertion-order keys). */
export function canonicalJson(obj: unknown): Uint8Array {
  return encoder.encode(JSON.stringify(obj));
}

/** UTF-8 encode a string to bytes. */
export function utf8Encode(str: string): Uint8Array {
  return encoder.encode(str);
}

/** UTF-8 decode bytes to a string. */
export function utf8Decode(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}
