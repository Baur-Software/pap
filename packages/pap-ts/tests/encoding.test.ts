import { describe, it, expect } from 'vitest';
import { base64urlEncode, base64urlDecode, sha256, sha256Hash, canonicalJson, utf8Encode } from '../src/encoding.js';

describe('base64url', () => {
  it('encodes and decodes empty bytes', () => {
    const empty = new Uint8Array(0);
    const encoded = base64urlEncode(empty);
    expect(encoded).toBe('');
    expect(base64urlDecode(encoded)).toEqual(empty);
  });

  it('roundtrips arbitrary bytes', () => {
    const data = new Uint8Array([0, 1, 2, 255, 254, 253, 128, 64]);
    const encoded = base64urlEncode(data);
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(encoded).not.toContain('=');
    const decoded = base64urlDecode(encoded);
    expect(decoded).toEqual(data);
  });

  it('roundtrips 32-byte key material', () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const decoded = base64urlDecode(base64urlEncode(key));
    expect(decoded).toEqual(key);
  });

  it('roundtrips 64-byte signature', () => {
    const sig = new Uint8Array(64);
    crypto.getRandomValues(sig);
    const decoded = base64urlDecode(base64urlEncode(sig));
    expect(decoded).toEqual(sig);
  });
});

describe('sha256', () => {
  it('produces 32-byte hash', () => {
    const hash = sha256(utf8Encode('hello'));
    expect(hash.length).toBe(32);
  });

  it('is deterministic', () => {
    const a = sha256(utf8Encode('test'));
    const b = sha256(utf8Encode('test'));
    expect(a).toEqual(b);
  });

  it('sha256Hash returns base64url string', () => {
    const hash = sha256Hash(utf8Encode('hello'));
    expect(typeof hash).toBe('string');
    expect(hash).not.toContain('+');
    expect(hash).not.toContain('/');
    expect(hash).not.toContain('=');
  });
});

describe('canonicalJson', () => {
  it('serializes objects to bytes', () => {
    const bytes = canonicalJson({ a: 1, b: 'hello' });
    const str = new TextDecoder().decode(bytes);
    expect(str).toBe('{"a":1,"b":"hello"}');
  });

  it('preserves insertion order', () => {
    const bytes = canonicalJson({ z: 1, a: 2 });
    const str = new TextDecoder().decode(bytes);
    expect(str).toBe('{"z":1,"a":2}');
  });

  it('handles null values', () => {
    const bytes = canonicalJson({ key: null });
    const str = new TextDecoder().decode(bytes);
    expect(str).toBe('{"key":null}');
  });

  it('handles nested objects', () => {
    const bytes = canonicalJson({ outer: { inner: true } });
    const str = new TextDecoder().decode(bytes);
    expect(str).toBe('{"outer":{"inner":true}}');
  });
});
