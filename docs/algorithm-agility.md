# Algorithm Agility

PAP v1.0 uses Ed25519 (RFC 8032) exclusively for all signatures.
This document describes the migration path for adding future algorithms.

## Current State

All signable artifacts carry a `SignatureAlgorithm` field (serialized as
the JWS `alg` string, e.g. `"EdDSA"`). The field defaults to `Ed25519`
when absent, maintaining backward compatibility with v1.0 artifacts.

The `SignatureAlgorithm` enum is defined in `pap-did` and is
`#[non_exhaustive]`, so adding a variant is not a semver-breaking change.

## Supported Algorithms

| Algorithm | JWS `alg` | Multicodec Prefix | Key Size | Sig Size | Status |
|-----------|-----------|-------------------|----------|----------|--------|
| Ed25519   | `EdDSA`   | `0xed01`          | 32 bytes | 64 bytes | **Supported** |
| ML-DSA-65 | TBD       | TBD               | TBD      | TBD      | Future |

## How to Add a New Algorithm

### 1. Add enum variant

In `crates/pap-did/src/algorithm.rs`, add a new variant:

```rust
#[non_exhaustive]
pub enum SignatureAlgorithm {
    #[serde(rename = "EdDSA")]
    Ed25519,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,  // FIPS 204
}
```

### 2. Implement metadata methods

Add `match` arms to every method on `SignatureAlgorithm`:
- `multicodec_prefix()` — the multicodec table entry for the new key type
- `jws_alg()` — the JWS algorithm identifier
- `verification_key_type()` — the W3C DID verification method type
- `proof_type()` — the Linked Data proof type
- `public_key_size()` — key size in bytes
- `signature_size()` — signature size in bytes
- `from_multicodec_prefix()` — reverse lookup from prefix bytes

### 3. Add signing/verification support

In each signable struct's `sign()` and `verify()` functions, add a
`match` arm for the new algorithm. Currently these functions accept
`ed25519_dalek::SigningKey` / `VerifyingKey` directly. For a new
algorithm, you have two options:

**Option A** (minimal): Add a separate `sign_ml_dsa()` / `verify_ml_dsa()`
method pair that accepts the ML-DSA key type.

**Option B** (future): Introduce a `Signer` trait that abstracts over
key types and modify `sign()` / `verify()` to accept `&dyn Signer`.

### 4. Update DID derivation

`public_key_to_did_for_algorithm()` and `did_to_public_key_bytes_with_algorithm()`
in `crates/pap-did/src/principal.rs` already support arbitrary algorithms
via the `SignatureAlgorithm` enum. The new algorithm's multicodec prefix
is used automatically.

### 5. Update PrincipalKeypair

Either extend `PrincipalKeypair` to support the new key type, or create
a new keypair struct (e.g., `MlDsaKeypair`). The `PrincipalSigner` trait
in `crates/pap-webauthn/src/signer.rs` already has an `algorithm()`
default method — override it in the new implementation.

### 6. Run tests

All existing tests are parameterizable by algorithm. Add test calls
with the new algorithm variant.

## Backward Compatibility

- Every `algorithm` field uses `#[serde(default)]`, so existing serialized
  data without this field deserializes to `Ed25519`.
- `canonical_bytes()` does NOT include the `algorithm` field for Ed25519
  mandates, preserving hash stability for existing artifacts.
- Implementations MUST reject algorithms they do not support.

## Hash Stability

The `canonical_bytes()` function (used for signing and hashing) excludes
the `algorithm` field when it equals the default (`Ed25519`). This means:

- Existing Ed25519 mandates produce the same hash before and after
  the algorithm agility change.
- Future non-Ed25519 mandates SHOULD include the algorithm in their
  canonical form for domain separation.

## No Breaking Changes

Adding a new `SignatureAlgorithm` variant does not break:
- Existing serialized data (serde default)
- Existing hash/signature verification (canonical form unchanged)
- Downstream crate compilation (`#[non_exhaustive]` requires wildcard match)
