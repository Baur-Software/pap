# TODOS

## Recovery / Shamir Secret Sharing

### [P1] Upgrade shard commitments from SHA-256 to HMAC for forgery resistance

**Priority:** P1
**Context:** `crates/pap-core/src/shamir.rs` — see module-level doc comment.

The current SHA-256 commitment includes `session_nonce` as a binding factor, but
`session_nonce` is published in the `ShardManifest`. A party who possesses the manifest
can therefore compute a valid commitment over arbitrary `shard_bytes` (SHA-256 has no key).
The scheme defends against accidental bit-flip/storage corruption but not against a
malicious trustee who wants to substitute their shard with a crafted fake.

The protocol threat model assumes trustee honesty at the social layer (a malicious trustee
can equally just withhold their shard). But the commitment should still be unforgeable for
defence in depth.

**Proposed fix:** replace `SHA-256(domain || nonce || index || threshold || total || shard_bytes)`
with `HMAC(key = KDF(seed, "pap:shard-commitment:v2"), data = nonce || index || threshold || total || shard_bytes)`.
The HMAC key is derived from the seed being split, so only the genuine shard-creator can
produce valid commitments. Verification during `reconstruct()` uses the reconstructed seed
after a first-pass interpolation to re-verify all commitment MACs, aborting if any mismatch.

This is a protocol-breaking change — all existing shards will be incompatible. Requires a
`version: 2` shard format and a migration note in the spec (§13.5).

**Noticed on:** `vk/3444-institutional-m` (adversarial review, 2026-04-04)

---

## Completed

<!-- Items completed in prior releases are listed here -->
