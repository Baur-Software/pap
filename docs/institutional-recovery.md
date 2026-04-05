# Institutional M-of-N Social Recovery for Principal Keypair

**Status:** Implemented
**Spec reference:** §13.5
**Crate:** `pap-core::shamir`

---

## Overview

Institutional recovery allows a principal to split their Ed25519 seed bytes into N shards using
Shamir Secret Sharing. The shards are distributed to trusted institutions (banks, notaries,
trusted contacts). If the principal's device is lost, any M of the N trustees can cooperate to
reconstruct the seed and restore the principal's identity — without any central authority.

This is a complementary mechanism to the notary co-signing scheme (§13.5, `pap-core::recovery`).
The key difference:

| Mechanism         | How it works                                      | What trustees hold        |
|-------------------|---------------------------------------------------|---------------------------|
| Notary co-signing | M trustees approve a *new* key replacing old one  | Nothing (sign on request) |
| Shamir SSS (this) | M trustees reconstruct the *original* seed        | A shard of the seed       |

---

## Threat Model

- **Lost device:** Principal loses phone/laptop. Wants to restore original DID. → SSS recovery.
- **Tampered shard:** A trustee's storage is compromised and the shard is modified. →
  Commitment verification at reconstruction time will detect the modification and reject the shard.
- **Replay across ceremonies:** An attacker collects valid shards from ceremony A and tries to use
  them with shards from ceremony B. → The `session_nonce` is unique per ceremony and all shards in
  one reconstruction must share the same nonce. Cross-ceremony mixing is rejected.
- **Fewer than M shards:** A partial set reveals no information about the secret (perfect secrecy
  of Shamir over GF(256)).
- **Curious trustee:** A trustee with fewer than M shards learns nothing about the seed.

---

## Shard Generation (Create Ceremony)

### Algorithm

Shamir Secret Sharing over GF(2^8) with irreducible polynomial `x^8 + x^4 + x^3 + x + 1`
(the AES/GCM polynomial, 0x11B). This field is standard and well-audited.

For a 32-byte seed `S = [s_0, s_1, ..., s_31]` and parameters (threshold=M, total=N):

1. Generate a 32-byte random `session_nonce` from a CSPRNG (`OsRng`).
2. For each byte index `i ∈ [0, 31]`:
   - Choose M−1 random coefficients `c_{i,1}, ..., c_{i,M-1}` over GF(256).
   - Define polynomial `f_i(x) = s_i + c_{i,1}·x + c_{i,2}·x² + ... + c_{i,M-1}·x^{M-1}`.
3. For each trustee index `j ∈ [1, N]`:
   - `shard_bytes_j = [f_0(j), f_1(j), ..., f_31(j)]`
4. For each shard `j`, compute tamper-detection commitment:
   ```
   commitment_j = SHA-256("pap:shard:v1" ‖ session_nonce ‖ [j] ‖ [M] ‖ [N] ‖ shard_bytes_j)
   ```

### Shard Wire Format (JSON)

```json
{
  "version": 1,
  "index": 2,
  "threshold": 2,
  "total": 3,
  "shard_bytes": "<base64url-no-pad 32 bytes>",
  "session_nonce": "<base64url-no-pad 32 bytes>",
  "commitment": "<base64url-no-pad SHA-256 32 bytes>",
  "created_at": "2026-04-04T00:00:00Z"
}
```

### Shard Manifest (Public)

The `ShardManifest` is published alongside the `RecoveryMandate` and contains public commitments
that allow verification without the seed:

```json
{
  "version": 1,
  "threshold": 2,
  "total": 3,
  "session_nonce": "<base64url-no-pad 32 bytes>",
  "commitments": [
    "<commitment for shard 1>",
    "<commitment for shard 2>",
    "<commitment for shard 3>"
  ],
  "created_at": "2026-04-04T00:00:00Z"
}
```

The manifest is safe to publish publicly. It reveals nothing about the seed but allows anyone to
verify that a presented shard is unmodified.

---

## Recovery Ceremony (Reconstruct)

1. The recovering principal collects M or more shards from trustees.
2. For each shard, verify the commitment:
   ```
   expected = SHA-256("pap:shard:v1" ‖ nonce ‖ [index] ‖ [threshold] ‖ [total] ‖ shard_bytes)
   assert commitment == expected
   ```
   Shards with invalid commitments are rejected immediately.
3. Verify all shards share the same `session_nonce`. Reject if any differ.
4. Verify shard indices are unique (no duplicate index).
5. Reconstruct: for each byte position `i`, apply Lagrange interpolation over GF(256) on the
   M `(index_j, shard_bytes_j[i])` pairs to recover `s_i = f_i(0)`.
6. The reconstructed 32-byte value is the original Ed25519 seed.
7. Derive the principal keypair from the seed and verify the resulting DID matches expectations.

### Lagrange Interpolation at 0 over GF(256)

For points `(x_0, y_0), ..., (x_{M-1}, y_{M-1})`:

```
f(0) = Σ_{j=0}^{M-1} y_j · Π_{k≠j} (0 - x_k) / (x_j - x_k)
     = Σ_{j=0}^{M-1} y_j · Π_{k≠j} x_k / (x_j ⊕ x_k)   [in GF(256), - = ⊕]
```

---

## Replay Attack Prevention

- `session_nonce` is 32 bytes of CSPRNG output, unique per ceremony.
- The commitment binds `session_nonce` so that a shard cannot be repurposed for a different
  ceremony even if the shard index and threshold happen to coincide.
- At reconstruction, all provided shards must have identical `session_nonce` values. If any shard
  has a different nonce, the reconstruction is rejected with `SessionNonceMismatch`.

---

## C FFI Surface

```c
/* Opaque shard handle */
typedef struct PapRecoveryShard PapRecoveryShard;

/* Opaque shard set — holds N shards from one ceremony */
typedef struct PapRecoveryShardSet PapRecoveryShardSet;

/* Create M-of-N shards from a 32-byte seed. Returns NULL on error. */
PapRecoveryShardSet *pap_recovery_create_shards(
    const uint8_t *seed_bytes,   /* [32] */
    uint8_t        threshold,    /* M */
    uint8_t        total_shares  /* N */
);

/* Number of shards in a set */
int pap_recovery_shard_count(const PapRecoveryShardSet *set);

/* Borrow the nth shard from a set (0-indexed, do NOT free individually) */
const PapRecoveryShard *pap_recovery_shard_get(const PapRecoveryShardSet *set, int index);

/* Free a shard set (and all shards within it) */
void pap_recovery_shard_set_free(PapRecoveryShardSet *set);

/* Reconstruct seed from shards. Returns 0 on success, -1 on error.
   seed_out must be a caller-allocated [32]-byte buffer. */
int pap_recovery_reconstruct(
    const PapRecoveryShard *const *shards,
    int                            shard_count,
    uint8_t                       *seed_out    /* [32] */
);

/* Serialize a shard to JSON. Caller frees with pap_string_free(). */
char *pap_recovery_shard_to_json(const PapRecoveryShard *shard);

/* Deserialize a shard from JSON. Caller frees with pap_recovery_shard_free(). */
PapRecoveryShard *pap_recovery_shard_from_json(const char *json);

/* Free a standalone shard (one returned by pap_recovery_shard_from_json). */
void pap_recovery_shard_free(PapRecoveryShard *shard);
```

---

## Papillon Integration

### Post-Onboarding Prompt

After the LLM setup wizard completes, Papillon shows a recovery setup prompt:

```
RECOVERY_SETUP — INSTITUTIONAL KEY SPLITTING

Split your identity key across 3 trusted contacts.
Any 2 can reconstruct your identity if your device is lost.

  [02] CONFIGURE   →  Set M and N
  [03] DISTRIBUTE  →  Review and export N shard files (one at a time)
  [04] CONFIRM     →  Mark as backed up
```

The flow is skippable and dismissible. A status indicator in the settings panel shows whether
recovery is configured.

### Tauri Commands

| Command                    | Args                                       | Returns                      |
|----------------------------|--------------------------------------------|------------------------------|
| `create_recovery_shards`   | `{ threshold: u8, total: u8 }`             | `RecoverySetupResult`        |
| `reconstruct_from_shards`  | `{ shards_json: Vec<String> }`             | `RecoveryReconstructResult`  |
| `mark_recovery_complete`   | _(none)_                                   | `()`                         |
| `get_recovery_status`      | _(none)_                                   | `RecoveryStatus`             |

### State

`RecoveryState` (Leptos context):
- `show_setup: RwSignal<bool>` — whether the setup modal is open
- `shards: RwSignal<Vec<RecoveryShardInfo>>` — generated shards for export
- `manifest_json: RwSignal<String>` — public shard manifest JSON
- `threshold: RwSignal<u8>` — user-selected M
- `total: RwSignal<u8>` — user-selected N
- `generating: RwSignal<bool>` — loading indicator
- `error: RwSignal<Option<String>>` — last error
- `setup_complete: RwSignal<bool>` — whether recovery has been set up

---

## Security Notes

1. **Seed zeroization:** `shamir::reconstruct()` returns `zeroize::Zeroizing<[u8; 32]>` so the
   reconstructed seed is automatically zeroized when the caller drops it. Shard bytes (`RecoveryShard`
   `Drop` impl) and polynomial coefficients (`ZeroizingCoeffs` wrapper) are zeroized immediately
   after use. The `seed_b64` intermediate string in `reconstruct_from_shards` is explicitly zeroized
   before the function returns.

2. **No novel cryptography:** GF(256) Shamir is a textbook algorithm with decades of analysis.
   The commitment scheme uses standard SHA-256. No custom primitives.

3. **Threshold enforced locally:** Reconstruction with fewer than M shards returns an incorrect
   (uniformly random-looking) result in the pure SSS sense. The commitment check ensures this
   case is detected: reconstruction only proceeds when all presented shards pass commitment
   verification and there are at least M shards.

4. **Index range:** Shard indices are in [1, 255]. Index 0 is reserved (it equals the secret in
   the polynomial, so evaluating at x=0 would expose the secret byte directly).

5. **The manifest is public:** The `ShardManifest` containing commitments and the `session_nonce`
   is safe to publish publicly. A `session_nonce` without shard values reveals nothing about the
   seed.

6. **TOCTOU guard in `reconstruct_from_shards`:** The signer write-lock is acquired before the
   DID-match check and held through the signer/seed installation. This prevents a concurrent
   `switch_profile` call from racing between the check and the write, which would otherwise allow
   a different identity to be silently overwritten.

7. **DB correctness:** The reconstructed seed is persisted to `profiles_db` (the authoritative
   profiles database) rather than the legacy key-value store. The legacy store is used only as a
   fallback on first-run (pre-migration) devices where no active profile record exists. Seeds written
   only to the legacy store would be silently reverted on the next restart.
