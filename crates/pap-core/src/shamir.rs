//! Shamir Secret Sharing over GF(2^8) for Ed25519 seed bytes (spec §13.5 extension).
//!
//! Splits a 32-byte Ed25519 seed into N shards using a (M, N) threshold scheme.
//! Any M shards can reconstruct the original seed; fewer than M reveal nothing
//! (perfect secrecy of Shamir over finite fields).
//!
//! ## Tamper Detection
//! Each shard carries a SHA-256 commitment over its index, threshold, total, session nonce,
//! and shard bytes. Any modification to a shard invalidates the commitment, which is
//! detected at reconstruction time before any Lagrange interpolation is attempted.
//!
//! ## Replay Attack Prevention
//! A 32-byte `session_nonce` is generated from a CSPRNG once per ceremony and embedded
//! in every shard. Reconstruction requires all shards to share the same nonce, preventing
//! cross-ceremony shard mixing.
//!
//! ## Field
//! GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B) — the same
//! field used by AES. Standard, well-analysed, no novel cryptography.

use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::PapError;

// ---------------------------------------------------------------------------
// GF(2^8) arithmetic
// ---------------------------------------------------------------------------

/// Multiply two GF(256) elements using the AES irreducible polynomial.
///
/// Constant-time (no secret-dependent branches or table lookups).
#[inline]
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        // If the LSB of b is set, XOR result with a.
        result ^= (b & 1).wrapping_neg() & a;
        // Shift a left and reduce mod 0x11B if the high bit was set.
        let hi = a & 0x80;
        a <<= 1;
        a ^= (hi >> 7).wrapping_neg() & 0x1b;
        b >>= 1;
    }
    result
}

/// Compute a^exp in GF(256) via square-and-multiply.
#[inline]
fn gf_pow(mut base: u8, mut exp: u8) -> u8 {
    let mut result = 1u8;
    while exp > 0 {
        if exp & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}

/// Multiplicative inverse in GF(256) via Fermat's little theorem: a^{-1} = a^{254}.
///
/// Returns 0 for input 0 (0 has no inverse; callers must never pass 0 to this function
/// via distinct x-coordinates, which the shard generation guarantees).
#[inline]
fn gf_inv(a: u8) -> u8 {
    gf_pow(a, 254)
}

/// Evaluate polynomial `f(x) = coeffs[0] + coeffs[1]*x + ... + coeffs[d]*x^d`
/// over GF(256) at the point `x`.
#[inline]
fn poly_eval(coeffs: &[u8], x: u8) -> u8 {
    // Horner's method for efficiency.
    let mut result = 0u8;
    for &c in coeffs.iter().rev() {
        result = gf_mul(result, x) ^ c;
    }
    result
}

/// Lagrange interpolation at x=0 over GF(256).
///
/// Given M points `(x_coords[i], y_coords[i])`, returns f(0) where f is the
/// unique polynomial of degree < M passing through all points.
///
/// # Panics
/// `x_coords` must not contain duplicate values or the value 0.
fn lagrange_at_zero(x_coords: &[u8], y_coords: &[u8]) -> u8 {
    debug_assert_eq!(x_coords.len(), y_coords.len());
    let n = x_coords.len();
    let mut secret = 0u8;
    for i in 0..n {
        // Compute the Lagrange basis polynomial evaluated at 0:
        //   L_i(0) = Π_{j≠i} (0 - x_j) / (x_i - x_j)
        //          = Π_{j≠i} x_j / (x_i XOR x_j)   [negation = identity in GF(2^k)]
        let mut num = 1u8;
        let mut den = 1u8;
        for j in 0..n {
            if i == j {
                continue;
            }
            num = gf_mul(num, x_coords[j]);
            den = gf_mul(den, x_coords[i] ^ x_coords[j]);
        }
        secret ^= gf_mul(y_coords[i], gf_mul(num, gf_inv(den)));
    }
    secret
}

// ---------------------------------------------------------------------------
// Commitment domain separator
// ---------------------------------------------------------------------------

const COMMITMENT_DOMAIN: &[u8] = b"pap:shard:v1";

fn compute_commitment(
    session_nonce: &[u8; 32],
    index: u8,
    threshold: u8,
    total: u8,
    shard_bytes: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COMMITMENT_DOMAIN);
    h.update(session_nonce);
    h.update([index, threshold, total]);
    h.update(shard_bytes);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single Shamir shard held by one trustee.
///
/// The shard is serializable to JSON for distribution to trustees.
/// Trustees should store the JSON blob securely (e.g., in an HSM, sealed envelope,
/// encrypted password manager entry, or bank safe).
// NOTE: no Zeroize derive — DateTime<Utc> doesn't implement Zeroize.
// Drop is implemented manually to zeroize the secret-carrying string fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryShard {
    /// Format version (currently 1).
    pub version: u8,
    /// Shard index in `[1, total]`. Unique within a ceremony.
    pub index: u8,
    /// Minimum shards required to reconstruct (M).
    pub threshold: u8,
    /// Total shards produced in this ceremony (N).
    pub total: u8,
    /// 32 bytes of GF(256) polynomial evaluations (one per seed byte), base64url-encoded.
    pub shard_bytes: String,
    /// 32-byte per-ceremony random nonce, base64url-encoded.
    /// All shards in one ceremony share the same nonce.
    pub session_nonce: String,
    /// SHA-256 commitment binding all fields for tamper detection, base64url-encoded.
    pub commitment: String,
    /// Creation timestamp (same for all shards in a ceremony).
    pub created_at: DateTime<Utc>,
}

impl Drop for RecoveryShard {
    fn drop(&mut self) {
        // shard_bytes and session_nonce carry secret material (GF polynomial
        // evaluations of the seed bytes, and the ceremony nonce). Zeroize them
        // before the heap allocation is released.
        self.shard_bytes.zeroize();
        self.session_nonce.zeroize();
        self.commitment.zeroize();
    }
}

impl RecoveryShard {
    /// Decode the raw 32 shard bytes from the base64url field.
    fn raw_shard_bytes(&self) -> Result<[u8; 32], PapError> {
        use base64::Engine;
        let v = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&self.shard_bytes)
            .map_err(|e| PapError::RecoveryError(format!("invalid shard_bytes encoding: {e}")))?;
        v.as_slice()
            .try_into()
            .map_err(|_| PapError::RecoveryError("shard_bytes must be 32 bytes".into()))
    }

    /// Decode the raw 32-byte session nonce.
    fn raw_session_nonce(&self) -> Result<[u8; 32], PapError> {
        use base64::Engine;
        let v = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&self.session_nonce)
            .map_err(|e| {
                PapError::RecoveryError(format!("invalid session_nonce encoding: {e}"))
            })?;
        v.as_slice()
            .try_into()
            .map_err(|_| PapError::RecoveryError("session_nonce must be 32 bytes".into()))
    }

    /// Verify this shard's commitment. Returns an error if the shard has been tampered with.
    ///
    /// Comparison is performed in constant time to avoid timing side-channels.
    pub fn verify_commitment(&self) -> Result<(), PapError> {
        use base64::Engine;
        let shard_bytes = self.raw_shard_bytes()?;
        let session_nonce = self.raw_session_nonce()?;
        let expected = compute_commitment(
            &session_nonce,
            self.index,
            self.threshold,
            self.total,
            &shard_bytes,
        );
        // Decode the stored commitment to raw bytes and compare using constant-time eq.
        let stored_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&self.commitment)
            .map_err(|e| PapError::RecoveryError(format!("invalid commitment encoding: {e}")))?;
        let stored: [u8; 32] = stored_bytes
            .as_slice()
            .try_into()
            .map_err(|_| PapError::RecoveryError("commitment must be 32 bytes".into()))?;
        // subtle::ConstantTimeEq prevents timing side-channels.
        if expected.ct_eq(&stored).unwrap_u8() == 0 {
            return Err(PapError::RecoveryError(format!(
                "shard {} commitment verification failed — shard has been tampered with",
                self.index
            )));
        }
        Ok(())
    }

    /// Serialize to a JSON string for distribution to a trustee.
    pub fn to_json(&self) -> Result<String, PapError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| PapError::Serialization(e.to_string()))
    }

    /// Deserialize from a JSON string received from a trustee.
    pub fn from_json(json: &str) -> Result<Self, PapError> {
        serde_json::from_str(json).map_err(|e| PapError::Serialization(e.to_string()))
    }
}

/// A public manifest describing a shard ceremony.
///
/// The manifest is safe to publish (it reveals nothing about the seed) and allows
/// independent verification that presented shards are unmodified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardManifest {
    /// Format version (currently 1).
    pub version: u8,
    /// Minimum shards required to reconstruct (M).
    pub threshold: u8,
    /// Total shards produced (N).
    pub total: u8,
    /// Per-ceremony random nonce (base64url), shared by all shards.
    pub session_nonce: String,
    /// One SHA-256 commitment per shard, in index order (1..=N).
    pub commitments: Vec<String>,
    /// Ceremony timestamp.
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Shard generation
// ---------------------------------------------------------------------------

/// Zeroizing wrapper for polynomial coefficient buffers.
#[derive(Zeroize)]
struct ZeroizingCoeffs(Vec<u8>);

impl Drop for ZeroizingCoeffs {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Create M-of-N shards from a 32-byte Ed25519 seed.
///
/// Returns `(shards, manifest)` where:
/// - `shards[i]` is the shard for trustee `i+1` (1-indexed).
/// - `manifest` is the public commitment manifest.
///
/// # Errors
/// Returns `InvalidRecoveryMandate` if:
/// - `threshold == 0` or `threshold > total_shares`
/// - `total_shares == 0` or `total_shares > 255`
pub fn create_shards(
    seed: &[u8; 32],
    threshold: u8,
    total_shares: u8,
) -> Result<(Vec<RecoveryShard>, ShardManifest), PapError> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    if total_shares == 0 {
        return Err(PapError::InvalidRecoveryMandate(
            "total_shares must be at least 1".into(),
        ));
    }
    if threshold == 0 || threshold > total_shares {
        return Err(PapError::InvalidRecoveryMandate(format!(
            "threshold {threshold} invalid for {total_shares} shares"
        )));
    }

    let mut rng = rand::rngs::OsRng;

    // Generate a unique per-ceremony nonce.
    let mut session_nonce = [0u8; 32];
    rng.fill_bytes(&mut session_nonce);

    let now = Utc::now();

    // For each of the 32 seed bytes, choose a random polynomial of degree (threshold - 1)
    // with constant term = the seed byte.  Evaluate at x = 1..=total_shares.
    let degree = threshold as usize - 1;

    // shard_data[j][i] = evaluation of polynomial_i at x = (j+1)
    // i.e., shard_data[j] = the 32-byte shard for trustee (j+1)
    let mut shard_data: Vec<[u8; 32]> = vec![[0u8; 32]; total_shares as usize];

    for byte_idx in 0..32usize {
        // Build the polynomial coefficients: [seed[byte_idx], c_1, c_2, ..., c_{degree}]
        let mut coeffs = ZeroizingCoeffs(vec![0u8; threshold as usize]);
        coeffs.0[0] = seed[byte_idx];
        if degree > 0 {
            rng.fill_bytes(&mut coeffs.0[1..]);
        }

        // Evaluate at each trustee's x-coordinate (1..=N).
        for j in 0..(total_shares as usize) {
            let x = (j + 1) as u8; // x ∈ [1, 255], never 0
            shard_data[j][byte_idx] = poly_eval(&coeffs.0, x);
        }
        // coeffs is zeroized when it drops.
    }

    // Build shard objects with tamper-detection commitments.
    let mut shards = Vec::with_capacity(total_shares as usize);
    let mut commitments = Vec::with_capacity(total_shares as usize);

    for j in 0..(total_shares as usize) {
        let index = (j + 1) as u8;
        let commitment_bytes =
            compute_commitment(&session_nonce, index, threshold, total_shares, &shard_data[j]);
        let commitment = b64.encode(commitment_bytes);

        shards.push(RecoveryShard {
            version: 1,
            index,
            threshold,
            total: total_shares,
            shard_bytes: b64.encode(shard_data[j]),
            session_nonce: b64.encode(session_nonce),
            commitment: commitment.clone(),
            created_at: now,
        });
        commitments.push(commitment);
    }

    // Zeroize raw shard data.
    for buf in shard_data.iter_mut() {
        buf.zeroize();
    }

    let manifest = ShardManifest {
        version: 1,
        threshold,
        total: total_shares,
        session_nonce: b64.encode(session_nonce),
        commitments,
        created_at: now,
    };

    Ok((shards, manifest))
}

// ---------------------------------------------------------------------------
// Reconstruction
// ---------------------------------------------------------------------------

/// Reconstruct the 32-byte seed from M or more shards.
///
/// Performs commitment verification and replay-attack detection before any
/// cryptographic reconstruction.
///
/// # Errors
/// - `RecoveryError` if a shard has been tampered with (commitment mismatch).
/// - `RecoveryError` if shards come from different ceremonies (session nonce mismatch).
/// - `RecoveryError` if shard indices are not unique.
/// - `ThresholdNotMet` if fewer than threshold shards are provided.
pub fn reconstruct(shards: &[&RecoveryShard]) -> Result<zeroize::Zeroizing<[u8; 32]>, PapError> {
    if shards.is_empty() {
        return Err(PapError::ThresholdNotMet(1, 0));
    }

    let threshold = shards[0].threshold as usize;

    if shards.len() < threshold {
        return Err(PapError::ThresholdNotMet(threshold, shards.len()));
    }

    // 1. Verify all commitments before any further processing.
    for shard in shards.iter() {
        shard.verify_commitment()?;
    }

    // 2. Verify consistent session nonce (no cross-ceremony mixing).
    // Decode to raw bytes and compare constant-time to avoid timing side-channels
    // and to handle any base64 encoding normalisation inconsistencies.
    let reference_nonce = shards[0].raw_session_nonce()?;
    for shard in shards.iter().skip(1) {
        let shard_nonce = shard.raw_session_nonce()?;
        if reference_nonce.ct_eq(&shard_nonce).unwrap_u8() == 0 {
            return Err(PapError::RecoveryError(
                "session nonce mismatch — shards are from different ceremonies".into(),
            ));
        }
    }

    // 3. Verify consistent threshold and total metadata.
    let expected_threshold = shards[0].threshold;
    let expected_total = shards[0].total;
    for shard in shards.iter().skip(1) {
        if shard.threshold != expected_threshold || shard.total != expected_total {
            return Err(PapError::RecoveryError(
                "shard metadata mismatch (threshold or total differs)".into(),
            ));
        }
    }

    // 4. Verify unique shard indices.
    let mut seen_indices = std::collections::HashSet::new();
    for shard in shards.iter() {
        if !seen_indices.insert(shard.index) {
            return Err(PapError::RecoveryError(format!(
                "duplicate shard index {}",
                shard.index
            )));
        }
        if shard.index == 0 {
            return Err(PapError::RecoveryError(
                "shard index 0 is reserved".into(),
            ));
        }
    }

    // 5. Decode shard bytes for reconstruction (only use first `threshold` shards).
    let working_shards = &shards[..threshold];
    let mut decoded: Vec<[u8; 32]> = Vec::with_capacity(threshold);
    let mut x_coords: Vec<u8> = Vec::with_capacity(threshold);
    for shard in working_shards.iter() {
        decoded.push(shard.raw_shard_bytes()?);
        x_coords.push(shard.index);
    }

    // 6. Lagrange interpolation at 0 for each byte.
    // Use Zeroizing so partial secret is cleared on early error exit.
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    for byte_idx in 0..32usize {
        let mut y_coords: Vec<u8> = decoded.iter().map(|s| s[byte_idx]).collect();
        secret[byte_idx] = lagrange_at_zero(&x_coords, &y_coords);
        y_coords.zeroize();
    }

    // Zeroize decoded shard bytes.
    for buf in decoded.iter_mut() {
        buf.zeroize();
    }

    Ok(secret)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Convenience: generate shards and immediately verify round-trip.
    fn make_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        seed
    }

    // ------------------------------------------------------------------
    // Happy-path tests
    // ------------------------------------------------------------------

    #[test]
    fn round_trip_1_of_1() {
        let seed = make_seed();
        let (shards, _manifest) = create_shards(&seed, 1, 1).unwrap();
        let refs: Vec<&RecoveryShard> = shards.iter().collect();
        let recovered = reconstruct(&refs).unwrap();
        assert_eq!(seed, *recovered);
    }

    #[test]
    fn round_trip_2_of_3() {
        let seed = make_seed();
        let (shards, _manifest) = create_shards(&seed, 2, 3).unwrap();

        // Any 2 of 3 shards reconstruct correctly.
        let r01: Vec<&RecoveryShard> = vec![&shards[0], &shards[1]];
        assert_eq!(seed, *reconstruct(&r01).unwrap());

        let r02: Vec<&RecoveryShard> = vec![&shards[0], &shards[2]];
        assert_eq!(seed, *reconstruct(&r02).unwrap());

        let r12: Vec<&RecoveryShard> = vec![&shards[1], &shards[2]];
        assert_eq!(seed, *reconstruct(&r12).unwrap());

        // All 3 shards also reconstruct correctly.
        let r012: Vec<&RecoveryShard> = shards.iter().collect();
        assert_eq!(seed, *reconstruct(&r012).unwrap());
    }

    #[test]
    fn round_trip_3_of_5() {
        let seed = make_seed();
        let (shards, _manifest) = create_shards(&seed, 3, 5).unwrap();

        // First 3 shards.
        let refs: Vec<&RecoveryShard> = shards[..3].iter().collect();
        assert_eq!(seed, *reconstruct(&refs).unwrap());

        // Shards 1, 3, 5 (indices 1, 3, 5).
        let alt: Vec<&RecoveryShard> = vec![&shards[0], &shards[2], &shards[4]];
        assert_eq!(seed, *reconstruct(&alt).unwrap());
    }

    #[test]
    fn commitment_verification_succeeds_on_unmodified_shards() {
        let seed = make_seed();
        let (shards, _) = create_shards(&seed, 2, 3).unwrap();
        for shard in &shards {
            assert!(shard.verify_commitment().is_ok());
        }
    }

    #[test]
    fn manifest_has_correct_commitments() {
        let seed = make_seed();
        let (shards, manifest) = create_shards(&seed, 2, 3).unwrap();
        assert_eq!(manifest.threshold, 2);
        assert_eq!(manifest.total, 3);
        assert_eq!(manifest.commitments.len(), 3);
        for (i, shard) in shards.iter().enumerate() {
            assert_eq!(shard.commitment, manifest.commitments[i]);
        }
    }

    #[test]
    fn json_round_trip() {
        let seed = make_seed();
        let (shards, _) = create_shards(&seed, 2, 3).unwrap();
        for shard in &shards {
            let json = shard.to_json().unwrap();
            let decoded = RecoveryShard::from_json(&json).unwrap();
            assert_eq!(shard.index, decoded.index);
            assert_eq!(shard.shard_bytes, decoded.shard_bytes);
            assert_eq!(shard.commitment, decoded.commitment);
        }
    }

    // ------------------------------------------------------------------
    // Adversarial tests
    // ------------------------------------------------------------------

    #[test]
    fn partial_shard_set_fails() {
        let seed = make_seed();
        let (shards, _) = create_shards(&seed, 3, 5).unwrap();
        // Only 2 shards provided but threshold is 3.
        let partial: Vec<&RecoveryShard> = shards[..2].iter().collect();
        let err = reconstruct(&partial).unwrap_err();
        assert!(matches!(err, PapError::ThresholdNotMet(3, 2)));
    }

    #[test]
    fn tampered_shard_bytes_detected() {
        let seed = make_seed();
        let (mut shards, _) = create_shards(&seed, 2, 3).unwrap();

        // Tamper with the shard_bytes field of the first shard.
        let mut bad = shards[0].clone();
        // Flip one bit in the base64-decoded bytes, then re-encode.
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut raw = b64.decode(&bad.shard_bytes).unwrap();
        raw[0] ^= 0xFF;
        bad.shard_bytes = b64.encode(&raw);

        let refs: Vec<&RecoveryShard> = vec![&bad, &shards[1]];
        let err = reconstruct(&refs).unwrap_err();
        assert!(
            matches!(err, PapError::RecoveryError(ref s) if s.contains("commitment verification failed")),
            "expected commitment failure, got: {err}"
        );

        // Silence unused_variable warning from the original shards vec mutation.
        let _ = shards.get(2);
    }

    #[test]
    fn tampered_commitment_field_detected() {
        let seed = make_seed();
        let (shards, _) = create_shards(&seed, 2, 3).unwrap();

        // Tamper only the commitment string (without changing shard_bytes).
        let mut bad = shards[0].clone();
        bad.commitment = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();

        let refs: Vec<&RecoveryShard> = vec![&bad, &shards[1]];
        let err = reconstruct(&refs).unwrap_err();
        assert!(
            matches!(err, PapError::RecoveryError(ref s) if s.contains("commitment verification failed")),
            "expected commitment failure, got: {err}"
        );
    }

    #[test]
    fn cross_ceremony_shard_mixing_rejected() {
        let seed_a = make_seed();
        let seed_b = make_seed();
        let (shards_a, _) = create_shards(&seed_a, 2, 3).unwrap();
        let (shards_b, _) = create_shards(&seed_b, 2, 3).unwrap();

        // Mix shard from ceremony A with shard from ceremony B.
        let mixed: Vec<&RecoveryShard> = vec![&shards_a[0], &shards_b[1]];
        let err = reconstruct(&mixed).unwrap_err();
        // The commitment on shards_b[1] will fail because its session_nonce differs.
        // (Either the session nonce mismatch or the commitment check catches it.)
        assert!(
            matches!(err, PapError::RecoveryError(_)),
            "expected RecoveryError for cross-ceremony mixing, got: {err}"
        );
    }

    #[test]
    fn duplicate_shard_index_rejected() {
        let seed = make_seed();
        let (shards, _) = create_shards(&seed, 2, 3).unwrap();
        // Present the same shard twice.
        let duplicates: Vec<&RecoveryShard> = vec![&shards[0], &shards[0]];
        let err = reconstruct(&duplicates).unwrap_err();
        assert!(
            matches!(err, PapError::RecoveryError(ref s) if s.contains("duplicate shard index")),
            "expected duplicate index error, got: {err}"
        );
    }

    #[test]
    fn empty_shard_list_rejected() {
        let err = reconstruct(&[]).unwrap_err();
        assert!(matches!(err, PapError::ThresholdNotMet(1, 0)));
    }

    #[test]
    fn zero_threshold_rejected() {
        let seed = make_seed();
        let err = create_shards(&seed, 0, 3).unwrap_err();
        assert!(matches!(err, PapError::InvalidRecoveryMandate(_)));
    }

    #[test]
    fn threshold_exceeds_total_rejected() {
        let seed = make_seed();
        let err = create_shards(&seed, 4, 3).unwrap_err();
        assert!(matches!(err, PapError::InvalidRecoveryMandate(_)));
    }

    #[test]
    fn zero_total_rejected() {
        let seed = make_seed();
        let err = create_shards(&seed, 1, 0).unwrap_err();
        assert!(matches!(err, PapError::InvalidRecoveryMandate(_)));
    }

    #[test]
    fn gf_mul_zero() {
        assert_eq!(gf_mul(0, 123), 0);
        assert_eq!(gf_mul(123, 0), 0);
    }

    #[test]
    fn gf_mul_identity() {
        for x in 1u8..=255 {
            assert_eq!(gf_mul(x, 1), x, "x * 1 should be x for x={x}");
        }
    }

    #[test]
    fn gf_inv_roundtrip() {
        for x in 1u8..=255 {
            assert_eq!(
                gf_mul(x, gf_inv(x)),
                1,
                "x * inv(x) should be 1 for x={x}"
            );
        }
    }
}
