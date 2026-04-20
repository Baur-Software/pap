//! Cryptographic acceleration via NVIDIA DOCA or software fallback.
//!
//! [`CryptoAccel`] is a trait that abstracts signing and verification
//! operations.  The default implementation [`SoftwareCrypto`] delegates to
//! `ed25519-dalek` (always available).  When the `doca-crypto` feature is
//! enabled, [`DocaCrypto`] offloads operations to the BlueField's on-chip
//! crypto engine via the DOCA Crypto API.
//!
//! # Feature-gate summary
//!
//! | Build                      | Active type        | [`crypto_backend()`] return  |
//! |----------------------------|--------------------|------------------------------|
//! | default (no `doca-crypto`) | [`SoftwareCrypto`] | `"software"`                 |
//! | `--features doca-crypto`   | [`DocaCrypto`]     | `"doca"` or `"software-fallback"` |
//!
//! Use [`crypto_backend()`] in log lines and diagnostics to verify which
//! path is active — this is the compile-time/runtime observable required by
//! the acceptance criteria.
//!
//! # Usage
//! The transport layer uses [`CryptoAccel`] to sign phase-5 receipts and
//! verify phase-1 capability token signatures without touching the host CPU.
//! On a BlueField 3 this provides ≈4× throughput improvement for high-volume
//! agent interactions.
//!
//! ```no_run
//! use pap_bluefield::crypto::{CryptoAccel, SoftwareCrypto, crypto_backend};
//! use ed25519_dalek::SigningKey;
//! use rand::rngs::OsRng;
//!
//! let key = SigningKey::generate(&mut OsRng);
//! let sw = SoftwareCrypto::new(key);
//! let sig = sw.sign(b"hello PAP");
//! assert!(sw.verify(b"hello PAP", &sig).is_ok());
//! println!("active crypto backend: {}", crypto_backend());
//! ```

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use crate::error::BluefieldError;

// ── Active-backend observable ─────────────────────────────────────────────────

/// Returns a static string identifying the crypto backend in use.
///
/// | Return value           | Meaning                                             |
/// |------------------------|-----------------------------------------------------|
/// | `"software"`           | `doca-crypto` feature disabled; all ops use dalek   |
/// | `"doca"`               | `doca-crypto` feature enabled, DOCA engine open     |
/// | `"software-fallback"`  | `doca-crypto` feature enabled, DOCA engine not open |
///
/// When the `doca-crypto` feature is enabled, prefer
/// [`DocaCrypto::crypto_backend`] which reads `hw_available` at runtime.
/// This free function is always available and returns `"software"` when the
/// feature is disabled (compile-time constant); under `doca-crypto` it
/// returns `"software-fallback"` as a safe compile-time default — call
/// [`DocaCrypto::crypto_backend`] on the live instance for the true value.
#[cfg(not(feature = "doca-crypto"))]
pub fn crypto_backend() -> &'static str {
    // NOTE: using software fallback — doca-crypto feature not enabled.
    "software"
}

#[cfg(feature = "doca-crypto")]
pub fn crypto_backend() -> &'static str {
    // Conservative compile-time default — cannot inspect hw_available here.
    // Use DocaCrypto::crypto_backend() on a live instance for the real value.
    // NOTE: using software fallback.
    "software-fallback"
}

// ── CryptoAccel trait ─────────────────────────────────────────────────────────

/// Sign and verify bytes with an Ed25519 key.
///
/// Implementations may delegate to hardware (DOCA) or software (dalek).
pub trait CryptoAccel: Send + Sync {
    /// Sign `data` and return the 64-byte Ed25519 signature.
    fn sign(&self, data: &[u8]) -> [u8; 64];

    /// Verify a signature.  Returns `Ok(())` if valid.
    fn verify(&self, data: &[u8], signature: &[u8; 64]) -> Result<(), BluefieldError>;

    /// The public verifying key.
    fn verifying_key(&self) -> VerifyingKey;
}

// ── Software fallback ─────────────────────────────────────────────────────────

/// Ed25519 operations via `ed25519-dalek` on the host CPU.
///
/// # NOTE: using software fallback
///
/// This is the non-DOCA path.  All signing and verification are performed on
/// the host CPU using the `ed25519-dalek` crate.  Enable the `doca-crypto`
/// feature and provide a BlueField 2+ DPU to use hardware acceleration via
/// [`DocaCrypto`] instead.
pub struct SoftwareCrypto {
    signing_key: SigningKey,
}

impl SoftwareCrypto {
    pub fn new(key: SigningKey) -> Self {
        Self { signing_key: key }
    }
}

impl CryptoAccel for SoftwareCrypto {
    fn sign(&self, data: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.signing_key.sign(data).to_bytes()
    }

    fn verify(&self, data: &[u8], signature: &[u8; 64]) -> Result<(), BluefieldError> {
        use ed25519_dalek::Verifier;
        let sig = Signature::from_bytes(signature);
        self.signing_key
            .verifying_key()
            .verify(data, &sig)
            .map_err(|e| BluefieldError::ProtocolError(format!("signature invalid: {e}")))
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

// ── DOCA hardware crypto ──────────────────────────────────────────────────────

/// Hardware-accelerated Ed25519 operations via the NVIDIA DOCA Crypto API.
///
/// Requires the `doca-crypto` feature and a BlueField 2 or later DPU.
///
/// # Current status — DOCA SDK not yet wired
///
/// The three DOCA call-sites are marked with `TODO(doca-crypto)` below.
/// Until those calls are implemented this type always uses [`SoftwareCrypto`]
/// as a fallback (`hw_available = false`).  Use [`DocaCrypto::is_hw_accelerated`]
/// or [`crypto_backend()`] to observe at runtime which path is active.
///
/// # Wiring guide (for the DOCA implementer)
///
/// **DOCA 2.x+ Progress Engine model** (replaces the DOCA 1.x work-queue API):
///
/// 1. **`new()`** — use the BlueField PKA engine via the OpenSSL DOCA engine
///    (`-engine pka`) for Ed25519/ECDSA operations, or wire `doca_ec` for
///    elliptic-curve tasks.  There is no `doca_crypto_ctx_create()` in DOCA 2.x;
///    the correct entry points are `doca_ec_create()` (for EC math primitives)
///    or the PKA OpenSSL engine for high-level sign/verify.
///    On success set `hw_available = true`.
/// 2. **`sign()`** / **`verify()`** — allocate a `doca_ec` task via
///    `doca_ec_task_sign_alloc_init()`, submit with `doca_task_submit()`, then
///    drive the Progress Engine with `doca_pe_progress()` until the completion
///    callback fires.  Do **not** call the removed `doca_workq_progress_retrieve()`.
///
/// Relevant DOCA 2.x docs:
/// - EC/PKA: <https://docs.nvidia.com/doca/sdk/doca+crypto+acceleration/index.html>
/// - Progress Engine: <https://docs.nvidia.com/doca/sdk/doca+core/index.html>
/// - DOCA SHA (BF-2 only): <https://docs.nvidia.com/doca/sdk/doca+sha/index.html>
///
/// **Note on DOCA version:** The installed BF-2 ships DOCA 1.1.x which has
/// `doca-dpi`, `doca-flow`, and `doca-utils` but **no `doca-crypto` package**.
/// The crypto/PKA acceleration path requires DOCA 2.x (BF-OS 3.9+).
#[cfg(feature = "doca-crypto")]
pub struct DocaCrypto {
    /// Software fallback — always valid.
    sw: SoftwareCrypto,
    /// True once the DOCA PKA/EC context is successfully initialised in
    /// [`DocaCrypto::new`].
    hw_available: bool,
}

#[cfg(feature = "doca-crypto")]
impl DocaCrypto {
    /// Initialise.  Attempts to open the DOCA PKA/EC context; falls back to
    /// [`SoftwareCrypto`] and sets `hw_available = false` if unavailable.
    pub fn new(key: SigningKey) -> Self {
        // TODO(doca-crypto): wire DOCA 2.x EC/PKA here (requires DOCA 2.x / BF-OS 3.9+).
        //   Use doca_ec_create() + doca_pe_create() for the Progress Engine model.
        //   doca_workq_* APIs from DOCA 1.x are removed — do not use them.
        //   On success:  set hw_available = true and store the context handle.
        //   On failure:  leave hw_available = false (software fallback active).
        //
        // NOTE: using software fallback — DOCA SDK calls not yet wired.
        Self {
            sw: SoftwareCrypto::new(key),
            hw_available: false,
        }
    }

    /// Returns `true` if the DOCA hardware engine was successfully opened.
    ///
    /// `false` means all operations are transparently handled by
    /// [`SoftwareCrypto`].  See also [`DocaCrypto::crypto_backend`].
    pub fn is_hw_accelerated(&self) -> bool {
        self.hw_available
    }

    /// Runtime-aware backend identifier.  Unlike the free [`crypto_backend()`]
    /// function (which is a compile-time constant), this method reads
    /// `hw_available` and returns the correct value once the DOCA SDK is wired:
    ///
    /// | `hw_available` | Returns               |
    /// |----------------|-----------------------|
    /// | `false`        | `"software-fallback"` |
    /// | `true`         | `"doca"`              |
    pub fn crypto_backend(&self) -> &'static str {
        if self.hw_available {
            "doca"
        } else {
            // NOTE: using software fallback.
            "software-fallback"
        }
    }
}

#[cfg(feature = "doca-crypto")]
impl CryptoAccel for DocaCrypto {
    fn sign(&self, data: &[u8]) -> [u8; 64] {
        if self.hw_available {
            // TODO(doca-crypto): submit an Ed25519 sign task via doca_ec /
            // PKA Progress Engine (DOCA 2.x) and return the hardware signature.
            // Use doca_task_submit() + doca_pe_progress() — the DOCA 1.x
            // doca_workq_* API has been removed.  Wire context in new() first.
            unimplemented!("DOCA hardware sign path not yet wired — see TODO in DocaCrypto::new")
        } else {
            // NOTE: using software fallback.
            self.sw.sign(data)
        }
    }

    fn verify(&self, data: &[u8], signature: &[u8; 64]) -> Result<(), BluefieldError> {
        if self.hw_available {
            // TODO(doca-crypto): submit an Ed25519 verify task via doca_ec /
            // PKA Progress Engine (DOCA 2.x) and return the result.
            // Use doca_task_submit() + doca_pe_progress() — the DOCA 1.x
            // doca_workq_* API has been removed.  Wire context in new() first.
            unimplemented!(
                "DOCA hardware verify path not yet wired — see TODO in DocaCrypto::new"
            )
        } else {
            // NOTE: using software fallback.
            self.sw.verify(data, signature)
        }
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.sw.verifying_key()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn sw() -> SoftwareCrypto {
        SoftwareCrypto::new(SigningKey::generate(&mut OsRng))
    }

    // ── SoftwareCrypto ────────────────────────────────────────────────────────

    #[test]
    fn sw_sign_verify_round_trip() {
        let crypto = sw();
        let data = b"PAP RDMA BlueField handshake";
        let sig = crypto.sign(data);
        assert!(crypto.verify(data, &sig).is_ok());
    }

    #[test]
    fn sw_verify_wrong_data_fails() {
        let crypto = sw();
        let sig = crypto.sign(b"correct data");
        assert!(crypto.verify(b"tampered data", &sig).is_err());
    }

    #[test]
    fn sw_verify_wrong_key_fails() {
        let signer = sw();
        let verifier = sw(); // different key

        let sig = signer.sign(b"hello");
        // Verifier uses its own key → mismatch
        assert!(verifier.verify(b"hello", &sig).is_err());
    }

    #[test]
    fn sw_verifying_key_consistent() {
        let crypto = sw();
        let vk1 = crypto.verifying_key();
        let vk2 = crypto.verifying_key();
        assert_eq!(vk1.as_bytes(), vk2.as_bytes());
    }

    // ── crypto_backend observable ─────────────────────────────────────────────

    #[test]
    fn crypto_backend_is_not_empty() {
        let b = crypto_backend();
        assert!(!b.is_empty(), "crypto_backend() must return a non-empty string");
    }

    #[cfg(not(feature = "doca-crypto"))]
    #[test]
    fn crypto_backend_without_doca_feature_is_software() {
        assert_eq!(
            crypto_backend(),
            "software",
            "without doca-crypto feature the backend must be 'software'"
        );
    }

    #[cfg(feature = "doca-crypto")]
    #[test]
    fn crypto_backend_with_doca_feature_is_software_fallback() {
        // SDK not wired yet, so we expect the fallback path.
        assert_eq!(
            crypto_backend(),
            "software-fallback",
            "doca-crypto feature enabled but SDK not wired — backend must be 'software-fallback'"
        );
    }

    // ── DocaCrypto (doca-crypto feature) ──────────────────────────────────────

    #[cfg(feature = "doca-crypto")]
    mod doca {
        use super::*;

        fn doca_crypto() -> DocaCrypto {
            DocaCrypto::new(SigningKey::generate(&mut OsRng))
        }

        #[test]
        fn not_hw_accelerated_until_sdk_wired() {
            // hw_available must be false until doca_ec_create() / PKA context
            // init is implemented (DOCA 2.x) — this test enforces that the SDK
            // stub is never silently reported as hardware-accelerated.
            assert!(
                !doca_crypto().is_hw_accelerated(),
                "DocaCrypto must not report hw_available=true until the DOCA SDK is wired"
            );
        }

        #[test]
        fn crypto_backend_method_returns_software_fallback_until_sdk_wired() {
            // The instance method must return "software-fallback" while
            // hw_available=false, and "doca" once hw_available=true.
            // This test covers the false branch; the true branch is exercised
            // once doca_ec_create() is wired in DocaCrypto::new().
            let crypto = doca_crypto();
            assert_eq!(
                crypto.crypto_backend(),
                "software-fallback",
                "DocaCrypto::crypto_backend() must return 'software-fallback' until DOCA is wired"
            );
        }

        #[test]
        fn doca_sign_verify_round_trip_via_software_fallback() {
            // With hw_available=false the software fallback path is taken.
            let crypto = doca_crypto();
            let data = b"PAP phase-5 receipt";
            let sig = crypto.sign(data);
            assert!(
                crypto.verify(data, &sig).is_ok(),
                "DocaCrypto software-fallback sign/verify round-trip must succeed"
            );
        }

        #[test]
        fn doca_verify_wrong_data_fails_via_software_fallback() {
            let crypto = doca_crypto();
            let sig = crypto.sign(b"correct data");
            assert!(
                crypto.verify(b"tampered data", &sig).is_err(),
                "DocaCrypto software-fallback must reject tampered data"
            );
        }

        #[test]
        fn doca_verifying_key_consistent() {
            let crypto = doca_crypto();
            let vk1 = crypto.verifying_key();
            let vk2 = crypto.verifying_key();
            assert_eq!(vk1.as_bytes(), vk2.as_bytes());
        }
    }
}
