//! Chaumian ecash blind-signed token issuance and verification (spec §13.1).
//!
//! Implements RFC 9474 RSABSSA-SHA384-PSS (non-augmented, `randomize = false`) using
//! [`blind-rsa-signatures`] v0.14. The `pap-core` crate holds the
//! protocol integration point (`PaymentProof::ecash`); this crate provides
//! the full Chaumian blind-signature protocol that produces the commitment
//! bytes.
//!
//! # Protocol flow
//!
//! ```text
//!  client                                     mint
//!  ──────────────────────────────────────────────────────────
//!  let blind_tok = ecash_request(&serial, &pk)?
//!  let msg = blind_tok.blinded_message()   ──[msg]──►
//!                                          ◄──[bs]──  ecash_mint_sign(msg, &kp)?
//!  let token = ecash_unblind(&blind_tok, bs, &pk)?
//!
//!  payee:
//!    assert!(ecash_verify(&token, &pk));
//!    ecash_redeem(&token, &pk, &mut registry)?;   // ok — first spend
//!    ecash_redeem(&token, &pk, &mut registry)?;   // EcashError::DoubleSpend
//! ```
//!
//! # Unlinkability
//!
//! The random blinding factor applied in `ecash_request` makes the
//! `blinded_message()` bytes statistically independent of the final
//! `(serial, signature)` pair. The mint cannot link a signing operation
//! to a subsequent redemption.
//!
//! # Double-spend prevention
//!
//! `ecash_redeem` atomically verifies the token and records its serial in
//! the [`EcashSpentRegistry`]. Any second call with the same serial returns
//! [`EcashError::DoubleSpend`] regardless of signature validity.

pub mod error;
pub use error::EcashError;

use std::collections::HashSet;

use blind_rsa_signatures::{
    reexports::rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey, LineEnding},
    reexports::rsa::RsaPublicKey,
    BlindSignature, KeyPair, MessageRandomizer, Options, PublicKey, Secret, Signature,
};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Mint keypair for issuing blind-signed ecash tokens.
///
/// The mint generates this once and keeps the private key secret. The public
/// key (PEM) is distributed to all clients and payees.
pub struct EcashMintKeypair {
    inner: KeyPair,
}

impl EcashMintKeypair {
    /// Generate a fresh mint keypair.
    ///
    /// `key_bits` MUST be ≥ 2048 in production. Use 1024 in tests only.
    pub fn generate(key_bits: usize) -> Result<Self, EcashError> {
        KeyPair::generate(key_bits)
            .map(|inner| EcashMintKeypair { inner })
            .map_err(|e| EcashError::BlindSignature(e.to_string()))
    }

    /// Return the corresponding public key for distribution to clients.
    pub fn to_public_key(&self) -> EcashMintPublicKey {
        EcashMintPublicKey {
            inner: self.inner.pk.clone(),
        }
    }

    /// Serialize the public key as a PKCS#1 PEM string.
    pub fn public_key_to_pem(&self) -> Result<String, EcashError> {
        self.inner
            .pk
            .0
            .to_pkcs1_pem(LineEnding::LF)
            .map(|s| s.to_string())
            .map_err(|e| EcashError::Pem(e.to_string()))
    }
}

/// Mint public key — distributed to clients and payees for blinding and
/// signature verification.
pub struct EcashMintPublicKey {
    inner: PublicKey,
}

impl EcashMintPublicKey {
    /// Load a mint public key from a PKCS#1 PEM string.
    pub fn from_pem(pem: &str) -> Result<Self, EcashError> {
        let rsa_pk =
            RsaPublicKey::from_pkcs1_pem(pem).map_err(|e| EcashError::Pem(e.to_string()))?;
        Ok(EcashMintPublicKey {
            inner: PublicKey(rsa_pk),
        })
    }
}

/// Client-side blind token.
///
/// Returned by [`ecash_request`]. Holds:
/// - the blinded serial (transmitted to the mint)
/// - the blinding secret + optional message randomizer (kept by the client)
///
/// **Never** send the full struct to the mint — only [`blinded_message()`].
///
/// [`blinded_message()`]: EcashBlindToken::blinded_message
pub struct EcashBlindToken {
    /// The original serial, needed for finalisation.
    serial: [u8; 32],
    /// Blinded serial bytes — the only part the mint sees.
    blinded_msg_bytes: Vec<u8>,
    /// Blinding secret bytes — kept by the client.
    secret_bytes: Vec<u8>,
    /// Optional 32-byte message randomizer (present when `randomize = true`).
    msg_randomizer_bytes: Option<[u8; 32]>,
}

impl EcashBlindToken {
    /// The bytes to transmit to the mint for signing.
    pub fn blinded_message(&self) -> &[u8] {
        &self.blinded_msg_bytes
    }
}

/// Redeemable ecash token — serial and unblinded mint signature.
///
/// Present to a payee; the payee:
/// 1. Calls [`ecash_verify`] to check the signature.
/// 2. Calls [`ecash_redeem`] to atomically verify and mark as spent.
/// 3. Stores the [`to_payment_proof`] commitment in the mandate.
///
/// [`to_payment_proof`]: EcashToken::to_payment_proof
pub struct EcashToken {
    /// 32-byte random serial chosen by the client.
    pub serial: [u8; 32],
    /// Unblinded RSA-PSS signature over `serial` under the mint's key.
    pub signature: Vec<u8>,
}

impl EcashToken {
    /// Base64url-no-pad SHA-256 of `serial ∥ signature`.
    ///
    /// This is the value stored in the mandate's `payment_proof` field.
    pub fn commitment(&self) -> String {
        use base64::Engine;
        let mut bytes = Vec::with_capacity(32 + self.signature.len());
        bytes.extend_from_slice(&self.serial);
        bytes.extend_from_slice(&self.signature);
        let digest = Sha256::digest(&bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    }

    /// Wrap this token's commitment in a `PaymentProof::Ecash` using the
    /// `pap-core` integration point.
    pub fn to_payment_proof(&self) -> pap_core::payment::PaymentProof {
        let mut bytes = Vec::with_capacity(32 + self.signature.len());
        bytes.extend_from_slice(&self.serial);
        bytes.extend_from_slice(&self.signature);
        pap_core::payment::PaymentProof::ecash(&bytes)
    }
}

/// In-memory double-spend registry.
///
/// Records serials of all redeemed tokens. In production this should be
/// replaced with a persistent, distributed store. The reference
/// implementation uses an in-memory `HashSet`.
#[derive(Default)]
pub struct EcashSpentRegistry {
    spent: HashSet<[u8; 32]>,
}

impl EcashSpentRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if `serial` has already been redeemed.
    pub fn is_spent(&self, serial: &[u8; 32]) -> bool {
        self.spent.contains(serial)
    }

    /// Number of spent tokens recorded.
    pub fn len(&self) -> usize {
        self.spent.len()
    }

    /// True if no tokens have been redeemed yet.
    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Protocol operations
// ---------------------------------------------------------------------------

/// **Client:** Blind a serial number for submission to the mint.
///
/// Returns an [`EcashBlindToken`] containing:
/// - [`blinded_message()`] — bytes to transmit to the mint.
/// - The blinding secret — kept internally for [`ecash_unblind`].
///
/// Two calls with the same `serial` produce statistically independent
/// `blinded_message()` values (unlinkability).
///
/// [`blinded_message()`]: EcashBlindToken::blinded_message
pub fn ecash_request(
    serial: &[u8; 32],
    mint_pk: &EcashMintPublicKey,
) -> Result<EcashBlindToken, EcashError> {
    let options = Options::default();
    // randomize = false → RSABSSA-SHA384-PSS (non-augmented).
    // Unlinkability is guaranteed by the random blinding factor r; the extra
    // message randomizer of the augmented scheme is not needed here.
    let result = mint_pk
        .inner
        .blind(serial.as_slice(), false, &options)
        .map_err(|e| EcashError::BlindSignature(e.to_string()))?;

    Ok(EcashBlindToken {
        serial: *serial,
        blinded_msg_bytes: result.blind_msg.0.clone(),
        secret_bytes: result.secret.0.clone(),
        // Non-augmented variant always has no message randomizer.
        msg_randomizer_bytes: None,
    })
}

/// **Mint:** Sign a blinded message received from a client.
///
/// `blinded_msg` is the bytes from [`EcashBlindToken::blinded_message`].
/// Returns raw blind-signature bytes to return to the client.
pub fn ecash_mint_sign(
    blinded_msg: &[u8],
    keypair: &EcashMintKeypair,
) -> Result<Vec<u8>, EcashError> {
    let options = Options::default();
    keypair
        .inner
        .sk
        .blind_sign(blinded_msg, &options)
        .map(|s: BlindSignature| s.0.clone())
        .map_err(|e| EcashError::BlindSignature(e.to_string()))
}

/// **Client:** Unblind the mint's signature to produce a spendable token.
///
/// `blind_sig` must be the raw bytes returned by the mint's call to
/// [`ecash_mint_sign`].
pub fn ecash_unblind(
    blind_token: &EcashBlindToken,
    blind_sig: &[u8],
    mint_pk: &EcashMintPublicKey,
) -> Result<EcashToken, EcashError> {
    let options = Options::default();

    let secret = Secret(blind_token.secret_bytes.clone());
    let msg_randomizer: Option<MessageRandomizer> =
        blind_token.msg_randomizer_bytes.map(MessageRandomizer);

    let bs = BlindSignature(blind_sig.to_vec());
    let sig: Signature = mint_pk
        .inner
        .finalize(
            &bs,
            &secret,
            msg_randomizer,
            blind_token.serial.as_slice(),
            &options,
        )
        .map_err(|e| EcashError::BlindSignature(e.to_string()))?;

    Ok(EcashToken {
        serial: blind_token.serial,
        signature: sig.0.clone(),
    })
}

/// **Payee:** Verify a token is valid under the mint's public key.
///
/// Does **not** check the spent registry — use [`ecash_redeem`] for an
/// atomic verify-and-record operation.
pub fn ecash_verify(token: &EcashToken, mint_pk: &EcashMintPublicKey) -> bool {
    let options = Options::default();
    let sig = Signature(token.signature.clone());
    mint_pk
        .inner
        .verify(&sig, None, token.serial.as_slice(), &options)
        .is_ok()
}

/// **Payee/Mint:** Verify a token and atomically record it as spent.
///
/// - Returns `Ok(())` on the first valid redemption.
/// - Returns `Err(EcashError::DoubleSpend)` if the serial is already in
///   `registry`.
/// - Returns `Err(EcashError::VerificationFailed)` if the signature is
///   invalid.
pub fn ecash_redeem(
    token: &EcashToken,
    mint_pk: &EcashMintPublicKey,
    registry: &mut EcashSpentRegistry,
) -> Result<(), EcashError> {
    if registry.is_spent(&token.serial) {
        return Err(EcashError::DoubleSpend);
    }
    if !ecash_verify(token, mint_pk) {
        return Err(EcashError::VerificationFailed);
    }
    registry.spent.insert(token.serial);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a 1024-bit test keypair. 1024 bits is test-only speed optimisation;
    /// production MUST use ≥ 2048.
    fn test_keypair() -> (EcashMintKeypair, EcashMintPublicKey) {
        let kp = EcashMintKeypair::generate(1024).expect("keygen");
        let pk = kp.to_public_key();
        (kp, pk)
    }

    fn test_serial() -> [u8; 32] {
        let mut s = [0u8; 32];
        s[31] = 1;
        s
    }

    // -------------------------------------------------------------------
    // 1. Full flow
    // -------------------------------------------------------------------

    #[test]
    fn ecash_full_flow() {
        let (kp, pk) = test_keypair();
        let serial = test_serial();

        let blind_tok = ecash_request(&serial, &pk).expect("request");
        let blind_sig = ecash_mint_sign(blind_tok.blinded_message(), &kp).expect("mint sign");
        let token = ecash_unblind(&blind_tok, &blind_sig, &pk).expect("unblind");

        assert!(ecash_verify(&token, &pk), "token should verify");

        let mut registry = EcashSpentRegistry::new();
        ecash_redeem(&token, &pk, &mut registry).expect("first redeem should succeed");
        assert_eq!(registry.len(), 1);
    }

    // -------------------------------------------------------------------
    // 2. Unlinkability
    // -------------------------------------------------------------------

    #[test]
    fn ecash_unlinkability_distinct_blinded_messages() {
        let (_kp, pk) = test_keypair();
        let serial = test_serial();

        let bt1 = ecash_request(&serial, &pk).expect("request 1");
        let bt2 = ecash_request(&serial, &pk).expect("request 2");

        // Same serial → different blinded messages (fresh random blinding factor).
        assert_ne!(
            bt1.blinded_message(),
            bt2.blinded_message(),
            "blinded messages must be distinct (unlinkability)"
        );
    }

    // -------------------------------------------------------------------
    // 3. Double-spend prevention
    // -------------------------------------------------------------------

    #[test]
    fn ecash_double_spend_rejected() {
        let (kp, pk) = test_keypair();
        let serial = test_serial();

        let blind_tok = ecash_request(&serial, &pk).expect("request");
        let blind_sig = ecash_mint_sign(blind_tok.blinded_message(), &kp).expect("mint sign");
        let token = ecash_unblind(&blind_tok, &blind_sig, &pk).expect("unblind");

        let mut registry = EcashSpentRegistry::new();
        ecash_redeem(&token, &pk, &mut registry).expect("first redeem");

        let err = ecash_redeem(&token, &pk, &mut registry).expect_err("second redeem must fail");
        assert!(
            matches!(err, EcashError::DoubleSpend),
            "expected DoubleSpend, got {err:?}"
        );
    }

    // -------------------------------------------------------------------
    // 4. Tampered serial is rejected
    // -------------------------------------------------------------------

    #[test]
    fn ecash_tampered_serial_rejected() {
        let (kp, pk) = test_keypair();
        let serial = test_serial();

        let blind_tok = ecash_request(&serial, &pk).expect("request");
        let blind_sig = ecash_mint_sign(blind_tok.blinded_message(), &kp).expect("mint sign");
        let mut token = ecash_unblind(&blind_tok, &blind_sig, &pk).expect("unblind");

        token.serial[31] ^= 0xff;
        assert!(
            !ecash_verify(&token, &pk),
            "tampered serial must not verify"
        );
    }

    // -------------------------------------------------------------------
    // 5. PaymentProof roundtrip
    // -------------------------------------------------------------------

    #[test]
    fn ecash_payment_proof_roundtrip() {
        let (kp, pk) = test_keypair();
        let serial = test_serial();

        let blind_tok = ecash_request(&serial, &pk).expect("request");
        let blind_sig = ecash_mint_sign(blind_tok.blinded_message(), &kp).expect("mint sign");
        let token = ecash_unblind(&blind_tok, &blind_sig, &pk).expect("unblind");

        let proof = token.to_payment_proof();
        proof.validate().expect("proof must be structurally valid");

        let json = serde_json::to_string(&proof).expect("serialize");
        let proof2: pap_core::payment::PaymentProof =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(proof.commitment(), proof2.commitment());
    }

    // -------------------------------------------------------------------
    // 6. PEM round-trip
    // -------------------------------------------------------------------

    #[test]
    fn ecash_pem_roundtrip() {
        let (kp, _pk) = test_keypair();
        let pem = kp.public_key_to_pem().expect("pem");

        let pk2 = EcashMintPublicKey::from_pem(&pem).expect("from pem");

        let serial = test_serial();
        let blind_tok = ecash_request(&serial, &pk2).expect("request");
        let blind_sig = ecash_mint_sign(blind_tok.blinded_message(), &kp).expect("mint sign");
        let token = ecash_unblind(&blind_tok, &blind_sig, &pk2).expect("unblind");
        assert!(ecash_verify(&token, &pk2));
    }

    // -------------------------------------------------------------------
    // 7. Test vector (spec §13.1.4)
    // -------------------------------------------------------------------
    //
    // Because blind-rsa-signatures v0.14 uses OsRng internally (no
    // injectable RNG), the blinding factor and PSS salt are
    // non-deterministic. The test therefore verifies structural properties
    // rather than pinning an exact commitment string.
    //
    // Run with `--nocapture` to print the commitment for documentation:
    //   cargo test -p pap-ecash ecash_test_vector -- --nocapture

    #[test]
    fn ecash_test_vector() {
        // 1024-bit key (test-only; production MUST use ≥ 2048).
        let kp = EcashMintKeypair::generate(1024).expect("keygen");
        let pk = kp.to_public_key();

        // Serial: 0x000…001 (32 bytes).
        let mut serial = [0u8; 32];
        serial[31] = 1;

        let blind_tok = ecash_request(&serial, &pk).expect("request");
        let blind_sig = ecash_mint_sign(blind_tok.blinded_message(), &kp).expect("sign");
        let token = ecash_unblind(&blind_tok, &blind_sig, &pk).expect("unblind");

        assert!(ecash_verify(&token, &pk), "test vector token must verify");

        let commitment = token.commitment();
        println!("§13.1.4 test vector commitment: {commitment}");

        // Structural: base64url-no-pad SHA-256 is always 43 characters.
        assert_eq!(
            commitment.len(),
            43,
            "SHA-256 base64url-no-pad must be 43 chars"
        );
        token
            .to_payment_proof()
            .validate()
            .expect("proof structurally valid");
    }
}
