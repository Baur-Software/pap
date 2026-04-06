//! WebAssembly bindings for the Chaumian ecash blind-signature scheme (spec §13.1).
//!
//! Exposes the full `pap-ecash` protocol surface — keypair generation,
//! blinding, mint signing, unblinding, verification, and payment-proof
//! commitment — to JavaScript/TypeScript.
//!
//! # Usage (browser / bundler)
//!
//! ```js
//! import init, { EcashMintKeypair, EcashBlindToken, ecashMintSign, ecashVerify } from 'pap-wasm';
//! await init();
//!
//! // Mint (server side in practice — shown here for completeness)
//! const kp = EcashMintKeypair.generate(2048);
//! const mintPem = kp.publicKeyPem();
//!
//! // Client: blind a random 32-byte serial
//! const serial = crypto.getRandomValues(new Uint8Array(32));
//! const blindTok = EcashBlindToken.request(serial, mintPem);
//! const blindedMsg = blindTok.blindedMessage();
//!
//! // Mint: sign (normally an RPC to the mint server)
//! const blindSig = ecashMintSign(kp, blindedMsg);
//!
//! // Client: unblind
//! const token = blindTok.unblind(blindSig, mintPem);
//! console.log("commitment:", token.paymentProofCommitment());
//!
//! // Payee: verify
//! const valid = ecashVerify(token.serial(), token.signature(), mintPem);
//! ```

use wasm_bindgen::prelude::*;

use pap_ecash::{
    ecash_mint_sign as rust_mint_sign, ecash_request, ecash_unblind, ecash_verify as rust_verify,
    EcashBlindToken as RustBlindToken, EcashMintKeypair as RustMintKeypair,
    EcashMintPublicKey as RustMintPublicKey, EcashToken as RustToken,
};

use crate::to_js_err;

// ---------------------------------------------------------------------------
// EcashMintKeypair
// ---------------------------------------------------------------------------

/// Ecash mint keypair — holds the RSA private key for signing blinded tokens.
///
/// The mint generates this once and keeps it secret. The public key (PEM) is
/// distributed to clients and payees.
#[wasm_bindgen]
pub struct EcashMintKeypair {
    inner: RustMintKeypair,
}

#[wasm_bindgen]
impl EcashMintKeypair {
    /// Generate a fresh mint keypair.
    ///
    /// `key_bits` — RSA modulus size. MUST be ≥ 2048 in production.
    /// **Warning:** key generation is CPU-intensive; prefer 2048 bits.
    pub fn generate(key_bits: u32) -> Result<EcashMintKeypair, JsError> {
        RustMintKeypair::generate(key_bits as usize)
            .map(|inner| EcashMintKeypair { inner })
            .map_err(to_js_err)
    }

    /// Serialize the mint's public key as a PKCS#1 PEM string.
    ///
    /// Distribute this to all clients and payees.
    #[wasm_bindgen(js_name = publicKeyPem)]
    pub fn public_key_pem(&self) -> Result<String, JsError> {
        self.inner.public_key_to_pem().map_err(to_js_err)
    }
}

// ---------------------------------------------------------------------------
// EcashBlindToken
// ---------------------------------------------------------------------------

/// Client-side blind token produced by [`EcashBlindToken.request`].
///
/// Send only [`blindedMessage()`] to the mint. The blinding secret is
/// kept inside this object and used by [`unblind()`].
///
/// [`blindedMessage()`]: EcashBlindToken::blinded_message
/// [`unblind()`]: EcashBlindToken::unblind
#[wasm_bindgen]
pub struct EcashBlindToken {
    inner: RustBlindToken,
}

#[wasm_bindgen]
impl EcashBlindToken {
    /// Blind `serial` against the mint's public key.
    ///
    /// `serial` — exactly 32 random bytes chosen by the client.
    /// `mint_public_pem` — PKCS#1 PEM from [`EcashMintKeypair.publicKeyPem`].
    pub fn request(serial: &[u8], mint_public_pem: &str) -> Result<EcashBlindToken, JsError> {
        let serial_arr: [u8; 32] = serial
            .try_into()
            .map_err(|_| JsError::new("serial must be exactly 32 bytes"))?;
        let pk = RustMintPublicKey::from_pem(mint_public_pem).map_err(to_js_err)?;
        ecash_request(&serial_arr, &pk)
            .map(|inner| EcashBlindToken { inner })
            .map_err(to_js_err)
    }

    /// The bytes to transmit to the mint for signing.
    ///
    /// **Only** these bytes should be sent; the rest of this object
    /// (blinding secret) must stay on the client.
    #[wasm_bindgen(js_name = blindedMessage)]
    pub fn blinded_message(&self) -> Vec<u8> {
        self.inner.blinded_message().to_vec()
    }

    /// Finalise the blind-sign exchange.
    ///
    /// `blind_sig` — raw bytes returned by the mint's call to [`ecashMintSign`].
    /// `mint_public_pem` — same PEM used during [`request`].
    ///
    /// Returns the spendable [`EcashToken`].
    ///
    /// [`ecashMintSign`]: ecash_mint_sign_wasm
    /// [`request`]: EcashBlindToken::request
    pub fn unblind(&self, blind_sig: &[u8], mint_public_pem: &str) -> Result<EcashToken, JsError> {
        let pk = RustMintPublicKey::from_pem(mint_public_pem).map_err(to_js_err)?;
        ecash_unblind(&self.inner, blind_sig, &pk)
            .map(|inner| EcashToken { inner })
            .map_err(to_js_err)
    }
}

// ---------------------------------------------------------------------------
// EcashToken
// ---------------------------------------------------------------------------

/// Redeemable ecash token — serial number and unblinded mint signature.
///
/// Present to a payee together with a call to [`ecashVerify`]; attach
/// the [`paymentProofCommitment`] to the mandate's `payment_proof` field.
///
/// [`ecashVerify`]: ecash_verify_wasm
/// [`paymentProofCommitment`]: EcashToken::payment_proof_commitment
#[wasm_bindgen]
pub struct EcashToken {
    inner: RustToken,
}

#[wasm_bindgen]
impl EcashToken {
    /// 32-byte random serial chosen by the client.
    pub fn serial(&self) -> Vec<u8> {
        self.inner.serial.to_vec()
    }

    /// Unblinded RSA-PSS signature over the serial.
    pub fn signature(&self) -> Vec<u8> {
        self.inner.signature.clone()
    }

    /// Base64url-no-pad SHA-256 of `serial ∥ signature`.
    ///
    /// This is the value to store in the mandate's `payment_proof.hash` field
    /// via `PaymentProof::ecash`.
    #[wasm_bindgen(js_name = paymentProofCommitment)]
    pub fn payment_proof_commitment(&self) -> String {
        self.inner.commitment()
    }
}

// ---------------------------------------------------------------------------
// Standalone functions
// ---------------------------------------------------------------------------

/// **Mint:** Sign a blinded message.
///
/// `keypair` — mint's keypair (from [`EcashMintKeypair.generate`]).
/// `blinded_msg` — bytes from [`EcashBlindToken.blindedMessage`].
///
/// Returns the raw blind-signature bytes to return to the client.
///
/// In production the mint is a server; this function is available in WASM
/// for testing or for browser-based demo mints.
#[wasm_bindgen(js_name = ecashMintSign)]
pub fn ecash_mint_sign_wasm(
    keypair: &EcashMintKeypair,
    blinded_msg: &[u8],
) -> Result<Vec<u8>, JsError> {
    rust_mint_sign(blinded_msg, &keypair.inner).map_err(to_js_err)
}

/// **Payee:** Verify a token against the mint's public key.
///
/// Returns `true` if the signature is valid; `false` otherwise.
/// Does not check the spent registry — double-spend prevention is
/// out-of-band in the browser (use a server-side registry).
#[wasm_bindgen(js_name = ecashVerify)]
pub fn ecash_verify_wasm(
    serial: &[u8],
    signature: &[u8],
    mint_public_pem: &str,
) -> Result<bool, JsError> {
    let serial_arr: [u8; 32] = serial
        .try_into()
        .map_err(|_| JsError::new("serial must be exactly 32 bytes"))?;
    let pk = RustMintPublicKey::from_pem(mint_public_pem).map_err(to_js_err)?;
    let token = RustToken {
        serial: serial_arr,
        signature: signature.to_vec(),
    };
    Ok(rust_verify(&token, &pk))
}
