//! Oblivious HTTP (RFC 9458) encapsulation and decapsulation.
//!
//! Implements real HPKE (RFC 9180) with DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM.
//! The placeholder magic-header stub is replaced with cryptographically sound operations.
//!
//! When `recipient_public_key` is `None` in `OhttpConfig`, all operations degrade gracefully
//! to plaintext passthrough — suitable for direct connections and local testing.
//!
//! # Key flow
//! 1. Server generates `OhttpKeyPair`, publishes public key in DID Document (`PAPObliviousHTTP`).
//! 2. Client calls `fetch_key_config(did_doc)` to obtain an `OhttpConfig` with the server key.
//! 3. `OhttpEncryptor::encrypt_request` → `(wire_bytes, OhttpResponseDecryptCtx)`.
//! 4. `OhttpServerDecryptor::decrypt_request` → `(plaintext, OhttpResponseEncryptCtx)`.
//! 5. Server calls `OhttpResponseEncryptCtx::encrypt_response` → ciphertext.
//! 6. Client calls `OhttpResponseDecryptCtx::decrypt_response` → plaintext.
//!
//! Steps 5 and 6 use AES-128-GCM keyed by material exported from the shared HPKE context,
//! ensuring the response is cryptographically bound to the corresponding request.

use std::fmt;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Key, KeyInit, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hpke::aead::AesGcm128;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use rand::rngs::OsRng;

use crate::error::TransportError;

// HPKE suite constants matching RFC 9458 §5 IANA identifiers
const KEM_ID: u16 = 0x0020; // DHKEM(X25519, HKDF-SHA256)
const KDF_ID: u16 = 0x0001; // HKDF-SHA256
const AEAD_ID: u16 = 0x0001; // AES-128-GCM

/// Wire format header length: key_id(1) + kem_id(2) + kdf_id(2) + aead_id(2) = 7 bytes.
const OHTTP_HDR_LEN: usize = 7;
/// X25519 encapped key length (32 bytes).
const ENCAPPED_KEY_LEN: usize = 32;
/// Minimum valid OHTTP request length (header + encapped key, before ciphertext).
const MIN_REQUEST_LEN: usize = OHTTP_HDR_LEN + ENCAPPED_KEY_LEN; // 39 bytes

// ------------------------------------------------------------------
// OhttpConfig
// ------------------------------------------------------------------

/// OHTTP configuration specifying HPKE suite, optional relay, and recipient public key.
#[derive(Clone)]
pub struct OhttpConfig {
    /// Optional relay URL; if None, client connects directly to origin.
    pub relay_url: Option<String>,
    /// HPKE KEM algorithm identifier.
    pub kem_id: u16,
    /// HPKE KDF algorithm identifier.
    pub kdf_id: u16,
    /// HPKE AEAD algorithm identifier.
    pub aead_id: u16,
    /// Server's HPKE public key bytes (32 bytes for X25519).
    /// `None` → passthrough mode: messages are not encrypted or decrypted.
    pub recipient_public_key: Option<Vec<u8>>,
    /// Key ID matching the server's `OhttpKeyConfig`.
    pub key_id: u8,
}

impl Default for OhttpConfig {
    fn default() -> Self {
        Self {
            relay_url: std::env::var("PAP_OHTTP_RELAY_URL").ok(),
            kem_id: KEM_ID,
            kdf_id: KDF_ID,
            aead_id: AEAD_ID,
            recipient_public_key: None,
            key_id: 1,
        }
    }
}

impl fmt::Debug for OhttpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OhttpConfig")
            .field("relay_url", &self.relay_url)
            .field("kem_id", &format!("0x{:04x}", self.kem_id))
            .field("kdf_id", &format!("0x{:04x}", self.kdf_id))
            .field("aead_id", &format!("0x{:04x}", self.aead_id))
            .field(
                "recipient_public_key",
                &self
                    .recipient_public_key
                    .as_ref()
                    .map(|k| format!("{} bytes", k.len())),
            )
            .field("key_id", &self.key_id)
            .finish()
    }
}

impl OhttpConfig {
    /// Create a new OHTTP config (alias for `Default::default()`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the relay URL.
    pub fn with_relay(mut self, relay_url: Option<String>) -> Self {
        self.relay_url = relay_url;
        self
    }

    /// Set the server's HPKE public key. Enables real HPKE encryption.
    pub fn with_recipient_public_key(mut self, key_bytes: Vec<u8>) -> Self {
        self.recipient_public_key = Some(key_bytes);
        self
    }

    /// Set the key ID matching the server's `OhttpKeyConfig`.
    pub fn with_key_id(mut self, id: u8) -> Self {
        self.key_id = id;
        self
    }

    /// Resolve the relay URL.
    ///
    /// Returns `self.relay_url` if set, otherwise falls back to the
    /// `PAP_OHTTP_RELAY_URL` environment variable.
    pub fn resolve_relay(&self) -> Option<String> {
        if self.relay_url.is_some() {
            self.relay_url.clone()
        } else {
            std::env::var("PAP_OHTTP_RELAY_URL").ok()
        }
    }
}

// ------------------------------------------------------------------
// OhttpKeyPair
// ------------------------------------------------------------------

/// X25519 keypair for a server-side OHTTP node.
///
/// Generated once at node startup and persisted alongside the principal identity.
/// The public key is published in the DID Document under the `PAPObliviousHTTP` service.
/// The private key is zeroized on drop.
pub struct OhttpKeyPair {
    private_bytes: [u8; 32],
    public_bytes: [u8; 32],
}

impl OhttpKeyPair {
    /// Generate a fresh X25519 keypair using OS randomness.
    pub fn generate() -> Self {
        let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut OsRng);
        let mut private_bytes = [0u8; 32];
        let mut public_bytes = [0u8; 32];
        private_bytes.copy_from_slice(sk.to_bytes().as_slice());
        public_bytes.copy_from_slice(pk.to_bytes().as_slice());
        Self { private_bytes, public_bytes }
    }

    /// Return the 32-byte X25519 public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_bytes
    }

    /// Reconstruct a keypair from stored private key bytes.
    ///
    /// # Panics
    /// Panics if `bytes` is not a valid 32-byte X25519 scalar.
    pub fn from_private_bytes(bytes: [u8; 32]) -> Self {
        let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&bytes)
            .expect("valid 32-byte X25519 private key scalar");
        let pk = X25519HkdfSha256::sk_to_pk(&sk);
        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(pk.to_bytes().as_slice());
        Self { private_bytes: bytes, public_bytes }
    }
}

impl Clone for OhttpKeyPair {
    fn clone(&self) -> Self {
        Self {
            private_bytes: self.private_bytes,
            public_bytes: self.public_bytes,
        }
    }
}

impl Drop for OhttpKeyPair {
    fn drop(&mut self) {
        // Volatile writes prevent the compiler from eliding the zero-fill
        for byte in self.private_bytes.iter_mut() {
            // SAFETY: we are writing to a field of self that we own
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

// ------------------------------------------------------------------
// OhttpKeyConfig
// ------------------------------------------------------------------

/// RFC 9458 §5 key configuration for publication in a DID Document.
///
/// Wire format (41 bytes):
/// ```text
/// key_id (1 byte) || kem_id (2 BE) || pub_key (32 bytes) ||
/// algo_list_len (2 BE = 0x0004) || kdf_id (2 BE) || aead_id (2 BE)
/// ```
pub struct OhttpKeyConfig {
    key_id: u8,
    keypair: OhttpKeyPair,
}

impl OhttpKeyConfig {
    /// Create a new key config.
    pub fn new(key_id: u8, keypair: OhttpKeyPair) -> Self {
        Self { key_id, keypair }
    }

    /// Serialize to RFC 9458 §5 wire format (41 bytes).
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(41);
        out.push(self.key_id);
        out.extend_from_slice(&KEM_ID.to_be_bytes());
        out.extend_from_slice(&self.keypair.public_bytes);
        // symmetric_algorithms: 2-byte list length + one entry (kdf_id + aead_id)
        out.extend_from_slice(&4u16.to_be_bytes()); // list length = 4 bytes
        out.extend_from_slice(&KDF_ID.to_be_bytes());
        out.extend_from_slice(&AEAD_ID.to_be_bytes());
        out
    }

    /// Parse RFC 9458 §5 wire bytes, returning `(key_id, public_key_bytes)`.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<(u8, [u8; 32]), TransportError> {
        // Minimum layout: key_id(1) + kem_id(2) + pub_key(32) + algo_len(2) + algo(4) = 41 bytes
        if bytes.len() < 41 {
            return Err(TransportError::OhttpDecryptionFailed(format!(
                "key config too short: {} bytes (need at least 41)",
                bytes.len()
            )));
        }
        let key_id = bytes[0];
        // bytes[1..3] = kem_id (informational), bytes[3..35] = public key
        let mut pub_key = [0u8; 32];
        pub_key.copy_from_slice(&bytes[3..35]);
        Ok((key_id, pub_key))
    }
}

// ------------------------------------------------------------------
// Response contexts
// ------------------------------------------------------------------

/// Per-request context returned by `OhttpEncryptor::encrypt_request`.
///
/// Holds AES-128-GCM key material (derived from the HPKE sender context export)
/// for decrypting the server's response. In passthrough mode, acts as identity.
#[derive(Debug)]
pub struct OhttpResponseDecryptCtx {
    /// Pre-exported 28-byte key material: `aes_key[0..16] || nonce[16..28]`.
    /// `None` = passthrough (no encryption in use).
    key_material: Option<[u8; 28]>,
}

impl OhttpResponseDecryptCtx {
    fn passthrough() -> Self {
        Self { key_material: None }
    }

    /// Decrypt the server's response using key material from the request HPKE context.
    ///
    /// Passthrough mode returns `ciphertext` unchanged.
    pub fn decrypt_response(&self, ciphertext: &[u8]) -> Result<Vec<u8>, TransportError> {
        let Some(ref km) = self.key_material else {
            return Ok(ciphertext.to_vec());
        };
        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&km[..16]));
        let nonce = Nonce::from_slice(&km[16..28]);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| TransportError::OhttpDecryptionFailed("AES-GCM authentication failed".into()))
    }
}

/// Per-request context returned by `OhttpServerDecryptor::decrypt_request`.
///
/// Holds AES-128-GCM key material (derived from the HPKE receiver context export)
/// for encrypting the response. In passthrough mode, acts as identity.
#[derive(Debug)]
pub struct OhttpResponseEncryptCtx {
    /// Pre-exported 28-byte key material: `aes_key[0..16] || nonce[16..28]`.
    /// `None` = passthrough.
    key_material: Option<[u8; 28]>,
}

impl OhttpResponseEncryptCtx {
    fn passthrough() -> Self {
        Self { key_material: None }
    }

    /// Encrypt a response using key material derived from the request HPKE context.
    ///
    /// Passthrough mode returns `plaintext` unchanged.
    pub fn encrypt_response(&self, plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        let Some(ref km) = self.key_material else {
            return Ok(plaintext.to_vec());
        };
        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&km[..16]));
        let nonce = Nonce::from_slice(&km[16..28]);
        cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| TransportError::OhttpEncryptionFailed(e.to_string()))
    }
}

// ------------------------------------------------------------------
// Internal helpers
// ------------------------------------------------------------------

/// Build the HPKE `info` string: `b"PAP OHTTP Request\x00" || key_id`.
fn request_info(key_id: u8) -> Vec<u8> {
    let mut v = b"PAP OHTTP Request\x00".to_vec();
    v.push(key_id);
    v
}

// ------------------------------------------------------------------
// OhttpEncryptor (client side)
// ------------------------------------------------------------------

/// OHTTP request encryptor (client side).
///
/// Uses DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM per RFC 9458.
/// When `config.recipient_public_key` is `None`, operates in passthrough mode.
#[derive(Clone)]
pub struct OhttpEncryptor {
    config: OhttpConfig,
}

impl OhttpEncryptor {
    /// Create a new encryptor from config.
    pub fn new(config: OhttpConfig) -> Self {
        Self { config }
    }

    /// Encrypt a request and return `(wire_bytes, response_decrypt_ctx)`.
    ///
    /// **Wire format** (when HPKE is active):
    /// `key_id(1) || kem_id(2) || kdf_id(2) || aead_id(2) || encapped_key(32) || ciphertext`
    ///
    /// **Passthrough** (no `recipient_public_key` configured):
    /// Returns `(plaintext.to_vec(), passthrough_ctx)` — no encryption header.
    pub fn encrypt_request(
        &self,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, OhttpResponseDecryptCtx), TransportError> {
        let Some(ref pub_key_bytes) = self.config.recipient_public_key else {
            return Ok((plaintext.to_vec(), OhttpResponseDecryptCtx::passthrough()));
        };

        let recipient_pk =
            <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(pub_key_bytes.as_slice())
                .map_err(|e| TransportError::OhttpEncryptionFailed(format!("invalid recipient key: {e}")))?;

        let info = request_info(self.config.key_id);

        let (enc, mut sender_ctx) =
            hpke::setup_sender::<AesGcm128, HkdfSha256, X25519HkdfSha256, _>(
                &OpModeS::Base,
                &recipient_pk,
                &info,
                &mut OsRng,
            )
            .map_err(|e| TransportError::OhttpEncryptionFailed(format!("HPKE setup_sender: {e}")))?;

        // Export response key material before sealing (export is sequence-independent).
        // hpke 0.11 API: export(label: &[u8], out: &mut [u8]) -> Result<(), HpkeError>
        let mut km = [0u8; 28];
        sender_ctx
            .export(b"PAP OHTTP Response\x00", &mut km)
            .map_err(|e| TransportError::OhttpEncryptionFailed(format!("HPKE export: {e}")))?;

        let ciphertext = sender_ctx
            .seal(plaintext, b"")
            .map_err(|e| TransportError::OhttpEncryptionFailed(format!("HPKE seal: {e}")))?;

        // Build wire bytes: hdr(7) || encapped_key(32) || ciphertext
        let enc_bytes = enc.to_bytes();
        let mut wire = Vec::with_capacity(OHTTP_HDR_LEN + ENCAPPED_KEY_LEN + ciphertext.len());
        wire.push(self.config.key_id);
        wire.extend_from_slice(&self.config.kem_id.to_be_bytes());
        wire.extend_from_slice(&self.config.kdf_id.to_be_bytes());
        wire.extend_from_slice(&self.config.aead_id.to_be_bytes());
        wire.extend_from_slice(enc_bytes.as_slice());
        wire.extend_from_slice(&ciphertext);

        Ok((wire, OhttpResponseDecryptCtx { key_material: Some(km) }))
    }
}

// ------------------------------------------------------------------
// OhttpServerDecryptor (server side)
// ------------------------------------------------------------------

/// OHTTP request decryptor (server side).
///
/// Constructed with `new_with_keypair` for real HPKE; `new(config)` for passthrough.
pub struct OhttpServerDecryptor {
    keypair: Option<OhttpKeyPair>,
}

impl Clone for OhttpServerDecryptor {
    fn clone(&self) -> Self {
        Self { keypair: self.keypair.clone() }
    }
}

impl OhttpServerDecryptor {
    /// Create a passthrough-mode decryptor (no keypair, no HPKE).
    ///
    /// Maintains backward compatibility with `AgentServer::with_ohttp(config)`.
    pub fn new(_config: OhttpConfig) -> Self {
        Self { keypair: None }
    }

    /// Create a decryptor with a server HPKE keypair (enables real RFC 9458 OHTTP).
    pub fn new_with_keypair(keypair: OhttpKeyPair) -> Self {
        Self { keypair: Some(keypair) }
    }

    /// Decrypt an OHTTP-encapsulated request.
    ///
    /// Returns `(plaintext, response_encrypt_ctx)`. The context **must** be used to
    /// encrypt the response via `OhttpResponseEncryptCtx::encrypt_response`, ensuring
    /// the response is bound to the same HPKE exchange as the request.
    ///
    /// In passthrough mode (no keypair), treats `wire` as plaintext directly.
    pub fn decrypt_request(
        &self,
        wire: &[u8],
    ) -> Result<(Vec<u8>, OhttpResponseEncryptCtx), TransportError> {
        let Some(ref keypair) = self.keypair else {
            return Ok((wire.to_vec(), OhttpResponseEncryptCtx::passthrough()));
        };

        if wire.len() < MIN_REQUEST_LEN {
            return Err(TransportError::OhttpDecryptionFailed(format!(
                "request too short: {} bytes (need at least {})",
                wire.len(),
                MIN_REQUEST_LEN
            )));
        }

        let key_id = wire[0];
        // wire[1..7] = kem/kdf/aead ids (we support one suite; parsed for future validation)
        let enc_slice = &wire[OHTTP_HDR_LEN..OHTTP_HDR_LEN + ENCAPPED_KEY_LEN];
        let ciphertext = &wire[MIN_REQUEST_LEN..];

        let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(enc_slice)
            .map_err(|e| TransportError::OhttpDecryptionFailed(format!("invalid encapped key: {e}")))?;

        let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&keypair.private_bytes)
            .map_err(|e| TransportError::OhttpDecryptionFailed(format!("invalid private key: {e}")))?;

        let info = request_info(key_id);

        let mut receiver_ctx =
            hpke::setup_receiver::<AesGcm128, HkdfSha256, X25519HkdfSha256>(
                &OpModeR::Base,
                &sk,
                &enc,
                &info,
            )
            .map_err(|e| TransportError::OhttpDecryptionFailed(format!("HPKE setup_receiver: {e}")))?;

        // Export response key material before opening (export is sequence-independent).
        // hpke 0.11 API: export(label: &[u8], out: &mut [u8]) -> Result<(), HpkeError>
        let mut km = [0u8; 28];
        receiver_ctx
            .export(b"PAP OHTTP Response\x00", &mut km)
            .map_err(|e| TransportError::OhttpDecryptionFailed(format!("HPKE export: {e}")))?;

        let plaintext = receiver_ctx
            .open(ciphertext, b"")
            .map_err(|_| TransportError::OhttpDecryptionFailed(
                "HPKE open failed — authentication mismatch or tampered ciphertext".into(),
            ))?;

        Ok((plaintext, OhttpResponseEncryptCtx { key_material: Some(km) }))
    }
}

// ------------------------------------------------------------------
// DID Document integration
// ------------------------------------------------------------------

/// Locate the `PAPObliviousHTTP` service in a DID Document and build an `OhttpConfig`
/// with the server's HPKE public key populated.
///
/// The service's `ohthpKeyConfig` field must be a base64url-encoded RFC 9458 §5 key config.
pub fn fetch_key_config(
    did_doc: &pap_did::DidDocument,
) -> Result<OhttpConfig, TransportError> {
    let service = did_doc
        .service
        .as_ref()
        .and_then(|svcs| svcs.iter().find(|s| s.service_type == "PAPObliviousHTTP"))
        .ok_or_else(|| {
            TransportError::OhttpEncryptionFailed(
                "DID Document has no PAPObliviousHTTP service".into(),
            )
        })?;

    let key_config_b64 = service.ohttp_key_config.as_ref().ok_or_else(|| {
        TransportError::OhttpEncryptionFailed(
            "PAPObliviousHTTP service missing ohthpKeyConfig field".into(),
        )
    })?;

    let bytes = URL_SAFE_NO_PAD
        .decode(key_config_b64)
        .map_err(|e| TransportError::OhttpEncryptionFailed(format!("base64url decode: {e}")))?;

    let (key_id, pub_key) = OhttpKeyConfig::from_wire_bytes(&bytes)?;

    Ok(OhttpConfig::default()
        .with_key_id(key_id)
        .with_recipient_public_key(pub_key.to_vec()))
}

// ------------------------------------------------------------------
// Unit tests
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ohttp_config_default() {
        let config = OhttpConfig::default();
        assert_eq!(config.kem_id, 0x0020);
        assert_eq!(config.kdf_id, 0x0001);
        assert_eq!(config.aead_id, 0x0001);
        assert!(config.recipient_public_key.is_none());
        assert_eq!(config.key_id, 1);
    }

    #[test]
    fn test_ohttp_config_with_relay() {
        let config = OhttpConfig::new().with_relay(Some("http://relay.example.com".to_string()));
        assert_eq!(config.relay_url, Some("http://relay.example.com".to_string()));
    }

    #[test]
    fn test_passthrough_encrypt_decrypt_roundtrip() -> Result<(), TransportError> {
        let config = OhttpConfig::default(); // no recipient_public_key
        let encryptor = OhttpEncryptor::new(config);
        let plaintext = b"passthrough test message";
        let (wire, ctx) = encryptor.encrypt_request(plaintext)?;
        // Passthrough: wire bytes equal plaintext
        assert_eq!(&wire, plaintext);
        let decrypted = ctx.decrypt_response(&wire)?;
        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_hpke_request_response_roundtrip() -> Result<(), TransportError> {
        let server_keypair = OhttpKeyPair::generate();
        let pub_key = server_keypair.public_key_bytes();

        let config = OhttpConfig::default()
            .with_recipient_public_key(pub_key.to_vec())
            .with_key_id(1);
        let encryptor = OhttpEncryptor::new(config);
        let server_decryptor = OhttpServerDecryptor::new_with_keypair(server_keypair);

        // Encrypt request
        let req_plaintext = b"request body";
        let (wire, resp_decrypt_ctx) = encryptor.encrypt_request(req_plaintext)?;
        assert!(wire.len() > req_plaintext.len(), "wire must be longer than plaintext");
        assert_eq!(wire.len(), MIN_REQUEST_LEN + req_plaintext.len() + 16); // +16 = GCM tag

        // Decrypt request on server
        let (decrypted_req, resp_encrypt_ctx) = server_decryptor.decrypt_request(&wire)?;
        assert_eq!(decrypted_req, req_plaintext);

        // Encrypt response on server, decrypt on client
        let resp_plaintext = b"response body";
        let encrypted_resp = resp_encrypt_ctx.encrypt_response(resp_plaintext)?;
        let decrypted_resp = resp_decrypt_ctx.decrypt_response(&encrypted_resp)?;
        assert_eq!(decrypted_resp, resp_plaintext);

        Ok(())
    }

    #[test]
    fn test_tamper_detection() -> Result<(), TransportError> {
        let server_keypair = OhttpKeyPair::generate();
        let pub_key = server_keypair.public_key_bytes();
        let config = OhttpConfig::default().with_recipient_public_key(pub_key.to_vec());
        let encryptor = OhttpEncryptor::new(config);
        let server_decryptor = OhttpServerDecryptor::new_with_keypair(server_keypair);

        let (mut wire, _ctx) = encryptor.encrypt_request(b"tamper me")?;
        wire[40] ^= 0xff; // flip a byte in the ciphertext region
        let result = server_decryptor.decrypt_request(&wire);
        assert!(
            matches!(result, Err(TransportError::OhttpDecryptionFailed(_))),
            "tampered ciphertext must return OhttpDecryptionFailed"
        );
        Ok(())
    }

    #[test]
    fn test_key_config_wire_format_roundtrip() {
        let keypair = OhttpKeyPair::generate();
        let pub_key = keypair.public_key_bytes();
        let config = OhttpKeyConfig::new(42, keypair);

        let wire = config.to_wire_bytes();
        assert_eq!(wire.len(), 41, "key config wire must be exactly 41 bytes");

        let (key_id, parsed_pub) = OhttpKeyConfig::from_wire_bytes(&wire).unwrap();
        assert_eq!(key_id, 42);
        assert_eq!(parsed_pub, pub_key);
    }
}
