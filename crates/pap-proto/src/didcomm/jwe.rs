//! ECDH-ES + A256GCM JWE operations for DIDComm v2 encrypted messages.
//!
//! Implements anonymous encryption (anoncrypt) using:
//! - X25519 key agreement (Ed25519 keys converted to X25519)
//! - Concat KDF (NIST SP 800-56A) for key derivation
//! - AES-256-GCM for authenticated encryption

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};

use crate::error::ProtoError;

use super::types::{
    DIDCommEncrypted, DIDCommPlaintext, JsonWebKey, JweProtectedHeader, JweRecipient,
    JweRecipientHeader,
};

/// Encrypt a DIDComm v2 plaintext message for a recipient.
///
/// Uses anonymous encryption (anoncrypt):
/// 1. Generate ephemeral X25519 keypair
/// 2. Convert recipient's Ed25519 public key to X25519
/// 3. Perform X25519 ECDH
/// 4. Derive AES-256 key via Concat KDF
/// 5. Encrypt with AES-256-GCM
pub fn encrypt_plaintext(
    plaintext: &DIDCommPlaintext,
    recipient_verifying_key: &VerifyingKey,
) -> Result<DIDCommEncrypted, ProtoError> {
    // Convert recipient Ed25519 public key to X25519
    let recipient_x25519_pub = ed25519_pub_to_x25519(recipient_verifying_key)?;

    // Generate ephemeral X25519 keypair
    let ephemeral_secret = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);

    // Perform ECDH
    let recipient_x25519_key = x25519_dalek::PublicKey::from(recipient_x25519_pub);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_x25519_key);

    // Compute apv = base64url(SHA-256(recipient_did_from_key))
    let recipient_did = pap_did::public_key_to_did(recipient_verifying_key);
    let apv_hash = Sha256::digest(recipient_did.as_bytes());
    let apv_b64 = URL_SAFE_NO_PAD.encode(apv_hash);

    // Derive content encryption key via Concat KDF
    let cek = concat_kdf(
        shared_secret.as_bytes(),
        "A256GCM",
        &[],       // apu: empty for anoncrypt
        &apv_hash, // apv: SHA-256(recipient_did)
        256,       // key length in bits
    )?;

    // Build protected header
    let header = JweProtectedHeader {
        typ: "application/didcomm-encrypted+json".into(),
        alg: "ECDH-ES".into(),
        enc: "A256GCM".into(),
        epk: JsonWebKey {
            kty: "OKP".into(),
            crv: "X25519".into(),
            x: URL_SAFE_NO_PAD.encode(ephemeral_public.as_bytes()),
        },
        apv: apv_b64,
    };
    let header_json =
        serde_json::to_string(&header).map_err(|e| ProtoError::DIDCommError(e.to_string()))?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());

    // Serialize plaintext
    let plaintext_json =
        serde_json::to_string(plaintext).map_err(|e| ProtoError::DIDCommError(e.to_string()))?;

    // Generate random 96-bit IV
    let mut iv_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut iv_bytes);

    // Encrypt with AES-256-GCM using protected header as AAD
    let cipher = Aes256Gcm::new_from_slice(&cek)
        .map_err(|e| ProtoError::DIDCommError(format!("cipher init failed: {e}")))?;
    let nonce = Nonce::from_slice(&iv_bytes);

    // AAD = ASCII bytes of the base64url-encoded protected header
    let aad = header_b64.as_bytes();
    let ciphertext_with_tag = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext_json.as_bytes(),
                aad,
            },
        )
        .map_err(|e| ProtoError::DIDCommError(format!("encryption failed: {e}")))?;

    // AES-GCM appends the 16-byte tag to the ciphertext
    let (ciphertext, tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);

    Ok(DIDCommEncrypted {
        protected_header: header_b64,
        recipients: vec![JweRecipient {
            header: JweRecipientHeader { kid: recipient_did },
            encrypted_key: String::new(), // empty for ECDH-ES direct
        }],
        iv: URL_SAFE_NO_PAD.encode(iv_bytes),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        tag: URL_SAFE_NO_PAD.encode(tag),
    })
}

/// Decrypt a DIDComm v2 encrypted message using the recipient's Ed25519 signing key.
///
/// The signing key is converted to X25519 for key agreement, then:
/// 1. Extract ephemeral public key from JWE header
/// 2. Perform X25519 ECDH
/// 3. Derive AES-256 key via Concat KDF
/// 4. Decrypt with AES-256-GCM
pub fn decrypt_message(
    encrypted: &DIDCommEncrypted,
    recipient_signing_key: &SigningKey,
) -> Result<DIDCommPlaintext, ProtoError> {
    // Decode and parse protected header
    let header_bytes = URL_SAFE_NO_PAD
        .decode(&encrypted.protected_header)
        .map_err(|e| ProtoError::DIDCommError(format!("invalid header encoding: {e}")))?;
    let header: JweProtectedHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| ProtoError::DIDCommError(format!("invalid header JSON: {e}")))?;

    if header.alg != "ECDH-ES" || header.enc != "A256GCM" {
        return Err(ProtoError::DIDCommError(format!(
            "unsupported JWE algorithms: alg={}, enc={}",
            header.alg, header.enc
        )));
    }

    // Extract ephemeral public key
    let epk_bytes = URL_SAFE_NO_PAD
        .decode(&header.epk.x)
        .map_err(|e| ProtoError::DIDCommError(format!("invalid epk encoding: {e}")))?;
    let epk_array: [u8; 32] = epk_bytes
        .try_into()
        .map_err(|_| ProtoError::DIDCommError("invalid epk length".into()))?;
    let ephemeral_public = x25519_dalek::PublicKey::from(epk_array);

    // Convert recipient's Ed25519 signing key to X25519 static secret
    let recipient_x25519_secret = ed25519_secret_to_x25519(recipient_signing_key);

    // Perform ECDH
    let shared_secret = recipient_x25519_secret.diffie_hellman(&ephemeral_public);

    // Decode apv from header for KDF
    let apv_bytes = URL_SAFE_NO_PAD
        .decode(&header.apv)
        .map_err(|e| ProtoError::DIDCommError(format!("invalid apv encoding: {e}")))?;

    // Derive content encryption key
    let cek = concat_kdf(
        shared_secret.as_bytes(),
        "A256GCM",
        &[],        // apu: empty for anoncrypt
        &apv_bytes, // apv
        256,
    )?;

    // Decode IV, ciphertext, and tag
    let iv_bytes = URL_SAFE_NO_PAD
        .decode(&encrypted.iv)
        .map_err(|e| ProtoError::DIDCommError(format!("invalid IV encoding: {e}")))?;
    let ciphertext_bytes = URL_SAFE_NO_PAD
        .decode(&encrypted.ciphertext)
        .map_err(|e| ProtoError::DIDCommError(format!("invalid ciphertext encoding: {e}")))?;
    let tag_bytes = URL_SAFE_NO_PAD
        .decode(&encrypted.tag)
        .map_err(|e| ProtoError::DIDCommError(format!("invalid tag encoding: {e}")))?;

    // Reassemble ciphertext + tag for AES-GCM
    let mut ct_with_tag = ciphertext_bytes;
    ct_with_tag.extend_from_slice(&tag_bytes);

    // Decrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&cek)
        .map_err(|e| ProtoError::DIDCommError(format!("cipher init failed: {e}")))?;
    let nonce = Nonce::from_slice(&iv_bytes);
    let aad = encrypted.protected_header.as_bytes();

    let plaintext_bytes = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &ct_with_tag,
                aad,
            },
        )
        .map_err(|_| {
            ProtoError::DIDCommError("decryption failed: invalid key or tampered data".into())
        })?;

    serde_json::from_slice(&plaintext_bytes)
        .map_err(|e| ProtoError::DIDCommError(format!("invalid plaintext JSON: {e}")))
}

/// Convert an Ed25519 verifying key (public) to X25519 public key bytes.
///
/// Uses the birational map from Edwards to Montgomery form:
/// `CompressedEdwardsY → EdwardsPoint → MontgomeryPoint`
fn ed25519_pub_to_x25519(vk: &VerifyingKey) -> Result<[u8; 32], ProtoError> {
    let compressed = CompressedEdwardsY::from_slice(vk.as_bytes())
        .map_err(|_| ProtoError::DIDCommError("invalid Ed25519 public key".into()))?;
    let edwards = compressed
        .decompress()
        .ok_or_else(|| ProtoError::DIDCommError("Ed25519 point decompression failed".into()))?;
    Ok(edwards.to_montgomery().to_bytes())
}

/// Convert an Ed25519 signing key (private) to X25519 static secret.
///
/// Per RFC 8032, the Ed25519 scalar is derived as SHA-512(seed)[0..32].
/// X25519 applies the same clamping, so we pass the hash output directly.
fn ed25519_secret_to_x25519(sk: &SigningKey) -> x25519_dalek::StaticSecret {
    let hash = Sha512::digest(sk.to_bytes());
    let mut x25519_bytes = [0u8; 32];
    x25519_bytes.copy_from_slice(&hash[..32]);
    x25519_dalek::StaticSecret::from(x25519_bytes)
}

/// Concat KDF (NIST SP 800-56A, Section 5.8.1) for JWE ECDH-ES.
///
/// Derives a symmetric key from an ECDH shared secret using a single
/// round of SHA-256 (sufficient for 256-bit keys).
///
/// ```text
/// key = SHA-256(
///     0x00000001 ||           // round number
///     Z ||                    // shared secret
///     len(algId) || algId ||  // algorithm identifier
///     len(apu) || apu ||      // Agreement PartyUInfo
///     len(apv) || apv ||      // Agreement PartyVInfo
///     keydatalen              // key length in bits (big-endian u32)
/// )
/// ```
fn concat_kdf(
    shared_secret: &[u8],
    algorithm: &str,
    apu: &[u8],
    apv: &[u8],
    key_bits: u32,
) -> Result<Vec<u8>, ProtoError> {
    if key_bits == 0 || key_bits % 8 != 0 {
        return Err(ProtoError::DIDCommError(format!(
            "key_bits must be a non-zero multiple of 8, got {key_bits}"
        )));
    }
    let key_bytes = (key_bits / 8) as usize;

    let mut hasher = Sha256::new();

    // Round number (1, as 4-byte big-endian)
    hasher.update(1u32.to_be_bytes());

    // Shared secret Z
    hasher.update(shared_secret);

    // AlgorithmID: length (4 bytes BE) || value
    let alg_bytes = algorithm.as_bytes();
    hasher.update((alg_bytes.len() as u32).to_be_bytes());
    hasher.update(alg_bytes);

    // PartyUInfo: length (4 bytes BE) || value
    hasher.update((apu.len() as u32).to_be_bytes());
    hasher.update(apu);

    // PartyVInfo: length (4 bytes BE) || value
    hasher.update((apv.len() as u32).to_be_bytes());
    hasher.update(apv);

    // SuppPubInfo: keydatalen in bits (4 bytes BE)
    hasher.update(key_bits.to_be_bytes());

    let hash = hasher.finalize();
    if key_bytes > hash.len() {
        return Err(ProtoError::DIDCommError(format!(
            "requested key size ({key_bytes} bytes) exceeds SHA-256 output ({} bytes); \
             multi-round KDF required for keys larger than 256 bits",
            hash.len()
        )));
    }
    Ok(hash[..key_bytes].to_vec())
}
