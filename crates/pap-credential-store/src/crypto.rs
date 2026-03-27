//! Key derivation and authenticated encryption for the vault.
//!
//! - Argon2id for password-based key derivation (OWASP recommended)
//! - AES-256-GCM for authenticated encryption (same as pap-proto JWE)

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::VaultError;
use crate::types::{EncryptedBlob, KdfParams, SensitiveKey};

/// Derive a 32-byte master key from a password and salt using Argon2id.
pub fn derive_master_key(
    password: &[u8],
    salt: &[u8; 32],
    params: &KdfParams,
) -> Result<SensitiveKey, VaultError> {
    let argon2_params = argon2::Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| VaultError::KdfError(e.to_string()))?;
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params,
    );

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| VaultError::KdfError(e.to_string()))?;

    Ok(SensitiveKey::new(output))
}

/// Encrypt plaintext with AES-256-GCM. Returns nonce + ciphertext (tag appended).
pub fn encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<EncryptedBlob, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::InvalidKeyMaterial(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::DecryptionFailed)?;

    Ok(EncryptedBlob {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt an AES-256-GCM ciphertext. The EncryptedBlob contains nonce + ciphertext+tag.
pub fn decrypt(key: &[u8; 32], blob: &EncryptedBlob, aad: &[u8]) -> Result<Vec<u8>, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::InvalidKeyMaterial(e.to_string()))?;
    let nonce = Nonce::from_slice(&blob.nonce);

    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: blob.ciphertext.as_slice(),
                aad,
            },
        )
        .map_err(|_| VaultError::DecryptionFailed)
}

/// Generate a random 32-byte vault key.
pub fn generate_vault_key() -> SensitiveKey {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    SensitiveKey::new(bytes)
}

/// Generate a random 32-byte salt.
pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = generate_vault_key();
        let plaintext = b"principal seed material";
        let aad = b"item-id-123";

        let blob = encrypt(key.as_bytes(), plaintext, aad).unwrap();
        let decrypted = decrypt(key.as_bytes(), &blob, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = generate_vault_key();
        let key2 = generate_vault_key();
        let blob = encrypt(key1.as_bytes(), b"secret", b"aad").unwrap();

        let result = decrypt(key2.as_bytes(), &blob, b"aad");
        assert!(result.is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = generate_vault_key();
        let blob = encrypt(key.as_bytes(), b"secret", b"correct-aad").unwrap();

        let result = decrypt(key.as_bytes(), &blob, b"wrong-aad");
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = generate_vault_key();
        let mut blob = encrypt(key.as_bytes(), b"secret", b"aad").unwrap();
        if let Some(byte) = blob.ciphertext.first_mut() {
            *byte ^= 0xff;
        }

        let result = decrypt(key.as_bytes(), &blob, b"aad");
        assert!(result.is_err());
    }

    #[test]
    fn kdf_produces_deterministic_key() {
        let salt = generate_salt();
        // Use minimal params for test speed
        let params = KdfParams {
            m_cost: 256,
            t_cost: 1,
            p_cost: 1,
        };
        let k1 = derive_master_key(b"password", &salt, &params).unwrap();
        let k2 = derive_master_key(b"password", &salt, &params).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn kdf_different_passwords_produce_different_keys() {
        let salt = generate_salt();
        let params = KdfParams {
            m_cost: 256,
            t_cost: 1,
            p_cost: 1,
        };
        let k1 = derive_master_key(b"password1", &salt, &params).unwrap();
        let k2 = derive_master_key(b"password2", &salt, &params).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn kdf_different_salts_produce_different_keys() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        let params = KdfParams {
            m_cost: 256,
            t_cost: 1,
            p_cost: 1,
        };
        let k1 = derive_master_key(b"password", &salt1, &params).unwrap();
        let k2 = derive_master_key(b"password", &salt2, &params).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }
}
