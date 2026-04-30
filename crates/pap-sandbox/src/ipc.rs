use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::SandboxError;
use crate::receipt::AttestationReceipt;

/// Encrypted execution context sent from parent to sandbox child.
/// All sensitive fields are encrypted with an ephemeral key;
/// the child decrypts only when needed for agent invocation.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecutionContext {
    /// Encrypted query bytes.
    pub query_enc: Vec<u8>,
    /// Encrypted disclosure set bytes.
    pub disclosure_enc: Vec<u8>,
    /// Encrypted session token bytes.
    pub session_token_enc: Vec<u8>,
    /// XChaCha20-Poly1305 nonce (24 bytes).
    pub nonce: Vec<u8>,
    /// X25519 ephemeral public key used for ECDH key agreement.
    pub ephemeral_public_key: Vec<u8>,
    /// Agent DID the sandbox process should invoke.
    pub agent_did: String,
    /// Agent name for logging and receipt construction.
    pub agent_name: String,
    /// PAP action type (e.g. "schema:SearchAction").
    pub action_type: String,
    /// Session ID from phase 1 handshake.
    pub session_id: String,
}

/// Encrypted result returned from sandbox child to parent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Encrypted JSON result bytes.
    pub result_enc: Vec<u8>,
    /// Nonce for decryption.
    pub nonce: Vec<u8>,
    /// Capability attestation receipt — not encrypted, must be signed.
    pub receipt: AttestationReceipt,
}

/// Plaintext execution context after decryption inside the sandbox.
pub struct DecryptedContext {
    pub query: String,
    pub disclosures: Vec<serde_json::Value>,
    pub session_token: Vec<u8>,
    pub agent_did: String,
    pub agent_name: String,
    pub action_type: String,
    pub session_id: String,
}

impl Drop for DecryptedContext {
    fn drop(&mut self) {
        // Zero sensitive fields on drop.
        self.query.zeroize();
        self.session_token.zeroize();
    }
}

/// Encrypt a slice of plaintext using XChaCha20-Poly1305 with the given key.
/// Returns (ciphertext, nonce).
pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), SandboxError> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Key, Nonce,
    };

    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    // 12-byte nonce for AES-256-GCM
    let nonce_bytes: [u8; 12] = {
        use rand::RngCore;
        let mut n = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut n);
        n
    };
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| SandboxError::EncryptionError(e.to_string()))?;

    Ok((ciphertext, nonce_bytes.to_vec()))
}

/// Decrypt ciphertext with AES-256-GCM.
pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8]) -> Result<Vec<u8>, SandboxError> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Key, Nonce,
    };

    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    if nonce.len() != 12 {
        return Err(SandboxError::EncryptionError(
            "invalid nonce length".to_string(),
        ));
    }
    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| SandboxError::EncryptionError(e.to_string()))
}

/// Derive a 32-byte shared key from an X25519 ephemeral keypair.
pub fn derive_shared_key(
    our_private: &x25519_dalek::StaticSecret,
    their_public: &x25519_dalek::PublicKey,
) -> [u8; 32] {
    let shared = our_private.diffie_hellman(their_public);
    // Use SHA-256 of the raw DH output as the symmetric key.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(shared.as_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"sensitive query data";

        let (ciphertext, nonce) = encrypt(plaintext, &key).expect("encrypt");
        let recovered = decrypt(&ciphertext, &key, &nonce).expect("decrypt");

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let (ciphertext, nonce) = encrypt(b"test", &key1).expect("encrypt");
        assert!(decrypt(&ciphertext, &key2, &nonce).is_err());
    }

    #[test]
    fn decrypt_with_wrong_nonce_fails() {
        let key = [0x42u8; 32];
        let (ciphertext, _nonce) = encrypt(b"test", &key).expect("encrypt");
        let bad_nonce = vec![0u8; 12];
        assert!(decrypt(&ciphertext, &key, &bad_nonce).is_err());
    }

    #[test]
    fn derive_shared_key_is_symmetric() {
        use rand::rngs::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        let alice_sk = StaticSecret::random_from_rng(OsRng);
        let alice_pk = PublicKey::from(&alice_sk);
        let bob_sk = StaticSecret::random_from_rng(OsRng);
        let bob_pk = PublicKey::from(&bob_sk);

        let alice_shared = derive_shared_key(&alice_sk, &bob_pk);
        let bob_shared = derive_shared_key(&bob_sk, &alice_pk);

        assert_eq!(alice_shared, bob_shared);
    }
}
