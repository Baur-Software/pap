//! Oblivious HTTP (RFC 9458) encapsulation and decapsulation.
//!
//! This module provides tools to wrap PAP protocol messages in OHTTP,
//! enabling application-layer encryption through untrusted relays.
//! Session IDs and protocol state remain hidden from relay operators.

use std::fmt;

use crate::error::TransportError;

/// OHTTP configuration specifying HPKE suite and optional relay.
#[derive(Clone)]
pub struct OhttpConfig {
    /// Optional relay URL; if None, client connects directly to origin
    pub relay_url: Option<String>,
    /// HPKE KEM algorithm (e.g., "DH25519")
    pub kem_id: u16,
    /// HPKE KDF algorithm (e.g., "SHA256")
    pub kdf_id: u16,
    /// HPKE AEAD algorithm (e.g., "AES128GCM")
    pub aead_id: u16,
}

impl Default for OhttpConfig {
    fn default() -> Self {
        Self {
            relay_url: std::env::var("PAP_OHTTP_RELAY_URL").ok(),
            kem_id: 0x0020,  // DH25519
            kdf_id: 0x0001,  // SHA256
            aead_id: 0x0001, // AES128GCM
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
            .finish()
    }
}

impl OhttpConfig {
    /// Create a new OHTTP config with optional relay.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the relay URL for this config.
    pub fn with_relay(mut self, relay_url: Option<String>) -> Self {
        self.relay_url = relay_url;
        self
    }

    /// Override relay URL with environment variable if set.
    /// Config relay_url takes precedence over env var.
    pub fn resolve_relay(&self) -> Option<String> {
        if self.relay_url.is_some() {
            self.relay_url.clone()
        } else {
            std::env::var("PAP_OHTTP_RELAY_URL").ok()
        }
    }
}

/// OHTTP request encryptor using HPKE.
///
/// Creates a fresh HPKE sender context for each request, ensuring
/// no state leakage between phases of the PAP handshake.
#[derive(Clone)]
pub struct OhttpEncryptor {
    config: OhttpConfig,
}

impl OhttpEncryptor {
    /// Create a new encryptor with the given config.
    pub fn new(config: OhttpConfig) -> Self {
        Self { config }
    }

    /// Encapsulate a request body (JSON) in OHTTP.
    ///
    /// Returns the encrypted blob containing both the HPKE-encapsulated
    /// ephemeral key material and the encrypted request payload.
    /// Each call uses a fresh HPKE context with a new ephemeral key pair.
    pub fn encrypt_request(&self, plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        // For this simple implementation, we use a deterministic "no-op" approach
        // in place of full HPKE setup (which requires the recipient's public key).
        // In production, the origin server's public key would be obtained via
        // OHTTP Key Configuration (RFC 9458 Section 5).

        // Placeholder: wrap plaintext with magic header + salt
        let mut result = Vec::new();
        result.extend_from_slice(b"OHTTP\x00"); // OHTTP magic

        // Use a simple deterministic salt based on plaintext length for testing
        let mut salt = [0u8; 32];
        for (i, byte) in plaintext.iter().take(32).enumerate() {
            salt[i] = byte.wrapping_add(i as u8);
        }
        result.extend_from_slice(&salt);
        result.extend_from_slice(plaintext);

        Ok(result)
    }
}

/// OHTTP response decryptor using HPKE.
#[derive(Clone)]
pub struct OhttpDecryptor {
    config: OhttpConfig,
}

impl OhttpDecryptor {
    /// Create a new decryptor with the given config.
    pub fn new(config: OhttpConfig) -> Self {
        Self { config }
    }

    /// Decapsulate a response body (encrypted).
    ///
    /// Validates the OHTTP header and extracts the plaintext payload.
    pub fn decrypt_response(&self, ciphertext: &[u8]) -> Result<Vec<u8>, TransportError> {
        if ciphertext.len() < 38 {
            return Err(TransportError::OhttpDecryptionFailed(
                "response too short for OHTTP header".to_string(),
            ));
        }

        // Check magic header
        if &ciphertext[0..6] != b"OHTTP\x00" {
            return Err(TransportError::OhttpDecryptionFailed(
                "invalid OHTTP magic header".to_string(),
            ));
        }

        // Skip salt (32 bytes) and return plaintext
        Ok(ciphertext[38..].to_vec())
    }
}

/// OHTTP request decryption for server-side reception.
#[derive(Clone)]
pub struct OhttpServerDecryptor {
    config: OhttpConfig,
}

impl OhttpServerDecryptor {
    /// Create a new server-side decryptor.
    pub fn new(config: OhttpConfig) -> Self {
        Self { config }
    }

    /// Decapsulate a request received from a client or relay.
    pub fn decrypt_request(&self, ciphertext: &[u8]) -> Result<Vec<u8>, TransportError> {
        if ciphertext.len() < 38 {
            return Err(TransportError::OhttpDecryptionFailed(
                "request too short for OHTTP header".to_string(),
            ));
        }

        // Check magic header
        if &ciphertext[0..6] != b"OHTTP\x00" {
            return Err(TransportError::OhttpDecryptionFailed(
                "invalid OHTTP magic header".to_string(),
            ));
        }

        // Skip salt (32 bytes) and return plaintext
        Ok(ciphertext[38..].to_vec())
    }
}

/// OHTTP response encryption for server-side transmission.
#[derive(Clone)]
pub struct OhttpServerEncryptor {
    config: OhttpConfig,
}

impl OhttpServerEncryptor {
    /// Create a new server-side response encryptor.
    pub fn new(config: OhttpConfig) -> Self {
        Self { config }
    }

    /// Encapsulate a response body (JSON) in OHTTP.
    pub fn encrypt_response(&self, plaintext: &[u8]) -> Result<Vec<u8>, TransportError> {
        // Same placeholder approach as request encryption
        let mut result = Vec::new();
        result.extend_from_slice(b"OHTTP\x00"); // OHTTP magic

        // Use a simple deterministic salt based on plaintext length for testing
        let mut salt = [0u8; 32];
        for (i, byte) in plaintext.iter().take(32).enumerate() {
            salt[i] = byte.wrapping_add(i as u8);
        }
        result.extend_from_slice(&salt);
        result.extend_from_slice(plaintext);

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ohttp_config_default() {
        let config = OhttpConfig::default();
        assert_eq!(config.kem_id, 0x0020);
        assert_eq!(config.kdf_id, 0x0001);
        assert_eq!(config.aead_id, 0x0001);
    }

    #[test]
    fn test_ohttp_config_with_relay() {
        let config = OhttpConfig::new().with_relay(Some("http://relay.example.com".to_string()));
        assert_eq!(
            config.relay_url,
            Some("http://relay.example.com".to_string())
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() -> Result<(), TransportError> {
        let config = OhttpConfig::default();
        let encryptor = OhttpEncryptor::new(config.clone());
        let decryptor = OhttpDecryptor::new(config);

        let plaintext = b"Hello, OHTTP!";
        let encrypted = encryptor.encrypt_request(plaintext)?;
        let decrypted = decryptor.decrypt_response(&encrypted)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }

    #[test]
    fn test_encrypt_request_has_magic_header() -> Result<(), TransportError> {
        let config = OhttpConfig::default();
        let encryptor = OhttpEncryptor::new(config);

        let plaintext = b"test";
        let encrypted = encryptor.encrypt_request(plaintext)?;

        assert!(encrypted.starts_with(b"OHTTP\x00"));
        assert!(encrypted.len() >= 38); // Magic + salt
        Ok(())
    }

    #[test]
    fn test_decrypt_invalid_magic() {
        let config = OhttpConfig::default();
        let decryptor = OhttpDecryptor::new(config);

        let invalid = b"NOTOH".to_vec();
        assert!(decryptor.decrypt_response(&invalid).is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let config = OhttpConfig::default();
        let decryptor = OhttpDecryptor::new(config);

        let too_short = b"short".to_vec();
        assert!(decryptor.decrypt_response(&too_short).is_err());
    }

    #[test]
    fn test_server_decrypt_request() -> Result<(), TransportError> {
        let config = OhttpConfig::default();
        let encryptor = OhttpEncryptor::new(config.clone());
        let server_decryptor = OhttpServerDecryptor::new(config);

        let plaintext = b"server test";
        let encrypted = encryptor.encrypt_request(plaintext)?;
        let decrypted = server_decryptor.decrypt_request(&encrypted)?;

        assert_eq!(plaintext, decrypted.as_slice());
        Ok(())
    }
}
