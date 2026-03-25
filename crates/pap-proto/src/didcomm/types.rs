//! DIDComm v2 message type definitions.
//!
//! These types represent the three DIDComm v2 message formats:
//! plaintext, signed (JWS), and encrypted (JWE).

use serde::{Deserialize, Serialize};

/// DIDComm v2 plaintext message.
///
/// The `body` field contains the full PAP `Envelope` as a JSON value,
/// preserving all PAP-level signatures and session semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDCommPlaintext {
    /// Unique message identifier (UUID v4).
    pub id: String,

    /// Media type: `"application/didcomm-plain+json"`.
    pub typ: String,

    /// Message type URI, e.g. `"https://pap.baur.dev/proto/1.0/session-did-ack"`.
    #[serde(rename = "type")]
    pub type_uri: String,

    /// Sender DID (optional per DIDComm v2 — always present for PAP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,

    /// Recipient DID(s).
    pub to: Vec<String>,

    /// Unix timestamp (seconds since epoch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<i64>,

    /// The PAP envelope payload as a JSON value.
    pub body: serde_json::Value,
}

/// DIDComm v2 signed message (JWS General JSON Serialization).
///
/// Contains the base64url-encoded plaintext payload and one or more
/// JWS signatures. PAP uses a single EdDSA (Ed25519) signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDCommSigned {
    /// Base64url-encoded plaintext JSON (no padding).
    pub payload: String,

    /// Array of JWS signatures (typically one for PAP).
    pub signatures: Vec<JwsSignature>,
}

/// A single JWS signature entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwsSignature {
    /// Base64url-encoded protected header JSON.
    #[serde(rename = "protected")]
    pub protected_header: String,

    /// Base64url-encoded Ed25519 signature bytes.
    pub signature: String,
}

/// DIDComm v2 encrypted message (JWE JSON Serialization).
///
/// Uses ECDH-ES (direct key agreement via X25519) with A256GCM
/// content encryption. The ephemeral public key is in the protected header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDCommEncrypted {
    /// Base64url-encoded protected header JSON.
    #[serde(rename = "protected")]
    pub protected_header: String,

    /// Per-recipient headers and (empty) encrypted keys.
    pub recipients: Vec<JweRecipient>,

    /// Base64url-encoded 96-bit initialization vector.
    pub iv: String,

    /// Base64url-encoded AES-256-GCM ciphertext.
    pub ciphertext: String,

    /// Base64url-encoded 128-bit authentication tag.
    pub tag: String,
}

/// JWE per-recipient structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JweRecipient {
    /// Recipient-specific unprotected header.
    pub header: JweRecipientHeader,

    /// Encrypted content-encryption key. Empty string for ECDH-ES direct.
    pub encrypted_key: String,
}

/// JWE recipient header identifying the recipient key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JweRecipientHeader {
    /// Recipient key identifier (DID).
    pub kid: String,
}

/// JWS protected header for Ed25519 signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct JwsProtectedHeader {
    /// Media type: `"application/didcomm-signed+json"`.
    pub typ: String,
    /// Algorithm: `"EdDSA"`.
    pub alg: String,
}

/// JWE protected header for ECDH-ES + A256GCM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct JweProtectedHeader {
    /// Media type: `"application/didcomm-encrypted+json"`.
    pub typ: String,
    /// Key agreement algorithm: `"ECDH-ES"`.
    pub alg: String,
    /// Content encryption algorithm: `"A256GCM"`.
    pub enc: String,
    /// Ephemeral public key for key agreement.
    pub epk: JsonWebKey,
    /// Agreement PartyVInfo (base64url, used in key derivation).
    pub apv: String,
}

/// JSON Web Key representation for X25519 ephemeral keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct JsonWebKey {
    /// Key type: `"OKP"` (Octet Key Pair).
    pub kty: String,
    /// Curve: `"X25519"`.
    pub crv: String,
    /// Base64url-encoded public key bytes.
    pub x: String,
}
