//! DIDComm v2 envelope compatibility layer for PAP.
//!
//! This module provides bidirectional translation between PAP protocol
//! envelopes and DIDComm v2 message formats (plaintext, signed, encrypted).
//! PAP mandate and session semantics are fully preserved — only the outer
//! envelope changes.
//!
//! Supported formats:
//! - **Plaintext**: DIDComm v2 plaintext message wrapping a PAP envelope
//! - **Signed**: Ed25519 JWS (General JSON Serialization) over plaintext
//! - **Encrypted**: ECDH-ES + A256GCM JWE (anoncrypt) over plaintext

mod jwe;
mod jws;
pub mod types;

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::envelope::Envelope;
use crate::error::ProtoError;
use types::{DIDCommEncrypted, DIDCommPlaintext, DIDCommSigned};

/// Base URI for PAP protocol message types in DIDComm format.
const PAP_TYPE_BASE: &str = "https://pap.baur.dev/proto/1.0/";

/// Translates PAP envelopes into DIDComm v2 message formats.
pub struct PapToDIDComm;

impl PapToDIDComm {
    /// Wrap a PAP envelope in a DIDComm v2 plaintext message.
    ///
    /// The full PAP envelope (including its own signature) is placed in the
    /// DIDComm `body` field, preserving all PAP semantics.
    pub fn to_plaintext(envelope: &Envelope) -> Result<DIDCommPlaintext, ProtoError> {
        let body =
            serde_json::to_value(envelope).map_err(|e| ProtoError::DIDCommError(e.to_string()))?;

        Ok(DIDCommPlaintext {
            id: uuid::Uuid::new_v4().to_string(),
            typ: "application/didcomm-plain+json".into(),
            type_uri: format!(
                "{}{}",
                PAP_TYPE_BASE,
                pap_message_type_slug(&envelope.payload)
            ),
            from: Some(envelope.sender.clone()),
            to: vec![envelope.recipient.clone()],
            created_time: Some(envelope.timestamp.timestamp()),
            body,
        })
    }

    /// Sign a PAP envelope as a DIDComm v2 signed message (Ed25519 JWS).
    ///
    /// The plaintext is first constructed, then signed with the provided key.
    /// This produces a JWS General JSON Serialization with a single `EdDSA` signature.
    pub fn to_signed(
        envelope: &Envelope,
        signing_key: &SigningKey,
    ) -> Result<DIDCommSigned, ProtoError> {
        let plaintext = Self::to_plaintext(envelope)?;
        jws::sign_plaintext(
            &plaintext,
            signing_key,
            pap_did::SignatureAlgorithm::Ed25519,
        )
    }

    /// Encrypt a PAP envelope as a DIDComm v2 encrypted message (ECDH-ES + A256GCM).
    ///
    /// The plaintext is first constructed, then encrypted for the recipient
    /// using anonymous encryption (anoncrypt). The recipient's Ed25519 public
    /// key is converted to X25519 for key agreement.
    pub fn to_encrypted(
        envelope: &Envelope,
        recipient_verifying_key: &VerifyingKey,
    ) -> Result<DIDCommEncrypted, ProtoError> {
        let plaintext = Self::to_plaintext(envelope)?;
        jwe::encrypt_plaintext(&plaintext, recipient_verifying_key)
    }
}

/// Translates DIDComm v2 messages back into PAP envelopes.
pub struct DIDCommToPap;

impl DIDCommToPap {
    /// Extract a PAP envelope from a DIDComm v2 plaintext message.
    pub fn from_plaintext(plaintext: &DIDCommPlaintext) -> Result<Envelope, ProtoError> {
        serde_json::from_value(plaintext.body.clone())
            .map_err(|e| ProtoError::DIDCommError(format!("invalid PAP envelope in body: {e}")))
    }

    /// Verify and extract a PAP envelope from a DIDComm v2 signed message.
    ///
    /// The JWS signature is verified against the provided key before
    /// extracting the inner PAP envelope.
    pub fn from_signed(
        signed: &DIDCommSigned,
        verifying_key: &VerifyingKey,
    ) -> Result<Envelope, ProtoError> {
        let plaintext = jws::verify_signed(signed, verifying_key)?;
        Self::from_plaintext(&plaintext)
    }

    /// Decrypt and extract a PAP envelope from a DIDComm v2 encrypted message.
    ///
    /// The recipient's Ed25519 signing key is converted to X25519 for
    /// key agreement, then the JWE is decrypted.
    pub fn from_encrypted(
        encrypted: &DIDCommEncrypted,
        recipient_signing_key: &SigningKey,
    ) -> Result<Envelope, ProtoError> {
        let plaintext = jwe::decrypt_message(encrypted, recipient_signing_key)?;
        Self::from_plaintext(&plaintext)
    }
}

/// Map a PAP `ProtocolMessage` variant to a kebab-case slug for DIDComm type URIs.
fn pap_message_type_slug(msg: &crate::message::ProtocolMessage) -> &'static str {
    use crate::message::ProtocolMessage;
    match msg {
        ProtocolMessage::TokenPresentation { .. } => "token-presentation",
        ProtocolMessage::TokenAccepted { .. } => "token-accepted",
        ProtocolMessage::TokenRejected { .. } => "token-rejected",
        ProtocolMessage::SessionDidExchange { .. } => "session-did-exchange",
        ProtocolMessage::SessionDidAck => "session-did-ack",
        ProtocolMessage::DisclosureOffer { .. } => "disclosure-offer",
        ProtocolMessage::DisclosureAccepted => "disclosure-accepted",
        ProtocolMessage::ExecutionResult { .. } => "execution-result",
        ProtocolMessage::ReceiptForCoSign { .. } => "receipt-for-cosign",
        ProtocolMessage::ReceiptCoSigned { .. } => "receipt-cosigned",
        ProtocolMessage::SessionClose { .. } => "session-close",
        ProtocolMessage::SessionClosed => "session-closed",
        ProtocolMessage::Error { .. } => "error",
        ProtocolMessage::StreamingMessage { .. } => "streaming-message",
        ProtocolMessage::StreamingAck { .. } => "streaming-ack",
    }
}

#[cfg(test)]
mod tests;
