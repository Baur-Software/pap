use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::ProtoError;
use crate::message::ProtocolMessage;

/// An envelope wraps a `ProtocolMessage` with routing, sequencing,
/// and integrity fields.
///
/// The envelope is what actually travels over any transport. The
/// transport layer serializes/deserializes envelopes — it never
/// touches the inner message directly.
///
/// After the DID exchange phase (phase 2), envelopes carry a signature
/// from the sender's ephemeral session key. Before phase 2, the
/// `signature` field is None (the token itself is already signed
/// by the orchestrator).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Unique envelope ID.
    pub id: String,

    /// Session ID this envelope belongs to.
    pub session_id: String,

    /// DID of the sender (principal, orchestrator, or session DID).
    pub sender: String,

    /// DID of the intended recipient.
    pub recipient: String,

    /// Monotonically increasing sequence number within this session.
    pub sequence: u64,

    /// The protocol message payload.
    pub payload: ProtocolMessage,

    /// ISO 8601 timestamp.
    pub timestamp: DateTime<Utc>,

    /// Ed25519 signature over the canonical payload bytes.
    /// Present after the DID exchange phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
}

impl Envelope {
    /// Create an unsigned envelope.
    pub fn new(
        session_id: impl Into<String>,
        sender: impl Into<String>,
        recipient: impl Into<String>,
        sequence: u64,
        payload: ProtocolMessage,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            session_id: session_id.into(),
            sender: sender.into(),
            recipient: recipient.into(),
            sequence,
            payload,
            timestamp: Utc::now(),
            signature: None,
        }
    }

    /// The canonical bytes that are signed: SHA-256(session_id || sequence || payload_json).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let payload_json =
            serde_json::to_string(&self.payload).expect("payload serialization cannot fail");
        let mut hasher = Sha256::new();
        hasher.update(self.session_id.as_bytes());
        hasher.update(self.sequence.to_be_bytes());
        hasher.update(payload_json.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Sign the envelope with an ephemeral session key.
    pub fn sign(&mut self, key: &SigningKey) {
        let bytes = self.signable_bytes();
        let sig = key.sign(&bytes);
        self.signature = Some(sig.to_bytes().to_vec());
    }

    /// Verify the envelope's signature against a session verifying key.
    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProtoError> {
        let sig_bytes = self
            .signature
            .as_ref()
            .ok_or(ProtoError::VerificationFailed)?;

        let signature = ed25519_dalek::Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ProtoError::VerificationFailed)?,
        );

        let bytes = self.signable_bytes();
        key.verify(&bytes, &signature)
            .map_err(|_| ProtoError::VerificationFailed)
    }

    /// Serialize to JSON bytes for transport.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProtoError> {
        serde_json::to_vec(self)
            .map_err(|e| ProtoError::SerializationError(e.to_string()))
    }

    /// Deserialize from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        serde_json::from_slice(bytes)
            .map_err(|e| ProtoError::SerializationError(e.to_string()))
    }
}
