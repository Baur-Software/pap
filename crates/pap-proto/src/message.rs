use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use serde::{Deserialize, Serialize};

/// The six protocol phases, mapped from the PAP spec's session handshake.
///
/// Each variant carries exactly the data that phase needs — no more.
/// The transport layer moves these as opaque payloads; it never inspects
/// the contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProtocolMessage {
    // ── Phase 1: Token Presentation ──────────────────────────────
    /// Initiator presents a capability token to the receiving agent.
    TokenPresentation { token: CapabilityToken },

    /// Receiver accepts the token and returns a session ID + its
    /// ephemeral session DID.
    TokenAccepted {
        session_id: String,
        receiver_session_did: String,
    },

    /// Receiver rejects the token with a reason.
    TokenRejected { reason: String },

    // ── Phase 2: Ephemeral DID Exchange ──────────────────────────
    /// Initiator sends its ephemeral session DID.
    SessionDidExchange { initiator_session_did: String },

    /// Receiver acknowledges the DID exchange. Session is now Open.
    SessionDidAck,

    // ── Phase 3: Disclosure ──────────────────────────────────────
    /// Initiator offers selective disclosures (SD-JWT claim values).
    /// Empty vec for zero-disclosure sessions.
    DisclosureOffer { disclosures: Vec<serde_json::Value> },

    /// Receiver acknowledges disclosures.
    DisclosureAccepted,

    // ── Phase 4: Execution ───────────────────────────────────────
    /// Receiver returns the execution result (Schema.org JSON-LD).
    ExecutionResult { result: serde_json::Value },

    // ── Phase 5: Receipt Co-signing ──────────────────────────────
    /// Initiator sends its half-signed receipt for the receiver to co-sign.
    ReceiptForCoSign { receipt: TransactionReceipt },

    /// Receiver returns the fully co-signed receipt.
    ReceiptCoSigned { receipt: TransactionReceipt },

    // ── Phase 6: Close ───────────────────────────────────────────
    /// Either side initiates session close.
    SessionClose { session_id: String },

    /// Acknowledgement of session close. Ephemeral keys discarded.
    SessionClosed,

    // ── Error ────────────────────────────────────────────────────
    /// Protocol-level error at any phase.
    Error { code: String, message: String },
}

impl ProtocolMessage {
    /// Human-readable message type for logging.
    pub fn message_type(&self) -> &'static str {
        match self {
            Self::TokenPresentation { .. } => "TokenPresentation",
            Self::TokenAccepted { .. } => "TokenAccepted",
            Self::TokenRejected { .. } => "TokenRejected",
            Self::SessionDidExchange { .. } => "SessionDidExchange",
            Self::SessionDidAck => "SessionDidAck",
            Self::DisclosureOffer { .. } => "DisclosureOffer",
            Self::DisclosureAccepted => "DisclosureAccepted",
            Self::ExecutionResult { .. } => "ExecutionResult",
            Self::ReceiptForCoSign { .. } => "ReceiptForCoSign",
            Self::ReceiptCoSigned { .. } => "ReceiptCoSigned",
            Self::SessionClose { .. } => "SessionClose",
            Self::SessionClosed => "SessionClosed",
            Self::Error { .. } => "Error",
        }
    }
}
