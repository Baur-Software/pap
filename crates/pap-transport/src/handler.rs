use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;

use crate::error::TransportError;

/// Trait that a receiving agent implements to handle protocol messages.
///
/// The transport layer calls these methods when it receives messages
/// from the initiating agent. Each method corresponds to a protocol
/// phase.
pub trait AgentHandler: Send + Sync {
    /// Phase 1: Validate an incoming capability token.
    /// Returns (session_id, receiver_session_did) on acceptance.
    fn handle_token(
        &self,
        token: CapabilityToken,
    ) -> Result<(String, String), TransportError>;

    /// Phase 2: Receive the initiator's ephemeral session DID.
    fn handle_did_exchange(
        &self,
        session_id: &str,
        initiator_session_did: &str,
    ) -> Result<(), TransportError>;

    /// Phase 3: Receive selective disclosures from the initiator.
    fn handle_disclosure(
        &self,
        session_id: &str,
        disclosures: Vec<serde_json::Value>,
    ) -> Result<(), TransportError>;

    /// Phase 4: Execute the requested action and return a result.
    fn execute(
        &self,
        session_id: &str,
    ) -> Result<serde_json::Value, TransportError>;

    /// Phase 5: Co-sign a receipt from the initiator.
    fn co_sign_receipt(
        &self,
        receipt: TransactionReceipt,
    ) -> Result<TransactionReceipt, TransportError>;

    /// Phase 6: Handle session close.
    fn handle_close(
        &self,
        session_id: &str,
    ) -> Result<(), TransportError>;
}
