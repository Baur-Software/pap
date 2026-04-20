//! Group chat room — a local `AgentHandler` that fans out `StreamingMessage`
//! frames to all connected members.
//!
//! # Model
//!
//! A room is an agent with its own DID. Each member runs the standard
//! 6-phase PAP handshake against the room DID (Phase 1–3: auth + scope,
//! Phase 4 execute: opens the streaming session, returning a
//! `schema:Conversation`). After Phase 4, each member's WebSocket session
//! stays open and both sides exchange `StreamingMessage` frames.
//!
//! When a member sends a `StreamingMessage`, the room fans it out to every
//! other connected member via an async channel. The sender receives a
//! `StreamingAck` immediately; recipients are pushed asynchronously.
//!
//! # Thread safety
//!
//! `GroupChatRoom` is `Send + Sync` and can be shared across Tokio tasks.
//! Member senders are stored in a `RwLock<HashMap>` keyed by session ID.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_did::SessionKeypair;
use pap_transport::handler::AgentHandler;
use pap_transport::TransportError;
use tokio::sync::mpsc;

/// A connected member's outbound channel.
type MemberSender = mpsc::Sender<serde_json::Value>;

/// A group chat room that fans out `StreamingMessage` frames to all members.
#[derive(Clone)]
pub struct GroupChatRoom {
    /// Stable identifier for this room (typically the room DID).
    room_id: String,
    /// Display name shown in `schema:Conversation.name`.
    room_name: String,
    /// Connected member sessions: session_id → outbound channel.
    members: Arc<RwLock<HashMap<String, MemberSender>>>,
}

impl GroupChatRoom {
    /// Create a new, empty room.
    pub fn new(room_id: impl Into<String>, room_name: impl Into<String>) -> Self {
        Self {
            room_id: room_id.into(),
            room_name: room_name.into(),
            members: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a member session and return the receiver end of its channel.
    ///
    /// The caller (typically the WS server loop) should forward messages
    /// arriving on `rx` to the member's WebSocket connection.
    pub fn add_member(
        &self,
        session_id: impl Into<String>,
        capacity: usize,
    ) -> mpsc::Receiver<serde_json::Value> {
        let (tx, rx) = mpsc::channel(capacity);
        // Recover from a poisoned lock rather than propagating a panic.
        let mut members = self.members.write().unwrap_or_else(|e| e.into_inner());
        members.insert(session_id.into(), tx);
        rx
    }

    /// Deregister a member session (called on Phase 6 close).
    pub fn remove_member(&self, session_id: &str) {
        if let Ok(mut members) = self.members.write() {
            members.remove(session_id);
        }
    }

    /// Number of currently connected members.
    pub fn member_count(&self) -> usize {
        self.members.read().map(|m| m.len()).unwrap_or(0)
    }

    /// Room identifier.
    pub fn room_id(&self) -> &str {
        &self.room_id
    }
}

impl AgentHandler for GroupChatRoom {
    /// Phase 1: validate the capability token then return a fresh ephemeral
    /// session DID for this room leg.
    ///
    /// Validation:
    /// - `token.target_did` must equal `self.room_id`; tokens addressed to a
    ///   different agent are rejected with `HandlerError`.
    ///
    /// The ephemeral session DID is generated from a real Ed25519 keypair via
    /// `pap_did::SessionKeypair` — resolves ISS-900.
    fn handle_token(&self, token: CapabilityToken) -> Result<(String, String), TransportError> {
        // ISS-900: validate that the token is addressed to this room.
        if token.target_did != self.room_id {
            return Err(TransportError::HandlerError(format!(
                "token target_did '{}' does not match room_id '{}'",
                token.target_did, self.room_id,
            )));
        }

        let session_id = uuid::Uuid::new_v4().to_string();
        // ISS-900: generate a real Ed25519 ephemeral keypair and derive the
        // did:key DID from its public key bytes.
        let room_session_did = SessionKeypair::generate().did();
        Ok((session_id, room_session_did))
    }

    /// Phase 2: record the initiator's session DID (no-op for room).
    fn handle_did_exchange(
        &self,
        _session_id: &str,
        _initiator_session_did: &str,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    /// Phase 3: accept any disclosures (no-op for room).
    fn handle_disclosure(
        &self,
        _session_id: &str,
        _disclosures: Vec<serde_json::Value>,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    /// Phase 4: return the room's `schema:Conversation` metadata to the
    /// connecting member.  This signals that the session is now open for
    /// streaming and the member should begin sending `StreamingMessage`
    /// frames rather than proceeding to Phase 5.
    fn execute(&self, _session_id: &str) -> Result<serde_json::Value, TransportError> {
        Ok(serde_json::json!({
            "@context": "https://schema.org",
            "@type": "Conversation",
            "identifier": self.room_id,
            "name": self.room_name,
            "description": "PAP group chat room",
        }))
    }

    /// Phase 4 streaming: fan out an incoming message to all other members.
    ///
    /// Returns `None` (ack-only to sender).  The room pushes the message to
    /// other members via their async channels; the WS server loop forwards
    /// those to their respective WebSocket connections.
    fn handle_stream_message(
        &self,
        session_id: &str,
        _id: &str,
        content: &serde_json::Value,
    ) -> Result<Option<serde_json::Value>, TransportError> {
        let members = self
            .members
            .read()
            .map_err(|_| TransportError::HandlerError("room: member lock poisoned".into()))?;
        for (sid, tx) in members.iter() {
            if sid != session_id {
                // Best-effort — drop if member channel is full.
                let _ = tx.try_send(content.clone());
            }
        }
        Ok(None)
    }

    /// Phase 5: co-sign receipt (no-op for room — members sign bilaterally).
    fn co_sign_receipt(
        &self,
        receipt: TransactionReceipt,
    ) -> Result<TransactionReceipt, TransportError> {
        Ok(receipt)
    }

    /// Phase 6: remove the member from the room on session close.
    fn handle_close(&self, session_id: &str) -> Result<(), TransportError> {
        self.remove_member(session_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ISS-900 tests
    // -----------------------------------------------------------------------

    /// Helper that mints a minimal (unsigned) CapabilityToken for testing.
    fn make_token(target_did: &str) -> CapabilityToken {
        use chrono::Utc;
        CapabilityToken::mint(
            target_did.to_string(),
            "schema:SearchAction".to_string(),
            "did:key:zIssuer".to_string(),
            Utc::now() + chrono::Duration::hours(1),
        )
    }

    #[test]
    fn handle_token_generates_valid_did_key() {
        let room = GroupChatRoom::new("did:key:zRoom1", "Test Room");
        let token = make_token("did:key:zRoom1");
        let (_session_id, room_session_did) = room.handle_token(token).unwrap();
        // The generated DID must follow the did:key method (ISS-900 stub returned did:pap:).
        assert!(
            room_session_did.starts_with("did:key:"),
            "expected did:key DID, got: {room_session_did}"
        );
    }

    #[test]
    fn handle_token_rejects_wrong_target_did() {
        let room = GroupChatRoom::new("did:key:zRoom1", "Test Room");
        let token = make_token("did:key:zOtherAgent");
        let err = room.handle_token(token).unwrap_err();
        match err {
            TransportError::HandlerError(msg) => {
                assert!(
                    msg.contains("does not match room_id"),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected HandlerError, got {other:?}"),
        }
    }

    #[test]
    fn room_add_remove_member() {
        let room = GroupChatRoom::new("did:key:zRoom1", "Test Room");
        assert_eq!(room.member_count(), 0);

        let _rx1 = room.add_member("session-1", 16);
        let _rx2 = room.add_member("session-2", 16);
        assert_eq!(room.member_count(), 2);

        room.remove_member("session-1");
        assert_eq!(room.member_count(), 1);
    }

    #[test]
    fn execute_returns_conversation() {
        let room = GroupChatRoom::new("did:key:zRoom1", "My Room");
        let result = room.execute("sess-abc").unwrap();
        assert_eq!(result["@type"], "Conversation");
        assert_eq!(result["identifier"], "did:key:zRoom1");
        assert_eq!(result["name"], "My Room");
    }

    #[tokio::test]
    async fn fanout_skips_sender() {
        let room = GroupChatRoom::new("did:key:zRoom1", "Test Room");
        let mut rx1 = room.add_member("session-1", 16);
        let mut rx2 = room.add_member("session-2", 16);

        let content = serde_json::json!({"text": "hello"});
        room.handle_stream_message("session-1", "msg-id-1", &content)
            .unwrap();

        // session-2 should receive the message
        let received = rx2.try_recv().expect("session-2 should have received");
        assert_eq!(received["text"], "hello");

        // session-1 (sender) should NOT receive its own message
        assert!(
            rx1.try_recv().is_err(),
            "sender should not receive its own message"
        );
    }
}
