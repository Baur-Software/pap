//! Bidirectional message channel abstraction for the BlueField transport.
//!
//! [`MessageChannel`] is the internal trait that both the real RDMA channel
//! and the in-memory mock channel implement.  The client and server are
//! generic over any `C: MessageChannel`, which allows the entire 6-phase
//! handshake to be tested end-to-end without physical BlueField hardware.
//!
//! # Feature gates
//! - `mock` feature (or `#[cfg(test)]`) enables [`MockChannel`] and
//!   [`MockChannel::pair()`] for test use.

use pap_proto::ProtocolMessage;

use crate::error::BluefieldError;

// ── Channel trait ─────────────────────────────────────────────────────────────

/// Ordered, reliable, bidirectional message channel.
///
/// Implementations must preserve message ordering within a session.
/// Each `send_msg` call corresponds to exactly one `recv_msg` call on the
/// remote side.
#[allow(async_fn_in_trait)]
pub trait MessageChannel: Send {
    /// Send a protocol message over the channel.
    async fn send_msg(&mut self, msg: &ProtocolMessage) -> Result<(), BluefieldError>;

    /// Receive the next protocol message from the channel.
    async fn recv_msg(&mut self) -> Result<ProtocolMessage, BluefieldError>;
}

// ── In-memory mock channel ───────────────────────────────────────────────────

/// In-memory message channel backed by tokio mpsc queues.
///
/// Used in tests and when the `mock` feature is enabled.  Messages are
/// serialised to JSON (matching the wire framing) so mock-based tests
/// exercise the same serialisation path as the real transport.
#[cfg(any(feature = "mock", test))]
pub struct MockChannel {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

#[cfg(any(feature = "mock", test))]
impl MockChannel {
    /// Create a connected pair of mock channels.
    ///
    /// Messages sent to `a` are received by `b` and vice-versa.  The capacity
    /// is 64 messages per direction.
    pub fn pair() -> (Self, Self) {
        let (tx_a, rx_a) = tokio::sync::mpsc::channel(64);
        let (tx_b, rx_b) = tokio::sync::mpsc::channel(64);
        let a = MockChannel { tx: tx_a, rx: rx_b };
        let b = MockChannel { tx: tx_b, rx: rx_a };
        (a, b)
    }
}

#[cfg(any(feature = "mock", test))]
impl MessageChannel for MockChannel {
    async fn send_msg(&mut self, msg: &ProtocolMessage) -> Result<(), BluefieldError> {
        let bytes = serde_json::to_vec(msg).map_err(BluefieldError::Json)?;
        self.tx
            .send(bytes)
            .await
            .map_err(|e| BluefieldError::RdmaError(format!("mock send failed: {e}")))
    }

    async fn recv_msg(&mut self) -> Result<ProtocolMessage, BluefieldError> {
        let bytes = self
            .rx
            .recv()
            .await
            .ok_or_else(|| BluefieldError::RdmaError("mock channel closed".into()))?;
        serde_json::from_slice(&bytes).map_err(BluefieldError::Json)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_pair_round_trip() {
        let (mut a, mut b) = MockChannel::pair();

        let sent = ProtocolMessage::SessionDidAck;
        a.send_msg(&sent).await.unwrap();
        let recv = b.recv_msg().await.unwrap();
        assert!(matches!(recv, ProtocolMessage::SessionDidAck));
    }

    #[tokio::test]
    async fn mock_pair_bidirectional() {
        let (mut a, mut b) = MockChannel::pair();

        // a → b
        a.send_msg(&ProtocolMessage::SessionClosed).await.unwrap();
        let from_a = b.recv_msg().await.unwrap();
        assert!(matches!(from_a, ProtocolMessage::SessionClosed));

        // b → a
        b.send_msg(&ProtocolMessage::SessionDidAck).await.unwrap();
        let from_b = a.recv_msg().await.unwrap();
        assert!(matches!(from_b, ProtocolMessage::SessionDidAck));
    }

    #[tokio::test]
    async fn mock_serialises_payload_correctly() {
        let (mut a, mut b) = MockChannel::pair();

        let msg = ProtocolMessage::TokenAccepted {
            session_id: "s-mock-42".into(),
            receiver_session_did: "did:key:zMock".into(),
            attestation: None,
        };
        a.send_msg(&msg).await.unwrap();
        match b.recv_msg().await.unwrap() {
            ProtocolMessage::TokenAccepted { session_id, .. } => {
                assert_eq!(session_id, "s-mock-42");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn mock_ordering_preserved() {
        let (mut a, mut b) = MockChannel::pair();

        let codes = ["E001", "E002", "E003"];

        // Queue 3 messages in order
        for code in codes {
            let msg = ProtocolMessage::Error {
                code: code.into(),
                message: format!("error-{code}"),
            };
            a.send_msg(&msg).await.unwrap();
        }

        // Receive in the same order
        for expected in codes {
            match b.recv_msg().await.unwrap() {
                ProtocolMessage::Error { code, .. } => assert_eq!(code, expected),
                other => panic!("unexpected: {other:?}"),
            }
        }
    }
}
