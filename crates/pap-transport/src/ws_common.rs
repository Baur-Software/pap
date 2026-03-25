//! Shared types for the WebSocket transport.
//!
//! `WsMessage` provides the routing information that HTTP transport gets
//! from URL paths (`/session/{id}/did`, etc.). Over WebSocket, a single
//! persistent connection carries all phases, so the `phase` field tells
//! the server which handler method to invoke.

use pap_proto::ProtocolMessage;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

/// Combined trait for async bidirectional streams.
///
/// Rust trait objects only allow one non-auto trait, so we combine
/// `AsyncRead + AsyncWrite` into a single supertrait. Blanket-implemented
/// for any type that satisfies all bounds.
pub(crate) trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Type-erased async stream for WebSocket connections.
///
/// Wraps either a plain `TcpStream` (tests) or a `TlsStream<TcpStream>`
/// (production) behind a boxed trait object so the WS client/server don't
/// need generic parameters in their public API.
pub(crate) type BoxedStream = Box<dyn AsyncStream>;

/// WebSocket transport message wrapper.
///
/// Provides the routing information that HTTP gets from URL paths.
/// This is internal to the WS transport — it does not change the
/// `pap-proto` protocol messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WsMessage {
    /// Protocol phase (1–6).
    pub phase: u8,

    /// Session ID (known after phase 1 response).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// The protocol message payload.
    /// `None` for phase 4 (execution request), which has no client payload
    /// (HTTP transport uses an empty POST body).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<ProtocolMessage>,
}
