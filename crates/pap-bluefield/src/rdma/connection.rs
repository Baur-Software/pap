//! RDMA connection establishment via TCP bootstrap.
//!
//! RDMA RC queue pairs must be told each other's QPN, LID/GID, and PSN before
//! any data can flow.  This module provides a minimal TCP bootstrap to exchange
//! that metadata, then completes the QP state machine so both ends are in RTS.
//!
//! # Protocol
//! 1. Server binds a TCP port and waits.
//! 2. Client connects; sends its [`QpInfo`] as a JSON line.
//! 3. Server replies with its own [`QpInfo`] JSON line.
//! 4. Both sides transition INIT → RTR → RTS independently.
//! 5. TCP connection is dropped; pure RDMA follows.
//!
//! # `RdmaConnection` as `MessageChannel`
//! After bootstrap, [`RdmaConnection`] implements [`crate::channel::MessageChannel`]
//! by serialising [`ProtocolMessage`]s with the length-prefix framing defined
//! in [`crate::frame`] and transferring them via RDMA SEND operations.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use pap_proto::ProtocolMessage;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::{TcpListener, TcpStream};

use super::context::DeviceContext;
use super::qp::{QpInfo, QueuePair};
use crate::channel::MessageChannel;
use crate::error::BluefieldError;

// ── RdmaConnection ────────────────────────────────────────────────────────────

/// A fully connected RDMA queue pair implementing [`MessageChannel`].
///
/// Operations are serialised by the inner `Mutex` since the QP state (buffer
/// contents, outstanding WRs) must not be accessed concurrently.
pub struct RdmaConnection {
    inner: Arc<Mutex<QueuePair>>,
}

impl RdmaConnection {
    fn new(qp: QueuePair) -> Self {
        Self {
            inner: Arc::new(Mutex::new(qp)),
        }
    }
}

impl MessageChannel for RdmaConnection {
    /// Serialise `msg` with a length-prefix frame and post a RDMA SEND.
    /// Blocks in `spawn_blocking` until the send completion appears.
    async fn send_msg(&mut self, msg: &ProtocolMessage) -> Result<(), BluefieldError> {
        let inner = Arc::clone(&self.inner);
        let msg = msg.clone();

        tokio::task::spawn_blocking(move || {
            let mut qp = inner.lock().expect("QP mutex poisoned");
            qp.send_frame(&msg)?;
            qp.poll_send_cq()
        })
        .await
        .map_err(|e| BluefieldError::RdmaError(format!("spawn_blocking panic: {e}")))?
    }

    /// Post a receive WR, then block until a frame arrives.
    async fn recv_msg(&mut self) -> Result<ProtocolMessage, BluefieldError> {
        let inner = Arc::clone(&self.inner);

        tokio::task::spawn_blocking(move || {
            let mut qp = inner.lock().expect("QP mutex poisoned");
            qp.post_recv()?;
            qp.recv_frame()
        })
        .await
        .map_err(|e| BluefieldError::RdmaError(format!("spawn_blocking panic: {e}")))?
    }
}

// ── Bootstrap helpers ─────────────────────────────────────────────────────────

/// Bring a freshly allocated QP through INIT → RTR → RTS using the remote
/// QP metadata exchanged over TCP.
fn transition_to_rts(
    qp: &mut QueuePair,
    remote: &QpInfo,
    dev: &DeviceContext,
) -> Result<(), BluefieldError> {
    qp.init(dev.port_num)?;
    qp.ready_to_receive(remote, dev.is_roce, dev.gid_index)?;
    qp.ready_to_send(qp.local_info().psn)?;
    Ok(())
}

// ── Bootstrap server ──────────────────────────────────────────────────────────

/// Listens on a TCP port and completes the RDMA bootstrap for one incoming
/// connection.
///
/// The server binds `0.0.0.0:bootstrap_port`.  Call [`RdmaBootstrapServer::accept`]
/// to await the next client, perform the QP exchange, and return a live
/// [`RdmaConnection`].
pub struct RdmaBootstrapServer {
    listener: TcpListener,
    dev: Arc<DeviceContext>,
}

impl RdmaBootstrapServer {
    /// Bind the bootstrap TCP listener.
    pub async fn bind(
        bootstrap_port: u16,
        dev: Arc<DeviceContext>,
    ) -> Result<Self, BluefieldError> {
        let addr = SocketAddr::from(([0, 0, 0, 0], bootstrap_port));
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| BluefieldError::BootstrapFailed(format!("TCP bind failed: {e}")))?;
        Ok(Self { listener, dev })
    }

    /// Port the listener is bound to (useful when bound to port 0).
    pub fn local_port(&self) -> u16 {
        self.listener.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    /// Accept one client, exchange QP info, and return a connected channel.
    pub async fn accept(&self) -> Result<RdmaConnection, BluefieldError> {
        let (stream, _peer) = self
            .listener
            .accept()
            .await
            .map_err(|e| BluefieldError::BootstrapFailed(format!("TCP accept: {e}")))?;

        let dev = Arc::clone(&self.dev);
        bootstrap_server_side(stream, dev).await
    }
}

async fn bootstrap_server_side(
    stream: TcpStream,
    dev: Arc<DeviceContext>,
) -> Result<RdmaConnection, BluefieldError> {
    let mut qp = QueuePair::create(&dev)?;

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = TokioBufReader::new(read_half);

    // Step 1: read client's QP info.
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|e| BluefieldError::BootstrapFailed(format!("read client QpInfo: {e}")))?;
    let remote: QpInfo = serde_json::from_str(line.trim())
        .map_err(|e| BluefieldError::BootstrapFailed(format!("parse client QpInfo: {e}")))?;

    // Step 2: send our QP info.
    let local_json = serde_json::to_string(qp.local_info())
        .map_err(|e| BluefieldError::BootstrapFailed(e.to_string()))?;
    write_half
        .write_all(format!("{local_json}\n").as_bytes())
        .await
        .map_err(|e| BluefieldError::BootstrapFailed(format!("send server QpInfo: {e}")))?;
    write_half.flush().await.ok();

    // Step 3: transition QP to RTS.
    transition_to_rts(&mut qp, &remote, &dev)?;

    Ok(RdmaConnection::new(qp))
}

// ── Bootstrap client ──────────────────────────────────────────────────────────

/// Connects to a [`RdmaBootstrapServer`] and returns a live [`RdmaConnection`].
pub struct RdmaBootstrapClient;

impl RdmaBootstrapClient {
    /// Connect to the server's bootstrap TCP port, exchange QP metadata, and
    /// return a fully connected RDMA channel.
    ///
    /// # Arguments
    /// * `server_addr` — e.g. `"192.168.200.1:7777"`
    /// * `dev` — the local BlueField device context
    pub async fn connect(
        server_addr: &str,
        dev: Arc<DeviceContext>,
    ) -> Result<RdmaConnection, BluefieldError> {
        let stream = TcpStream::connect(server_addr).await.map_err(|e| {
            BluefieldError::BootstrapFailed(format!("TCP connect to {server_addr}: {e}"))
        })?;

        bootstrap_client_side(stream, dev).await
    }
}

async fn bootstrap_client_side(
    stream: TcpStream,
    dev: Arc<DeviceContext>,
) -> Result<RdmaConnection, BluefieldError> {
    let mut qp = QueuePair::create(&dev)?;

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = TokioBufReader::new(read_half);

    // Step 1: send our QP info.
    let local_json = serde_json::to_string(qp.local_info())
        .map_err(|e| BluefieldError::BootstrapFailed(e.to_string()))?;
    write_half
        .write_all(format!("{local_json}\n").as_bytes())
        .await
        .map_err(|e| BluefieldError::BootstrapFailed(format!("send client QpInfo: {e}")))?;
    write_half.flush().await.ok();

    // Step 2: read server's QP info.
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|e| BluefieldError::BootstrapFailed(format!("read server QpInfo: {e}")))?;
    let remote: QpInfo = serde_json::from_str(line.trim())
        .map_err(|e| BluefieldError::BootstrapFailed(format!("parse server QpInfo: {e}")))?;

    // Step 3: transition QP to RTS.
    transition_to_rts(&mut qp, &remote, &dev)?;

    Ok(RdmaConnection::new(qp))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qp_info_json_round_trip() {
        let info = QpInfo {
            qpn: 12345,
            lid: 7,
            gid: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            psn: 42,
        };
        let json = serde_json::to_string(&info).unwrap();
        let decoded: QpInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.qpn, 12345);
        assert_eq!(decoded.lid, 7);
        assert_eq!(decoded.psn, 42);
        assert_eq!(decoded.gid, info.gid);
    }
}
