//! Full PAP 6-phase handshake over real RDMA on a single BlueField card.
//!
//! Spawns a bootstrap server and a client in the **same process**.  Both
//! endpoints open the same physical BlueField device and create independent
//! RC queue pairs; the hardware routes frames through its internal loopback
//! path — no second machine, no connected switch port required.
//!
//! # Usage
//!
//! ```text
//! # default device, port 7777, GID index 0
//! cargo run -p pap-bluefield --example loopback
//!
//! # explicit device/port/GID
//! cargo run -p pap-bluefield --example loopback -- \
//!     --device mlx5_0 --port 7777 --gid-index 1
//! ```
//!
//! # Choosing the right GID index
//!
//! On RoCEv2 (Ethernet) adapters, GID index 0 is typically a link-local GID
//! (`fe80::…`) that may not support loopback routing.  If the example hangs
//! waiting for RDMA completions, re-run with `--gid-index 1` (or whichever
//! index is listed as a routable IPv4/IPv6 address by `show_gids`).
//!
//! On native InfiniBand (IB) adapters, GID index 0 always works and loopback
//! is handled by the subnet manager.
//!
//! # How RDMA loopback works
//!
//! ```text
//! ┌──────────── Host CPU ────────────────────────────────────────────────┐
//! │                                                                      │
//! │  Server task                         Client task                    │
//! │  RdmaBootstrapServer                 RdmaBootstrapClient            │
//! │  QueuePair (QPN A)  ←── PCIe ──→   QueuePair (QPN B)              │
//! │                          ↕                                          │
//! │               BlueField internal switch / loopback                  │
//! └──────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! The QP state machine requires each side to know the other's QPN, LID/GID,
//! and initial PSN.  These are exchanged over a short-lived TCP connection to
//! `127.0.0.1:<port>` (the bootstrap channel), after which the TCP socket is
//! dropped and all PAP traffic flows over RDMA SEND operations.

use std::sync::Arc;

use pap_bluefield::{
    handle_channel, rdma::context::DeviceContext, BluefieldClient, RdmaBootstrapClient,
    RdmaBootstrapServer,
};
use pap_core::{receipt::TransactionReceipt, session::CapabilityToken};
use pap_proto::ProtocolMessage;
use pap_transport::{AgentHandler, TransportError};

// ── Demo handler ──────────────────────────────────────────────────────────────

/// Minimal receiver-side handler that logs each PAP phase and returns canned
/// responses — suitable for loopback smoke-testing.
struct DemoHandler;

impl AgentHandler for DemoHandler {
    fn handle_token(&self, token: CapabilityToken) -> Result<(String, String), TransportError> {
        println!("[server] phase 1 — token accepted  action={}", token.action);
        Ok((
            "session-rdma-loopback".into(),
            "did:key:zBlueFieldReceiver".into(),
        ))
    }

    fn handle_did_exchange(&self, sid: &str, did: &str) -> Result<(), TransportError> {
        println!("[server] phase 2 — DID exchange  sid={sid}  initiator_did={did}");
        Ok(())
    }

    fn handle_disclosure(
        &self,
        sid: &str,
        disclosures: Vec<serde_json::Value>,
    ) -> Result<(), TransportError> {
        println!(
            "[server] phase 3 — disclosures  sid={sid}  n={}",
            disclosures.len()
        );
        Ok(())
    }

    fn execute(&self, sid: &str) -> Result<serde_json::Value, TransportError> {
        println!("[server] phase 4 — execute  sid={sid}");
        Ok(serde_json::json!({
            "@context": "https://schema.org",
            "@type":    "SearchResultsPage",
            "transport": "rdma",
            "name":     "BlueField loopback result — OK"
        }))
    }

    fn co_sign_receipt(&self, r: TransactionReceipt) -> Result<TransactionReceipt, TransportError> {
        println!(
            "[server] phase 5 — co-signing receipt  session={}",
            r.session_id
        );
        Ok(r)
    }

    fn handle_close(&self, sid: &str) -> Result<(), TransportError> {
        println!("[server] phase 6 — session closed  sid={sid}");
        Ok(())
    }
}

// ── CLI ───────────────────────────────────────────────────────────────────────

struct Args {
    /// RDMA device name, e.g. `"mlx5_0"`.  `None` → first enumerated device.
    device: Option<String>,
    /// TCP port for QP metadata bootstrap.
    port: u16,
    /// GID table index.  Try `1` if GID 0 is link-local and loopback stalls.
    gid_index: u8,
}

impl Args {
    fn parse() -> Self {
        let mut it = std::env::args().skip(1).peekable();
        let mut device = None;
        let mut port = 7777u16;
        let mut gid_index = 0u8;

        while let Some(a) = it.next() {
            match a.as_str() {
                "--device" | "-d" => {
                    device = it.next();
                }
                "--port" | "-p" => {
                    if let Some(v) = it.next() {
                        port = v.parse().expect("--port: expected u16");
                    }
                }
                "--gid-index" | "-g" => {
                    if let Some(v) = it.next() {
                        gid_index = v.parse().expect("--gid-index: expected u8");
                    }
                }
                "--help" | "-h" => {
                    println!("usage: loopback [--device <name>] [--port <u16>] [--gid-index <u8>]");
                    std::process::exit(0);
                }
                other => eprintln!("warning: unknown argument '{other}'"),
            }
        }

        Self {
            device,
            port,
            gid_index,
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // ── Open RDMA device ──────────────────────────────────────────────────
    //
    // Both server and client share the same Arc<DeviceContext>.  ibverbs
    // allows multiple queue pairs per protection domain, so creating two QPs
    // (one per side) from a single PD is fully supported.
    let dev_name = args.device.as_deref();
    println!(
        "Opening RDMA device: {}  port=1  gid_index={}",
        dev_name.unwrap_or("<first available>"),
        args.gid_index
    );

    let dev = Arc::new(DeviceContext::open(dev_name, 1, args.gid_index)?);
    println!("Opened: {}\n", dev.device_name());

    // ── Bootstrap server ──────────────────────────────────────────────────
    //
    // Bind TCP; the server task below will call `accept()` once, complete the
    // QP exchange, and then run the PAP protocol loop.
    let server = RdmaBootstrapServer::bind(args.port, Arc::clone(&dev)).await?;
    let local_port = server.local_port();
    println!("Bootstrap TCP listening on 0.0.0.0:{local_port}");

    let handler = Arc::new(DemoHandler);

    let server_task = {
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            // accept() performs the TCP QP exchange and transitions the QP to
            // RTS state, then returns an RdmaConnection ready for PAP frames.
            match server.accept().await {
                Ok(conn) => {
                    if let Err(e) = handle_channel(handler, conn).await {
                        eprintln!("[server] session error: {e}");
                    }
                }
                Err(e) => eprintln!("[server] accept error: {e}"),
            }
        })
    };

    // Yield so the server task can reach listener.accept() before we connect.
    // (The OS listen backlog handles the race if we connect slightly early,
    //  but yielding keeps the output ordering clean.)
    tokio::task::yield_now().await;

    // ── Client — connect back to 127.0.0.1 ───────────────────────────────
    let bootstrap_addr = format!("127.0.0.1:{local_port}");
    println!("[client] connecting to {bootstrap_addr} …");

    let conn = RdmaBootstrapClient::connect(&bootstrap_addr, Arc::clone(&dev)).await?;
    let mut client = BluefieldClient::new(conn);
    println!("[client] RDMA connection established\n");

    // ── Phase 1: capability token ─────────────────────────────────────────
    println!("[client] phase 1 — presenting capability token …");
    let token = CapabilityToken::mint(
        "did:key:zBlueFieldReceiver".into(),
        "https://schema.org/SearchAction".into(),
        "did:key:zLoopbackIssuer".into(),
        chrono::Utc::now() + chrono::TimeDelta::hours(1),
    );

    let session_id = match client.present_token(token).await? {
        ProtocolMessage::TokenAccepted {
            session_id,
            receiver_session_did,
            ..
        } => {
            println!(
                "[client] phase 1 — accepted  session={session_id}  receiver={receiver_session_did}"
            );
            session_id
        }
        ProtocolMessage::TokenRejected { reason } => {
            return Err(format!("phase 1 rejected: {reason}").into());
        }
        other => return Err(format!("phase 1: unexpected reply {other:?}").into()),
    };

    // ── Phase 2: ephemeral DID exchange ───────────────────────────────────
    println!("[client] phase 2 — ephemeral DID exchange …");
    client
        .exchange_did("did:key:zLoopbackInitiatorEphemeral".into())
        .await?;
    println!("[client] phase 2 — ack received");

    // ── Phase 3: selective disclosures ────────────────────────────────────
    println!("[client] phase 3 — disclosure offer (zero disclosures) …");
    client.send_disclosures(vec![]).await?;
    println!("[client] phase 3 — accepted");

    // ── Phase 4: execution ────────────────────────────────────────────────
    println!("[client] phase 4 — requesting execution …");
    match client.request_execution().await? {
        ProtocolMessage::ExecutionResult { result } => {
            println!("[client] phase 4 — result: {result}");
        }
        other => return Err(format!("phase 4: unexpected reply {other:?}").into()),
    }

    // ── Phase 5: receipt co-signing ───────────────────────────────────────
    println!("[client] phase 5 — exchanging receipt …");
    let receipt = TransactionReceipt {
        session_id: session_id.clone(),
        action: "https://schema.org/SearchAction".into(),
        initiating_agent_did: "did:key:zLoopbackInitiator".into(),
        receiving_agent_did: "did:key:zBlueFieldReceiver".into(),
        disclosed_by_initiator: vec![],
        disclosed_by_receiver: vec![],
        executed: "loopback search completed over rdma".into(),
        returned: "search results page".into(),
        payment_proof_commitment: None,
        timestamp: chrono::Utc::now(),
        signatures: vec![],
        attestations: vec![],
    };

    match client.exchange_receipt(receipt).await? {
        ProtocolMessage::ReceiptCoSigned { receipt } => {
            println!(
                "[client] phase 5 — co-signed  session={}",
                receipt.session_id
            );
        }
        other => return Err(format!("phase 5: unexpected reply {other:?}").into()),
    }

    // ── Phase 6: close ────────────────────────────────────────────────────
    println!("[client] phase 6 — closing session …");
    client.close_session(session_id).await?;
    println!("[client] phase 6 — done\n");

    // Wait for the server task to finish cleanly.
    server_task.await?;

    println!("PAP RDMA loopback: all 6 phases complete ✓");
    Ok(())
}
