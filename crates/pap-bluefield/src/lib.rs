//! RDMA transport and hardware-accelerated crypto for PAP via NVIDIA BlueField DPU.
//!
//! # Overview
//!
//! This crate provides an alternative transport backend for the Principal Agent
//! Protocol (PAP) that exploits the capabilities of NVIDIA BlueField Data
//! Processing Units (DPUs):
//!
//! * **Ultra-low latency** — RDMA RC queue pairs bypass the host OS network
//!   stack entirely, cutting agent-to-agent round-trip times to ≈ 2 µs on a
//!   single BlueField 3 card (vs. ≈ 100 µs for localhost HTTP).
//!
//! * **Hardware crypto** (`doca` feature) — Ed25519 signing and AES-GCM
//!   encryption are offloaded to the BlueField's on-chip crypto engine,
//!   freeing host CPU cycles for application logic.  The software fallback
//!   (ed25519-dalek) is always present and is the default when `doca` is
//!   absent.
//!
//! * **Kernel bypass** — message delivery never touches the host kernel's
//!   TCP/IP stack; perfect for high-frequency data-centre agent meshes.
//!
//! # Architecture
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────────┐
//! │  Application                                                          │
//! │   BluefieldClient<RdmaConnection>   BluefieldServer<MyAgentHandler>  │
//! └──────────────┬────────────────────────────────┬────────────────────── ┘
//!                │  MessageChannel                │
//! ┌──────────────▼────────────────────────────────▼───────────────────────┐
//! │  RDMA layer (rdma feature)                                            │
//! │   RdmaBootstrapClient          RdmaBootstrapServer                   │
//! │     └─ TCP bootstrap exchange QP metadata ─┘                         │
//! │   RdmaConnection (RC QP in RTS state)                                │
//! │     ├─ RegisteredBuffer (ibv_reg_mr)                                 │
//! │     ├─ QueuePair  (ibv_create_qp + state transitions)               │
//! │     └─ DeviceContext (ibv_open_device + ibv_alloc_pd)               │
//! └───────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Quick start (real hardware)
//!
//! ```ignore
//! // Requires the `rdma` feature (default) and a BlueField card with MLNX_OFED / DOCA.
//! use std::sync::Arc;
//! use pap_bluefield::rdma::{context::DeviceContext, connection::RdmaBootstrapClient};
//! use pap_bluefield::client::BluefieldClient;
//!
//! async fn example() -> Result<(), pap_bluefield::BluefieldError> {
//!     let dev = Arc::new(DeviceContext::open(None, 1, 0)?);
//!     let client = BluefieldClient::connect_rdma("192.168.200.2:7777", dev).await?;
//!     Ok(())
//! }
//! ```
//!
//! # Quick start (mock — no hardware required)
//!
//! ```ignore
//! // See tests in client.rs / server.rs for full end-to-end examples.
//! use pap_bluefield::{BluefieldClient, channel::MockChannel, server::handle_channel};
//! ```
//!
//! # Feature flags
//!
//! | Feature       | What it enables                                             |
//! |---------------|-------------------------------------------------------------|
//! | `rdma`        | Real RDMA transport via `rdma-sys` / libibverbs (default)   |
//! | `doca`        | Hardware Ed25519/AES-GCM via NVIDIA DOCA SDK (opt-in)        |
//! | `mock`        | In-memory [`channel::MockChannel`] (always on in `#[test]`)|

// ── Crate-level lint relaxations ──────────────────────────────────────────────
// ibverbs unsafe wrappers necessarily take raw pointers.
#![cfg_attr(feature = "rdma", allow(clippy::not_unsafe_ptr_arg_deref))]

pub mod channel;
pub mod client;
pub mod crypto;
pub mod error;
pub mod frame;
pub mod server;

#[cfg(feature = "rdma")]
pub mod rdma;

// ── Top-level re-exports ──────────────────────────────────────────────────────

pub use client::BluefieldClient;
pub use error::BluefieldError;
pub use server::handle_channel;

#[cfg(any(feature = "mock", test))]
pub use channel::MockChannel;

#[cfg(feature = "rdma")]
pub use rdma::connection::{RdmaBootstrapClient, RdmaBootstrapServer, RdmaConnection};
