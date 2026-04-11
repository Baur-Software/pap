//! RDMA transport primitives for the BlueField DPU.
//!
//! This module wraps the raw `rdma-sys` ibverbs API with safe, idiomatic Rust
//! types.  The public surface is intentionally minimal:
//!
//! * [`context::DeviceContext`] — opens a BlueField device and allocates a
//!   protection domain.
//! * [`memory::RegisteredBuffer`] — heap-allocated, ibverbs-registered DMA
//!   buffer.  Pinned for its lifetime; must not move.
//! * [`qp::QueuePair`] — an RC (Reliable Connected) queue pair with dedicated
//!   send and receive completion queues.
//! * [`connection::RdmaConnection`] — a fully connected (RTS) queue pair plus
//!   the framing layer.  Implements [`crate::channel::MessageChannel`].
//!
//! ## Bootstrap
//!
//! Before RDMA data can flow, both sides must exchange Queue Pair metadata
//! (QPN, LID, GID, PSN) and transition their QPs through INIT → RTR → RTS.
//! [`connection::RdmaBootstrapServer`] and [`connection::RdmaBootstrapClient`]
//! handle this over a short-lived TCP connection.

pub mod connection;
pub mod context;
pub mod memory;
pub mod qp;
