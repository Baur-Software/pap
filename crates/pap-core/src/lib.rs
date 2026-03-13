//! Core protocol primitives for the Principal Agent Protocol.
//!
//! - `scope` — Schema.org action references, deny-by-default, disclosure sets
//! - `mandate` — hierarchical delegation with chain verification and decay
//! - `session` — capability tokens, session state machine
//! - `receipt` — co-signed transaction receipts (property refs only, no values)
//! - `error` — protocol error types

pub mod scope;
pub mod mandate;
pub mod session;
pub mod receipt;
pub mod error;

pub use error::PapError;
