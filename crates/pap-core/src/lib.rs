//! Core protocol primitives for the Principal Agent Protocol.
//!
//! - `scope` — Schema.org action references, deny-by-default, disclosure sets
//! - `mandate` — hierarchical delegation with chain verification and decay
//! - `session` — capability tokens, session state machine
//! - `receipt` — co-signed transaction receipts (property refs only, no values)
//! - `extensions` — continuity tokens, auto-approval policies (spec section 9)
//! - `error` — protocol error types

pub mod error;
pub mod extensions;
pub mod mandate;
pub mod receipt;
pub mod scope;
pub mod session;

pub use error::PapError;
