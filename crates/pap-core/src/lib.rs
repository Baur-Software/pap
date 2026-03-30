//! Core protocol primitives for the Principal Agent Protocol.
//!
//! - `scope` — Schema.org action references, deny-by-default, disclosure sets
//! - `mandate` — hierarchical delegation with chain verification and decay
//! - `session` — capability tokens, session state machine
//! - `receipt` — co-signed transaction receipts (property refs only, no values),
//!   bilateral session attestation, per-action reputation segmentation
//! - `payment` — Lightning/Ecash payment proof commitments (spec section 13.1)
//! - `extensions` — continuity tokens, auto-approval policies (spec section 9)
//! - `recovery` — M-of-N social recovery via designated notaries (spec section 13.5)
//! - `error` — protocol error types

pub mod error;
pub mod extensions;
pub mod mandate;
pub mod payment;
pub mod receipt;
pub mod recovery;
pub mod scope;
pub mod session;

pub use error::PapError;
pub use receipt::{
    AttestationStatus, ReputationProfile, ReputationSegment, SessionAttestation, SessionOutcome,
};

#[cfg(feature = "tee")]
pub use pap_tee;
