//! Optional TEE attestation extension for the Principal Agent Protocol.
//!
//! Implements spec section 13.6: TEE Attestation. A mandate or session
//! MAY carry attestation evidence proving an agent executes within an
//! isolated enclave. This crate provides:
//!
//! - [`AttestationEvidence`] — RATS-compliant attestation object (RFC 9334)
//! - [`EnclaveType`] — TEE platform identifiers (SGX, SEV-SNP, TrustZone, Software)
//! - [`AttestationVerifier`] — trait for platform-specific report verification
//! - [`SoftwareSimulator`] — software-simulated attestation for testing
//!
//! # Trust Boundaries (spec section 13.6.3)
//!
//! TEE attestation provides evidence of code integrity, not behavioral
//! correctness. Specifically:
//!
//! - A TEE attestation MUST NOT be treated as equivalent to a mandate.
//!   An agent in a TEE still requires a valid mandate chain.
//! - A TEE attestation MUST NOT be used to expand scope beyond what
//!   the mandate permits.
//! - The principal MAY use TEE attestation as an input to auto-approval
//!   policies but MUST NOT be required to accept TEE attestation as a
//!   substitute for consent.

pub mod attestation;
pub mod error;
pub mod simulator;
pub mod verifier;

pub use attestation::{AttestationEvidence, EnclaveType};
pub use error::TeeError;
pub use simulator::SoftwareSimulator;
pub use verifier::{verify_common, AttestationVerifier, MAX_ATTESTATION_AGE_SECS};
