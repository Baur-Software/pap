//! DID document generation, principal keypairs, and ephemeral session keypairs
//! for the Principal Agent Protocol.
//!
//! Implements `did:key` method using Ed25519 as specified in W3C DID Core.

mod document;
mod error;
mod principal;
mod session;

pub use document::DidDocument;
pub use error::DidError;
pub use principal::PrincipalKeypair;
pub use principal::{did_to_public_key_bytes, public_key_to_did};
pub use session::SessionKeypair;
