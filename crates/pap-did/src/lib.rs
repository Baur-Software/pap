//! DID document generation, principal keypairs, and ephemeral session keypairs
//! for the Principal Agent Protocol.
//!
//! Implements `did:key` method using Ed25519 as specified in W3C DID Core.

mod principal;
mod session;
mod document;
mod error;

pub use principal::PrincipalKeypair;
pub use principal::{public_key_to_did, did_to_public_key_bytes};
pub use session::SessionKeypair;
pub use document::DidDocument;
pub use error::DidError;
