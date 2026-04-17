//! DID document generation, principal keypairs, and ephemeral session keypairs
//! for the Principal Agent Protocol.
//!
//! Implements `did:key` method using Ed25519 as specified in W3C DID Core.
//!
//! # WASM Support
//!
//! Enable the `wasm` feature for browser environments:
//!
//! ```toml
//! pap-did = { path = "...", features = ["wasm"] }
//! ```
//!
//! This activates `getrandom/js` so that `OsRng` routes entropy through
//! `crypto.getRandomValues()` on `wasm32-unknown-unknown` targets.
//!
//! **Security note**: WASM linear memory cannot guarantee zeroization of
//! Ed25519 seed material after use. See `docs/WASM_SECURITY.md` for details
//! and recommended mitigations.

mod algorithm;
mod document;
mod error;
mod principal;
mod session;

pub use algorithm::SignatureAlgorithm;
pub use document::DidDocument;
pub use document::Service;
pub use error::DidError;
pub use principal::PrincipalKeypair;
pub use principal::{
    did_to_public_key_bytes, did_to_public_key_bytes_with_algorithm, public_key_to_did,
    public_key_to_did_for_algorithm, verify_key_from_did,
};
pub use session::SessionKeypair;
