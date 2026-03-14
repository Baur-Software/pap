//! W3C Verifiable Credential envelope and SD-JWT selective disclosure
//! for the Principal Agent Protocol.
//!
//! References:
//! - W3C VC Data Model 2.0: https://www.w3.org/TR/vc-data-model-2.0/
//! - SD-JWT: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-08.txt

mod credential;
mod error;
mod sd_jwt;

pub use credential::VerifiableCredential;
pub use sd_jwt::SelectiveDisclosureJwt;
pub use sd_jwt::Disclosure;
pub use error::CredentialError;
