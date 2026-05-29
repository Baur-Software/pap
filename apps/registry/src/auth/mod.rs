//! Pluggable authentication module for the PAP registry.
//!
//! Provides Bearer token validation and Axum extractors for securing
//! admin endpoints and API routes.

pub mod bearer;
pub mod extractor;

pub use bearer::BearerTokenValidator;
