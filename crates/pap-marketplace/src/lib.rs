//! Agent advertisement schema and marketplace discovery
//! for the Principal Agent Protocol.
//!
//! Marketplace agents publish signed JSON-LD advertisements describing
//! their capabilities using Schema.org types. The registry is local/file-based
//! for the PoC, with federation planned for later.

mod advertisement;
mod registry;
mod error;

pub use advertisement::AgentAdvertisement;
pub use registry::MarketplaceRegistry;
pub use error::MarketplaceError;
