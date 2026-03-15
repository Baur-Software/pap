//! Agent advertisement schema and marketplace discovery
//! for the Principal Agent Protocol.
//!
//! Marketplace agents publish signed JSON-LD advertisements describing
//! their capabilities using Schema.org types. The registry is local/file-based
//! for the PoC, with federation planned for later.

mod advertisement;
mod error;
mod registry;

pub use advertisement::AgentAdvertisement;
pub use error::MarketplaceError;
pub use registry::MarketplaceRegistry;
