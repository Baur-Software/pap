//! Papillion agent wiring.
//!
//! Standard agents live in `pap-agents` crate (shared with Chrysalis).
//! Only app-specific agents (on-device AI, social discovery, trait beacon)
//! remain here — they need app-level dependencies like ModelManager or
//! FederatedRegistry that don't belong in the shared crate.

pub mod on_device_ai;
pub mod social_discovery;
pub mod trait_beacon;

// Re-export the shared agent crate so existing `crate::agents::*` imports work.
pub use pap_agents::*;
