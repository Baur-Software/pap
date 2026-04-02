//! Shared PAP agent implementations.
//!
//! This crate provides the `AgentExecutor` trait, `SimpleAgent<E>` wrapper,
//! and all standard agent implementations. Both Papillon and Chrysalis
//! depend on this crate — agents are defined once, used everywhere.
//!
//! # Architecture
//!
//! ```text
//! pap-transport   defines AgentHandler trait (6-phase protocol)
//!       |
//! pap-agents      provides AgentExecutor (2 methods) + SimpleAgent wrapper
//!       |
//! apps/*          use build_agents() to get registry + handlers
//! ```
//!
//! # Adding a new agent
//!
//! 1. Create `src/agents/my_agent.rs` implementing `AgentExecutor`
//! 2. Re-export from `src/agents/mod.rs`
//! 3. Add one line in `registry::build_agents()` — done.

pub mod agents;
pub mod dynamic;
pub mod executor;
pub mod registry;
pub mod session_store;
mod simple;

pub use dynamic::{DynamicAgentDef, DynamicAgentSource, HttpEndpointConfig, HttpMethod, is_safe_url};
pub use executor::{AgentExecutor, AgentMeta};
pub use registry::{build_agents, AgentSet};
pub use simple::SimpleAgent;
