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
pub mod catalog;
pub mod dynamic;
pub mod dynamic_handler;
pub mod executor;
pub mod llm;
pub mod registry;
pub mod session_store;
mod simple;

pub use catalog::load_catalog;
pub use dynamic::{DynamicAgentDef, DynamicAgentSource, HttpEndpointConfig, HttpMethod, is_safe_url};
pub use dynamic_handler::DynamicAgentHandler;
pub use executor::{AgentExecutor, AgentMeta};
pub use llm::{builtin_model_catalog, BuiltInModelInfo, LlmProvider, ModelAvailability, ModelDownloadProgress};
pub use registry::{build_agents, AgentSet};
pub use simple::SimpleAgent;
