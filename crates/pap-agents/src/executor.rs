//! `AgentExecutor` trait and `AgentMeta` — the simplified agent interface.
//!
//! Instead of implementing all 6 `AgentHandler` phases, agents implement
//! `AgentExecutor` with just `meta()` + `execute(query)`. Wrap in
//! `SimpleAgent::new(executor)` to get the full protocol handler.

use pap_transport::TransportError;

/// Metadata describing an agent's identity, capabilities, and disclosure
/// requirements. Single source of truth — used for advertisement generation,
/// registry seeding, and intent detection.
pub struct AgentMeta {
    pub name: &'static str,
    /// Semantic version (e.g. "1.0.0"). Included in advertisement signature.
    pub version: &'static str,
    pub provider: &'static str,
    pub action: &'static str,
    pub object_types: &'static [&'static str],
    pub requires_disclosure: &'static [&'static str],
    pub returns: &'static [&'static str],
    /// Configurable properties advertised to principals as schema.org
    /// `PropertyValueSpecification` objects. Defaults to empty.
    pub configurable_properties: Vec<serde_json::Value>,
}

/// Simplified trait for standard query-in / JSON-LD-out agents.
///
/// Implement this instead of `AgentHandler` directly. Wrap in
/// `SimpleAgent::new(executor)` to get the full 6-phase handler
/// with session management, disclosure extraction, and receipt co-signing.
pub trait AgentExecutor: Send + Sync {
    /// This agent's metadata — name, action type, disclosure requirements, etc.
    fn meta(&self) -> AgentMeta;

    /// Execute the agent's logic with the extracted query string.
    /// Return Schema.org JSON-LD.
    fn execute(&self, query: &str) -> Result<serde_json::Value, TransportError>;
}
