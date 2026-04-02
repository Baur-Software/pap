//! Unified agent registration — single source of truth.
//!
//! `build_agents()` creates signed advertisements, generates keypairs,
//! and wraps executors into handlers — all from each executor's `AgentMeta`.
//! No more 3-file string matching.

use std::collections::HashMap;
use std::sync::Arc;

use pap_did::PrincipalKeypair;
use pap_federation::FederatedRegistry;
use pap_marketplace::AgentAdvertisement;
use pap_transport::AgentHandler;

use crate::agents::web_reader::WebReaderExecutor;
use crate::executor::{AgentExecutor, AgentMeta};
use crate::simple::SimpleAgent;

/// Result of building the agent registry.
pub struct AgentSet {
    /// Federation registry with all agents registered.
    pub registry: FederatedRegistry,
    /// Agent keypairs for handshake co-signing (keyed by agent name).
    pub keypairs: HashMap<String, PrincipalKeypair>,
    /// Agent handlers for local execution (keyed by agent name).
    pub handlers: HashMap<String, Arc<dyn AgentHandler>>,
}

/// Build the standard set of PAP agents.
///
/// Each executor provides its own metadata — no separate seed file needed.
/// Returns everything an app needs: registry, keypairs, and handlers.
///
/// Pass additional executors via `extra` to extend beyond the defaults
/// (e.g., on-device AI which requires app-specific dependencies).
pub fn build_agents(extra: Vec<(&'static str, Arc<dyn AgentHandler>, AgentMeta)>) -> AgentSet {
    let mut registry = FederatedRegistry::new();
    let mut keypairs = HashMap::new();
    let mut handlers: HashMap<String, Arc<dyn AgentHandler>> = HashMap::new();

    // Only compiled agent: HTML parsing requires custom Rust (not expressible as TOML).
    register_executor(
        WebReaderExecutor,
        &mut registry,
        &mut keypairs,
        &mut handlers,
    );

    // Register extra agents (e.g., on-device AI, app-specific agents)
    for (name, handler, meta) in extra {
        register_handler(
            name,
            handler,
            meta,
            &mut registry,
            &mut keypairs,
            &mut handlers,
        );
    }

    AgentSet {
        registry,
        keypairs,
        handlers,
    }
}

/// Register an `AgentExecutor` — creates signed ad, wraps in SimpleAgent, stores everything.
fn register_executor<E: AgentExecutor + 'static>(
    executor: E,
    registry: &mut FederatedRegistry,
    keypairs: &mut HashMap<String, PrincipalKeypair>,
    handlers: &mut HashMap<String, Arc<dyn AgentHandler>>,
) {
    let meta = executor.meta();
    let name = meta.name.to_string();

    let kp = PrincipalKeypair::generate();
    let did = kp.did();

    let mut ad = AgentAdvertisement::new(
        meta.name,
        meta.provider,
        &did,
        meta.capability_vec(),
        meta.object_types_vec(),
        meta.requires_disclosure_vec(),
        meta.returns_vec(),
    );
    ad.sign(kp.signing_key());
    registry
        .register_local(ad)
        .expect("agent registration should not fail");

    handlers.insert(name.clone(), Arc::new(SimpleAgent::new(executor)));
    keypairs.insert(name, kp);
}

/// Register a pre-built `AgentHandler` with explicit metadata.
/// Used for agents that can't use `SimpleAgent` (e.g., on-device AI).
fn register_handler(
    name: &str,
    handler: Arc<dyn AgentHandler>,
    meta: AgentMeta,
    registry: &mut FederatedRegistry,
    keypairs: &mut HashMap<String, PrincipalKeypair>,
    handlers: &mut HashMap<String, Arc<dyn AgentHandler>>,
) {
    let kp = PrincipalKeypair::generate();
    let did = kp.did();

    let mut ad = AgentAdvertisement::new(
        meta.name,
        meta.provider,
        &did,
        meta.capability_vec(),
        meta.object_types_vec(),
        meta.requires_disclosure_vec(),
        meta.returns_vec(),
    );
    ad.sign(kp.signing_key());
    registry
        .register_local(ad)
        .expect("agent registration should not fail");

    handlers.insert(name.to_string(), handler);
    keypairs.insert(name.to_string(), kp);
}

// ── AgentMeta helpers for creating Vec<String> from static slices ──

impl AgentMeta {
    pub fn capability_vec(&self) -> Vec<String> {
        vec![self.action.to_string()]
    }

    pub fn object_types_vec(&self) -> Vec<String> {
        self.object_types.iter().map(|s| s.to_string()).collect()
    }

    pub fn requires_disclosure_vec(&self) -> Vec<String> {
        self.requires_disclosure
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    pub fn returns_vec(&self) -> Vec<String> {
        self.returns.iter().map(|s| s.to_string()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_agents_registers_all_standard() {
        let set = build_agents(vec![]);
        assert_eq!(set.handlers.len(), 1);
        assert_eq!(set.keypairs.len(), 1);
        assert!(set.handlers.contains_key("Web Page Reader"));
    }

    #[test]
    fn names_match_between_handlers_and_keypairs() {
        let set = build_agents(vec![]);
        for name in set.handlers.keys() {
            assert!(
                set.keypairs.contains_key(name),
                "Handler '{}' has no matching keypair",
                name
            );
        }
    }

    #[test]
    fn all_advertisements_are_signed() {
        let set = build_agents(vec![]);
        for ad in set.registry.all_advertisements() {
            assert!(
                ad.signature.is_some(),
                "Agent '{}' has empty signature",
                ad.name
            );
            assert!(
                ad.signed_by.starts_with("did:key:"),
                "Agent '{}' signed_by is not a valid DID: {}",
                ad.name,
                ad.signed_by
            );
        }
    }

    #[test]
    fn all_advertisements_have_valid_schema_org_actions() {
        let set = build_agents(vec![]);
        for ad in set.registry.all_advertisements() {
            assert!(
                !ad.capability.is_empty(),
                "Agent '{}' has no capabilities",
                ad.name
            );
            for cap in &ad.capability {
                assert!(
                    cap.starts_with("schema:"),
                    "Agent '{}' capability '{}' is not a Schema.org action",
                    ad.name,
                    cap
                );
            }
        }
    }

    #[test]
    fn advertisements_match_handler_count() {
        let set = build_agents(vec![]);
        assert_eq!(
            set.registry.all_advertisements().len(),
            set.handlers.len(),
            "Advertisement count doesn't match handler count"
        );
    }

    #[test]
    fn advertisements_are_re_registrable_in_fresh_registry() {
        // This tests the seeding pattern used by the registry app:
        // build_agents() → iterate advertisements → register in new registry
        let set = build_agents(vec![]);
        let ads = set.registry.all_advertisements().to_vec();

        let mut fresh_registry = FederatedRegistry::new();
        for ad in &ads {
            fresh_registry
                .register_local(ad.clone())
                .unwrap_or_else(|e| panic!("Failed to re-register '{}': {e}", ad.name));
        }

        assert_eq!(
            fresh_registry.all_advertisements().len(),
            ads.len(),
            "Re-registered registry should have same agent count"
        );
    }

}
