use std::collections::HashMap;
use std::sync::RwLock;

use pap_did::PrincipalKeypair;
use pap_federation::FederatedRegistry;
use pap_webauthn::{PrincipalSigner, SoftwareSigner};
use papillion_shared::{DemoRunResult, OrchestratorConfig, SuccessorDesignation};

use crate::inference::ModelManager;
use crate::seed::seed_demo_registry;

pub const DEMO_REGISTRY_URL: &str = "pap://demo";

/// Application state managed by Tauri.
pub struct AppState {
    pub signer: RwLock<Option<Box<dyn PrincipalSigner + Send + Sync>>>,
    /// Raw 32-byte Ed25519 seed for signing and key export.
    pub principal_seed: RwLock<Option<[u8; 32]>>,
    pub registries: RwLock<HashMap<String, FederatedRegistry>>,
    pub bookmarks: RwLock<Vec<String>>,
    pub orchestrator_config: RwLock<OrchestratorConfig>,
    /// On-device Candle model for the BuiltIn LLM provider.
    pub model_manager: tokio::sync::Mutex<ModelManager>,
    /// Demo agent keypairs retained for simulating both sides of the handshake.
    pub demo_agent_keypairs: RwLock<HashMap<String, PrincipalKeypair>>,
    /// Completed demo run results for the activity feed.
    pub completed_runs: RwLock<Vec<DemoRunResult>>,
    /// Whether the principal key has been exported/backed up.
    pub key_backed_up: RwLock<bool>,
    /// Forward-looking successor designations.
    pub successor_designations: RwLock<Vec<SuccessorDesignation>>,
}

impl Default for AppState {
    fn default() -> Self {
        let mut registries = HashMap::new();
        let (registry, agent_keypairs) = seed_demo_registry();
        registries.insert(DEMO_REGISTRY_URL.to_string(), registry);

        // Auto-generate identity on startup
        let keypair = PrincipalKeypair::generate();
        let raw_seed = keypair.signing_key().to_bytes();
        let signer = SoftwareSigner::from_keypair(keypair);

        Self {
            signer: RwLock::new(Some(Box::new(signer))),
            principal_seed: RwLock::new(Some(raw_seed)),
            registries: RwLock::new(registries),
            bookmarks: RwLock::new(vec![DEMO_REGISTRY_URL.to_string()]),
            orchestrator_config: RwLock::new(OrchestratorConfig::default()),
            model_manager: tokio::sync::Mutex::new(ModelManager::new()),
            demo_agent_keypairs: RwLock::new(agent_keypairs),
            completed_runs: RwLock::new(Vec::new()),
            key_backed_up: RwLock::new(false),
            successor_designations: RwLock::new(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_registry_url_is_pap_demo() {
        assert_eq!(DEMO_REGISTRY_URL, "pap://demo");
    }

    #[test]
    fn default_state_has_identity() {
        let state = AppState::default();
        let signer = state.signer.read().unwrap();
        assert!(signer.is_some());
    }

    #[test]
    fn default_state_has_seed() {
        let state = AppState::default();
        let seed = state.principal_seed.read().unwrap();
        assert!(seed.is_some());
        assert_eq!(seed.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn default_state_has_demo_registry() {
        let state = AppState::default();
        let registries = state.registries.read().unwrap();
        assert!(registries.contains_key(DEMO_REGISTRY_URL));
    }

    #[test]
    fn default_state_demo_registry_has_agents() {
        let state = AppState::default();
        let registries = state.registries.read().unwrap();
        let demo = registries.get(DEMO_REGISTRY_URL).unwrap();
        assert_eq!(demo.len(), 5);
    }

    #[test]
    fn default_state_has_demo_bookmark() {
        let state = AppState::default();
        let bookmarks = state.bookmarks.read().unwrap();
        assert_eq!(bookmarks.len(), 1);
        assert_eq!(bookmarks[0], DEMO_REGISTRY_URL);
    }

    #[test]
    fn default_state_orchestrator_config_is_builtin() {
        let state = AppState::default();
        let config = state.orchestrator_config.read().unwrap();
        assert!(matches!(config.llm_provider, papillion_shared::LlmProvider::BuiltIn { .. }));
    }

    #[test]
    fn default_state_has_agent_keypairs() {
        let state = AppState::default();
        let keypairs = state.demo_agent_keypairs.read().unwrap();
        assert_eq!(keypairs.len(), 5);
    }

    #[test]
    fn default_state_no_completed_runs() {
        let state = AppState::default();
        let runs = state.completed_runs.read().unwrap();
        assert!(runs.is_empty());
    }

    #[test]
    fn default_state_key_not_backed_up() {
        let state = AppState::default();
        let backed_up = state.key_backed_up.read().unwrap();
        assert!(!*backed_up);
    }

    #[test]
    fn default_state_no_successors() {
        let state = AppState::default();
        let successors = state.successor_designations.read().unwrap();
        assert!(successors.is_empty());
    }

    #[test]
    fn default_state_identity_did_starts_with_prefix() {
        let state = AppState::default();
        let signer = state.signer.read().unwrap();
        let did = signer.as_ref().unwrap().did();
        assert!(did.starts_with("did:key:z"), "DID should start with did:key:z, got {did}");
    }
}
