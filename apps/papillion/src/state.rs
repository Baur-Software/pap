use std::collections::HashMap;
use std::sync::RwLock;

use pap_did::PrincipalKeypair;
use pap_federation::FederatedRegistry;
use pap_webauthn::{PrincipalSigner, SoftwareSigner};
use papillion_shared::{DemoRunResult, OrchestratorConfig, SuccessorDesignation};

use crate::inference::ModelManager;

#[cfg(any(test, feature = "demo"))]
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
    #[cfg(any(test, feature = "demo"))]
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
        // Auto-generate identity on startup
        let keypair = PrincipalKeypair::generate();
        let raw_seed = keypair.signing_key().to_bytes();
        let signer = SoftwareSigner::from_keypair(keypair);

        #[cfg(any(test, feature = "demo"))]
        let (registries, bookmarks, demo_agent_keypairs) = {
            use crate::seed::seed_demo_registry;
            let mut regs = HashMap::new();
            let (registry, agent_keypairs) = seed_demo_registry();
            regs.insert(DEMO_REGISTRY_URL.to_string(), registry);
            (
                regs,
                vec![DEMO_REGISTRY_URL.to_string()],
                agent_keypairs,
            )
        };

        #[cfg(not(any(test, feature = "demo")))]
        let (registries, bookmarks) = (HashMap::new(), Vec::new());

        Self {
            signer: RwLock::new(Some(Box::new(signer))),
            principal_seed: RwLock::new(Some(raw_seed)),
            registries: RwLock::new(registries),
            bookmarks: RwLock::new(bookmarks),
            orchestrator_config: RwLock::new(OrchestratorConfig::default()),
            model_manager: tokio::sync::Mutex::new(ModelManager::new()),
            #[cfg(any(test, feature = "demo"))]
            demo_agent_keypairs: RwLock::new(demo_agent_keypairs),
            completed_runs: RwLock::new(Vec::new()),
            key_backed_up: RwLock::new(false),
            successor_designations: RwLock::new(Vec::new()),
        }
    }
}
