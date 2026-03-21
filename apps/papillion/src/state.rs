use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use pap_did::PrincipalKeypair;
use pap_federation::FederatedRegistry;
use pap_webauthn::{PrincipalSigner, SoftwareSigner};
use papillion_shared::{ScenarioRunResult, OrchestratorConfig, SuccessorDesignation};

use crate::inference::ModelManager;
use crate::seed::seed_registry;

pub const LOCAL_REGISTRY_URL: &str = "pap://local";

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
    /// Agent keypairs retained for both sides of the PAP handshake.
    pub agent_keypairs: RwLock<HashMap<String, PrincipalKeypair>>,
    /// Completed run results for the activity feed.
    pub completed_runs: RwLock<Vec<ScenarioRunResult>>,
    /// Whether the principal key has been exported/backed up.
    pub key_backed_up: RwLock<bool>,
    /// Forward-looking successor designations.
    pub successor_designations: RwLock<Vec<SuccessorDesignation>>,
    /// Tauri resource directory (set during app setup).
    /// Bundled model files live under `{resource_dir}/models/`.
    pub resource_dir: RwLock<PathBuf>,
}

impl Default for AppState {
    fn default() -> Self {
        let mut registries = HashMap::new();
        let (registry, agent_keypairs) = seed_registry();
        registries.insert(LOCAL_REGISTRY_URL.to_string(), registry);

        // Auto-generate identity on startup
        let keypair = PrincipalKeypair::generate();
        let raw_seed = keypair.signing_key().to_bytes();
        let signer = SoftwareSigner::from_keypair(keypair);

        Self {
            signer: RwLock::new(Some(Box::new(signer))),
            principal_seed: RwLock::new(Some(raw_seed)),
            registries: RwLock::new(registries),
            bookmarks: RwLock::new(vec![LOCAL_REGISTRY_URL.to_string()]),
            orchestrator_config: RwLock::new(OrchestratorConfig::default()),
            model_manager: tokio::sync::Mutex::new(ModelManager::new()),
            agent_keypairs: RwLock::new(agent_keypairs),
            completed_runs: RwLock::new(Vec::new()),
            key_backed_up: RwLock::new(false),
            successor_designations: RwLock::new(Vec::new()),
            resource_dir: RwLock::new(PathBuf::new()),
        }
    }
}
