use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use pap_did::PrincipalKeypair;
use pap_federation::FederatedRegistry;
use pap_transport::{AgentHandler, EndpointRegistry};
use pap_webauthn::{PrincipalSigner, SoftwareSigner};
use papillion_shared::{OrchestratorConfig, ScenarioRunResult, SuccessorDesignation};

use crate::agents::{DuckDuckGoAgent, OnDeviceAiAgent, WikipediaAgent};
use crate::inference::ModelManager;
use crate::seed::seed_registry;

pub const LOCAL_REGISTRY_URL: &str = "pap://local";

/// Default port for the federation + agent TLS server.
pub const DEFAULT_FEDERATION_PORT: u16 = 7890;

/// Application state managed by Tauri.
pub struct AppState {
    pub signer: RwLock<Option<Box<dyn PrincipalSigner + Send + Sync>>>,
    /// Raw 32-byte Ed25519 seed for signing and key export.
    pub principal_seed: RwLock<Option<[u8; 32]>>,
    /// Remote registry caches keyed by URL.
    pub registries: RwLock<HashMap<String, FederatedRegistry>>,
    /// The node's own registry — shared with the federation HTTP server.
    /// This is the single source of truth for locally registered agents.
    pub local_registry: Arc<Mutex<FederatedRegistry>>,
    pub bookmarks: RwLock<Vec<String>>,
    pub orchestrator_config: RwLock<OrchestratorConfig>,
    /// On-device Candle model for the BuiltIn LLM provider.
    pub model_manager: Arc<tokio::sync::Mutex<ModelManager>>,
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
    /// Local agent handlers keyed by agent name.
    /// These implement `AgentHandler` and process the 6-phase handshake.
    pub local_agents: HashMap<String, Arc<dyn AgentHandler>>,
    /// DID → transport endpoint mapping for agent resolution.
    pub endpoint_registry: RwLock<EndpointRegistry>,
    /// Port the TLS federation+agent server listens on.
    pub federation_port: u16,
    /// The node's TLS-secured endpoint, e.g. `https://0.0.0.0:7890`.
    /// Set after the server starts.
    pub node_endpoint: RwLock<String>,
    /// SHA-256 hex fingerprint of this node's TLS certificate.
    /// Peers pin this to verify our identity — no CA trust chain.
    pub node_cert_fingerprint: RwLock<String>,
}

impl AppState {
    /// Create a clone suitable for moving to a background thread.
    /// This wraps all the Arc/RwLock fields which are already thread-safe and shareable.
    pub fn clone_for_background(&self) -> Self {
        Self {
            signer: RwLock::new(None), // Signer will be recreated from seed in background thread
            principal_seed: RwLock::new(*self.principal_seed.read().unwrap()),
            registries: RwLock::new(HashMap::new()), // Will be populated on demand
            local_registry: self.local_registry.clone(),
            bookmarks: RwLock::new(self.bookmarks.read().unwrap().clone()),
            orchestrator_config: RwLock::new(self.orchestrator_config.read().unwrap().clone()),
            model_manager: self.model_manager.clone(),
            agent_keypairs: RwLock::new(HashMap::new()), // Will be populated on demand
            completed_runs: RwLock::new(self.completed_runs.read().unwrap().clone()),
            key_backed_up: RwLock::new(*self.key_backed_up.read().unwrap()),
            successor_designations: RwLock::new(
                self.successor_designations.read().unwrap().clone(),
            ),
            resource_dir: RwLock::new(self.resource_dir.read().unwrap().clone()),
            local_agents: self.local_agents.clone(),
            endpoint_registry: RwLock::new(EndpointRegistry::new()),
            federation_port: self.federation_port,
            node_endpoint: RwLock::new(self.node_endpoint.read().unwrap().clone()),
            node_cert_fingerprint: RwLock::new(self.node_cert_fingerprint.read().unwrap().clone()),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        let (registry, agent_keypairs) = seed_registry();
        let local_registry = Arc::new(Mutex::new(registry));

        // Auto-generate identity on startup
        let keypair = PrincipalKeypair::generate();
        let raw_seed = keypair.signing_key().to_bytes();
        let signer = SoftwareSigner::from_keypair(keypair);

        let model_manager = Arc::new(tokio::sync::Mutex::new(ModelManager::new()));

        // Spawn local agents — these are real AgentHandler implementations
        let mut local_agents: HashMap<String, Arc<dyn AgentHandler>> = HashMap::new();
        local_agents.insert("DuckDuckGo Search".into(), Arc::new(DuckDuckGoAgent::new()));
        local_agents.insert(
            "Wikipedia Knowledge".into(),
            Arc::new(WikipediaAgent::new()),
        );
        local_agents.insert(
            "On-Device AI".into(),
            Arc::new(OnDeviceAiAgent::new(model_manager.clone())),
        );

        Self {
            signer: RwLock::new(Some(Box::new(signer))),
            principal_seed: RwLock::new(Some(raw_seed)),
            registries: RwLock::new(HashMap::new()),
            local_registry,
            bookmarks: RwLock::new(vec![LOCAL_REGISTRY_URL.to_string()]),
            orchestrator_config: RwLock::new(OrchestratorConfig::default()),
            model_manager,
            agent_keypairs: RwLock::new(agent_keypairs),
            completed_runs: RwLock::new(Vec::new()),
            key_backed_up: RwLock::new(false),
            successor_designations: RwLock::new(Vec::new()),
            resource_dir: RwLock::new(PathBuf::new()),
            local_agents,
            endpoint_registry: RwLock::new(EndpointRegistry::new()),
            federation_port: DEFAULT_FEDERATION_PORT,
            node_endpoint: RwLock::new(String::new()),
            node_cert_fingerprint: RwLock::new(String::new()),
        }
    }
}
