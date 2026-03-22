use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use base64::Engine;
use pap_did::PrincipalKeypair;
use pap_federation::FederatedRegistry;
use pap_transport::{AgentHandler, EndpointRegistry};
use pap_webauthn::{PrincipalSigner, SoftwareSigner};
use papillion_shared::{OrchestratorConfig, SuccessorDesignation};

use crate::agents::{DuckDuckGoAgent, OnDeviceAiAgent, WikipediaAgent};
use crate::db::Database;
use crate::inference::ModelManager;
use crate::seed::seed_registry;

pub const LOCAL_REGISTRY_URL: &str = "pap://local";

/// Default port for the federation + agent TLS server.
pub const DEFAULT_FEDERATION_PORT: u16 = 7890;

/// Atomic identity state: signer and raw seed stored together to prevent
/// intermediate states where they diverge.
pub struct IdentityState {
    pub signer: Option<Box<dyn PrincipalSigner + Send + Sync>>,
    pub principal_seed: Option<[u8; 32]>,
}

/// Application state managed by Tauri.
pub struct AppState {
    /// Atomic identity state (signer + seed) — protects against intermediate states
    /// where one is updated but not the other.
    pub identity: RwLock<IdentityState>,
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
    /// Persistent SQLite database for experience memory.
    /// Stores episodes, agent profiles, and retention policies.
    pub db: Arc<Database>,
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
    /// Create AppState with a persistent database at the given path.
    pub fn new(db_path: &std::path::Path) -> Self {
        let db = Database::open(db_path).expect("failed to open experience memory database");
        Self::with_db(Arc::new(db))
    }

    /// Create a clone suitable for moving to a background thread.
    /// This wraps all the Arc/RwLock fields which are already thread-safe and shareable.
    pub fn clone_for_background(&self) -> Self {
        let current_identity = self.identity.read().unwrap();
        Self {
            identity: RwLock::new(IdentityState {
                signer: None, // Signer will be recreated from seed in background thread
                principal_seed: current_identity.principal_seed,
            }),
            registries: RwLock::new(HashMap::new()), // Will be populated on demand
            local_registry: self.local_registry.clone(),
            bookmarks: RwLock::new(self.bookmarks.read().unwrap().clone()),
            orchestrator_config: RwLock::new(self.orchestrator_config.read().unwrap().clone()),
            model_manager: self.model_manager.clone(),
            agent_keypairs: RwLock::new(HashMap::new()), // Will be populated on demand
            db: self.db.clone(),
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

    fn with_db(db: Arc<Database>) -> Self {
        let (registry, agent_keypairs) = seed_registry();
        let local_registry = Arc::new(Mutex::new(registry));

        // Try to load persisted seed; generate a new one if none exists
        let (raw_seed, keypair) = match db.get_setting("principal_seed_b64").ok().flatten() {
            Some(seed_b64) => {
                if let Ok(bytes) =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&seed_b64)
                {
                    if let Ok(seed) = <[u8; 32]>::try_from(bytes.as_slice()) {
                        if let Ok(kp) = PrincipalKeypair::from_bytes(&seed) {
                            (seed, kp)
                        } else {
                            let kp = PrincipalKeypair::generate();
                            (kp.signing_key().to_bytes(), kp)
                        }
                    } else {
                        let kp = PrincipalKeypair::generate();
                        (kp.signing_key().to_bytes(), kp)
                    }
                } else {
                    let kp = PrincipalKeypair::generate();
                    (kp.signing_key().to_bytes(), kp)
                }
            }
            None => {
                let kp = PrincipalKeypair::generate();
                let seed = kp.signing_key().to_bytes();
                // Persist the newly generated seed
                let seed_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed);
                if let Err(e) = db.set_setting("principal_seed_b64", &seed_b64) {
                    eprintln!("Failed to persist principal seed: {e}");
                }
                (seed, kp)
            }
        };
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
            identity: RwLock::new(IdentityState {
                signer: Some(Box::new(signer)),
                principal_seed: Some(raw_seed),
            }),
            registries: RwLock::new(HashMap::new()),
            local_registry,
            bookmarks: RwLock::new(vec![LOCAL_REGISTRY_URL.to_string()]),
            orchestrator_config: RwLock::new(OrchestratorConfig::default()),
            model_manager,
            agent_keypairs: RwLock::new(agent_keypairs),
            db,
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

impl Default for AppState {
    fn default() -> Self {
        // Fallback: use a temp database (data lost on restart).
        // In production, lib.rs uses AppState::new() with app_data_dir.
        let db =
            Database::open(&PathBuf::from("papillion.db")).expect("failed to open fallback db");
        Self::with_db(Arc::new(db))
    }
}
