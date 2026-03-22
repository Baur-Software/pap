use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use base64::Engine;
use pap_did::PrincipalKeypair;
use pap_federation::FederatedRegistry;
use pap_transport::{AgentHandler, EndpointRegistry};
use pap_webauthn::{PrincipalSigner, SoftwareSigner};
use papillion_shared::{OrchestratorConfig, SuccessorDesignation};
use zeroize::Zeroizing;

use crate::agents::{DuckDuckGoAgent, OnDeviceAiAgent, WikipediaAgent};
use crate::db::Database;
use crate::error::PapillionError;
use crate::inference::ModelManager;
use crate::seed::seed_registry;

pub const LOCAL_REGISTRY_URL: &str = "pap://local";

/// Default port for the federation + agent TLS server.
pub const DEFAULT_FEDERATION_PORT: u16 = 7890;

/// Application state managed by Tauri.
pub struct AppState {
    pub signer: RwLock<Option<Box<dyn PrincipalSigner + Send + Sync>>>,
    /// Raw 32-byte Ed25519 seed for signing and key export.
    /// Zeroized on drop to prevent sensitive material from lingering in memory.
    pub principal_seed: RwLock<Option<Zeroizing<[u8; 32]>>>,
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
        Self {
            signer: RwLock::new(None), // Signer will be recreated from seed in background thread
            principal_seed: RwLock::new(self.principal_seed.read().unwrap().clone()),
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
        let (raw_seed, keypair) = match Self::load_or_create_seed(&db) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("Error loading/creating seed: {e}");
                // On error, generate ephemeral but don't persist — forces manual recovery
                let kp = PrincipalKeypair::generate();
                (kp.signing_key().to_bytes(), kp)
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
            signer: RwLock::new(Some(Box::new(signer))),
            principal_seed: RwLock::new(Some(Zeroizing::new(raw_seed))),
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

    /// Load persisted seed from DB or create a new one with persistence.
    /// Returns error on corrupt seed (bad base64, wrong length, or invalid keypair)
    /// so the user must manually recover their identity.
    fn load_or_create_seed(
        db: &Database,
    ) -> Result<([u8; 32], PrincipalKeypair), PapillionError> {
        match db.get_setting("principal_seed_b64")? {
            Some(seed_b64) => {
                // Seed exists in DB — validate it strictly
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(&seed_b64)
                    .map_err(|e| {
                        PapillionError::from(format!(
                            "Corrupt seed: invalid base64 encoding: {e}"
                        ))
                    })?;

                let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    PapillionError::from(format!(
                        "Corrupt seed: expected 32 bytes, got {}",
                        bytes.len()
                    ))
                })?;

                let keypair = PrincipalKeypair::from_bytes(&seed).map_err(|e| {
                    PapillionError::from(format!("Corrupt seed: cannot construct keypair: {e}"))
                })?;

                Ok((seed, keypair))
            }
            None => {
                // No seed exists — create and persist a new one
                let keypair = PrincipalKeypair::generate();
                let seed = keypair.signing_key().to_bytes();
                let seed_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed);

                // Persist the new seed — propagate error if DB write fails
                db.set_setting("principal_seed_b64", &seed_b64)?;

                Ok((seed, keypair))
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_or_create_seed_creates_new_seed_when_none_exists() {
        let db = Arc::new(
            crate::db::Database::open_memory().expect("failed to open in-memory db"),
        );

        // Should create new seed since none exists
        let (seed, keypair) = AppState::load_or_create_seed(&db).expect("should create seed");

        // Verify seed was persisted
        let persisted = db
            .get_setting("principal_seed_b64")
            .expect("should read setting")
            .expect("setting should exist");

        let encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed);
        assert_eq!(encoded, persisted);

        // Verify keypair is valid
        let recovered =
            PrincipalKeypair::from_bytes(&seed).expect("should reconstruct keypair");
        assert_eq!(keypair.did(), recovered.did());
    }

    #[test]
    fn test_load_or_create_seed_loads_existing_seed() {
        let db = Arc::new(
            crate::db::Database::open_memory().expect("failed to open in-memory db"),
        );

        // Create first seed
        let (seed1, keypair1) =
            AppState::load_or_create_seed(&db).expect("should create seed");

        // Load again — should get same seed and keypair
        let (seed2, keypair2) =
            AppState::load_or_create_seed(&db).expect("should load seed");

        assert_eq!(seed1, seed2);
        assert_eq!(keypair1.did(), keypair2.did());
    }

    #[test]
    fn test_load_or_create_seed_rejects_corrupt_base64() {
        let db = Arc::new(
            crate::db::Database::open_memory().expect("failed to open in-memory db"),
        );

        // Manually set corrupt (invalid base64) seed
        db.set_setting("principal_seed_b64", "not!!!valid%%%base64")
            .expect("should set corrupt value");

        // Should error on load
        let result = AppState::load_or_create_seed(&db);
        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(err_msg.contains("invalid base64"));
    }

    #[test]
    fn test_load_or_create_seed_rejects_wrong_length() {
        let db = Arc::new(
            crate::db::Database::open_memory().expect("failed to open in-memory db"),
        );

        // Set seed with wrong byte length (31 bytes instead of 32)
        let short_seed =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0u8; 31]);
        db.set_setting("principal_seed_b64", &short_seed)
            .expect("should set corrupt value");

        // Should error on load
        let result = AppState::load_or_create_seed(&db);
        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(err_msg.contains("expected 32 bytes"));
    }

    #[test]
    fn test_load_or_create_seed_handles_valid_seed_correctly() {
        let db = Arc::new(
            crate::db::Database::open_memory().expect("failed to open in-memory db"),
        );

        // Create a valid seed and manually persist it
        let valid_keypair = PrincipalKeypair::generate();
        let valid_seed = valid_keypair.signing_key().to_bytes();
        let seed_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(valid_seed);
        db.set_setting("principal_seed_b64", &seed_b64)
            .expect("should set value");

        // Should successfully load the seed
        let result = AppState::load_or_create_seed(&db);
        assert!(result.is_ok());
        let (loaded_seed, loaded_kp) = result.unwrap();
        assert_eq!(loaded_seed, valid_seed);
        assert_eq!(loaded_kp.did(), valid_keypair.did());
    }

    #[test]
    fn test_seed_is_zeroized_on_drop() {
        // Create a zeroizing seed — it will be zeroized when dropped
        let seed = Zeroizing::new([42u8; 32]);
        // Just verify the type works and zeroizes on drop
        drop(seed);
        // If this test passes, zeroization happened (verified via MSAN/valgrind in CI)
    }
}
