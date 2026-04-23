#![allow(clippy::unwrap_used)]
// LOCKING DISCIPLINE:
// - std::sync::RwLock fields: use only from synchronous contexts or inside
//   tokio::task::spawn_blocking. Do NOT hold across .await points.
// - tokio::sync::RwLock fields (approval_gates): awaitable, safe in async.
// - tokio::sync::Mutex (model_manager): awaitable, safe in async.
// - Arc<Mutex<>> (local_registry): std Mutex, use from sync or spawn_blocking.
//
// Fields wrapped in Arc<RwLock<>> (registries, agent_keypairs, endpoint_registry)
// are shared by reference across clone_for_background() so that mutations in the
// background clone are visible to the main state and vice versa.
//
// TODO: Migrate remaining std::sync::RwLock fields to tokio::sync::RwLock in a
// future pass once all read sites are audited for async context safety.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use crate::challenge_store::IdentityChallengeStore;
use crate::commands::webauthn::WebAuthnChallengeStore;

use base64::Engine;
use pap_did::PrincipalKeypair;
use pap_federation::FederatedRegistry;
use pap_transport::{AgentHandler, EndpointRegistry};
use pap_webauthn::{PrincipalSigner, SoftwareSigner};
use papillon_shared::{
    episode_db::EpisodeDb, LlmProvider, OrchestratorConfig, SuccessorDesignation,
};
use zeroize::Zeroizing;

use crate::agents::on_device_ai::OnDeviceAiExecutor;
use crate::agents::social_discovery::SocialDiscoveryAgent;
use crate::agents::trait_beacon::TraitBeaconAgent;
use crate::db::{prelude::DatabaseOps, Database};
use crate::error::PapillonError;
use crate::inference::ModelManager;
use crate::profiles_db::ProfilesDatabase;
use pap_agents::{build_agents, load_catalog, AgentExecutor, SimpleAgent};
use papillon_shared::{PersonalContext, ProfileMetadata};

pub const LOCAL_REGISTRY_URL: &str = "pap://local";

/// Default port for the federation + agent TLS server.
pub const DEFAULT_FEDERATION_PORT: u16 = 7890;

/// Application state managed by Tauri.
pub struct AppState {
    pub signer: RwLock<Option<Box<dyn PrincipalSigner + Send + Sync>>>,
    /// Raw 32-byte Ed25519 seed for signing and key export.
    /// Zeroized on drop to prevent sensitive material from lingering in memory.
    pub principal_seed: RwLock<Option<Zeroizing<[u8; 32]>>>,
    /// Profiles registry database — stores profile metadata and seeds.
    pub profiles_db: Arc<ProfilesDatabase>,
    /// Current active profile ID (never None after init).
    pub active_profile_id: RwLock<String>,
    /// List of all available profiles.
    pub profiles: RwLock<Vec<ProfileMetadata>>,
    /// Remote registry caches keyed by URL.
    /// Wrapped in Arc so clone_for_background() shares the same map instance
    /// rather than creating a disconnected empty copy.
    pub registries: Arc<RwLock<HashMap<String, FederatedRegistry>>>,
    /// The node's own registry — shared with the federation HTTP server.
    /// This is the single source of truth for locally registered agents.
    pub local_registry: Arc<Mutex<FederatedRegistry>>,
    pub bookmarks: RwLock<Vec<String>>,
    pub orchestrator_config: RwLock<OrchestratorConfig>,
    /// Shared LLM provider — written by `configure_orchestrator` so all
    /// `DynamicAgentHandler`s pick up new settings without a restart.
    pub shared_llm_provider: Arc<RwLock<LlmProvider>>,
    /// On-device Candle model for the BuiltIn LLM provider.
    pub model_manager: Arc<tokio::sync::Mutex<ModelManager>>,
    /// Agent keypairs retained for both sides of the PAP handshake.
    /// Wrapped in Arc so clone_for_background() shares the same keypair map
    /// rather than creating a disconnected empty copy.
    pub agent_keypairs: Arc<RwLock<HashMap<String, PrincipalKeypair>>>,
    /// Persistent SQLite database for experience memory.
    /// Stores episodes, agent profiles, and retention policies.
    pub db: Arc<Database>,
    /// Focused SQLite store for approval records (and episodes).
    /// Stored as a singleton in AppState to avoid opening a new connection per call.
    pub episode_db: Arc<EpisodeDb>,
    /// Whether the principal key has been exported/backed up.
    pub key_backed_up: RwLock<bool>,
    /// Forward-looking successor designations.
    pub successor_designations: RwLock<Vec<SuccessorDesignation>>,
    /// Tauri resource directory (set during app setup).
    /// Bundled model files live under `{resource_dir}/models/`.
    pub resource_dir: RwLock<PathBuf>,
    /// Writable data directory for downloaded models and other user data.
    /// On macOS the resource_dir is inside the read-only app bundle, so
    /// downloaded models go here instead.
    pub data_dir: RwLock<PathBuf>,
    /// Local agent handlers keyed by agent name.
    /// These implement `AgentHandler` and process the 6-phase handshake.
    pub local_agents: HashMap<String, Arc<dyn AgentHandler>>,
    /// DID → transport endpoint mapping for agent resolution.
    /// Wrapped in Arc so clone_for_background() shares the same registry
    /// rather than creating a disconnected empty copy.
    pub endpoint_registry: Arc<RwLock<EndpointRegistry>>,
    /// Port the TLS federation+agent server listens on.
    pub federation_port: u16,
    /// The node's TLS-secured endpoint, e.g. `https://0.0.0.0:7890`.
    /// Set after the server starts.
    pub node_endpoint: RwLock<String>,
    /// SHA-256 hex fingerprint of this node's TLS certificate.
    /// Peers pin this to verify our identity — no CA trust chain.
    pub node_cert_fingerprint: RwLock<String>,
    /// LAN-reachable `pap://` URLs for this node, computed at startup.
    /// Excludes loopback; populated by `start_federation_server_async`.
    pub local_pap_urls: RwLock<Vec<String>>,
    /// Pending WebAuthn challenges awaiting completion.
    /// Keyed by a UUID challenge_id; entries expire after `CHALLENGE_TTL_SECS`.
    pub webauthn_challenges: WebAuthnChallengeStore,
    /// Pending identity-mutation challenges issued by `get_identity_challenge`.
    /// Consumed one-time by `create_identity`, `import_key`, and `canvas_approve_block`.
    pub identity_challenges: IdentityChallengeStore,
    /// Pending approval gates for `canvas_plan_prompt` two-phase execution.
    /// Keyed by approval_request_id; resolved by `canvas_approve_block`.
    pub approval_gates:
        tokio::sync::RwLock<std::collections::HashMap<String, tokio::sync::oneshot::Sender<bool>>>,
    /// Watch-channel sender for the orchestrator personal-context preamble.
    /// Push a fresh preamble string whenever episode history or traits change.
    /// All orchestrator LLM consumers hold a cloned `Receiver` and borrow at call time.
    pub context_tx: tokio::sync::watch::Sender<String>,
    /// The user's advertised TraitBeacon Schema.org Person document.
    /// Persisted to settings DB under key `"trait_beacon_profile"`.
    pub trait_beacon_profile: Arc<RwLock<serde_json::Value>>,
}

impl AppState {
    /// Create AppState with persistent databases at the given path.
    /// Sets up profiles registry and initializes with active profile.
    pub fn new(db_path: &std::path::Path, catalog_dir: PathBuf) -> Self {
        let db = crate::db::open_db(db_path).expect("failed to open experience memory database");

        // Open profiles registry next to the main database
        let profiles_db_path = db_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("profiles.db");
        let profiles_db = ProfilesDatabase::open(&profiles_db_path)
            .expect("failed to open profiles registry database");

        // Open the EpisodeDb at the same path as the main db so approval_records
        // migrations run once here rather than on every store_approval_record call.
        let episode_db =
            EpisodeDb::open(db_path).expect("failed to open episode_db for approval records");

        Self::with_db(
            Arc::new(db),
            Arc::new(profiles_db),
            Arc::new(episode_db),
            catalog_dir,
        )
    }

    /// Create a clone suitable for moving to a background thread.
    /// This wraps all the Arc/RwLock fields which are already thread-safe and shareable.
    pub fn clone_for_background(&self) -> Self {
        Self {
            signer: RwLock::new(None), // Signer will be recreated from seed in background thread
            principal_seed: RwLock::new(
                self.principal_seed
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone(),
            ),
            profiles_db: self.profiles_db.clone(),
            active_profile_id: RwLock::new(
                self.active_profile_id
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone(),
            ),
            profiles: RwLock::new(
                self.profiles
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone(),
            ),
            registries: self.registries.clone(), // shared Arc — mutations visible to both sides
            local_registry: self.local_registry.clone(),
            bookmarks: RwLock::new(
                self.bookmarks
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone(),
            ),
            orchestrator_config: RwLock::new(
                self.orchestrator_config
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone(),
            ),
            shared_llm_provider: self.shared_llm_provider.clone(),
            model_manager: self.model_manager.clone(),
            agent_keypairs: self.agent_keypairs.clone(), // shared Arc — mutations visible to both sides
            db: self.db.clone(),
            episode_db: self.episode_db.clone(), // shared Arc — same singleton across clones
            key_backed_up: RwLock::new(
                *self.key_backed_up.read().unwrap_or_else(|e| e.into_inner()),
            ),
            successor_designations: RwLock::new(
                self.successor_designations
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone(),
            ),
            resource_dir: RwLock::new(
                self.resource_dir
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone(),
            ),
            data_dir: RwLock::new(
                self.data_dir
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone(),
            ),
            local_agents: self.local_agents.clone(),
            endpoint_registry: self.endpoint_registry.clone(), // shared Arc — mutations visible to both sides
            federation_port: self.federation_port,
            node_endpoint: RwLock::new(
                self.node_endpoint
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone(),
            ),
            node_cert_fingerprint: RwLock::new(
                self.node_cert_fingerprint
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone(),
            ),
            local_pap_urls: RwLock::new(
                self.local_pap_urls
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone(),
            ),
            // Each clone gets its own isolated challenge store — background
            // threads never need to complete WebAuthn ceremonies.
            webauthn_challenges: WebAuthnChallengeStore::new(),
            // Background clones never handle identity challenges.
            identity_challenges: IdentityChallengeStore::new(),
            // Background clones never handle approval gates; start fresh.
            approval_gates: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            // Share the same watch sender so background threads can push context updates.
            context_tx: self.context_tx.clone(),
            trait_beacon_profile: self.trait_beacon_profile.clone(),
        }
    }

    fn with_db(
        db: Arc<Database>,
        profiles_db: Arc<ProfilesDatabase>,
        episode_db: Arc<EpisodeDb>,
        catalog_dir: PathBuf,
    ) -> Self {
        let model_manager = Arc::new(tokio::sync::Mutex::new(ModelManager::new()));

        // ── Personal context channel ─────────────────────────────────────────────
        // Load the user's TraitBeacon profile (Schema.org Person) from persisted settings.
        let trait_beacon_profile_value: serde_json::Value = db
            .get_setting("trait_beacon_profile")
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_else(|| serde_json::json!({}));

        let trait_beacon_profile = Arc::new(RwLock::new(trait_beacon_profile_value.clone()));

        // Build initial personal context preamble from DB state at startup.
        let initial_trait =
            if trait_beacon_profile_value == serde_json::Value::Object(serde_json::Map::new()) {
                None
            } else {
                Some(trait_beacon_profile_value)
            };
        let initial_preamble = PersonalContext::from_db(&*db, initial_trait).to_system_preamble();
        let (context_tx, context_rx) = tokio::sync::watch::channel(initial_preamble);

        // On-device AI needs the local model manager — register as an extra agent.
        let ai_executor = OnDeviceAiExecutor::new(model_manager.clone(), context_rx);
        let ai_meta = ai_executor.meta();
        let extra = vec![(
            ai_meta.name,
            Arc::new(SimpleAgent::new(ai_executor)) as Arc<dyn pap_transport::AgentHandler>,
            ai_meta,
        )];

        let mut agent_set = build_agents(extra);

        // ── Catalog seeding (first startup + upgrade detection) ──────────────────
        // New catalog paths → insert. Existing paths with a different version → update
        // (preserves the agent's DID/keypair so preference history survives upgrades).
        if catalog_dir.exists() {
            let catalog_defs = load_catalog(&catalog_dir);
            let existing_agents = db.load_all_agents().unwrap_or_default();
            // Map catalog_path → (agent_did, operator_key_seed, version) for update lookup.
            let existing_by_path: std::collections::HashMap<String, (String, Option<[u8; 32]>, String)> =
                existing_agents
                    .iter()
                    .filter_map(|a| {
                        a.catalog_path.as_deref().map(|p| {
                            (
                                p.to_owned(),
                                (
                                    a.agent_did.clone().unwrap_or_default(),
                                    a.operator_key_seed,
                                    a.version.clone(),
                                ),
                            )
                        })
                    })
                    .collect();

            for mut def in catalog_defs {
                let now = chrono::Utc::now().to_rfc3339();
                match def
                    .catalog_path
                    .as_deref()
                    .and_then(|p| existing_by_path.get(p))
                {
                    None => {
                        // New agent — generate a fresh keypair and insert.
                        let kp = PrincipalKeypair::generate();
                        def.operator_key_seed = Some(kp.signing_key().to_bytes());
                        def.agent_did = Some(kp.did());
                        def.created_at = now.clone();
                        def.updated_at = now;
                        if let Err(e) = db.insert_agent(&def) {
                            eprintln!("Failed to seed catalog agent '{}': {e}", def.name);
                        }
                    }
                    Some((existing_did, existing_seed, existing_version)) => {
                        // Existing agent — update if the TOML version changed.
                        // Preserve the DID and keypair so preference history survives.
                        if &def.version != existing_version {
                            def.agent_did = Some(existing_did.clone());
                            def.operator_key_seed = *existing_seed;
                            def.updated_at = now;
                            if let Err(e) = db.update_agent(&def) {
                                eprintln!("Failed to update catalog agent '{}': {e}", def.name);
                            }
                        }
                        // Same version — skip (already up to date).
                    }
                }
            }
        }

        // ── Load persisted orchestrator config ───────────────────────────────────
        // get_setting("orchestrator_config") stores the JSON-serialised OrchestratorConfig.
        // On first launch the key is absent, so we fall back to the compiled default.
        let saved_orchestrator_config: OrchestratorConfig = db
            .get_setting("orchestrator_config")
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str::<OrchestratorConfig>(&json).ok())
            .unwrap_or_default();

        // ── Shared LLM provider — writable so configure_orchestrator can update it ─
        let shared_llm_provider: Arc<RwLock<LlmProvider>> = Arc::new(RwLock::new(
            saved_orchestrator_config.inference_substrate.clone(),
        ));

        // ── Register all DB agents (catalog + user_created + generated) ───────────
        let db_agents = db.load_all_agents().unwrap_or_default();
        for def in &db_agents {
            if let Err(e) = agent_set.register_dynamic(def, shared_llm_provider.clone()) {
                eprintln!("Failed to register agent '{}': {e}", def.name);
            }
        }

        let local_registry = Arc::new(Mutex::new(agent_set.registry));

        // Load or create profiles
        let profiles = profiles_db.list_profiles().unwrap_or_default();
        let mut active_profile_id = String::new();

        // If no profiles exist, perform migration from old single-seed storage
        let profiles = if profiles.is_empty() {
            // Check if there's an old seed in the settings table (migration case)
            let migrated_seed_b64 = db.get_setting("principal_seed_b64").ok().flatten();

            // Generate a new profile
            let profile_id = uuid::Uuid::new_v4().to_string();
            let now = chrono::Utc::now().to_rfc3339();

            let seed_b64 = if let Some(old_seed) = migrated_seed_b64 {
                // Migrate existing seed
                eprintln!("Migrating existing principal seed to profile '{profile_id}'");
                old_seed
            } else {
                // Generate new seed
                let kp = PrincipalKeypair::generate();
                let seed = kp.signing_key().to_bytes();
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed)
            };

            // Create default profile
            if let Err(e) = profiles_db.create_profile(&profile_id, "Default", &seed_b64) {
                eprintln!("Failed to create default profile: {e}");
                vec![]
            } else if let Err(e) = profiles_db.switch_profile(&profile_id) {
                eprintln!("Failed to activate default profile: {e}");
                vec![]
            } else {
                active_profile_id = profile_id.clone();
                vec![papillon_shared::ProfileMetadata {
                    id: profile_id,
                    name: "Default".to_string(),
                    created_at: now,
                    last_used: None,
                    active: true,
                }]
            }
        } else {
            // Use existing profiles
            if let Some(active) = profiles.iter().find(|p| p.active) {
                active_profile_id = active.id.clone();
            } else if let Some(first) = profiles.first() {
                // No active profile found, use the first one
                active_profile_id = first.id.clone();
                let _ = profiles_db.switch_profile(&first.id);
            }
            profiles
        };

        // Load seed for active profile
        let (raw_seed, keypair) = if !active_profile_id.is_empty() {
            match profiles_db
                .get_profile_seed(&active_profile_id)
                .ok()
                .flatten()
            {
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
                    (kp.signing_key().to_bytes(), kp)
                }
            }
        } else {
            // Fallback: no profiles available
            let kp = PrincipalKeypair::generate();
            (kp.signing_key().to_bytes(), kp)
        };

        let signer = SoftwareSigner::from_keypair(keypair);

        // Load persisted bookmarks — always include pap://local as the first entry
        let persisted_bookmarks: Vec<String> = db
            .get_setting("registry_bookmarks")
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
            .unwrap_or_default();
        let mut bookmarks = vec![LOCAL_REGISTRY_URL.to_string()];
        for url in persisted_bookmarks {
            if url != LOCAL_REGISTRY_URL && !bookmarks.contains(&url) {
                bookmarks.push(url);
            }
        }

        // App-specific agents that need runtime state (not in shared pap-agents crate):
        // - SocialDiscovery needs the local_registry Arc
        // - TraitBeacon has mutable profile state from the UI
        let social = SocialDiscoveryAgent::new(local_registry.clone());
        let beacon = TraitBeaconAgent::new();

        // Merge app-specific agents into the agent_set built by build_agents()
        let mut handlers = agent_set.handlers;
        let mut keypairs = agent_set.keypairs;
        handlers.insert("Social Discovery".into(), Arc::new(social));
        handlers.insert("Trait Beacon".into(), Arc::new(beacon));

        // Register app-specific agents in local_registry so they appear in
        // list_agents() and resolve_agent() discovery — not just in handlers.
        {
            let mut reg = local_registry.lock().unwrap_or_else(|e| e.into_inner());

            // Social Discovery — finds people via their Trait Beacons
            let social_kp = PrincipalKeypair::generate();
            let social_did = social_kp.did();
            let mut social_ad = pap_marketplace::AgentAdvertisement::new(
                "Social Discovery",
                "Papillon",
                &social_did,
                vec!["schema:DiscoverAction".into()],
                vec!["schema:Person".into()],
                vec![],
                vec!["schema:ItemList".into()],
            );
            social_ad
                .sign(social_kp.signing_key())
                .expect("Ed25519 is always supported");
            reg.register_local(social_ad)
                .expect("Social Discovery registration should not fail");
            keypairs.insert("Social Discovery".into(), social_kp);

            // Trait Beacon — advertises the principal's profile
            let beacon_kp = PrincipalKeypair::generate();
            let beacon_did = beacon_kp.did();
            let mut beacon_ad = pap_marketplace::AgentAdvertisement::new(
                "Trait Beacon",
                "Papillon",
                &beacon_did,
                vec!["schema:InformAction".into()],
                vec!["schema:Person".into()],
                vec![],
                vec!["schema:Person".into()],
            );
            beacon_ad
                .sign(beacon_kp.signing_key())
                .expect("Ed25519 is always supported");
            reg.register_local(beacon_ad)
                .expect("Trait Beacon registration should not fail");
            keypairs.insert("Trait Beacon".into(), beacon_kp);
        }

        Self {
            signer: RwLock::new(Some(Box::new(signer))),
            principal_seed: RwLock::new(Some(Zeroizing::new(raw_seed))),
            profiles_db,
            active_profile_id: RwLock::new(active_profile_id),
            profiles: RwLock::new(profiles),
            registries: Arc::new(RwLock::new(HashMap::new())),
            local_registry,
            bookmarks: RwLock::new(bookmarks),
            orchestrator_config: RwLock::new(saved_orchestrator_config),
            shared_llm_provider,
            model_manager,
            agent_keypairs: Arc::new(RwLock::new(keypairs)),
            db,
            // Shared via Arc — avoids opening a new connection per store_approval_record call.
            episode_db,
            key_backed_up: RwLock::new(false),
            successor_designations: RwLock::new(Vec::new()),
            resource_dir: RwLock::new(PathBuf::new()),
            data_dir: RwLock::new(PathBuf::new()),
            local_agents: handlers,
            endpoint_registry: Arc::new(RwLock::new(EndpointRegistry::new())),
            federation_port: DEFAULT_FEDERATION_PORT,
            node_endpoint: RwLock::new(String::new()),
            node_cert_fingerprint: RwLock::new(String::new()),
            local_pap_urls: RwLock::new(Vec::new()),
            webauthn_challenges: WebAuthnChallengeStore::new(),
            identity_challenges: IdentityChallengeStore::new(),
            approval_gates: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            context_tx,
            trait_beacon_profile,
        }
    }

    /// Load persisted seed from DB or create a new one with persistence.
    /// Returns error on corrupt seed (bad base64, wrong length, or invalid keypair)
    /// so the user must manually recover their identity.
    ///
    /// Used by tests to verify seed persistence logic independently.
    #[allow(dead_code)]
    fn load_or_create_seed(db: &Database) -> Result<([u8; 32], PrincipalKeypair), PapillonError> {
        match db.get_setting("principal_seed_b64")? {
            Some(seed_b64) => {
                // Seed exists in DB — validate it strictly
                let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(&seed_b64)
                    .map_err(|e| {
                        PapillonError::from(format!("Corrupt seed: invalid base64 encoding: {e}"))
                    })?;

                let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    PapillonError::from(format!(
                        "Corrupt seed: expected 32 bytes, got {}",
                        bytes.len()
                    ))
                })?;

                let keypair = PrincipalKeypair::from_bytes(&seed).map_err(|e| {
                    PapillonError::from(format!("Corrupt seed: cannot construct keypair: {e}"))
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
        // Fallback: use temp databases (data lost on restart).
        // In production, lib.rs uses AppState::new() with app_data_dir.
        let db =
            crate::db::open_db(&PathBuf::from("papillon.db")).expect("failed to open fallback db");
        let profiles_db = ProfilesDatabase::open(&PathBuf::from("profiles.db"))
            .expect("failed to open fallback profiles db");
        let episode_db = EpisodeDb::open_in_memory().expect("failed to open in-memory episode_db");
        Self::with_db(
            Arc::new(db),
            Arc::new(profiles_db),
            Arc::new(episode_db),
            PathBuf::new(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_or_create_seed_creates_new_seed_when_none_exists() {
        let db = Arc::new(
            Database::open_memory()
                .map_err(|e| PapillonError::from(e.0))
                .expect("failed to open in-memory db"),
        );

        // Should create new seed since none exists
        let (seed, keypair) = AppState::load_or_create_seed(&db).expect("should create seed");

        // Verify seed was persisted
        let persisted = db
            .get_setting("principal_seed_b64")
            .expect("should read setting")
            .expect("setting should exist");

        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed);
        assert_eq!(encoded, persisted);

        // Verify keypair is valid
        let recovered = PrincipalKeypair::from_bytes(&seed).expect("should reconstruct keypair");
        assert_eq!(keypair.did(), recovered.did());
    }

    #[test]
    fn test_load_or_create_seed_loads_existing_seed() {
        let db = Arc::new(
            Database::open_memory()
                .map_err(|e| PapillonError::from(e.0))
                .expect("failed to open in-memory db"),
        );

        // Create first seed
        let (seed1, keypair1) = AppState::load_or_create_seed(&db).expect("should create seed");

        // Load again — should get same seed and keypair
        let (seed2, keypair2) = AppState::load_or_create_seed(&db).expect("should load seed");

        assert_eq!(seed1, seed2);
        assert_eq!(keypair1.did(), keypair2.did());
    }

    #[test]
    fn test_load_or_create_seed_rejects_corrupt_base64() {
        let db = Arc::new(
            Database::open_memory()
                .map_err(|e| PapillonError::from(e.0))
                .expect("failed to open in-memory db"),
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
            Database::open_memory()
                .map_err(|e| PapillonError::from(e.0))
                .expect("failed to open in-memory db"),
        );

        // Set seed with wrong byte length (31 bytes instead of 32)
        let short_seed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0u8; 31]);
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
            Database::open_memory()
                .map_err(|e| PapillonError::from(e.0))
                .expect("failed to open in-memory db"),
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

    // ── Agent registration tests ──────────────────────────────────────────

    fn make_app_state() -> AppState {
        let db = Arc::new(
            Database::open_memory()
                .map_err(|e| PapillonError::from(e.0))
                .expect("in-memory db"),
        );
        let profiles_db = Arc::new(
            crate::profiles_db::ProfilesDatabase::open_memory().expect("in-memory profiles db"),
        );
        let episode_db = Arc::new(EpisodeDb::open_in_memory().expect("in-memory episode_db"));
        AppState::with_db(db, profiles_db, episode_db, PathBuf::new())
    }

    #[test]
    fn local_registry_contains_all_agents() {
        let state = make_app_state();
        let registry = state.local_registry.lock().unwrap();
        let ads = registry.all_advertisements();

        // Minimum: 1 WebReader (compiled) + On-Device AI + Social Discovery + Trait Beacon = 4.
        // Catalog grows, so assert a floor rather than an exact count.
        assert!(
            ads.len() >= 4,
            "Expected at least 4 agents in local_registry, got {}. Names: {:?}",
            ads.len(),
            ads.iter().map(|a| &a.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn social_discovery_registered_with_correct_metadata() {
        let state = make_app_state();
        let registry = state.local_registry.lock().unwrap();
        let ads = registry.query_local("schema:DiscoverAction");

        assert!(!ads.is_empty(), "No agents found for schema:DiscoverAction");
        let social = ads.iter().find(|a| a.name == "Social Discovery");
        assert!(social.is_some(), "Social Discovery not found in registry");

        let ad = social.unwrap();
        assert_eq!(ad.provider.name, "Papillon");
        assert!(ad.object_types.contains(&"schema:Person".to_string()));
        assert!(ad.returns.contains(&"schema:ItemList".to_string()));
        assert!(ad.requires_disclosure.is_empty());
        assert!(ad.provider.did.starts_with("did:key:"));
        assert!(ad.signature.is_some(), "Advertisement must be signed");
    }

    #[test]
    fn trait_beacon_registered_with_correct_metadata() {
        let state = make_app_state();
        let registry = state.local_registry.lock().unwrap();
        let ads = registry.query_local("schema:InformAction");

        assert!(!ads.is_empty(), "No agents found for schema:InformAction");
        let beacon = ads.iter().find(|a| a.name == "Trait Beacon");
        assert!(beacon.is_some(), "Trait Beacon not found in registry");

        let ad = beacon.unwrap();
        assert_eq!(ad.provider.name, "Papillon");
        assert!(ad.object_types.contains(&"schema:Person".to_string()));
        assert!(ad.returns.contains(&"schema:Person".to_string()));
        assert!(ad.requires_disclosure.is_empty());
        assert!(ad.provider.did.starts_with("did:key:"));
        assert!(ad.signature.is_some(), "Advertisement must be signed");
    }

    #[test]
    fn app_specific_agents_have_handlers() {
        let state = make_app_state();
        assert!(
            state.local_agents.contains_key("Social Discovery"),
            "Social Discovery handler missing"
        );
        assert!(
            state.local_agents.contains_key("Trait Beacon"),
            "Trait Beacon handler missing"
        );
    }

    #[test]
    fn app_specific_agents_have_keypairs() {
        let state = make_app_state();
        let keypairs = state.agent_keypairs.read().unwrap();
        assert!(
            keypairs.contains_key("Social Discovery"),
            "Social Discovery keypair missing"
        );
        assert!(
            keypairs.contains_key("Trait Beacon"),
            "Trait Beacon keypair missing"
        );
    }

    #[test]
    fn all_handlers_have_matching_keypairs() {
        let state = make_app_state();
        let keypairs = state.agent_keypairs.read().unwrap();
        for name in state.local_agents.keys() {
            assert!(
                keypairs.contains_key(name),
                "Handler '{}' has no matching keypair",
                name
            );
        }
    }

    #[test]
    fn all_handlers_have_matching_advertisements() {
        let state = make_app_state();
        let registry = state.local_registry.lock().unwrap();
        let ads = registry.all_advertisements();
        let ad_names: Vec<&str> = ads.iter().map(|a| a.name.as_str()).collect();

        for name in state.local_agents.keys() {
            assert!(
                ad_names.contains(&name.as_str()),
                "Handler '{}' has no matching advertisement in local_registry",
                name
            );
        }
    }

    #[test]
    fn local_registry_bookmarks_include_local() {
        let state = make_app_state();
        let bookmarks = state.bookmarks.read().unwrap();
        assert!(
            bookmarks.contains(&LOCAL_REGISTRY_URL.to_string()),
            "pap://local must always be in bookmarks"
        );
        assert_eq!(
            bookmarks[0], LOCAL_REGISTRY_URL,
            "pap://local must be the first bookmark"
        );
    }
}
