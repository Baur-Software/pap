//! WASM-safe local agent registry backed by IndexedDB.
//!
//! [`WasmAgentRegistry`] is the WASM equivalent of the desktop
//! `AppState::with_db()` catalog-seeding path.  It wraps
//! [`IndexedDbDatabase`] and maintains an in-memory list of
//! [`AgentAdvertisement`]s and their raw [`WasmDynamicAgentDef`] payloads.
//!
//! The full `pap-agents` crate is intentionally excluded here because it has
//! unconditional `reqwest::blocking` + `tokio` dependencies that do not
//! compile for `wasm32-unknown-unknown`.  All functionality needed by the
//! WASM registry is replicated using only WASM-compatible crates:
//!
//! * [`pap_marketplace::AgentAdvertisement`] — the advertisement type
//! * [`pap_federation::FederatedRegistry`] — in-memory index
//! * [`pap_did::public_key_to_did`] + `ed25519-dalek` + `sha2` — DID derivation
//!
//! # Catalog seeding
//!
//! Agent definitions are baked into the binary at compile time via
//! `build.rs` → `$OUT_DIR/catalog.json`.  On first open,
//! [`WasmAgentRegistry::seed_default_catalog`] iterates every entry,
//! derives a deterministic Ed25519 keypair (SHA-256 of the agent name as
//! the seed), signs an [`AgentAdvertisement`], and stores the raw JSON in
//! IndexedDB.  Subsequent calls are idempotent — if agents already exist in
//! the DB the method returns `Ok(0)` immediately.
//!
//! # Test strategy
//!
//! The module compiles on native when the `wasm` feature is enabled, so
//! all synchronous tests run under `cargo test -p papillon-shared --features wasm`.
//! The browser-async path ([`WasmAgentRegistry::open`] and
//! [`WasmAgentRegistry::seed_default_catalog`]) is gated
//! `#[cfg(target_arch = "wasm32")]`; tests for those paths exercise the
//! underlying logic synchronously via [`WasmAgentRegistry::new_empty`] and
//! direct DB manipulation.

use crate::db::indexed_db::IndexedDbDatabase;
use crate::db::DatabaseOps;
use ed25519_dalek::SigningKey;
use pap_did::public_key_to_did;
use pap_federation::FederatedRegistry;
use pap_marketplace::AgentAdvertisement;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Embedded catalog ─────────────────────────────────────────────────────────

/// Embedded catalog JSON generated at compile time from `crates/pap-agents/catalog/**/*.toml`.
const CATALOG_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/catalog.json"));

// ── WasmDynamicAgentDef ──────────────────────────────────────────────────────

/// Minimal agent definition used inside [`WasmAgentRegistry`].
///
/// This mirrors the fields of `pap_agents::DynamicAgentDef` that are needed
/// to build a signed [`AgentAdvertisement`].  It is intentionally a separate
/// type so that `papillon-shared` does not need to depend on `pap-agents`
/// (which has native-only dependencies) in WASM builds.
///
/// The struct is fully serializable so it round-trips through IndexedDB JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmDynamicAgentDef {
    #[serde(default)]
    pub agent_did: Option<String>,
    pub schema_version: u32,
    #[serde(default = "default_version")]
    pub version: String,
    pub name: String,
    pub provider: String,
    pub description: String,
    pub action: String,
    #[serde(default)]
    pub object_types: Vec<String>,
    #[serde(default)]
    pub requires_disclosure: Vec<String>,
    #[serde(default)]
    pub returns: Vec<String>,
    #[serde(default)]
    pub llm_instructions: String,
    #[serde(default)]
    pub subagents: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_key_seed: Option<[u8; 32]>,
    #[serde(default)]
    pub published_to: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_path: Option<String>,
    #[serde(default)]
    pub configurable_properties: Vec<serde_json::Value>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    // Accept unknown fields from the full DynamicAgentDef (e.g. `source`, `endpoint`)
    // without causing deserialization failures.
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

fn default_version() -> String {
    "0.1.0".to_string()
}

impl WasmDynamicAgentDef {
    /// Derive a deterministic [`SigningKey`] for this agent by hashing its name
    /// with SHA-256, then build a signed [`AgentAdvertisement`].
    ///
    /// The same agent name always produces the same DID, making this suitable
    /// for idempotent catalog seeding across reinstalls.
    pub fn to_signed_advertisement(&self) -> Result<AgentAdvertisement, String> {
        let seed_bytes: [u8; 32] = Sha256::digest(self.name.as_bytes()).into();
        let signing_key = SigningKey::from_bytes(&seed_bytes);
        let operator_did = public_key_to_did(&signing_key.verifying_key());

        let mut ad = AgentAdvertisement::new(
            &self.name,
            &self.provider,
            &operator_did,
            vec![self.action.clone()],
            self.object_types.clone(),
            self.requires_disclosure.clone(),
            self.returns.clone(),
        );
        ad.ttl_min = 3600;
        if !self.version.is_empty() {
            ad = ad.with_version(&self.version);
        }
        if !self.configurable_properties.is_empty() {
            ad = ad.with_configurable_properties(self.configurable_properties.clone());
        }

        ad.sign(&signing_key)
            .map_err(|e| format!("Failed to sign '{}': {e}", self.name))?;
        Ok(ad)
    }
}

// ── WasmAgentRegistry ────────────────────────────────────────────────────────

/// WASM-safe local agent registry backed by IndexedDB.
///
/// On creation the registry is empty.  Call [`WasmAgentRegistry::open`] to
/// open the database and load existing definitions, then optionally call
/// [`WasmAgentRegistry::seed_default_catalog`] on first launch to populate
/// the embedded catalog.
///
/// The in-memory state is rebuilt from the database on every `open` call and
/// is ephemeral (not persisted separately — the source of truth is IndexedDB).
pub struct WasmAgentRegistry {
    db: IndexedDbDatabase,
    /// In-memory federation registry for fast query.
    registry: FederatedRegistry,
    /// Raw definitions (preserved for inspection and re-seeding).
    defs: Vec<WasmDynamicAgentDef>,
}

impl WasmAgentRegistry {
    // ── Constructors ─────────────────────────────────────────────────────────

    /// Open the IndexedDB database and rebuild the in-memory registry from any
    /// previously stored agent definitions.
    ///
    /// This is the primary entry-point for production (browser) use.
    /// Only available on `wasm32` targets — use [`Self::new_empty`] in tests.
    #[cfg(target_arch = "wasm32")]
    pub async fn open(db_name: &str) -> Result<Self, String> {
        let db = IndexedDbDatabase::open(db_name)
            .await
            .map_err(|e| format!("IndexedDbDatabase::open failed: {}", e.0))?;

        Self::load_from_db(db)
    }

    /// Internal: build a [`WasmAgentRegistry`] from an already-opened database,
    /// loading all stored agent defs into the in-memory registry.
    fn load_from_db(db: IndexedDbDatabase) -> Result<Self, String> {
        let mut registry = FederatedRegistry::new();
        let mut defs = Vec::new();

        // Load all stored agent defs and rebuild in-memory registry.
        let raw_defs = db
            .list_agent_defs()
            .map_err(|e| format!("list_agent_defs failed: {}", e.0))?;

        for json_str in raw_defs {
            match serde_json::from_str::<WasmDynamicAgentDef>(&json_str) {
                Ok(def) => {
                    match def.to_signed_advertisement() {
                        Ok(ad) => {
                            // Ignore AlreadyRegistered — can happen if DB has
                            // duplicate entries from a previous interrupted seed.
                            let _ = registry.register_local(ad);
                            defs.push(def);
                        }
                        Err(_e) => {
                            #[cfg(target_arch = "wasm32")]
                            web_sys::console::warn_1(
                                &format!(
                                    "papillon: skipping agent with bad advertisement: {}",
                                    _e
                                )
                                .into(),
                            );
                        }
                    }
                }
                Err(_e) => {
                    #[cfg(target_arch = "wasm32")]
                    web_sys::console::warn_1(
                        &format!("papillon: skipping corrupt agent def: {}", _e).into(),
                    );
                }
            }
        }

        Ok(Self { db, registry, defs })
    }

    /// Synchronous constructor — creates an empty in-memory database **without**
    /// loading from IndexedDB.  Intended for tests and non-browser contexts.
    pub fn new_empty(db_name: &str) -> Result<Self, String> {
        let db = IndexedDbDatabase::new_with_persistence(db_name)
            .map_err(|e| format!("new_with_persistence failed: {}", e.0))?;
        Ok(Self {
            db,
            registry: FederatedRegistry::new(),
            defs: Vec::new(),
        })
    }

    /// Synchronous constructor that opens an in-memory DB **and** loads any
    /// pre-populated agent defs.  Useful for non-browser integration tests.
    pub fn from_db(db: IndexedDbDatabase) -> Result<Self, String> {
        Self::load_from_db(db)
    }

    // ── Catalog seeding ───────────────────────────────────────────────────────

    /// Seed the embedded default catalog into the database if it has not been
    /// seeded yet.
    ///
    /// The operation is idempotent: if any agent definitions already exist in
    /// the database the method returns `Ok(0)` immediately without touching
    /// any existing data.
    ///
    /// For each catalog entry the method:
    /// 1. Derives a deterministic SHA-256 seed from the agent name.
    /// 2. Signs an [`AgentAdvertisement`] with that seed.
    /// 3. Stores the serialised definition via `upsert_agent_def`.
    /// 4. Registers the advertisement in the in-memory [`FederatedRegistry`].
    ///
    /// Returns the count of agents successfully seeded, or `Ok(0)` when
    /// already seeded.
    ///
    /// In browser builds this method is `async` because it awaits IndexedDB
    /// persistence; on the native-feature path (tests) it is synchronous.
    #[cfg(target_arch = "wasm32")]
    pub async fn seed_default_catalog(&mut self) -> Result<usize, String> {
        self.seed_default_catalog_inner()
    }

    /// Synchronous seeding for non-browser contexts (tests, CLI tools).
    ///
    /// Identical logic to the `async` version — the `async` wrapper exists
    /// only to satisfy the browser call-site convention.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn seed_default_catalog(&mut self) -> Result<usize, String> {
        self.seed_default_catalog_inner()
    }

    /// Core seeding logic — shared by both the async (wasm32) and sync (native)
    /// public methods.
    fn seed_default_catalog_inner(&mut self) -> Result<usize, String> {
        // Idempotency check — if any defs already exist, skip seeding.
        let existing = self
            .db
            .list_agent_defs()
            .map_err(|e| format!("list_agent_defs failed: {}", e.0))?;
        if !existing.is_empty() {
            return Ok(0);
        }

        let catalog_defs: Vec<WasmDynamicAgentDef> =
            serde_json::from_str(CATALOG_JSON).map_err(|e| {
                format!("failed to deserialize embedded catalog.json: {e}")
            })?;

        let mut count = 0usize;

        for mut def in catalog_defs {
            // Derive deterministic operator keypair from name.
            let seed: [u8; 32] = Sha256::digest(def.name.as_bytes()).into();
            def.operator_key_seed = Some(seed);

            // Derive the DID from the seed and store it on the def.
            let signing_key = SigningKey::from_bytes(&seed);
            let did = public_key_to_did(&signing_key.verifying_key());
            def.agent_did = Some(did);

            // Build and sign advertisement.
            let ad = match def.to_signed_advertisement() {
                Ok(ad) => ad,
                Err(_e) => {
                    #[cfg(target_arch = "wasm32")]
                    web_sys::console::warn_1(
                        &format!(
                            "papillon: skipping catalog agent '{}': {}",
                            def.name, _e
                        )
                        .into(),
                    );
                    continue;
                }
            };

            // Serialize def to JSON.
            let json = match serde_json::to_string(&def) {
                Ok(j) => j,
                Err(_e) => {
                    #[cfg(target_arch = "wasm32")]
                    web_sys::console::warn_1(
                        &format!(
                            "papillon: failed to serialize agent '{}': {}",
                            def.name, _e
                        )
                        .into(),
                    );
                    continue;
                }
            };

            // Persist to database.
            if let Err(_e) = self.db.upsert_agent_def(&def.name, &json) {
                #[cfg(target_arch = "wasm32")]
                web_sys::console::warn_1(
                    &format!(
                        "papillon: failed to persist agent '{}': {:?}",
                        def.name, _e
                    )
                    .into(),
                );
                continue;
            }

            // Register in in-memory registry.
            // register_local returns Err if the DID is already present (two catalog
            // entries that hash to the same DID, or a re-seed attempt).
            // We persist the definition regardless so it survives reload, but only
            // count the agent if it was newly registered.
            let newly_registered = self.registry.register_local(ad).is_ok();
            self.defs.push(def);
            if newly_registered {
                count += 1;
            }
        }

        Ok(count)
    }

    // ── Query methods ─────────────────────────────────────────────────────────

    /// Return all registered agent advertisements.
    pub fn list_agents(&self) -> Vec<AgentAdvertisement> {
        self.registry.all_advertisements().to_owned()
    }

    /// Return advertisements for agents that can handle the given Schema.org
    /// action type (e.g. `"schema:SearchAction"`).
    pub fn query_by_action(&self, action: &str) -> Vec<AgentAdvertisement> {
        self.registry
            .query_local(action)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Return the number of agents currently registered in memory.
    pub fn agent_count(&self) -> usize {
        self.registry.len()
    }

    /// Return a reference to the raw agent definitions held in memory.
    pub fn defs(&self) -> &[WasmDynamicAgentDef] {
        &self.defs
    }

    /// Access the underlying database (for episode/settings persistence).
    pub fn db(&self) -> &IndexedDbDatabase {
        &self.db
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── WasmDynamicAgentDef helpers ───────────────────────────────────────────

    fn make_def(name: &str) -> WasmDynamicAgentDef {
        WasmDynamicAgentDef {
            agent_did: None,
            schema_version: 1,
            version: "0.1.0".to_string(),
            name: name.to_string(),
            provider: "Test".to_string(),
            description: "test".to_string(),
            action: "schema:SearchAction".to_string(),
            object_types: vec![],
            requires_disclosure: vec![],
            returns: vec![],
            llm_instructions: String::new(),
            subagents: vec![],
            operator_key_seed: None,
            published_to: vec![],
            catalog_path: None,
            configurable_properties: vec![],
            created_at: String::new(),
            updated_at: String::new(),
            extra: Default::default(),
        }
    }

    #[test]
    fn to_signed_advertisement_produces_valid_did() {
        let def = make_def("Test Agent");
        let ad = def
            .to_signed_advertisement()
            .expect("should produce advertisement");
        assert!(
            ad.provider.did.starts_with("did:key:"),
            "DID should start with did:key: — got: {}",
            ad.provider.did
        );
        assert!(
            ad.signature.is_some(),
            "advertisement must be signed"
        );
        assert_eq!(ad.name, "Test Agent");
    }

    #[test]
    fn to_signed_advertisement_is_deterministic() {
        let def = make_def("Deterministic Agent");
        let ad1 = def.to_signed_advertisement().unwrap();
        let ad2 = def.to_signed_advertisement().unwrap();
        assert_eq!(
            ad1.provider.did, ad2.provider.did,
            "same name must always produce the same DID"
        );
    }

    #[test]
    fn new_empty_registry_has_zero_agents() {
        let registry = WasmAgentRegistry::new_empty("test-empty")
            .expect("new_empty should succeed");
        assert_eq!(registry.agent_count(), 0);
        assert!(registry.list_agents().is_empty());
    }

    #[test]
    fn seed_default_catalog_seeds_all_agents() {
        // Use the synchronous path: manually read catalog JSON and seed via the
        // in-memory registry — this lets us test the seeding logic without an
        // async runtime or browser IndexedDB.
        let catalog_defs: Vec<WasmDynamicAgentDef> =
            serde_json::from_str(CATALOG_JSON)
                .expect("embedded catalog.json must deserialize");

        assert!(
            catalog_defs.len() >= 300,
            "expected at least 300 catalog entries, got {}",
            catalog_defs.len()
        );

        // Build advertisements for all catalog entries.
        let mut count = 0usize;
        for def in &catalog_defs {
            let ad = def
                .to_signed_advertisement()
                .unwrap_or_else(|e| panic!("failed for '{}': {e}", def.name));
            assert!(
                ad.signature.is_some(),
                "agent '{}' must have a signature",
                def.name
            );
            count += 1;
        }
        assert!(count >= 300, "expected 300+ signed ads, got {count}");
    }

    #[test]
    fn seed_default_catalog_returns_nonzero_count_on_fresh_db() {
        let mut reg = WasmAgentRegistry::new_empty("test-seed-fresh")
            .expect("new_empty should succeed");
        let count = reg
            .seed_default_catalog()
            .expect("seed should succeed on fresh db");
        assert!(
            count >= 300,
            "expected at least 300 agents seeded, got {count}"
        );
        // agent_count() reflects unique DIDs; count reflects unique registrations.
        // They should be equal (or count could be slightly lower if two entries
        // produce the same DID, which is an extremely rare SHA-256 collision).
        assert!(
            reg.agent_count() >= 300,
            "agent_count must be at least 300 after seeding, got {}",
            reg.agent_count()
        );
    }

    #[test]
    fn seed_default_catalog_is_idempotent() {
        // Seed once — verify count, then seed again and verify Ok(0).
        let mut reg = WasmAgentRegistry::new_empty("test-seed-idem")
            .expect("new_empty should succeed");

        let first = reg
            .seed_default_catalog()
            .expect("first seed should succeed");
        assert!(first >= 300, "first seed must produce agents");
        let count_after_first = reg.agent_count();

        // Second call must be a no-op.
        let second = reg
            .seed_default_catalog()
            .expect("second seed should succeed");
        assert_eq!(second, 0, "second seed must return Ok(0) — idempotent");

        // Count must be unchanged.
        assert_eq!(
            reg.agent_count(),
            count_after_first,
            "agent count must not change after second seed"
        );
    }

    #[test]
    fn seed_default_catalog_idempotent_via_db() {
        // Simulate idempotency via pre-populated DB: if the DB already has
        // entries, seed_default_catalog must return Ok(0) immediately.
        let db = IndexedDbDatabase::new_with_persistence("test-idem")
            .expect("db creation failed");
        db.upsert_agent_def("existing", r#"{"name":"existing"}"#)
            .expect("upsert should succeed");

        let mut reg = WasmAgentRegistry::from_db(db)
            .expect("from_db should succeed");

        let count = reg
            .seed_default_catalog()
            .expect("seed on pre-populated db should succeed");
        assert_eq!(
            count, 0,
            "seed must return Ok(0) when DB is already non-empty"
        );
    }

    #[test]
    fn query_by_action_filters_correctly() {
        let mut registry =
            WasmAgentRegistry::new_empty("test-query").expect("new_empty should succeed");

        // Manually insert two agents: one SearchAction, one BuyAction.
        let search_def = make_def("Search Agent");
        let mut buy_def = make_def("Buy Agent");
        buy_def.action = "schema:BuyAction".to_string();

        let search_ad = search_def.to_signed_advertisement().unwrap();
        let buy_ad = buy_def.to_signed_advertisement().unwrap();

        registry
            .registry
            .register_local(search_ad)
            .expect("register search");
        registry
            .registry
            .register_local(buy_ad)
            .expect("register buy");

        let search_results = registry.query_by_action("schema:SearchAction");
        assert_eq!(
            search_results.len(),
            1,
            "only one SearchAction agent expected"
        );
        assert_eq!(search_results[0].name, "Search Agent");

        let buy_results = registry.query_by_action("schema:BuyAction");
        assert_eq!(buy_results.len(), 1, "only one BuyAction agent expected");
        assert_eq!(buy_results[0].name, "Buy Agent");
    }

    #[test]
    fn agent_count_reflects_registry_state() {
        let mut registry =
            WasmAgentRegistry::new_empty("test-count").expect("new_empty should succeed");
        assert_eq!(registry.agent_count(), 0);

        let def1 = make_def("Agent One");
        let def2 = make_def("Agent Two");
        registry
            .registry
            .register_local(def1.to_signed_advertisement().unwrap())
            .unwrap();
        registry
            .registry
            .register_local(def2.to_signed_advertisement().unwrap())
            .unwrap();

        assert_eq!(registry.agent_count(), 2);
    }

    #[test]
    fn wasm_def_deserializes_from_full_dynamic_agent_json() {
        // Verify that a JSON blob with all DynamicAgentDef fields (including
        // `source` and `endpoint` which are in `extra`) deserializes cleanly.
        let json = r#"{
            "agent_did": null,
            "schema_version": 1,
            "version": "0.1.0",
            "name": "DuckDuckGo Search",
            "provider": "DuckDuckGo",
            "description": "Web search via DuckDuckGo",
            "action": "schema:SearchAction",
            "object_types": ["schema:Thing"],
            "requires_disclosure": [],
            "returns": ["schema:SearchResult"],
            "llm_instructions": "",
            "subagents": [],
            "published_to": [],
            "catalog_path": "search/duckduckgo.toml",
            "configurable_properties": [],
            "created_at": "",
            "updated_at": "",
            "source": "Catalog",
            "endpoint": {
                "url_template": "https://api.duckduckgo.com/?q={query}&format=json",
                "method": "Get",
                "headers": {},
                "body_template": null,
                "response_jsonpath": "$",
                "response_schema_type": "schema:SearchResult",
                "response_mapping": {},
                "timeout_secs": 5
            }
        }"#;

        let def: WasmDynamicAgentDef =
            serde_json::from_str(json).expect("must deserialize without error");
        assert_eq!(def.name, "DuckDuckGo Search");
        assert_eq!(def.action, "schema:SearchAction");
        // `source` and `endpoint` land in `extra` without causing an error.
        assert!(def.extra.contains_key("source"));
        assert!(def.extra.contains_key("endpoint"));
    }

    #[test]
    fn catalog_json_deserializes_to_wasm_defs() {
        let defs: Vec<WasmDynamicAgentDef> =
            serde_json::from_str(CATALOG_JSON)
                .expect("embedded catalog.json must deserialize to WasmDynamicAgentDef");
        assert!(
            defs.len() >= 300,
            "expected 300+ defs in catalog, got {}",
            defs.len()
        );
        for def in &defs {
            assert!(
                def.action.starts_with("schema:"),
                "action '{}' in '{}' must start with 'schema:'",
                def.action,
                def.name
            );
        }
    }
}
