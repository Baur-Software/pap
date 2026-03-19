use std::collections::HashMap;
use std::sync::RwLock;

use pap_did::PrincipalKeypair;
use pap_federation::FederatedRegistry;
use pap_webauthn::{PrincipalSigner, SoftwareSigner};
use papillion_shared::OrchestratorConfig;

use crate::seed::seed_demo_registry;

pub const DEMO_REGISTRY_URL: &str = "pap://demo";

/// Application state managed by Tauri.
pub struct AppState {
    pub signer: RwLock<Option<Box<dyn PrincipalSigner + Send + Sync>>>,
    pub registries: RwLock<HashMap<String, FederatedRegistry>>,
    pub bookmarks: RwLock<Vec<String>>,
    pub orchestrator_config: RwLock<OrchestratorConfig>,
}

impl Default for AppState {
    fn default() -> Self {
        let mut registries = HashMap::new();
        registries.insert(DEMO_REGISTRY_URL.to_string(), seed_demo_registry());

        // Auto-generate identity on startup
        let keypair = PrincipalKeypair::generate();
        let signer = SoftwareSigner::from_keypair(keypair);

        Self {
            signer: RwLock::new(Some(Box::new(signer))),
            registries: RwLock::new(registries),
            bookmarks: RwLock::new(vec![DEMO_REGISTRY_URL.to_string()]),
            orchestrator_config: RwLock::new(OrchestratorConfig::default()),
        }
    }
}
