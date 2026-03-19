use std::collections::HashMap;
use std::sync::RwLock;

use pap_federation::FederatedRegistry;
use pap_webauthn::PrincipalSigner;

use crate::seed::seed_demo_registry;

pub const DEMO_REGISTRY_URL: &str = "pap://demo";

/// Application state managed by Tauri.
pub struct AppState {
    /// The principal's signer (None until identity is created/loaded).
    pub signer: RwLock<Option<Box<dyn PrincipalSigner + Send + Sync>>>,

    /// Connected federated registries, keyed by URL.
    pub registries: RwLock<HashMap<String, FederatedRegistry>>,

    /// Bookmarked registry URLs.
    pub bookmarks: RwLock<Vec<String>>,
}

impl Default for AppState {
    fn default() -> Self {
        let mut registries = HashMap::new();
        registries.insert(DEMO_REGISTRY_URL.to_string(), seed_demo_registry());

        Self {
            signer: RwLock::new(None),
            registries: RwLock::new(registries),
            bookmarks: RwLock::new(vec![DEMO_REGISTRY_URL.to_string()]),
        }
    }
}
