use std::collections::HashMap;
use std::sync::RwLock;

use pap_federation::FederatedRegistry;
use pap_webauthn::PrincipalSigner;

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
        Self {
            signer: RwLock::new(None),
            registries: RwLock::new(HashMap::new()),
            bookmarks: RwLock::new(Vec::new()),
        }
    }
}
