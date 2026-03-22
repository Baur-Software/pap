use std::sync::{Arc, Mutex};

use pap_federation::registry::FederatedRegistry;

use crate::config::Config;
use crate::db::RegistryStore;

/// Shared application state passed into all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<Mutex<FederatedRegistry>>,
    pub store: Arc<RegistryStore>,
    pub node_did: String,
    pub node_endpoint: String,
    pub cert_fingerprint: String,
    pub admin_token: Option<String>,
}

impl AppState {
    pub fn new(
        registry: Arc<Mutex<FederatedRegistry>>,
        store: Arc<RegistryStore>,
        node_did: String,
        config: &Config,
        cert_fingerprint: String,
    ) -> Self {
        Self {
            registry,
            store,
            node_did,
            node_endpoint: config.public_endpoint.clone(),
            cert_fingerprint,
            admin_token: config.admin_token.clone(),
        }
    }

    /// Check whether the given Bearer token is authorized for admin access.
    /// If no admin token is configured, all requests are allowed.
    pub fn is_authorized(&self, token: Option<&str>) -> bool {
        match &self.admin_token {
            None => true,
            Some(expected) => token.map(|t| t == expected).unwrap_or(false),
        }
    }
}
