use std::collections::HashMap;

/// Maps DIDs to transport endpoints (URLs for HTTP, addresses for other transports).
///
/// In production this would be backed by DID Document service endpoints.
/// For now it's a simple in-memory registry.
pub struct EndpointRegistry {
    endpoints: HashMap<String, String>,
}

impl EndpointRegistry {
    pub fn new() -> Self {
        Self {
            endpoints: HashMap::new(),
        }
    }

    /// Register a DID → endpoint mapping.
    pub fn register(&mut self, did: impl Into<String>, endpoint: impl Into<String>) {
        self.endpoints.insert(did.into(), endpoint.into());
    }

    /// Resolve a DID to its transport endpoint.
    pub fn resolve(&self, did: &str) -> Option<&str> {
        self.endpoints.get(did).map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }
}

impl Default for EndpointRegistry {
    fn default() -> Self {
        Self::new()
    }
}
