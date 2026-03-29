use std::env;

/// Runtime configuration for the registry server.
///
/// Reads from environment variables with sensible defaults.
#[derive(Debug, Clone)]
pub struct Config {
    /// Port the HTTP server listens on. Default: 7890.
    pub port: u16,

    /// Host to bind to. Default: 0.0.0.0.
    pub host: String,

    /// Optional Bearer token required for admin API routes.
    /// If None, admin routes are unrestricted (suitable for trusted networks).
    pub admin_token: Option<String>,

    /// Public endpoint URL advertised to federation peers.
    /// Example: "https://registry.example.com:7890"
    pub public_endpoint: String,
}

impl Config {
    pub fn from_env() -> Self {
        let port: u16 = env::var("PAP_REGISTRY_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(7890);

        let host = env::var("PAP_REGISTRY_HOST").unwrap_or_else(|_| "0.0.0.0".into());

        let public_endpoint = env::var("PAP_REGISTRY_ENDPOINT")
            .unwrap_or_else(|_| format!("https://{}:{}", host, port));

        let admin_token = env::var("PAP_REGISTRY_ADMIN_TOKEN").ok();

        Self {
            port,
            host,
            admin_token,
            public_endpoint,
        }
    }
}
