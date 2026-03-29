use std::env;

/// Runtime configuration for the registry server.
///
/// Reads from environment variables with sensible defaults.
#[derive(Debug, Clone)]
pub struct Config {
    /// Port the HTTPS server listens on. Default: 7890.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env-var tests must run serially to avoid races.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_registry_env() {
        env::remove_var("PAP_REGISTRY_PORT");
        env::remove_var("PAP_REGISTRY_HOST");
        env::remove_var("PAP_REGISTRY_ENDPOINT");
        env::remove_var("PAP_REGISTRY_ADMIN_TOKEN");
    }

    #[test]
    fn defaults_when_no_env_vars() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();

        let config = Config::from_env();
        assert_eq!(config.port, 7890);
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.public_endpoint, "https://0.0.0.0:7890");
        assert!(config.admin_token.is_none());
    }

    #[test]
    fn default_endpoint_uses_https() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();

        let config = Config::from_env();
        assert!(
            config.public_endpoint.starts_with("https://"),
            "expected https:// prefix, got: {}",
            config.public_endpoint
        );
    }

    #[test]
    fn custom_port_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_PORT", "9999");

        let config = Config::from_env();
        assert_eq!(config.port, 9999);
        assert!(config.public_endpoint.contains(":9999"));

        env::remove_var("PAP_REGISTRY_PORT");
    }

    #[test]
    fn invalid_port_falls_back_to_default() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_PORT", "not-a-number");

        let config = Config::from_env();
        assert_eq!(config.port, 7890);

        env::remove_var("PAP_REGISTRY_PORT");
    }

    #[test]
    fn custom_host_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_HOST", "127.0.0.1");

        let config = Config::from_env();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.public_endpoint, "https://127.0.0.1:7890");

        env::remove_var("PAP_REGISTRY_HOST");
    }

    #[test]
    fn explicit_endpoint_overrides_derived() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_ENDPOINT", "https://registry.example.com");

        let config = Config::from_env();
        assert_eq!(config.public_endpoint, "https://registry.example.com");

        env::remove_var("PAP_REGISTRY_ENDPOINT");
    }

    #[test]
    fn admin_token_from_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_ADMIN_TOKEN", "secret-token-123");

        let config = Config::from_env();
        assert_eq!(config.admin_token.as_deref(), Some("secret-token-123"));

        env::remove_var("PAP_REGISTRY_ADMIN_TOKEN");
    }

    #[test]
    fn config_is_clone_and_debug() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();

        let config = Config::from_env();
        let cloned = config.clone();
        assert_eq!(config.port, cloned.port);
        // Debug impl works without panic
        let _ = format!("{:?}", config);
    }
}
