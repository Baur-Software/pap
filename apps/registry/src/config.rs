use std::env;

/// Default maximum HTTP request body size in bytes (256 KB).
/// Used in both `Config::from_env()` and the test router to prevent drift.
pub const DEFAULT_MAX_BODY_BYTES: usize = 256 * 1024;

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

    /// Disable TLS and serve over plain HTTP.
    /// Set `PAP_REGISTRY_NO_TLS=true` for local development.
    pub no_tls: bool,

    /// Maximum advertisements accepted from a single principal DID.
    /// Enforced at POST /api/agents. Default: 100.
    pub max_ads_per_principal: usize,

    /// When `true`, delete the SQLite database file at startup so migrations
    /// run against a clean slate.  **Destructive** — all stored agents, peers,
    /// and the node identity are lost.  Only meaningful for SQLite; ignored for
    /// Postgres.  Set `PAP_REGISTRY_RESET_DB=true` to enable.
    pub reset_db: bool,

    /// When `true`, the server will refuse to start if `admin_token` is not
    /// set.  Use `PAP_REGISTRY_REQUIRE_AUTH=true` in production environments
    /// where unauthenticated admin access is unacceptable.
    pub require_auth: bool,

    /// Maximum allowed HTTP request body size in bytes.
    /// Requests exceeding this limit are rejected with 413 Payload Too Large.
    /// Default: 262144 (256 KB). Override via `PAP_REGISTRY_MAX_BODY_BYTES`.
    pub max_body_bytes: usize,
}

impl Config {
    pub fn from_env() -> Self {
        let port: u16 = env::var("PAP_REGISTRY_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(7890);

        let host = env::var("PAP_REGISTRY_HOST").unwrap_or_else(|_| "0.0.0.0".into());

        let no_tls = env::var("PAP_REGISTRY_NO_TLS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let scheme = if no_tls { "http" } else { "https" };
        let public_endpoint = env::var("PAP_REGISTRY_ENDPOINT")
            .unwrap_or_else(|_| format!("{scheme}://{}:{}", host, port));

        let admin_token = env::var("PAP_REGISTRY_ADMIN_TOKEN").ok();

        let max_ads_per_principal: usize = env::var("PAP_REGISTRY_MAX_ADS_PER_PRINCIPAL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);

        let reset_db = env::var("PAP_REGISTRY_RESET_DB")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let require_auth = env::var("PAP_REGISTRY_REQUIRE_AUTH")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let max_body_bytes = env::var("PAP_REGISTRY_MAX_BODY_BYTES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_BODY_BYTES);

        Self {
            port,
            host,
            admin_token,
            public_endpoint,
            no_tls,
            max_ads_per_principal,
            reset_db,
            require_auth,
            max_body_bytes,
        }
    }

    /// Build the default CORS origin allowlist from env config.
    ///
    /// Used to seed the `settings` DB table on first boot when no persisted
    /// value exists yet.  Returns a comma-separated string ready for storage,
    /// e.g. `"https://localhost:7890"`.
    pub fn default_cors_origins(&self) -> String {
        let scheme = if self.no_tls { "http" } else { "https" };
        // Always include localhost so the bundled admin UI works even when the
        // server binds 0.0.0.0.
        let mut origins = vec![format!("{scheme}://localhost:{}", self.port)];
        // If the operator explicitly bound a non-wildcard host, include it too.
        if self.host != "0.0.0.0" && self.host != "localhost" {
            origins.push(format!("{scheme}://{}:{}", self.host, self.port));
        }
        origins.join(",")
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
        env::remove_var("PAP_REGISTRY_NO_TLS");
        env::remove_var("PAP_REGISTRY_RESET_DB");
        env::remove_var("PAP_REGISTRY_REQUIRE_AUTH");
        env::remove_var("PAP_REGISTRY_MAX_BODY_BYTES");
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
        assert!(!config.no_tls);
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
    fn no_tls_uses_http_endpoint() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_NO_TLS", "true");

        let config = Config::from_env();
        assert!(config.no_tls);
        assert_eq!(config.public_endpoint, "http://0.0.0.0:7890");

        env::remove_var("PAP_REGISTRY_NO_TLS");
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

    #[test]
    fn reset_db_defaults_to_false() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();

        let config = Config::from_env();
        assert!(!config.reset_db);
    }

    #[test]
    fn reset_db_enabled_by_true_string() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_RESET_DB", "true");

        let config = Config::from_env();
        assert!(config.reset_db);

        env::remove_var("PAP_REGISTRY_RESET_DB");
    }

    #[test]
    fn reset_db_enabled_by_one() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_RESET_DB", "1");

        let config = Config::from_env();
        assert!(config.reset_db);

        env::remove_var("PAP_REGISTRY_RESET_DB");
    }

    // ── default_cors_origins ──────────────────────────────────────────────────

    #[test]
    fn default_cors_origins_0000_bind_returns_only_localhost() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();

        let config = Config::from_env(); // host=0.0.0.0, port=7890, no_tls=false
        let origins = config.default_cors_origins();
        assert_eq!(origins, "https://localhost:7890");
    }

    #[test]
    fn default_cors_origins_explicit_host_included() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_HOST", "192.168.1.10");
        env::set_var("PAP_REGISTRY_NO_TLS", "true");

        let config = Config::from_env();
        let origins = config.default_cors_origins();
        assert!(
            origins.contains("http://localhost:7890"),
            "missing localhost"
        );
        assert!(
            origins.contains("http://192.168.1.10:7890"),
            "missing explicit host"
        );

        env::remove_var("PAP_REGISTRY_HOST");
        env::remove_var("PAP_REGISTRY_NO_TLS");
    }

    // ── require_auth ──────────────────────────────────────────────────────────

    #[test]
    fn require_auth_defaults_false() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();

        let cfg = Config::from_env();
        assert!(!cfg.require_auth);
    }

    #[test]
    fn require_auth_set_true() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_REQUIRE_AUTH", "true");

        let cfg = Config::from_env();
        assert!(cfg.require_auth);

        env::remove_var("PAP_REGISTRY_REQUIRE_AUTH");
    }

    // ── max_body_bytes ────────────────────────────────────────────────────────

    #[test]
    fn max_body_bytes_default() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        let cfg = Config::from_env();
        assert_eq!(cfg.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
    }

    #[test]
    fn max_body_bytes_custom() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_MAX_BODY_BYTES", "65536");
        let cfg = Config::from_env();
        assert_eq!(cfg.max_body_bytes, 65536);
    }

    #[test]
    fn max_body_bytes_invalid_fallback_to_default() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_MAX_BODY_BYTES", "not-a-number");
        let cfg = Config::from_env();
        assert_eq!(cfg.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
    }
}
