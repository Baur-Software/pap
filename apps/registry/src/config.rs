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

    /// Confirmation guard for the destructive `reset_db` operation.
    /// Must be set to `"yes-i-understand"` via `PAP_REGISTRY_RESET_DB_CONFIRM`
    /// in addition to `PAP_REGISTRY_RESET_DB=true` for the wipe to occur.
    /// This two-variable requirement prevents accidental DB deletion in production
    /// when operators copy env files or set `RESET_DB` without realising the impact.
    pub reset_db_confirm: bool,

    /// When `true`, the server will refuse to start if `admin_token` is not
    /// set.  Use `PAP_REGISTRY_REQUIRE_AUTH=true` in production environments
    /// where unauthenticated admin access is unacceptable.
    pub require_auth: bool,

    /// Maximum allowed HTTP request body size in bytes.
    /// Requests exceeding this limit are rejected with 413 Payload Too Large.
    /// Default: 262144 (256 KB). Override via `PAP_REGISTRY_MAX_BODY_BYTES`.
    pub max_body_bytes: usize,

    /// Sustained request rate per second per IP address for the leaky-bucket
    /// rate limiter.  Default: 20. Override via `PAP_REGISTRY_RATE_LIMIT_RPS`.
    pub rate_limit_rps: u64,

    /// Maximum burst size for the rate limiter (number of requests that can
    /// be issued in excess of the sustained rate before throttling begins).
    /// Default: 60. Override via `PAP_REGISTRY_RATE_LIMIT_BURST`.
    pub rate_limit_burst: u32,

    /// Optional OIDC issuer URL for token validation.
    /// Used for validating bearer tokens from an OpenID Connect provider.
    /// Set via `PAP_REGISTRY_OIDC_ISSUER`.
    pub oidc_issuer: Option<String>,

    /// Optional OIDC audience identifier for token validation.
    /// Must match the "aud" claim in OIDC tokens.
    /// Set via `PAP_REGISTRY_OIDC_AUDIENCE`.
    pub oidc_audience: Option<String>,

    /// AWS region for accessing secrets and other AWS services.
    /// Default: "us-east-1". Override via `PAP_REGISTRY_AWS_REGION`.
    pub aws_region: String,

    /// Enable API key authentication for programmatic access.
    /// When true, clients can authenticate using API keys stored in AWS Secrets Manager.
    /// Set via `PAP_REGISTRY_ENABLE_API_KEYS=true/false`. Default: false.
    pub enable_api_keys: bool,
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

        let reset_db_confirm = env::var("PAP_REGISTRY_RESET_DB_CONFIRM")
            .map(|v| v.eq_ignore_ascii_case("yes-i-understand"))
            .unwrap_or(false);

        let require_auth = env::var("PAP_REGISTRY_REQUIRE_AUTH")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let max_body_bytes = env::var("PAP_REGISTRY_MAX_BODY_BYTES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_BODY_BYTES);

        let rate_limit_rps = env::var("PAP_REGISTRY_RATE_LIMIT_RPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20u64);

        let rate_limit_burst = env::var("PAP_REGISTRY_RATE_LIMIT_BURST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60u32);

        let oidc_issuer = env::var("PAP_REGISTRY_OIDC_ISSUER").ok();

        let oidc_audience = env::var("PAP_REGISTRY_OIDC_AUDIENCE").ok();

        let aws_region = env::var("PAP_REGISTRY_AWS_REGION")
            .unwrap_or_else(|_| "us-east-1".into());

        let enable_api_keys = env::var("PAP_REGISTRY_ENABLE_API_KEYS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Self {
            port,
            host,
            admin_token,
            public_endpoint,
            no_tls,
            max_ads_per_principal,
            reset_db,
            reset_db_confirm,
            require_auth,
            max_body_bytes,
            rate_limit_rps,
            rate_limit_burst,
            oidc_issuer,
            oidc_audience,
            aws_region,
            enable_api_keys,
        }
    }

    /// Returns `true` only when both `reset_db` is set **and** the operator has
    /// provided the explicit confirmation string `"yes-i-understand"` via
    /// `PAP_REGISTRY_RESET_DB_CONFIRM`.  This two-variable guard prevents
    /// accidental database wipes when `RESET_DB=true` is copied from a dev
    /// env file into production without understanding the consequences.
    pub fn reset_db_confirmed(&self) -> bool {
        self.reset_db && self.reset_db_confirm
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
        env::remove_var("PAP_REGISTRY_RESET_DB_CONFIRM");
        env::remove_var("PAP_REGISTRY_REQUIRE_AUTH");
        env::remove_var("PAP_REGISTRY_MAX_BODY_BYTES");
        env::remove_var("PAP_REGISTRY_RATE_LIMIT_RPS");
        env::remove_var("PAP_REGISTRY_RATE_LIMIT_BURST");
        env::remove_var("PAP_REGISTRY_OIDC_ISSUER");
        env::remove_var("PAP_REGISTRY_OIDC_AUDIENCE");
        env::remove_var("PAP_REGISTRY_AWS_REGION");
        env::remove_var("PAP_REGISTRY_ENABLE_API_KEYS");
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

    // ── rate_limit_rps / rate_limit_burst ─────────────────────────────────────

    #[test]
    fn rate_limit_defaults() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        let cfg = Config::from_env();
        assert_eq!(cfg.rate_limit_rps, 20);
        assert_eq!(cfg.rate_limit_burst, 60);
    }

    #[test]
    fn rate_limit_custom_values() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_RATE_LIMIT_RPS", "5");
        env::set_var("PAP_REGISTRY_RATE_LIMIT_BURST", "10");
        let cfg = Config::from_env();
        assert_eq!(cfg.rate_limit_rps, 5);
        assert_eq!(cfg.rate_limit_burst, 10);

        env::remove_var("PAP_REGISTRY_RATE_LIMIT_RPS");
        env::remove_var("PAP_REGISTRY_RATE_LIMIT_BURST");
    }

    // ── reset_db_confirmed ────────────────────────────────────────────────────

    #[test]
    fn reset_db_requires_confirmation() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_RESET_DB", "true");
        let cfg = Config::from_env();
        assert!(!cfg.reset_db_confirmed());
    }

    #[test]
    fn reset_db_confirmed_when_both_set() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_RESET_DB", "true");
        env::set_var("PAP_REGISTRY_RESET_DB_CONFIRM", "yes-i-understand");
        let cfg = Config::from_env();
        assert!(cfg.reset_db_confirmed());
    }

    #[test]
    fn reset_db_false_even_with_confirmation() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_RESET_DB_CONFIRM", "yes-i-understand");
        let cfg = Config::from_env();
        assert!(!cfg.reset_db_confirmed());
    }

    // ── Edge cases: admin_token empty string ──────────────────────────────────

    /// An empty-string token is `Some("")`, NOT `None`.
    /// This is a documented footgun: operators who set `PAP_REGISTRY_ADMIN_TOKEN=""`
    /// get `Some("")` which bypasses the `admin_token.is_none()` warning in
    /// `check_auth_config`, yet the empty token still provides no real security
    /// because any caller who sends `Authorization: Bearer ` would be admitted.
    #[test]
    fn admin_token_empty_string_is_some_not_none() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_ADMIN_TOKEN", "");

        let cfg = Config::from_env();
        // Empty-string env var comes through as Some("") — NOT None.
        assert_eq!(cfg.admin_token.as_deref(), Some(""));
        assert!(cfg.admin_token.is_some(), "empty string must not be None");

        env::remove_var("PAP_REGISTRY_ADMIN_TOKEN");
    }

    // ── Edge cases: port boundaries ───────────────────────────────────────────

    #[test]
    fn port_max_valid_u16() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_PORT", "65535");

        let cfg = Config::from_env();
        assert_eq!(cfg.port, 65535);

        env::remove_var("PAP_REGISTRY_PORT");
    }

    #[test]
    fn port_overflow_u16_falls_back_to_default() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        // 65536 overflows u16::MAX (65535) — parse::<u16>() returns Err
        env::set_var("PAP_REGISTRY_PORT", "65536");

        let cfg = Config::from_env();
        assert_eq!(cfg.port, 7890, "overflow must fall back to default 7890");

        env::remove_var("PAP_REGISTRY_PORT");
    }

    #[test]
    fn port_zero_parses_and_is_accepted() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_PORT", "0");

        let cfg = Config::from_env();
        // Port 0 is a valid u16 — the OS picks an ephemeral port when bound.
        assert_eq!(cfg.port, 0);

        env::remove_var("PAP_REGISTRY_PORT");
    }

    // ── Edge cases: rate limit zero values ────────────────────────────────────

    /// `PAP_REGISTRY_RATE_LIMIT_RPS=0` parses as 0 — NOT the default 20.
    /// Note: tower-governor with per_second(0) will panic at startup.
    /// This test documents the parsing behaviour; callers must validate > 0.
    #[test]
    fn rate_limit_rps_zero_parses_as_zero_not_default() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_RATE_LIMIT_RPS", "0");

        let cfg = Config::from_env();
        assert_eq!(cfg.rate_limit_rps, 0, "zero is a valid parse result");

        env::remove_var("PAP_REGISTRY_RATE_LIMIT_RPS");
    }

    #[test]
    fn rate_limit_burst_zero_parses_as_zero_not_default() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_RATE_LIMIT_BURST", "0");

        let cfg = Config::from_env();
        assert_eq!(cfg.rate_limit_burst, 0, "zero is a valid parse result");

        env::remove_var("PAP_REGISTRY_RATE_LIMIT_BURST");
    }

    #[test]
    fn rate_limit_rps_u64_max_parses() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_RATE_LIMIT_RPS", &u64::MAX.to_string());

        let cfg = Config::from_env();
        assert_eq!(cfg.rate_limit_rps, u64::MAX);

        env::remove_var("PAP_REGISTRY_RATE_LIMIT_RPS");
    }

    // ── Edge cases: max_body_bytes zero / very large ───────────────────────────

    #[test]
    fn max_body_bytes_zero_parses_as_zero() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_MAX_BODY_BYTES", "0");

        let cfg = Config::from_env();
        // Zero is valid (means all bodies are rejected).
        assert_eq!(cfg.max_body_bytes, 0);

        env::remove_var("PAP_REGISTRY_MAX_BODY_BYTES");
    }

    #[test]
    fn max_body_bytes_negative_string_falls_back_to_default() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        // "-1" fails parse::<usize>() on all platforms (usize is unsigned)
        env::set_var("PAP_REGISTRY_MAX_BODY_BYTES", "-1");

        let cfg = Config::from_env();
        assert_eq!(cfg.max_body_bytes, DEFAULT_MAX_BODY_BYTES);

        env::remove_var("PAP_REGISTRY_MAX_BODY_BYTES");
    }

    // ── Edge cases: reset_db_confirm case insensitivity ───────────────────────

    #[test]
    fn reset_db_confirm_uppercase_works() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_RESET_DB", "true");
        env::set_var("PAP_REGISTRY_RESET_DB_CONFIRM", "YES-I-UNDERSTAND");

        let cfg = Config::from_env();
        assert!(
            cfg.reset_db_confirmed(),
            "uppercase YES-I-UNDERSTAND must be accepted"
        );

        env::remove_var("PAP_REGISTRY_RESET_DB");
        env::remove_var("PAP_REGISTRY_RESET_DB_CONFIRM");
    }

    #[test]
    fn reset_db_confirm_mixed_case_works() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_RESET_DB", "true");
        env::set_var("PAP_REGISTRY_RESET_DB_CONFIRM", "Yes-I-Understand");

        let cfg = Config::from_env();
        assert!(
            cfg.reset_db_confirmed(),
            "mixed-case Yes-I-Understand must be accepted"
        );

        env::remove_var("PAP_REGISTRY_RESET_DB");
        env::remove_var("PAP_REGISTRY_RESET_DB_CONFIRM");
    }

    #[test]
    fn reset_db_confirm_wrong_phrase_not_accepted() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_RESET_DB", "true");
        env::set_var("PAP_REGISTRY_RESET_DB_CONFIRM", "yes-please");

        let cfg = Config::from_env();
        assert!(
            !cfg.reset_db_confirmed(),
            "wrong confirmation phrase must not activate reset"
        );

        env::remove_var("PAP_REGISTRY_RESET_DB");
        env::remove_var("PAP_REGISTRY_RESET_DB_CONFIRM");
    }

    #[test]
    fn reset_db_confirm_empty_string_not_accepted() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_RESET_DB", "true");
        env::set_var("PAP_REGISTRY_RESET_DB_CONFIRM", "");

        let cfg = Config::from_env();
        assert!(
            !cfg.reset_db_confirmed(),
            "empty confirmation string must not activate reset"
        );

        env::remove_var("PAP_REGISTRY_RESET_DB");
        env::remove_var("PAP_REGISTRY_RESET_DB_CONFIRM");
    }

    // ── Edge cases: require_auth case insensitivity and "1" value ────────────

    #[test]
    fn require_auth_accepts_numeric_one() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_REQUIRE_AUTH", "1");

        let cfg = Config::from_env();
        assert!(
            cfg.require_auth,
            "PAP_REGISTRY_REQUIRE_AUTH=1 must enable require_auth"
        );

        env::remove_var("PAP_REGISTRY_REQUIRE_AUTH");
    }

    #[test]
    fn require_auth_false_string_not_accepted() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_REQUIRE_AUTH", "false");

        let cfg = Config::from_env();
        assert!(
            !cfg.require_auth,
            "PAP_REGISTRY_REQUIRE_AUTH=false must leave require_auth false"
        );

        env::remove_var("PAP_REGISTRY_REQUIRE_AUTH");
    }

    // ── Edge cases: no_tls boolean parsing ───────────────────────────────────

    #[test]
    fn no_tls_accepts_numeric_one() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_NO_TLS", "1");

        let cfg = Config::from_env();
        assert!(cfg.no_tls, "PAP_REGISTRY_NO_TLS=1 must enable no_tls");
        assert!(cfg.public_endpoint.starts_with("http://"));

        env::remove_var("PAP_REGISTRY_NO_TLS");
    }
}
