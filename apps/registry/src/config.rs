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

    /// Allowed CORS origins.  Read from `PAP_REGISTRY_ALLOWED_ORIGINS` as a
    /// comma-separated list of exact origin strings, e.g.:
    ///   `http://localhost:3000,https://registry.example.com`
    ///
    /// Default (when the variable is unset or empty): `["http://localhost:7890",
    /// "https://localhost:7890"]` — local-dev only.
    ///
    /// Set to the literal string `"*"` to restore the open policy (not
    /// recommended outside air-gapped / fully-trusted networks).
    pub allowed_origins: AllowedOrigins,
}

/// CORS origin allowlist derived from `PAP_REGISTRY_ALLOWED_ORIGINS`.
#[derive(Debug, Clone)]
pub enum AllowedOrigins {
    /// Permit every origin (`*`).  Only use on fully-trusted networks.
    Any,
    /// Exact-match allowlist.  Cross-origin requests from any other origin are
    /// rejected at the CORS preflight stage.
    List(Vec<String>),
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

        let allowed_origins = parse_allowed_origins(
            env::var("PAP_REGISTRY_ALLOWED_ORIGINS").ok().as_deref(),
            no_tls,
            &host,
            port,
        );

        Self {
            port,
            host,
            admin_token,
            public_endpoint,
            no_tls,
            max_ads_per_principal,
            reset_db,
            allowed_origins,
        }
    }
}

/// Parse the `PAP_REGISTRY_ALLOWED_ORIGINS` value into an [`AllowedOrigins`].
///
/// Rules:
/// - `None` / empty string → local-dev default (`http(s)://localhost:<port>`)
/// - `"*"` → [`AllowedOrigins::Any`] (open policy — use with care)
/// - anything else → split on commas, trim whitespace, collect into
///   [`AllowedOrigins::List`]
pub(crate) fn parse_allowed_origins(
    raw: Option<&str>,
    no_tls: bool,
    host: &str,
    port: u16,
) -> AllowedOrigins {
    match raw {
        None | Some("") => {
            // Default: allow the node's own origin on both http and https so
            // the bundled admin UI always works out of the box.
            let scheme = if no_tls { "http" } else { "https" };
            // Include both localhost variants regardless of the bound host so
            // the admin UI works when the server binds 0.0.0.0 but the browser
            // hits localhost.
            let mut origins = vec![format!("{scheme}://localhost:{port}")];
            // If the operator explicitly set a non-wildcard host, include it
            // as well (e.g. 127.0.0.1 or a hostname).
            if host != "0.0.0.0" && host != "localhost" {
                origins.push(format!("{scheme}://{host}:{port}"));
            }
            AllowedOrigins::List(origins)
        }
        Some("*") => AllowedOrigins::Any,
        Some(list) => {
            let origins = list
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if origins.is_empty() {
                // Treat a string of only commas/spaces like unset.
                parse_allowed_origins(None, no_tls, host, port)
            } else {
                AllowedOrigins::List(origins)
            }
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
        env::remove_var("PAP_REGISTRY_NO_TLS");
        env::remove_var("PAP_REGISTRY_RESET_DB");
        env::remove_var("PAP_REGISTRY_ALLOWED_ORIGINS");
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

    // ── CORS origin allowlist ─────────────────────────────────────────────────

    #[test]
    fn allowed_origins_default_is_localhost_list() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();

        let config = Config::from_env();
        match &config.allowed_origins {
            AllowedOrigins::List(origins) => {
                assert!(
                    !origins.is_empty(),
                    "default allowlist must not be empty"
                );
                assert!(
                    origins.iter().any(|o| o.contains("localhost")),
                    "default allowlist must include localhost, got: {origins:?}"
                );
            }
            AllowedOrigins::Any => panic!("default must not be Any (open)"),
        }
    }

    #[test]
    fn allowed_origins_wildcard_becomes_any() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_ALLOWED_ORIGINS", "*");

        let config = Config::from_env();
        assert!(
            matches!(config.allowed_origins, AllowedOrigins::Any),
            "\"*\" must produce AllowedOrigins::Any"
        );

        env::remove_var("PAP_REGISTRY_ALLOWED_ORIGINS");
    }

    #[test]
    fn allowed_origins_list_parsed_correctly() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var(
            "PAP_REGISTRY_ALLOWED_ORIGINS",
            "https://registry.example.com, https://app.example.com",
        );

        let config = Config::from_env();
        match &config.allowed_origins {
            AllowedOrigins::List(origins) => {
                assert_eq!(origins.len(), 2);
                assert!(origins.contains(&"https://registry.example.com".to_owned()));
                assert!(origins.contains(&"https://app.example.com".to_owned()));
            }
            AllowedOrigins::Any => panic!("explicit list must not produce Any"),
        }

        env::remove_var("PAP_REGISTRY_ALLOWED_ORIGINS");
    }

    #[test]
    fn allowed_origins_empty_string_falls_back_to_default() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_registry_env();
        env::set_var("PAP_REGISTRY_ALLOWED_ORIGINS", "");

        let config = Config::from_env();
        assert!(
            matches!(config.allowed_origins, AllowedOrigins::List(_)),
            "empty string must fall back to default list"
        );

        env::remove_var("PAP_REGISTRY_ALLOWED_ORIGINS");
    }

    #[test]
    fn parse_allowed_origins_explicit_host_included_in_default() {
        use super::parse_allowed_origins;
        let origins = parse_allowed_origins(None, true, "192.168.1.10", 7890);
        match origins {
            AllowedOrigins::List(list) => {
                assert!(
                    list.contains(&"http://localhost:7890".to_owned()),
                    "localhost must always be in default list"
                );
                assert!(
                    list.contains(&"http://192.168.1.10:7890".to_owned()),
                    "explicit host must be included when not 0.0.0.0"
                );
            }
            AllowedOrigins::Any => panic!("must not be Any"),
        }
    }

    #[test]
    fn parse_allowed_origins_wildcard_host_not_duplicated() {
        use super::parse_allowed_origins;
        let origins = parse_allowed_origins(None, false, "0.0.0.0", 7890);
        match origins {
            AllowedOrigins::List(list) => {
                assert_eq!(
                    list.len(),
                    1,
                    "0.0.0.0 bind should produce exactly one default origin, got: {list:?}"
                );
                assert_eq!(list[0], "https://localhost:7890");
            }
            AllowedOrigins::Any => panic!("must not be Any"),
        }
    }
}
