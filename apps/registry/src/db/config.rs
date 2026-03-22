use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(tag = "driver", rename_all = "lowercase")]
pub enum DbConfig {
    Sqlite { url: Option<String> },
    Postgres { url: String },
}

impl DbConfig {
    /// Resolve the database config:
    /// 1. Read `db.yml` from the working directory if present.
    /// 2. Otherwise use `PAP_REGISTRY_DB` env var as a SQLite path.
    /// 3. Otherwise default to `./registry.db`.
    pub fn resolve() -> Self {
        if let Ok(text) = std::fs::read_to_string("db.yml") {
            match serde_yaml::from_str::<DbConfig>(&text) {
                Ok(cfg) => return cfg,
                Err(e) => panic!("db.yml is present but could not be parsed: {e}"),
            }
        }
        let path = std::env::var("PAP_REGISTRY_DB")
            .unwrap_or_else(|_| "./registry.db".into());
        DbConfig::Sqlite {
            url: Some(format!("sqlite:{path}?mode=rwc")),
        }
    }

    pub fn connection_string(&self) -> String {
        match self {
            DbConfig::Sqlite { url } => url
                .clone()
                .unwrap_or_else(|| "sqlite:./registry.db?mode=rwc".into()),
            DbConfig::Postgres { url } => url.clone(),
        }
    }
}
