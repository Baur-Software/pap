use anyhow::{Context, Result};
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
    pub fn resolve() -> Result<Self> {
        if let Ok(text) = std::fs::read_to_string("db.yml") {
            return serde_yaml::from_str::<DbConfig>(&text)
                .context("db.yml is present but could not be parsed");
        }
        let path = std::env::var("PAP_REGISTRY_DB").unwrap_or_else(|_| "./registry.db".into());
        Ok(DbConfig::Sqlite {
            url: Some(format!("sqlite:{path}?mode=rwc")),
        })
    }

    pub fn connection_string(&self) -> String {
        match self {
            DbConfig::Sqlite { url } => url
                .clone()
                .unwrap_or_else(|| "sqlite:./registry.db?mode=rwc".into()),
            DbConfig::Postgres { url } => url.clone(),
        }
    }

    /// Return the on-disk file path for a SQLite database, stripping the
    /// `sqlite:` scheme prefix and `?mode=rwc` query string.  Returns `None`
    /// for Postgres configurations or in-memory (`sqlite::memory:`) URLs.
    pub fn sqlite_file_path(&self) -> Option<String> {
        match self {
            DbConfig::Sqlite { url } => {
                let raw = url.as_deref().unwrap_or("sqlite:./registry.db?mode=rwc");
                let path = raw.strip_prefix("sqlite:")?;
                // Exclude the special in-memory designator.
                if path.starts_with(':') {
                    return None;
                }
                Some(path.split('?').next().unwrap_or(path).to_string())
            }
            DbConfig::Postgres { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_file_path_extracts_path() {
        let cfg = DbConfig::Sqlite {
            url: Some("sqlite:/data/registry.db?mode=rwc".into()),
        };
        assert_eq!(cfg.sqlite_file_path(), Some("/data/registry.db".into()));
    }

    #[test]
    fn sqlite_file_path_relative() {
        let cfg = DbConfig::Sqlite {
            url: Some("sqlite:./registry.db?mode=rwc".into()),
        };
        assert_eq!(cfg.sqlite_file_path(), Some("./registry.db".into()));
    }

    #[test]
    fn sqlite_file_path_no_query_string() {
        let cfg = DbConfig::Sqlite {
            url: Some("sqlite:/data/registry.db".into()),
        };
        assert_eq!(cfg.sqlite_file_path(), Some("/data/registry.db".into()));
    }

    #[test]
    fn sqlite_file_path_in_memory_returns_none() {
        let cfg = DbConfig::Sqlite {
            url: Some("sqlite::memory:".into()),
        };
        assert_eq!(cfg.sqlite_file_path(), None);
    }

    #[test]
    fn sqlite_file_path_none_url_uses_default() {
        let cfg = DbConfig::Sqlite { url: None };
        assert_eq!(cfg.sqlite_file_path(), Some("./registry.db".into()));
    }

    #[test]
    fn sqlite_file_path_postgres_returns_none() {
        let cfg = DbConfig::Postgres {
            url: "postgres://localhost/registry".into(),
        };
        assert_eq!(cfg.sqlite_file_path(), None);
    }

    #[test]
    fn connection_string_sqlite_default() {
        let cfg = DbConfig::Sqlite { url: None };
        assert_eq!(cfg.connection_string(), "sqlite:./registry.db?mode=rwc");
    }

    #[test]
    fn connection_string_postgres() {
        let url = "postgres://localhost/registry".to_string();
        let cfg = DbConfig::Postgres { url: url.clone() };
        assert_eq!(cfg.connection_string(), url);
    }
}
