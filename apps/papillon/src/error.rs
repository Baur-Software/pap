use serde::Serialize;

/// Serializable error type for Tauri command responses.
#[derive(Debug, Clone, Serialize)]
pub struct PapillonError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for PapillonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl From<String> for PapillonError {
    fn from(msg: String) -> Self {
        Self {
            code: "INTERNAL".into(),
            message: msg,
        }
    }
}

impl From<&str> for PapillonError {
    fn from(msg: &str) -> Self {
        Self {
            code: "INTERNAL".into(),
            message: msg.to_string(),
        }
    }
}
