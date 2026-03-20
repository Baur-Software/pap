use serde::Serialize;

/// Serializable error type for Tauri command responses.
#[derive(Debug, Clone, Serialize)]
pub struct PapillionError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for PapillionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl From<String> for PapillionError {
    fn from(msg: String) -> Self {
        Self {
            code: "INTERNAL".into(),
            message: msg,
        }
    }
}

impl From<&str> for PapillionError {
    fn from(msg: &str) -> Self {
        Self {
            code: "INTERNAL".into(),
            message: msg.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_string() {
        let err = PapillionError::from("something went wrong".to_string());
        assert_eq!(err.code, "INTERNAL");
        assert_eq!(err.message, "something went wrong");
    }

    #[test]
    fn from_str() {
        let err = PapillionError::from("bad input");
        assert_eq!(err.code, "INTERNAL");
        assert_eq!(err.message, "bad input");
    }

    #[test]
    fn display_format() {
        let err = PapillionError {
            code: "NOT_FOUND".into(),
            message: "Agent not found".into(),
        };
        assert_eq!(format!("{err}"), "NOT_FOUND: Agent not found");
    }

    #[test]
    fn display_internal_format() {
        let err = PapillionError::from("test error");
        assert_eq!(format!("{err}"), "INTERNAL: test error");
    }

    #[test]
    fn clone_preserves_fields() {
        let err = PapillionError {
            code: "TIMEOUT".into(),
            message: "Connection timed out".into(),
        };
        let cloned = err.clone();
        assert_eq!(cloned.code, "TIMEOUT");
        assert_eq!(cloned.message, "Connection timed out");
    }

    #[test]
    fn serialize_json() {
        let err = PapillionError::from("test");
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("INTERNAL"));
        assert!(json.contains("test"));
    }
}
