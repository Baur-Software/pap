/// Bearer token validation with constant-time comparison.
///
/// This module provides secure token validation to prevent timing-based
/// token oracle attacks. When no token is configured, validation always passes.
#[derive(Debug, Clone)]
pub struct BearerTokenValidator {
    /// The expected token, if any. When None, validation always succeeds.
    expected_token: Option<String>,
}

impl BearerTokenValidator {
    /// Create a new validator from an optional token.
    pub fn new(token: Option<String>) -> Self {
        Self {
            expected_token: token,
        }
    }

    /// Validate an incoming Bearer token using constant-time comparison.
    ///
    /// Returns:
    /// - `true` if no token is configured (disabled mode)
    /// - `true` if the token matches the configured token
    /// - `false` if a token is expected but not provided or doesn't match
    pub fn validate(&self, incoming_token: Option<&str>) -> bool {
        match &self.expected_token {
            None => true, // No token configured — always allow
            Some(expected) => incoming_token
                .map(|t| constant_time_eq::constant_time_eq(t.as_bytes(), expected.as_bytes()))
                .unwrap_or(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bearer_token_valid() {
        let validator = BearerTokenValidator::new(Some("secret-token".to_string()));
        assert!(validator.validate(Some("secret-token")));
    }

    #[test]
    fn test_bearer_token_invalid() {
        let validator = BearerTokenValidator::new(Some("secret-token".to_string()));
        assert!(!validator.validate(Some("wrong-token")));
        assert!(!validator.validate(None));
    }

    #[test]
    fn test_bearer_token_none_disables_check() {
        let validator = BearerTokenValidator::new(None);
        assert!(validator.validate(Some("anything")));
        assert!(validator.validate(None));
    }
}
