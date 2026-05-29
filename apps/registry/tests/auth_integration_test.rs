#[cfg(test)]
mod auth_integration {
    use pap_registry::auth::BearerTokenValidator;

    #[test]
    fn test_bearer_token_middleware_accepts_valid_token() {
        let token = "secret-token".to_string();
        let validator = BearerTokenValidator::new(Some(token));

        // Simulate middleware check
        let result = validator.validate(Some("secret-token"));
        assert!(result, "Valid token should be accepted");
    }

    #[test]
    fn test_bearer_token_middleware_rejects_invalid_token() {
        let token = "secret-token".to_string();
        let validator = BearerTokenValidator::new(Some(token));

        let result = validator.validate(Some("wrong-token"));
        assert!(!result, "Invalid token should be rejected");

        // Also test with None (no token provided)
        let result_none = validator.validate(None);
        assert!(!result_none, "Missing token should be rejected");
    }

    #[test]
    fn test_bearer_token_middleware_allows_any_when_disabled() {
        let validator = BearerTokenValidator::new(None);

        // When no token is configured, any token should be accepted
        assert!(validator.validate(Some("anything")));
        assert!(validator.validate(Some("")));
        assert!(validator.validate(None));
    }

    #[test]
    fn test_bearer_token_uses_constant_time_comparison() {
        let token = "secret".to_string();
        let validator = BearerTokenValidator::new(Some(token));

        // Constant-time comparison should prevent timing attacks
        let result1 = validator.validate(Some("secret"));
        let result2 = validator.validate(Some("wrong"));

        // Both should complete in similar time (can't easily test this,
        // but the implementation uses constant_time_eq)
        assert!(result1, "Valid token should return true");
        assert!(!result2, "Invalid token should return false");
    }
}
