//! Protocol extensions from PAP v0.1 spec sections 9.1–9.4.
//! These are not required for a minimal compliant implementation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::PapError;
use crate::scope::Scope;

// ─── 9.3 Continuity Tokens ─────────────────────────────────────────

/// Encrypted relationship state that a vendor writes at session close
/// and hands to the orchestrator. The orchestrator stores it locally.
/// When the principal returns, they present the token. The vendor
/// decrypts it and has full context. If the principal wants to sever
/// the relationship, they delete the token.
///
/// The vendor cannot write to the continuity token without the
/// principal presenting it. TTL is set by the principal, not the vendor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuityToken {
    /// Schema.org type describing the shape of the encrypted payload,
    /// inspectable by the orchestrator without decrypting
    pub schema_type: String,
    /// The vendor's DID that issued this token
    pub vendor_did: String,
    /// Encrypted payload — only the vendor can decrypt
    pub encrypted_payload: String,
    /// TTL set by the principal, not the vendor
    pub ttl: DateTime<Utc>,
    /// When the token was issued
    pub issued_at: DateTime<Utc>,
}

impl ContinuityToken {
    /// Create a new continuity token.
    pub fn new(
        schema_type: impl Into<String>,
        vendor_did: impl Into<String>,
        encrypted_payload: impl Into<String>,
        ttl: DateTime<Utc>,
    ) -> Self {
        Self {
            schema_type: schema_type.into(),
            vendor_did: vendor_did.into(),
            encrypted_payload: encrypted_payload.into(),
            ttl,
            issued_at: Utc::now(),
        }
    }

    /// Check if the token has expired (principal-controlled TTL).
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.ttl
    }
}

// ─── 9.4 Auto-Approval Tiers ───────────────────────────────────────

/// A principal-authored policy for automatic approval of micro-transactions.
/// Cannot be more permissive than the underlying mandate. An agent cannot
/// trigger a policy change by requesting it. Policies are principal-authored
/// and orchestrator-enforced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoApprovalPolicy {
    /// Human-readable policy name
    pub name: String,
    /// The scope this policy applies to — must be a subset of the
    /// mandate's scope (a constraint, not an expansion)
    pub scope: Scope,
    /// Maximum transaction value for auto-approval (currency-agnostic)
    pub max_value: Option<f64>,
    /// If true, only auto-approve when zero additional disclosure is
    /// required beyond what the mandate already covers
    pub zero_additional_disclosure: bool,
    /// When this policy was authored by the principal
    pub authored_at: DateTime<Utc>,
}

impl AutoApprovalPolicy {
    pub fn new(name: impl Into<String>, scope: Scope) -> Self {
        Self {
            name: name.into(),
            scope,
            max_value: None,
            zero_additional_disclosure: true,
            authored_at: Utc::now(),
        }
    }

    pub fn with_max_value(mut self, max_value: f64) -> Self {
        self.max_value = Some(max_value);
        self
    }

    pub fn allow_additional_disclosure(mut self) -> Self {
        self.zero_additional_disclosure = false;
        self
    }

    /// Validate that this policy does not exceed the given mandate scope.
    /// Auto-approval policies cannot be more permissive than the mandate.
    pub fn validate_against_mandate(&self, mandate_scope: &Scope) -> Result<(), PapError> {
        if mandate_scope.contains(&self.scope) {
            Ok(())
        } else {
            Err(PapError::PolicyExceedsMandate)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::ScopeAction;
    use chrono::Duration;

    #[test]
    fn continuity_token_creation_and_expiry() {
        let token = ContinuityToken::new(
            "schema:Order",
            "did:key:zvendor",
            "encrypted-blob-here",
            Utc::now() + Duration::hours(24),
        );

        assert_eq!(token.schema_type, "schema:Order");
        assert!(!token.is_expired());
    }

    #[test]
    fn continuity_token_expired() {
        let token = ContinuityToken::new(
            "schema:Order",
            "did:key:zvendor",
            "encrypted-blob",
            Utc::now() - Duration::hours(1), // already expired
        );
        assert!(token.is_expired());
    }

    #[test]
    fn continuity_token_serialization_roundtrip() {
        let token = ContinuityToken::new(
            "schema:Subscription",
            "did:key:zvendor",
            "encrypted-state",
            Utc::now() + Duration::hours(72),
        );
        let json = serde_json::to_string(&token).unwrap();
        let token2: ContinuityToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token.vendor_did, token2.vendor_did);
        assert_eq!(token.schema_type, token2.schema_type);
    }

    #[test]
    fn auto_approval_within_mandate() {
        let mandate_scope = Scope::new(vec![
            ScopeAction::new("schema:SearchAction"),
            ScopeAction::new("schema:PayAction"),
        ]);

        let policy = AutoApprovalPolicy::new(
            "Auto-approve search",
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
        );

        assert!(policy.validate_against_mandate(&mandate_scope).is_ok());
    }

    #[test]
    fn auto_approval_exceeds_mandate_rejected() {
        let mandate_scope = Scope::new(vec![ScopeAction::new("schema:SearchAction")]);

        let policy = AutoApprovalPolicy::new(
            "Auto-approve payments",
            Scope::new(vec![ScopeAction::new("schema:PayAction")]),
        );

        assert!(matches!(
            policy.validate_against_mandate(&mandate_scope),
            Err(PapError::PolicyExceedsMandate)
        ));
    }

    #[test]
    fn auto_approval_with_value_cap() {
        let policy = AutoApprovalPolicy::new(
            "Small purchases",
            Scope::new(vec![ScopeAction::new("schema:PayAction")]),
        )
        .with_max_value(20.0);

        assert_eq!(policy.max_value, Some(20.0));
        assert!(policy.zero_additional_disclosure); // default: require zero extra disclosure
    }

    #[test]
    fn auto_approval_defaults_to_zero_disclosure() {
        let policy = AutoApprovalPolicy::new(
            "Default policy",
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
        );
        assert!(policy.zero_additional_disclosure);
    }
}
