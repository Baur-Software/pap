use crate::receipt::{AttestationReceipt, CapabilityProof, MemoryProtection};

fn test_proof() -> CapabilityProof {
    CapabilityProof {
        seccomp_rules_hash: Some("abc123".to_string()),
        pledge_promises: None,
        entitlements_applied: None,
        memory_protection: MemoryProtection {
            mlock_applied: true,
            encryption_used: true,
            sensitive_buffers_wiped: true,
        },
        timeout_enforced_secs: 30,
        network_blocked: true,
        filesystem_restricted: true,
        subprocess_blocked: true,
    }
}

#[test]
fn hash_result_is_hex_sha256() {
    let val = serde_json::json!({ "@type": "SearchResultsPage" });
    let hash = AttestationReceipt::hash_result(&val);
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn hash_result_changes_with_content() {
    let v1 = serde_json::json!({ "name": "alpha" });
    let v2 = serde_json::json!({ "name": "beta" });
    assert_ne!(
        AttestationReceipt::hash_result(&v1),
        AttestationReceipt::hash_result(&v2)
    );
}

#[test]
fn timeout_receipt_has_correct_fields() {
    let r = AttestationReceipt::timeout(
        "session-1".into(),
        "did:key:z6Mk".into(),
        "TestAgent".into(),
        "schema:SearchAction".into(),
        10_500,
        test_proof(),
    );
    assert!(r.aborted);
    assert_eq!(r.exit_code, -1);
    assert_eq!(r.execution_duration_ms, 10_500);
    let reason = r.abort_reason.unwrap();
    assert!(reason.contains("timeout"));
}

#[test]
fn killed_receipt_records_reason() {
    let r = AttestationReceipt::killed(
        "session-2".into(),
        "did:key:z6Mk".into(),
        "TestAgent".into(),
        "schema:SearchAction".into(),
        3_000,
        "user rejected".into(),
        test_proof(),
    );
    assert!(r.aborted);
    assert_eq!(r.abort_reason.unwrap(), "user rejected");
}

#[test]
fn receipt_serializes_and_deserializes() {
    let r = AttestationReceipt::timeout(
        "sid".into(),
        "did:key:z".into(),
        "Agent".into(),
        "schema:SearchAction".into(),
        1000,
        test_proof(),
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: AttestationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back.session_id, r.session_id);
    assert_eq!(back.aborted, r.aborted);
}
