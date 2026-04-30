use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Proof that specific capability constraints were enforced during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityProof {
    /// SHA-256 hex hash of the seccomp BPF bytecode applied (Linux only).
    pub seccomp_rules_hash: Option<String>,
    /// Exact pledge(2) promises applied (BSD only).
    pub pledge_promises: Option<String>,
    /// macOS entitlement keys applied.
    pub entitlements_applied: Option<Vec<String>>,
    /// Memory protection details.
    pub memory_protection: MemoryProtection,
    /// Timeout value that was enforced.
    pub timeout_enforced_secs: u64,
    /// Whether network access was denied.
    pub network_blocked: bool,
    /// Whether filesystem access was restricted.
    pub filesystem_restricted: bool,
    /// Whether subprocess spawning was denied.
    pub subprocess_blocked: bool,
}

/// Memory protection applied during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProtection {
    /// Whether mlock(2) was called to pin buffers to physical RAM.
    pub mlock_applied: bool,
    /// Whether execution context was encrypted before IPC transfer.
    pub encryption_used: bool,
    /// Whether sensitive buffers were zeroed after use.
    pub sensitive_buffers_wiped: bool,
}

/// Cryptographically attestable record of a completed (or aborted) agent execution.
/// Embedded in phase 5 co-signing: the principal signs this to produce a
/// transaction-level proof of enforcement constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReceipt {
    pub session_id: String,
    pub agent_did: String,
    pub agent_name: String,
    pub action_type: String,
    pub timestamp: DateTime<Utc>,
    pub execution_duration_ms: u64,
    pub capability_enforcement: CapabilityProof,
    /// SHA-256 hex hash of the execution result value.
    /// Per PAP spec: hash only, never the value itself.
    pub result_hash: String,
    /// OS process exit code.
    pub exit_code: i32,
    /// Whether execution completed normally or was aborted.
    pub aborted: bool,
    /// Reason for abort, if any.
    pub abort_reason: Option<String>,
}

impl AttestationReceipt {
    /// Hash a JSON result value for inclusion in the receipt.
    pub fn hash_result(result: &serde_json::Value) -> String {
        let serialized = result.to_string();
        let digest = Sha256::digest(serialized.as_bytes());
        hex::encode(digest)
    }

    /// Build a receipt for a timed-out execution.
    pub fn timeout(
        session_id: String,
        agent_did: String,
        agent_name: String,
        action_type: String,
        elapsed_ms: u64,
        proof: CapabilityProof,
    ) -> Self {
        Self {
            session_id,
            agent_did,
            agent_name,
            action_type,
            timestamp: Utc::now(),
            execution_duration_ms: elapsed_ms,
            capability_enforcement: proof,
            result_hash: String::new(),
            exit_code: -1,
            aborted: true,
            abort_reason: Some("execution timeout exceeded".to_string()),
        }
    }

    /// Build a receipt for a user-terminated execution.
    pub fn killed(
        session_id: String,
        agent_did: String,
        agent_name: String,
        action_type: String,
        elapsed_ms: u64,
        reason: String,
        proof: CapabilityProof,
    ) -> Self {
        Self {
            session_id,
            agent_did,
            agent_name,
            action_type,
            timestamp: Utc::now(),
            execution_duration_ms: elapsed_ms,
            capability_enforcement: proof,
            result_hash: String::new(),
            exit_code: -1,
            aborted: true,
            abort_reason: Some(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_result_is_deterministic() {
        let val = serde_json::json!({"@type": "Thing", "name": "test"});
        let h1 = AttestationReceipt::hash_result(&val);
        let h2 = AttestationReceipt::hash_result(&val);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn hash_result_differs_for_different_values() {
        let a = serde_json::json!({"name": "a"});
        let b = serde_json::json!({"name": "b"});
        assert_ne!(
            AttestationReceipt::hash_result(&a),
            AttestationReceipt::hash_result(&b)
        );
    }

    #[test]
    fn timeout_receipt_is_marked_aborted() {
        let proof = CapabilityProof {
            seccomp_rules_hash: None,
            pledge_promises: None,
            entitlements_applied: None,
            memory_protection: MemoryProtection {
                mlock_applied: false,
                encryption_used: false,
                sensitive_buffers_wiped: false,
            },
            timeout_enforced_secs: 5,
            network_blocked: true,
            filesystem_restricted: true,
            subprocess_blocked: true,
        };
        let r = AttestationReceipt::timeout(
            "sid".into(),
            "did:key:z123".into(),
            "TestAgent".into(),
            "schema:SearchAction".into(),
            5100,
            proof,
        );
        assert!(r.aborted);
        assert_eq!(r.exit_code, -1);
        assert!(r.abort_reason.unwrap().contains("timeout"));
    }
}
