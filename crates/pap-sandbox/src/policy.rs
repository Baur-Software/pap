use serde::{Deserialize, Serialize};

use crate::os_capabilities;
use crate::receipt::{CapabilityProof, MemoryProtection};

/// Capability constraints applied to a sandboxed agent execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityPolicy {
    /// Maximum wall-clock seconds before the execution is killed.
    pub execution_timeout_secs: u64,
    /// Allow outbound network syscalls (socket/connect/sendto).
    pub network_allowed: bool,
    /// Allow filesystem reads beyond the sandbox scratch space.
    pub filesystem_allowed: bool,
    /// Allow spawning child processes (fork/exec/clone).
    pub subprocess_allowed: bool,
    /// Linux: raw seccomp-bpf filter bytecode serialised as hex.
    /// When `None`, the spawner builds a policy from the boolean flags above.
    pub seccomp_rules: Option<String>,
    /// BSD: pledge(2) promises string.
    /// When `None`, derived from boolean flags.
    pub pledge_promises: Option<String>,
    /// macOS: entitlement keys to apply.
    pub entitlements: Option<Vec<String>>,
    /// Whether to verify agent signatures on tokens and receipts.
    pub require_signature_validation: bool,
    /// Agent category used for cascade lookup (e.g. "external_api", "local").
    pub category: String,
}

impl Default for CapabilityPolicy {
    fn default() -> Self {
        Self {
            execution_timeout_secs: 30,
            network_allowed: false,
            filesystem_allowed: false,
            subprocess_allowed: false,
            seccomp_rules: None,
            pledge_promises: None,
            entitlements: None,
            require_signature_validation: true,
            category: "default".to_string(),
        }
    }
}

impl CapabilityPolicy {
    /// Resolve a final policy from three priority tiers:
    /// agent-specific override > category default > global default.
    pub fn resolve(
        agent_override: Option<CapabilityPolicy>,
        category_default: Option<CapabilityPolicy>,
        global_default: CapabilityPolicy,
    ) -> Self {
        agent_override
            .or(category_default)
            .unwrap_or(global_default)
    }

    /// Build a `CapabilityProof` reflecting what will *actually* be enforced
    /// on this OS — the intersection of what this policy requests and what the
    /// OS can deliver at runtime.
    ///
    /// Use this when constructing an `AttestationReceipt` so the receipt only
    /// claims enforcement for mechanisms that actually applied.
    pub fn effective_enforcement(&self) -> CapabilityProof {
        let caps = os_capabilities::detect();

        let seccomp_hash = if caps.seccomp_available {
            self.seccomp_rules.as_deref().map(|r| {
                use sha2::{Digest, Sha256};
                hex::encode(Sha256::digest(r.as_bytes()))
            })
        } else {
            None
        };

        let pledge = if caps.pledge_available {
            Some(self.effective_pledge_promises())
        } else {
            None
        };

        let entitlements = if caps.sandbox_framework_available {
            self.entitlements.clone()
        } else {
            None
        };

        CapabilityProof {
            seccomp_rules_hash: seccomp_hash,
            pledge_promises: pledge,
            entitlements_applied: entitlements,
            memory_protection: MemoryProtection {
                mlock_applied: caps.mlock_available,
                encryption_used: true,
                sensitive_buffers_wiped: true,
            },
            timeout_enforced_secs: self.execution_timeout_secs,
            network_blocked: !self.network_allowed && caps.network_restriction_available,
            filesystem_restricted: !self.filesystem_allowed
                && caps.filesystem_restriction_available,
            subprocess_blocked: !self.subprocess_allowed && caps.process_spawn_available,
        }
    }

    /// Return the pledge(2) promises string derived from boolean flags,
    /// falling back to an explicit override if provided.
    pub fn effective_pledge_promises(&self) -> String {
        if let Some(ref p) = self.pledge_promises {
            return p.clone();
        }
        let mut promises = vec!["stdio"];
        if self.filesystem_allowed {
            promises.push("rpath");
            promises.push("wpath");
            promises.push("cpath");
        }
        if self.network_allowed {
            promises.push("inet");
            promises.push("dns");
        }
        if self.subprocess_allowed {
            promises.push("proc");
            promises.push("exec");
        }
        promises.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_uses_agent_override_first() {
        let agent = CapabilityPolicy {
            execution_timeout_secs: 5,
            ..Default::default()
        };
        let result = CapabilityPolicy::resolve(Some(agent.clone()), None, Default::default());
        assert_eq!(result.execution_timeout_secs, 5);
    }

    #[test]
    fn resolve_falls_back_to_category() {
        let category = CapabilityPolicy {
            execution_timeout_secs: 60,
            ..Default::default()
        };
        let result = CapabilityPolicy::resolve(None, Some(category), Default::default());
        assert_eq!(result.execution_timeout_secs, 60);
    }

    #[test]
    fn resolve_falls_back_to_global() {
        let result = CapabilityPolicy::resolve(None, None, Default::default());
        assert_eq!(result.execution_timeout_secs, 30);
    }

    #[test]
    fn pledge_promises_derived_from_flags() {
        let policy = CapabilityPolicy {
            network_allowed: true,
            filesystem_allowed: false,
            ..Default::default()
        };
        let promises = policy.effective_pledge_promises();
        assert!(promises.contains("stdio"));
        assert!(promises.contains("inet"));
        assert!(!promises.contains("rpath"));
    }

    #[test]
    fn pledge_promises_override_wins() {
        let policy = CapabilityPolicy {
            network_allowed: true,
            pledge_promises: Some("stdio".to_string()),
            ..Default::default()
        };
        assert_eq!(policy.effective_pledge_promises(), "stdio");
    }
}
