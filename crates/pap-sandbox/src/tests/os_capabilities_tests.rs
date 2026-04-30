use crate::os_capabilities::detect;
use crate::policy::CapabilityPolicy;

#[test]
fn detect_is_cached_same_pointer() {
    let a = detect();
    let b = detect();
    assert!(
        std::ptr::eq(a, b),
        "detect() should return the same cached pointer"
    );
}

#[test]
fn platform_is_non_empty_and_known() {
    let caps = detect();
    assert!(!caps.platform.is_empty());
    // Must be one of the known platforms — "unknown" means the cfg ladder has a gap.
    assert_ne!(caps.platform, "unknown", "platform reported as 'unknown'");
}

#[test]
fn effective_enforcement_timeout_matches_policy() {
    let policy = CapabilityPolicy {
        execution_timeout_secs: 42,
        ..Default::default()
    };
    let proof = policy.effective_enforcement();
    assert_eq!(proof.timeout_enforced_secs, 42);
}

#[test]
fn effective_enforcement_encryption_always_true() {
    let proof = CapabilityPolicy::default().effective_enforcement();
    assert!(proof.memory_protection.encryption_used);
    assert!(proof.memory_protection.sensitive_buffers_wiped);
}

#[test]
fn effective_enforcement_network_blocked_when_not_allowed() {
    let caps = detect();
    let policy = CapabilityPolicy {
        network_allowed: false,
        ..Default::default()
    };
    let proof = policy.effective_enforcement();
    // network_blocked is only true when the OS can actually enforce it
    if caps.network_restriction_available {
        assert!(proof.network_blocked);
    } else {
        assert!(
            !proof.network_blocked,
            "cannot claim network blocked without OS support"
        );
    }
}

#[test]
fn effective_enforcement_network_not_blocked_when_allowed() {
    let policy = CapabilityPolicy {
        network_allowed: true,
        ..Default::default()
    };
    let proof = policy.effective_enforcement();
    // If the policy allows network, we must NOT claim it's blocked
    assert!(!proof.network_blocked);
}

#[test]
fn effective_enforcement_mlock_reflects_os_capability() {
    let caps = detect();
    let proof = CapabilityPolicy::default().effective_enforcement();
    // mlock_applied in the proof must match what the OS reported
    assert_eq!(proof.memory_protection.mlock_applied, caps.mlock_available);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_seccomp_field_is_set_when_available() {
    let caps = detect();
    if caps.seccomp_available {
        // With explicit rules, hash should appear in proof
        let policy = CapabilityPolicy {
            seccomp_rules: Some("allow-all".to_string()),
            ..Default::default()
        };
        let proof = policy.effective_enforcement();
        assert!(
            proof.seccomp_rules_hash.is_some(),
            "seccomp hash missing despite seccomp_available=true"
        );
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn non_linux_seccomp_hash_is_none() {
    let proof = CapabilityPolicy {
        seccomp_rules: Some("anything".to_string()),
        ..Default::default()
    }
    .effective_enforcement();
    assert!(
        proof.seccomp_rules_hash.is_none(),
        "seccomp hash should be None on non-Linux"
    );
}
