use crate::policy::CapabilityPolicy;

#[test]
fn cascade_agent_override_wins_over_category_and_global() {
    let agent = CapabilityPolicy {
        execution_timeout_secs: 5,
        network_allowed: true,
        ..Default::default()
    };
    let category = CapabilityPolicy {
        execution_timeout_secs: 60,
        ..Default::default()
    };
    let global = CapabilityPolicy {
        execution_timeout_secs: 30,
        ..Default::default()
    };
    let resolved = CapabilityPolicy::resolve(Some(agent), Some(category), global);
    assert_eq!(resolved.execution_timeout_secs, 5);
    assert!(resolved.network_allowed);
}

#[test]
fn cascade_category_wins_over_global_when_no_agent_override() {
    let category = CapabilityPolicy {
        execution_timeout_secs: 120,
        filesystem_allowed: true,
        ..Default::default()
    };
    let global = CapabilityPolicy::default();
    let resolved = CapabilityPolicy::resolve(None, Some(category), global);
    assert_eq!(resolved.execution_timeout_secs, 120);
    assert!(resolved.filesystem_allowed);
}

#[test]
fn cascade_global_used_when_no_overrides() {
    let global = CapabilityPolicy {
        execution_timeout_secs: 10,
        ..Default::default()
    };
    let resolved = CapabilityPolicy::resolve(None, None, global);
    assert_eq!(resolved.execution_timeout_secs, 10);
}

#[test]
fn pledge_promises_derived_for_network_agent() {
    let p = CapabilityPolicy {
        network_allowed: true,
        filesystem_allowed: false,
        subprocess_allowed: false,
        ..Default::default()
    };
    let promises = p.effective_pledge_promises();
    assert!(promises.contains("inet"), "network should add 'inet'");
    assert!(promises.contains("stdio"), "stdio always included");
    assert!(!promises.contains("rpath"), "filesystem off");
    assert!(!promises.contains("proc"), "subprocess off");
}

#[test]
fn pledge_explicit_override_is_not_derived() {
    let p = CapabilityPolicy {
        network_allowed: true,
        pledge_promises: Some("stdio rpath".to_string()),
        ..Default::default()
    };
    // Explicit override — network_allowed=true is ignored
    assert_eq!(p.effective_pledge_promises(), "stdio rpath");
}

#[test]
fn default_policy_denies_network_filesystem_subprocess() {
    let p = CapabilityPolicy::default();
    assert!(!p.network_allowed);
    assert!(!p.filesystem_allowed);
    assert!(!p.subprocess_allowed);
    assert!(p.require_signature_validation);
}
