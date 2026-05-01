#[cfg(test)]
mod tests {
    use crate::ipc::ExecutionContext;
    use crate::policy::CapabilityPolicy;
    use crate::spawner::{AgentSpawner, ExecutionState, NoopSpawner};

    #[tokio::test]
    async fn test_noop_spawner_spawn_returns_handle() {
        let spawner = NoopSpawner;
        let context = ExecutionContext {
            query_enc: vec![],
            disclosure_enc: vec![],
            session_token_enc: vec![],
            nonce: vec![],
            ephemeral_public_key: vec![],
            agent_did: "did:key:z6Mk...".to_string(),
            agent_name: "test-agent".to_string(),
            action_type: "test".to_string(),
            session_id: "session-123".to_string(),
        };

        let policy = CapabilityPolicy::default();

        let result = spawner.spawn(policy, context).await;
        assert!(result.is_ok(), "NoopSpawner should always return Ok");

        let handle = result.unwrap();
        assert!(!handle.id.is_empty());
        assert_eq!(handle.agent_did, "did:key:z6Mk...");
        assert_eq!(handle.agent_name, "test-agent");
    }

    #[tokio::test]
    async fn test_noop_spawner_poll_state_immediately_completed() {
        let spawner = NoopSpawner;
        let context = ExecutionContext {
            query_enc: vec![],
            disclosure_enc: vec![],
            session_token_enc: vec![],
            nonce: vec![],
            ephemeral_public_key: vec![],
            agent_did: "did:key:z6Mk...".to_string(),
            agent_name: "test-agent".to_string(),
            action_type: "test".to_string(),
            session_id: "session-123".to_string(),
        };

        let policy = CapabilityPolicy::default();
        let handle = spawner.spawn(policy, context).await.unwrap();

        let state = spawner.poll_state(&handle).await;
        assert!(state.is_ok(), "poll_state should return Ok");

        match state.unwrap() {
            ExecutionState::Completed {
                exit_code,
                elapsed_ms,
            } => {
                assert_eq!(exit_code, 0);
                assert_eq!(elapsed_ms, 0);
            }
            _ => panic!("NoopSpawner should report Completed state"),
        }
    }

    #[tokio::test]
    async fn test_noop_spawner_collect_result_generates_receipt() {
        let spawner = NoopSpawner;
        let context = ExecutionContext {
            query_enc: vec![],
            disclosure_enc: vec![],
            session_token_enc: vec![],
            nonce: vec![],
            ephemeral_public_key: vec![],
            agent_did: "did:key:z6Mk...".to_string(),
            agent_name: "test-agent".to_string(),
            action_type: "test".to_string(),
            session_id: "session-123".to_string(),
        };

        let policy = CapabilityPolicy::default();
        let handle = spawner.spawn(policy, context).await.unwrap();

        let result = spawner.collect_result(&handle).await;
        assert!(result.is_ok(), "collect_result should return Ok");

        let (_exec_result, receipt) = result.unwrap();

        // Receipt should have empty capability proof (no isolation).
        assert!(receipt.capability_enforcement.seccomp_rules_hash.is_none());
        assert!(receipt.capability_enforcement.pledge_promises.is_none());
        assert!(receipt.capability_enforcement.entitlements_applied.is_none());

        // All protections should be false (no isolation).
        assert!(!receipt.capability_enforcement.memory_protection.mlock_applied);
        assert!(!receipt.capability_enforcement.memory_protection.encryption_used);
        assert!(!receipt.capability_enforcement.memory_protection.sensitive_buffers_wiped);

        // No capability blocking.
        assert!(!receipt.capability_enforcement.network_blocked);
        assert!(!receipt.capability_enforcement.filesystem_restricted);
        assert!(!receipt.capability_enforcement.subprocess_blocked);

        assert_eq!(receipt.exit_code, 0);
        assert!(!receipt.aborted);
    }

    #[tokio::test]
    async fn test_noop_spawner_terminate_succeeds() {
        let spawner = NoopSpawner;
        let context = ExecutionContext {
            query_enc: vec![],
            disclosure_enc: vec![],
            session_token_enc: vec![],
            nonce: vec![],
            ephemeral_public_key: vec![],
            agent_did: "did:key:z6Mk...".to_string(),
            agent_name: "test-agent".to_string(),
            action_type: "test".to_string(),
            session_id: "session-123".to_string(),
        };

        let policy = CapabilityPolicy::default();
        let handle = spawner.spawn(policy, context).await.unwrap();

        let result = spawner.terminate(&handle, "test termination").await;
        assert!(result.is_ok(), "terminate should always succeed");
    }
}
