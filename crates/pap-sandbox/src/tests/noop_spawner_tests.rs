#[cfg(test)]
mod tests {
    use crate::ipc::ExecutionContext;
    use crate::policy::CapabilityPolicy;
    use crate::spawner::{AgentSpawner, NoopSpawner};

    fn test_context() -> ExecutionContext {
        ExecutionContext {
            query_enc: vec![],
            disclosure_enc: vec![],
            session_token_enc: vec![],
            nonce: vec![],
            ephemeral_public_key: vec![],
            agent_did: "did:key:z6Mk...".to_string(),
            agent_name: "test-agent".to_string(),
            action_type: "test".to_string(),
            session_id: "session-123".to_string(),
        }
    }

    #[tokio::test]
    async fn test_noop_spawner_spawn_returns_error() {
        let spawner = NoopSpawner;
        let result = spawner.spawn(CapabilityPolicy::default(), test_context()).await;

        assert!(result.is_err(), "NoopSpawner::spawn must error");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("no sandbox implementation"),
            "error should explain why, got: {msg}"
        );
    }

    #[tokio::test]
    async fn test_noop_spawner_poll_state_returns_error() {
        let spawner = NoopSpawner;
        let handle = crate::spawner::ExecutionHandle::new("did:key:z6Mk...", "test-agent");

        let result = spawner.poll_state(&handle).await;
        assert!(result.is_err(), "NoopSpawner::poll_state must error");
    }

    #[tokio::test]
    async fn test_noop_spawner_collect_result_returns_error() {
        let spawner = NoopSpawner;
        let handle = crate::spawner::ExecutionHandle::new("did:key:z6Mk...", "test-agent");

        let result = spawner.collect_result(&handle).await;
        assert!(result.is_err(), "NoopSpawner::collect_result must error");
    }

    #[tokio::test]
    async fn test_noop_spawner_terminate_succeeds() {
        let spawner = NoopSpawner;
        let handle = crate::spawner::ExecutionHandle::new("did:key:z6Mk...", "test-agent");

        let result = spawner.terminate(&handle, "test termination").await;
        assert!(result.is_ok(), "terminate is idempotent, always succeeds");
    }
}
