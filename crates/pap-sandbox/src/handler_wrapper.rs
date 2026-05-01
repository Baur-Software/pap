//! `SandboxedHandlerWrapper` — composes an `AgentHandler` with an `AgentSpawner`.
//!
//! All six PAP protocol phases are delegated to the inner handler unchanged.
//! Phase 4 (`execute`) is the exception: when sandbox is enabled the wrapper
//! drives the full spawn → poll → collect cycle through the `AgentSpawner`,
//! then returns the decrypted result to the transport layer as if the inner
//! handler had produced it directly.
//!
//! `AgentHandler::execute` is synchronous (called inside
//! `tokio::task::spawn_blocking` by `AgentServer`).  The async spawner is
//! driven via `tokio::runtime::Handle::current().block_on(...)`.

use std::sync::Arc;
use std::time::Duration;

use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_transport::error::TransportError;
use pap_transport::handler::AgentHandler;

use crate::error::SandboxError;
use crate::ipc::{decrypt, encrypt, ExecutionContext};
use crate::policy::CapabilityPolicy;
use crate::spawner::{AgentSpawner, ExecutionState};

/// Wraps an `AgentHandler` with optional sandbox execution enforcement.
///
/// - `sandbox_enabled = true`: `execute()` runs the inner handler inside a
///   sandboxed child process managed by `spawner`.
/// - `sandbox_enabled = false`: `execute()` is delegated directly to the inner
///   handler with no isolation — equivalent to the original unsandboxed path.
pub struct SandboxedHandlerWrapper {
    inner: Arc<dyn AgentHandler>,
    spawner: Arc<dyn AgentSpawner>,
    policy: CapabilityPolicy,
    sandbox_enabled: bool,
    /// Agent DID, name, and action_type for receipt construction.
    agent_did: String,
    agent_name: String,
    action_type: String,
}

impl SandboxedHandlerWrapper {
    pub fn new(
        inner: Arc<dyn AgentHandler>,
        spawner: Arc<dyn AgentSpawner>,
        policy: CapabilityPolicy,
        sandbox_enabled: bool,
        agent_did: impl Into<String>,
        agent_name: impl Into<String>,
        action_type: impl Into<String>,
    ) -> Self {
        Self {
            inner,
            spawner,
            policy,
            sandbox_enabled,
            agent_did: agent_did.into(),
            agent_name: agent_name.into(),
            action_type: action_type.into(),
        }
    }

    fn execute_sandboxed(&self, session_id: &str) -> Result<serde_json::Value, TransportError> {
        let handle = tokio::runtime::Handle::current();

        // Build an encrypted execution context.  The "query" here is the
        // session_id — the child process resolves the actual session state
        // from its own handler instance.  The symmetric key is ephemeral;
        // for the registry use-case the child runs in-process, so the key
        // is shared through the context envelope itself.
        let ephemeral_key: [u8; 32] = {
            use rand::RngCore;
            let mut k = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut k);
            k
        };

        let (query_enc, nonce) =
            encrypt(session_id.as_bytes(), &ephemeral_key).map_err(sandbox_to_transport)?;

        let context = ExecutionContext {
            query_enc,
            disclosure_enc: vec![],
            session_token_enc: vec![],
            nonce,
            ephemeral_public_key: ephemeral_key.to_vec(), // simplified: key in-band
            agent_did: self.agent_did.clone(),
            agent_name: self.agent_name.clone(),
            action_type: self.action_type.clone(),
            session_id: session_id.to_string(),
        };

        // Spawn the sandboxed process.
        let exec_handle = handle
            .block_on(self.spawner.spawn(self.policy.clone(), context))
            .map_err(sandbox_to_transport)?;

        // Poll until completion or timeout.  Use saturating arithmetic so a
        // pathological policy value (e.g. u64::MAX) does not wrap to zero.
        let timeout_ms = self
            .policy
            .execution_timeout_secs
            .saturating_mul(1000)
            .saturating_add(5000); // 5 s grace beyond policy timeout
        let poll_interval = Duration::from_millis(50);
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);

        loop {
            let state = handle
                .block_on(self.spawner.poll_state(&exec_handle))
                .map_err(sandbox_to_transport)?;

            match state {
                ExecutionState::Completed { .. } => break,
                ExecutionState::TimedOut { .. } => {
                    return Err(TransportError::ServerError(
                        "sandbox execution timed out".into(),
                    ))
                }
                ExecutionState::Killed { reason, .. } | ExecutionState::Failed { reason, .. } => {
                    return Err(TransportError::ServerError(format!(
                        "sandbox execution failed: {reason}"
                    )))
                }
                ExecutionState::Pending | ExecutionState::Running { .. } => {
                    if std::time::Instant::now() >= deadline {
                        let _ =
                            handle.block_on(self.spawner.terminate(&exec_handle, "poll timeout"));
                        return Err(TransportError::ServerError(
                            "sandbox poll deadline exceeded".into(),
                        ));
                    }
                    std::thread::sleep(poll_interval);
                }
            }
        }

        // Collect result — for the current in-process spawner implementations
        // the result contains the actual execution output.  The receipt is
        // available here for phase 5 embedding (future work).
        let (exec_result, _receipt) = handle
            .block_on(self.spawner.collect_result(&exec_handle))
            .map_err(sandbox_to_transport)?;

        if exec_result.result_enc.is_empty() {
            return Err(TransportError::ServerError(
                "sandbox spawner returned no encrypted result — \
                 IPC pipeline broken, refusing to fall back to unsandboxed execution"
                    .into(),
            ));
        }

        // The result is decrypted with the same ephemeral_key used for
        // encryption above.  For an in-process spawner this key is already in
        // scope; for a future out-of-process spawner it would be derived via
        // ECDH using the ephemeral_public_key field in the context envelope.
        let plaintext = decrypt(&exec_result.result_enc, &ephemeral_key, &exec_result.nonce)
            .map_err(sandbox_to_transport)?;

        serde_json::from_slice(&plaintext)
            .map_err(|e| TransportError::ServerError(format!("result deserialization: {e}")))
    }
}

impl AgentHandler for SandboxedHandlerWrapper {
    fn handle_token(&self, token: CapabilityToken) -> Result<(String, String), TransportError> {
        self.inner.handle_token(token)
    }

    fn handle_did_exchange(
        &self,
        session_id: &str,
        initiator_session_did: &str,
    ) -> Result<(), TransportError> {
        self.inner
            .handle_did_exchange(session_id, initiator_session_did)
    }

    fn handle_disclosure(
        &self,
        session_id: &str,
        disclosures: Vec<serde_json::Value>,
    ) -> Result<(), TransportError> {
        self.inner.handle_disclosure(session_id, disclosures)
    }

    fn execute(&self, session_id: &str) -> Result<serde_json::Value, TransportError> {
        if self.sandbox_enabled {
            self.execute_sandboxed(session_id)
        } else {
            self.inner.execute(session_id)
        }
    }

    fn co_sign_receipt(
        &self,
        receipt: TransactionReceipt,
    ) -> Result<TransactionReceipt, TransportError> {
        self.inner.co_sign_receipt(receipt)
    }

    fn handle_close(&self, session_id: &str) -> Result<(), TransportError> {
        self.inner.handle_close(session_id)
    }

    fn handle_stream_message(
        &self,
        session_id: &str,
        id: &str,
        content: &serde_json::Value,
    ) -> Result<Option<serde_json::Value>, TransportError> {
        self.inner.handle_stream_message(session_id, id, content)
    }
}

fn sandbox_to_transport(e: SandboxError) -> TransportError {
    TransportError::ServerError(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spawner::NoopSpawner;

    struct EchoHandler;
    impl AgentHandler for EchoHandler {
        fn handle_token(&self, _t: CapabilityToken) -> Result<(String, String), TransportError> {
            Ok(("sid".into(), "did:key:z0".into()))
        }
        fn handle_did_exchange(&self, _s: &str, _d: &str) -> Result<(), TransportError> {
            Ok(())
        }
        fn handle_disclosure(
            &self,
            _s: &str,
            _d: Vec<serde_json::Value>,
        ) -> Result<(), TransportError> {
            Ok(())
        }
        fn execute(&self, _s: &str) -> Result<serde_json::Value, TransportError> {
            Ok(serde_json::json!({"@type": "Thing", "name": "echo"}))
        }
        fn co_sign_receipt(
            &self,
            r: TransactionReceipt,
        ) -> Result<TransactionReceipt, TransportError> {
            Ok(r)
        }
        fn handle_close(&self, _s: &str) -> Result<(), TransportError> {
            Ok(())
        }
    }

    #[test]
    fn passthrough_when_disabled() {
        // sandbox_enabled=false: execute() delegates directly to inner handler,
        // no async spawner involved — safe to call from a plain #[test].
        let wrapper = SandboxedHandlerWrapper::new(
            Arc::new(EchoHandler),
            Arc::new(NoopSpawner),
            CapabilityPolicy::default(),
            false,
            "did:key:z0",
            "EchoAgent",
            "schema:SearchAction",
        );
        let result = wrapper.execute("test-session");
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["name"], "echo");
    }

    #[test]
    fn sandboxed_path_with_noop_surfaces_error() {
        // NoopSpawner::spawn() returns PlatformUnsupported — sandbox failures
        // must surface as errors, never silently fall back to unsandboxed execution.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            tokio::task::spawn_blocking(move || {
                let wrapper = SandboxedHandlerWrapper::new(
                    Arc::new(EchoHandler),
                    Arc::new(NoopSpawner),
                    CapabilityPolicy::default(),
                    true,
                    "did:key:z0",
                    "EchoAgent",
                    "schema:SearchAction",
                );
                wrapper.execute("test-session")
            })
            .await
            .expect("spawn_blocking did not panic")
        });
        assert!(result.is_err(), "NoopSpawner must error, not silently pass");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("sandbox") || msg.contains("platform"),
            "error should mention sandbox/platform, got: {msg}"
        );
    }
}
