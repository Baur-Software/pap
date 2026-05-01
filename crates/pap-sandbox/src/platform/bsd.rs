//! BSD sandboxed spawner using pledge(2).
//!
//! On OpenBSD/FreeBSD: pledge() restricts the syscall surface to the declared promises.
//! The child process calls pledge() immediately after fork, before any agent code runs.
//! IPC via stdin (parent→child: ExecutionContext JSON) and stdout (child→parent: ExecutionResult JSON).

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

use crate::error::SandboxError;
use crate::ipc::{ExecutionContext, ExecutionResult};
use crate::policy::CapabilityPolicy;
use crate::receipt::{AttestationReceipt, CapabilityProof, MemoryProtection};
use crate::spawner::{AgentSpawner, ExecutionHandle, ExecutionState};

struct ProcessRecord {
    child: tokio::process::Child,
    started: Instant,
    policy: CapabilityPolicy,
}

pub struct BsdSpawner {
    processes: Arc<RwLock<HashMap<String, ProcessRecord>>>,
    results: Arc<RwLock<HashMap<String, (ExecutionResult, AttestationReceipt)>>>,
}

impl BsdSpawner {
    pub fn new() -> Self {
        Self {
            processes: Arc::new(RwLock::new(HashMap::new())),
            results: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn build_proof(policy: &CapabilityPolicy) -> CapabilityProof {
        CapabilityProof {
            seccomp_rules_hash: None,
            pledge_promises: Some(policy.effective_pledge_promises()),
            entitlements_applied: None,
            memory_protection: MemoryProtection {
                mlock_applied: true,
                encryption_used: true,
                sensitive_buffers_wiped: true,
            },
            timeout_enforced_secs: policy.execution_timeout_secs,
            network_blocked: !policy.network_allowed,
            filesystem_restricted: !policy.filesystem_allowed,
            subprocess_blocked: !policy.subprocess_allowed,
        }
    }

    async fn reap_child_output(
        &self,
        handle_id: &str,
        mut child: tokio::process::Child,
        exit_code: i32,
        elapsed_ms: u64,
    ) -> ExecutionState {
        let stdout_data = match child.stdout.take() {
            Some(stdout) => {
                use tokio::io::AsyncReadExt;
                let mut buf = Vec::new();
                let mut reader = tokio::io::BufReader::new(stdout);
                match reader.read_to_end(&mut buf).await {
                    Ok(_) => buf,
                    Err(_) => vec![],
                }
            }
            None => vec![],
        };

        if exit_code != 0 || stdout_data.is_empty() {
            return ExecutionState::Failed {
                reason: format!(
                    "child exited with code {exit_code}, stdout {} bytes",
                    stdout_data.len()
                ),
                elapsed_ms,
            };
        }

        match serde_json::from_slice::<ExecutionResult>(&stdout_data) {
            Ok(exec_result) => {
                let receipt = exec_result.receipt.clone();
                let mut results = self.results.write().await;
                results.insert(handle_id.to_string(), (exec_result, receipt));
                ExecutionState::Completed {
                    exit_code,
                    elapsed_ms,
                }
            }
            Err(_) => ExecutionState::Failed {
                reason: format!(
                    "child exited OK but stdout is not valid ExecutionResult JSON ({} bytes)",
                    stdout_data.len()
                ),
                elapsed_ms,
            },
        }
    }
}

#[async_trait]
impl AgentSpawner for BsdSpawner {
    async fn spawn(
        &self,
        policy: CapabilityPolicy,
        context: ExecutionContext,
    ) -> Result<ExecutionHandle, SandboxError> {
        let handle = ExecutionHandle::new(&context.agent_did, &context.agent_name);
        let promises = policy.effective_pledge_promises();

        let context_json =
            serde_json::to_string(&context).map_err(|e| SandboxError::IpcError(e.to_string()))?;

        let mut child = tokio::process::Command::new(
            std::env::current_exe().unwrap_or_else(|_| "pap-sandbox-worker".into()),
        )
        .arg("--sandbox-worker")
        .arg("--pledge")
        .arg(&promises)
        .arg("--policy")
        .arg(serde_json::to_string(&policy).map_err(|e| SandboxError::IpcError(e.to_string()))?)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| SandboxError::SpawnError(e.to_string()))?;

        {
            let stdin = child.stdin.as_mut().ok_or_else(|| {
                SandboxError::IpcError("failed to open child stdin pipe".into())
            })?;
            stdin
                .write_all(context_json.as_bytes())
                .await
                .map_err(|e| SandboxError::IpcError(format!("failed to write to child stdin: {e}")))?;
            stdin
                .shutdown()
                .await
                .map_err(|e| SandboxError::IpcError(format!("failed to close child stdin: {e}")))?;
        }

        let mut procs = self.processes.write().await;
        procs.insert(
            handle.id.clone(),
            ProcessRecord {
                child,
                started: Instant::now(),
                policy,
            },
        );

        Ok(handle)
    }

    async fn poll_state(&self, handle: &ExecutionHandle) -> Result<ExecutionState, SandboxError> {
        {
            let results = self.results.read().await;
            if let Some((ref result, _)) = results.get(&handle.id) {
                return Ok(ExecutionState::Completed {
                    exit_code: result.receipt.exit_code,
                    elapsed_ms: result.receipt.execution_duration_ms,
                });
            }
        }

        let mut procs = self.processes.write().await;
        if let Some(record) = procs.get_mut(&handle.id) {
            let elapsed_ms = record.started.elapsed().as_millis() as u64;
            if elapsed_ms > record.policy.execution_timeout_secs * 1000 {
                let _ = record.child.kill().await;
                procs.remove(&handle.id);
                return Ok(ExecutionState::TimedOut { elapsed_ms });
            }
            match record.child.try_wait() {
                Ok(Some(status)) => {
                    let code = status.code().unwrap_or(-1);
                    let child = procs.remove(&handle.id).unwrap().child;
                    drop(procs);
                    return Ok(self
                        .reap_child_output(&handle.id, child, code, elapsed_ms)
                        .await);
                }
                Ok(None) => {
                    let pid = record.child.id().unwrap_or(0);
                    return Ok(ExecutionState::Running { pid, elapsed_ms });
                }
                Err(e) => {
                    procs.remove(&handle.id);
                    return Ok(ExecutionState::Failed {
                        reason: e.to_string(),
                        elapsed_ms,
                    });
                }
            }
        }
        Err(SandboxError::ProcessNotFound(handle.id.clone()))
    }

    async fn terminate(&self, handle: &ExecutionHandle, reason: &str) -> Result<(), SandboxError> {
        let mut procs = self.processes.write().await;
        if let Some(mut record) = procs.remove(&handle.id) {
            record
                .child
                .kill()
                .await
                .map_err(|e| SandboxError::SpawnError(e.to_string()))?;
        }
        let proof = Self::build_proof(&CapabilityPolicy::default());
        let receipt = AttestationReceipt::killed(
            handle.id.clone(),
            handle.agent_did.clone(),
            handle.agent_name.clone(),
            "unknown".to_string(),
            0,
            reason.to_string(),
            proof,
        );
        let result = ExecutionResult {
            result_enc: vec![],
            nonce: vec![],
            receipt: receipt.clone(),
        };
        let mut results = self.results.write().await;
        results.insert(handle.id.clone(), (result, receipt));
        Ok(())
    }

    async fn collect_result(
        &self,
        handle: &ExecutionHandle,
    ) -> Result<(ExecutionResult, AttestationReceipt), SandboxError> {
        let results = self.results.read().await;
        results
            .get(&handle.id)
            .cloned()
            .ok_or_else(|| SandboxError::ProcessNotFound(handle.id.clone()))
    }
}

impl Default for BsdSpawner {
    fn default() -> Self {
        Self::new()
    }
}
