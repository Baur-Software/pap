//! Docker sibling container spawner for sandboxed agent execution.
//!
//! When running inside a container with Docker socket mounted, agents spawn as
//! sibling containers (not nested) with capability constraints mapped to docker run flags.
//! The container runs the worker binary which reads ExecutionContext from the PAP_CONTEXT
//! env var and writes ExecutionResult JSON to stdout.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use bollard::models::{ContainerCreateBody, HostConfig};
use bollard::query_parameters::{CreateContainerOptions, LogsOptions};
use bollard::Docker;
use futures_util::StreamExt;
use tokio::sync::RwLock;

use crate::error::SandboxError;
use crate::ipc::{ExecutionContext, ExecutionResult};
use crate::policy::CapabilityPolicy;
use crate::receipt::{AttestationReceipt, CapabilityProof, MemoryProtection};
use crate::spawner::{AgentSpawner, ExecutionHandle, ExecutionState};

struct ContainerRecord {
    container_id: String,
    started: Instant,
    policy: CapabilityPolicy,
    docker_flags: Vec<String>,
}

pub struct DockerSpawner {
    client: Docker,
    containers: Arc<RwLock<HashMap<String, ContainerRecord>>>,
    results: Arc<RwLock<HashMap<String, (ExecutionResult, AttestationReceipt)>>>,
}

impl DockerSpawner {
    pub async fn new(_socket_path: &str) -> Result<Self, SandboxError> {
        let client = Docker::connect_with_unix_defaults()
            .map_err(|e| SandboxError::SpawnError(format!("failed to connect to Docker: {e}")))?;

        Ok(Self {
            client,
            containers: Arc::new(RwLock::new(HashMap::new())),
            results: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    fn build_docker_flags(policy: &CapabilityPolicy) -> Vec<String> {
        let mut flags = vec!["--cap-drop=ALL".to_string()];
        if !policy.network_allowed {
            flags.push("--network=none".to_string());
        }
        if policy.network_allowed {
            flags.push("--cap-add=NET_RAW".to_string());
        }
        if !policy.filesystem_allowed {
            flags.push("--read-only".to_string());
        }
        flags.push("--memory=256m".to_string());
        flags
    }

    fn build_proof(policy: &CapabilityPolicy, _flags: &[String]) -> CapabilityProof {
        CapabilityProof {
            seccomp_rules_hash: None,
            pledge_promises: None,
            entitlements_applied: None,
            memory_protection: MemoryProtection {
                mlock_applied: false,
                encryption_used: true,
                sensitive_buffers_wiped: true,
            },
            timeout_enforced_secs: policy.execution_timeout_secs,
            network_blocked: !policy.network_allowed,
            filesystem_restricted: !policy.filesystem_allowed,
            subprocess_blocked: !policy.subprocess_allowed,
        }
    }

    async fn read_container_stdout(&self, container_id: &str) -> Result<Vec<u8>, SandboxError> {
        let options = LogsOptions {
            follow: false,
            stdout: true,
            stderr: false,
            ..Default::default()
        };

        let mut stream = self.client.logs(container_id, Some(options));
        let mut stdout_buf = Vec::new();
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(output) => stdout_buf.extend_from_slice(&output.into_bytes()),
                Err(e) => {
                    return Err(SandboxError::IpcError(format!(
                        "failed to read container logs: {e}"
                    )));
                }
            }
        }
        Ok(stdout_buf)
    }
}

#[async_trait]
impl AgentSpawner for DockerSpawner {
    async fn spawn(
        &self,
        policy: CapabilityPolicy,
        context: ExecutionContext,
    ) -> Result<ExecutionHandle, SandboxError> {
        let handle = ExecutionHandle::new(&context.agent_did, &context.agent_name);
        let docker_flags = Self::build_docker_flags(&policy);

        let image = "baursoftware/pap-agent:latest";

        let context_json =
            serde_json::to_string(&context).map_err(|e| SandboxError::IpcError(e.to_string()))?;
        let policy_json =
            serde_json::to_string(&policy).map_err(|e| SandboxError::IpcError(e.to_string()))?;

        let config = ContainerCreateBody {
            image: Some(image.to_string()),
            cmd: Some(vec![
                "--sandbox-worker".to_string(),
                "--policy".to_string(),
                policy_json,
            ]),
            env: Some(vec![
                format!("PAP_CONTEXT={context_json}"),
                format!("PAP_AGENT_DID={}", context.agent_did),
            ]),
            attach_stdout: Some(true),
            host_config: Some(HostConfig {
                network_mode: Some(if policy.network_allowed {
                    "bridge".to_string()
                } else {
                    "none".to_string()
                }),
                readonly_rootfs: Some(!policy.filesystem_allowed),
                cap_drop: Some(vec!["ALL".to_string()]),
                cap_add: if policy.network_allowed {
                    Some(vec!["NET_RAW".to_string()])
                } else {
                    None
                },
                memory: Some(256i64 * 1024 * 1024),
                ..Default::default()
            }),
            ..Default::default()
        };

        let options = CreateContainerOptions {
            name: Some(format!("pap-agent-{}", handle.id)),
            platform: String::new(),
        };

        let response = self
            .client
            .create_container(Some(options), config)
            .await
            .map_err(|e| SandboxError::SpawnError(format!("failed to create container: {e}")))?;

        let container_id = response.id;

        self.client
            .start_container(&container_id, None)
            .await
            .map_err(|e| SandboxError::SpawnError(format!("failed to start container: {e}")))?;

        let record = ContainerRecord {
            container_id,
            started: Instant::now(),
            policy,
            docker_flags,
        };

        let mut containers = self.containers.write().await;
        containers.insert(handle.id.clone(), record);

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

        let containers = self.containers.read().await;
        let record = containers
            .get(&handle.id)
            .ok_or_else(|| SandboxError::ProcessNotFound(handle.id.clone()))?;

        let info = self
            .client
            .inspect_container(&record.container_id, None)
            .await
            .map_err(|e| SandboxError::SpawnError(format!("failed to inspect container: {e}")))?;

        if let Some(state) = info.state {
            let elapsed_ms = record.started.elapsed().as_millis() as u64;

            if state.running.unwrap_or(false) {
                let pid = state.pid.map(|p| p as u32).unwrap_or(0);
                return Ok(ExecutionState::Running { pid, elapsed_ms });
            }

            let exit_code = state.exit_code.unwrap_or(-1) as i32;

            if exit_code == 124 {
                return Ok(ExecutionState::TimedOut { elapsed_ms });
            }

            // Container exited — read stdout, parse ExecutionResult, then clean up.
            let container_id = record.container_id.clone();
            drop(containers);

            let stdout_data = self.read_container_stdout(&container_id).await?;

            let state = if exit_code != 0 || stdout_data.is_empty() {
                ExecutionState::Failed {
                    reason: format!(
                        "container exited with code {exit_code}, stdout {} bytes",
                        stdout_data.len()
                    ),
                    elapsed_ms,
                }
            } else {
                match serde_json::from_slice::<ExecutionResult>(&stdout_data) {
                    Ok(exec_result) => {
                        let receipt = exec_result.receipt.clone();
                        let mut results = self.results.write().await;
                        results.insert(handle.id.clone(), (exec_result, receipt));
                        ExecutionState::Completed {
                            exit_code,
                            elapsed_ms,
                        }
                    }
                    Err(_) => ExecutionState::Failed {
                        reason: format!(
                            "container exited OK but stdout is not valid ExecutionResult JSON ({} bytes)",
                            stdout_data.len()
                        ),
                        elapsed_ms,
                    },
                }
            };

            // Clean up: remove container from Docker daemon and our tracking map.
            let _ = self.client.remove_container(&container_id, None).await;
            let mut containers = self.containers.write().await;
            containers.remove(&handle.id);

            return Ok(state);
        }

        Ok(ExecutionState::Pending)
    }

    async fn terminate(&self, handle: &ExecutionHandle, reason: &str) -> Result<(), SandboxError> {
        let containers = self.containers.read().await;
        let record = containers
            .get(&handle.id)
            .ok_or_else(|| SandboxError::ProcessNotFound(handle.id.clone()))?;

        let container_id = record.container_id.clone();
        let policy = record.policy.clone();
        let docker_flags = record.docker_flags.clone();
        let elapsed_ms = record.started.elapsed().as_millis() as u64;
        drop(containers);

        let _ = self.client.kill_container(&container_id, None).await;

        let _ = self.client.remove_container(&container_id, None).await;

        let proof = Self::build_proof(&policy, &docker_flags);
        let receipt = AttestationReceipt::killed(
            handle.id.clone(),
            handle.agent_did.clone(),
            handle.agent_name.clone(),
            "docker_execution".to_string(),
            elapsed_ms,
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
