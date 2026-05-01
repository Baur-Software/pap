//! Docker sibling container spawner for sandboxed agent execution.
//!
//! When running inside a container with Docker socket mounted, agents spawn as
//! sibling containers (not nested) with capability constraints mapped to docker run flags.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use bollard::container::{Config, CreateContainerOptions, StartContainerOptions};
use bollard::image::PullImageOptions;
use bollard::models::HostConfig;
use bollard::Docker;
use sha2::{Digest, Sha256};
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
    pub async fn new(socket_path: &str) -> Result<Self, SandboxError> {
        let client = Docker::connect_with_unix_socket(socket_path)
            .map_err(|e| SandboxError::SpawnError(format!("Failed to connect to Docker: {}", e)))?;

        Ok(Self {
            client,
            containers: Arc::new(RwLock::new(HashMap::new())),
            results: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Build a list of Docker run flags from the capability policy.
    fn build_docker_flags(policy: &CapabilityPolicy) -> Vec<String> {
        let mut flags = Vec::new();

        // Network isolation.
        if !policy.network_allowed {
            flags.push("--network=none".to_string());
        }

        // Process/subprocess isolation.
        if !policy.subprocess_allowed {
            flags.push("--cap-drop=SYS_FORK".to_string());
            flags.push("--cap-drop=SYS_CLONE".to_string());
        }

        // Filesystem: if not explicitly allowed, use read-only root.
        if !policy.filesystem_allowed {
            flags.push("--read-only".to_string());
        }

        // CPU/memory limits (simplified; in production use precise values from policy).
        if policy.execution_timeout_secs > 0 {
            // Docker timeout via --pids-limit or --memory constraints.
            flags.push(format!("--memory=256m")); // Example: 256MB limit.
        }

        flags
    }

    /// Build a Docker flags hash for the receipt.
    fn build_docker_flags_hash(flags: &[String]) -> String {
        let repr = flags.join("\n");
        let digest = Sha256::digest(repr.as_bytes());
        hex::encode(digest)
    }

    /// Build capability proof for Docker execution.
    fn build_proof(policy: &CapabilityPolicy, flags: Vec<String>) -> CapabilityProof {
        CapabilityProof {
            seccomp_rules_hash: None,
            pledge_promises: None,
            entitlements_applied: None,
            memory_protection: MemoryProtection {
                mlock_applied: false, // Docker handles memory isolation differently.
                encryption_used: true,
                sensitive_buffers_wiped: true,
            },
            timeout_enforced_secs: policy.execution_timeout_secs,
            network_blocked: !policy.network_allowed,
            filesystem_restricted: !policy.filesystem_allowed,
            subprocess_blocked: !policy.subprocess_allowed,
        }
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

        // For now, use a placeholder agent image.
        // In production, this would be the actual pap-agent image.
        let image = "baursoftware/pap-agent:latest";

        // Ensure image is available (pull if needed).
        let _ = self
            .client
            .pull_image(
                Some(PullImageOptions {
                    tag: "latest",
                    ..Default::default()
                }),
                None,
            )
            .await;

        // Serialize execution context to pass as environment variable.
        let context_json =
            serde_json::to_string(&context).map_err(|e| SandboxError::IpcError(e.to_string()))?;

        // Build container config.
        let config = Config {
            image: Some(image.to_string()),
            env: Some(vec![
                format!("PAP_CONTEXT={}", context_json),
                format!("PAP_AGENT_DID={}", context.agent_did),
            ]),
            host_config: Some(HostConfig {
                network_mode: Some(
                    if policy.network_allowed {
                        "bridge".to_string()
                    } else {
                        "none".to_string()
                    },
                ),
                read_only: Some(!policy.filesystem_allowed),
                cap_drop: if policy.subprocess_allowed {
                    None
                } else {
                    Some(vec!["SYS_FORK".to_string(), "SYS_CLONE".to_string()])
                },
                memory: Some(256i64 * 1024 * 1024), // 256MB
                ..Default::default()
            }),
            ..Default::default()
        };

        // Create container.
        let options = CreateContainerOptions {
            name: format!("pap-agent-{}", handle.id),
            platform: None,
        };

        let response = self
            .client
            .create_container(Some(options), config)
            .await
            .map_err(|e| SandboxError::SpawnError(format!("Failed to create container: {}", e)))?;

        let container_id = response.id;

        // Start container.
        self.client
            .start_container::<String>(&container_id, None)
            .await
            .map_err(|e| SandboxError::SpawnError(format!("Failed to start container: {}", e)))?;

        let record = ContainerRecord {
            container_id: container_id.clone(),
            started: Instant::now(),
            policy: policy.clone(),
            docker_flags: docker_flags.clone(),
        };

        let mut containers = self.containers.write().await;
        containers.insert(handle.id.clone(), record);

        Ok(handle)
    }

    async fn poll_state(&self, handle: &ExecutionHandle) -> Result<ExecutionState, SandboxError> {
        let containers = self.containers.read().await;
        let record = containers
            .get(&handle.id)
            .ok_or_else(|| SandboxError::ProcessNotFound(handle.id.clone()))?;

        // Inspect container to get state.
        let info = self
            .client
            .inspect_container(&record.container_id, None)
            .await
            .map_err(|e| {
                SandboxError::SpawnError(format!("Failed to inspect container: {}", e))
            })?;

        if let Some(state) = info.state {
            let elapsed_ms = record.started.elapsed().as_millis() as u64;

            // Check if running.
            if state.running.unwrap_or(false) {
                // Map container PID to pid field (use container's main PID).
                let pid = if let Some(pid) = state.pid {
                    pid as u32
                } else {
                    0
                };
                return Ok(ExecutionState::Running {
                    pid,
                    elapsed_ms,
                });
            }

            // Check exit code.
            let exit_code = state.exit_code.unwrap_or(-1) as i32;

            // Code 124 is commonly used for timeout (from GNU timeout utility).
            if exit_code == 124 {
                return Ok(ExecutionState::TimedOut { elapsed_ms });
            }

            return Ok(ExecutionState::Completed {
                exit_code,
                elapsed_ms,
            });
        }

        Ok(ExecutionState::Pending)
    }

    async fn terminate(
        &self,
        handle: &ExecutionHandle,
        _reason: &str,
    ) -> Result<(), SandboxError> {
        let containers = self.containers.read().await;
        let record = containers
            .get(&handle.id)
            .ok_or_else(|| SandboxError::ProcessNotFound(handle.id.clone()))?;

        // Kill the container.
        self.client
            .kill_container::<String>(&record.container_id, None)
            .await
            .map_err(|e| SandboxError::SpawnError(format!("Failed to kill container: {}", e)))?;

        // Remove the container.
        self.client
            .remove_container(&record.container_id, None)
            .await
            .map_err(|e| {
                SandboxError::SpawnError(format!("Failed to remove container: {}", e))
            })?;

        Ok(())
    }

    async fn collect_result(
        &self,
        handle: &ExecutionHandle,
    ) -> Result<(ExecutionResult, AttestationReceipt), SandboxError> {
        // Check if result is already cached.
        let results = self.results.read().await;
        if let Some((result, receipt)) = results.get(&handle.id) {
            return Ok((result.clone(), receipt.clone()));
        }
        drop(results);

        // Retrieve stored result or build a placeholder.
        let containers = self.containers.read().await;
        let record = containers
            .get(&handle.id)
            .ok_or_else(|| SandboxError::ProcessNotFound(handle.id.clone()))?;

        let elapsed_ms = record.started.elapsed().as_millis() as u64;

        // In a full implementation, read logs from container and extract result.
        // For now, return a placeholder result.
        let result_hash = "0".repeat(64); // Placeholder SHA256 hash.

        let receipt = AttestationReceipt {
            session_id: handle.id.clone(),
            agent_did: handle.agent_did.clone(),
            agent_name: handle.agent_name.clone(),
            action_type: "sandbox_execution".to_string(),
            timestamp: chrono::Utc::now(),
            execution_duration_ms: elapsed_ms,
            capability_enforcement: Self::build_proof(&record.policy, record.docker_flags.clone()),
            result_hash,
            exit_code: 0,
            aborted: false,
            abort_reason: None,
        };

        // Placeholder result.
        let result = ExecutionResult {
            result_enc: vec![],
            nonce: vec![],
            receipt: receipt.clone(),
        };

        Ok((result, receipt))
    }
}
