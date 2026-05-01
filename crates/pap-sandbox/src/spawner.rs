use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::SandboxError;
use crate::ipc::{ExecutionContext, ExecutionResult};
use crate::policy::CapabilityPolicy;
use crate::receipt::AttestationReceipt;

/// Opaque handle to a spawned sandbox process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionHandle {
    pub id: String,
    pub agent_did: String,
    pub agent_name: String,
    pub spawned_at: DateTime<Utc>,
}

impl ExecutionHandle {
    pub fn new(agent_did: impl Into<String>, agent_name: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            agent_did: agent_did.into(),
            agent_name: agent_name.into(),
            spawned_at: Utc::now(),
        }
    }
}

/// Runtime state of a sandboxed agent execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state")]
pub enum ExecutionState {
    Pending,
    Running { pid: u32, elapsed_ms: u64 },
    Completed { exit_code: i32, elapsed_ms: u64 },
    TimedOut { elapsed_ms: u64 },
    Killed { reason: String, elapsed_ms: u64 },
    Failed { reason: String, elapsed_ms: u64 },
}

/// Platform abstraction for sandboxed process spawning.
///
/// Each OS backend implements this trait:
/// - Linux: seccomp BPF + process namespaces
/// - BSD: pledge(2)
/// - macOS: entitlements / Sandbox.framework
/// - Windows: Job Objects
#[async_trait]
pub trait AgentSpawner: Send + Sync {
    /// Spawn a sandboxed agent process with the given policy and encrypted context.
    async fn spawn(
        &self,
        policy: CapabilityPolicy,
        context: ExecutionContext,
    ) -> Result<ExecutionHandle, SandboxError>;

    /// Poll the current state of a running sandbox.
    async fn poll_state(&self, handle: &ExecutionHandle) -> Result<ExecutionState, SandboxError>;

    /// Terminate a running sandbox immediately.
    async fn terminate(&self, handle: &ExecutionHandle, reason: &str) -> Result<(), SandboxError>;

    /// Retrieve the execution result and capability attestation receipt.
    /// Only valid after `poll_state` returns `Completed`.
    async fn collect_result(
        &self,
        handle: &ExecutionHandle,
    ) -> Result<(ExecutionResult, AttestationReceipt), SandboxError>;
}

/// Fallback spawner when no sandbox implementation is available.
/// Every method returns an error — sandbox failures are never silenced.
pub struct NoopSpawner;

#[async_trait]
impl AgentSpawner for NoopSpawner {
    async fn spawn(
        &self,
        _policy: CapabilityPolicy,
        _context: ExecutionContext,
    ) -> Result<ExecutionHandle, SandboxError> {
        Err(SandboxError::PlatformUnsupported(
            "no sandbox implementation available (no OS capabilities, no Docker socket)".into(),
        ))
    }

    async fn poll_state(&self, handle: &ExecutionHandle) -> Result<ExecutionState, SandboxError> {
        Err(SandboxError::ProcessNotFound(handle.id.clone()))
    }

    async fn terminate(
        &self,
        _handle: &ExecutionHandle,
        _reason: &str,
    ) -> Result<(), SandboxError> {
        Ok(())
    }

    async fn collect_result(
        &self,
        handle: &ExecutionHandle,
    ) -> Result<(ExecutionResult, AttestationReceipt), SandboxError> {
        Err(SandboxError::ProcessNotFound(handle.id.clone()))
    }
}

/// Select the platform-appropriate spawner at runtime.
/// Detects OS capabilities first, then falls back to Docker or unsandboxed execution.
pub async fn new_spawner() -> Result<Box<dyn AgentSpawner>, SandboxError> {
    use crate::platform::detection::{detect_runtime, RuntimeEnvironment};

    match detect_runtime().await {
        RuntimeEnvironment::Bare {
            seccomp,
            pledge: _,
            entitlements: _,
            job_objects: _,
        } => {
            #[cfg(target_os = "linux")]
            if seccomp {
                return Ok(Box::new(crate::platform::linux::LinuxSpawner::new()));
            }

            #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
            if pledge {
                return Ok(Box::new(crate::platform::bsd::BsdSpawner::new()));
            }

            #[cfg(target_os = "macos")]
            if entitlements {
                return Ok(Box::new(crate::platform::macos::MacosSpawner::new()));
            }

            #[cfg(target_os = "windows")]
            {
                return Ok(Box::new(crate::platform::windows::WindowsSpawner::new()));
            }

            #[allow(unreachable_code)]
            Err(SandboxError::PlatformUnsupported(format!(
                "OS reports bare metal but no capabilities detected ({})",
                std::env::consts::OS
            )))
        }

        RuntimeEnvironment::Docker { socket_path } => {
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
            {
                let docker_spawner = crate::platform::docker::DockerSpawner::new(&socket_path).await?;
                Ok(Box::new(docker_spawner))
            }

            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
            {
                let _ = socket_path;
                Err(SandboxError::PlatformUnsupported(
                    "Docker socket detected but bollard not available on this platform".into(),
                ))
            }
        }

        RuntimeEnvironment::Unsupported => {
            Err(SandboxError::PlatformUnsupported(
                "no sandbox implementation available: no OS capabilities, no Docker socket".into(),
            ))
        }
    }
}
