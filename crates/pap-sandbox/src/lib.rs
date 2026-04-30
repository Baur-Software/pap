pub mod error;
pub mod ipc;
pub mod memory;
pub mod os_capabilities;
pub mod platform;
pub mod policy;
pub mod receipt;
pub mod spawner;

#[cfg(test)]
mod tests;

#[cfg(feature = "tauri")]
pub mod tauri_commands;

pub use error::SandboxError;
pub use ipc::{decrypt, encrypt, ExecutionContext, ExecutionResult};
pub use memory::SecureBuffer;
pub use os_capabilities::{detect as detect_os_capabilities, OsCapabilities};
pub use policy::CapabilityPolicy;
pub use receipt::{AttestationReceipt, CapabilityProof, MemoryProtection};
pub use spawner::{new_spawner, AgentSpawner, ExecutionHandle, ExecutionState};
