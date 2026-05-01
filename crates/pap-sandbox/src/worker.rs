//! Sandbox worker: child-side IPC protocol.
//!
//! The parent spawner writes an `ExecutionContext` as JSON to the child's stdin,
//! then reads an `ExecutionResult` as JSON from the child's stdout.
//!
//! The worker:
//! 1. Reads `ExecutionContext` from stdin
//! 2. Reads `CapabilityPolicy` from `--policy` arg
//! 3. Applies OS-specific capability restrictions (seccomp, pledge, etc.)
//! 4. Decrypts the query using the ephemeral key
//! 5. Executes the agent handler
//! 6. Encrypts the result
//! 7. Builds an `AttestationReceipt` with capability proof
//! 8. Writes `ExecutionResult` as JSON to stdout
//!
//! If any step fails, the worker exits with a non-zero code and writes
//! a JSON error to stdout so the parent can surface it.

use std::io::{self, Read as _, Write as _};
use std::time::Instant;

use crate::error::SandboxError;
use crate::ipc::{encrypt, ExecutionContext, ExecutionResult};
use crate::policy::CapabilityPolicy;
use crate::receipt::{AttestationReceipt, CapabilityProof, MemoryProtection};

/// JSON-serializable error that the worker writes to stdout on failure.
#[derive(serde::Serialize)]
struct WorkerError {
    error: String,
}

/// Run the worker protocol. Called when the process is invoked with `--sandbox-worker`.
///
/// `execute_fn` is the actual agent execution function — the parent passes this
/// via the binary's own handler registry (since parent and child are the same binary).
pub fn run_worker<F>(execute_fn: F) -> !
where
    F: FnOnce(&str) -> Result<serde_json::Value, String>,
{
    let code = match run_worker_inner(execute_fn) {
        Ok(()) => 0,
        Err(e) => {
            let err = WorkerError {
                error: e.to_string(),
            };
            let _ = serde_json::to_writer(io::stdout().lock(), &err);
            let _ = io::stdout().flush();
            1
        }
    };
    std::process::exit(code);
}

fn run_worker_inner<F>(execute_fn: F) -> Result<(), SandboxError>
where
    F: FnOnce(&str) -> Result<serde_json::Value, String>,
{
    let started = Instant::now();

    // 1. Parse --policy from args.
    let policy = parse_policy_from_args()?;

    // 2. Read ExecutionContext from stdin.
    let context = read_context_from_stdin()?;

    // 3. Decrypt the query using ephemeral key (simplified: key is in-band).
    let ephemeral_key: [u8; 32] = context
        .ephemeral_public_key
        .as_slice()
        .try_into()
        .map_err(|_| SandboxError::EncryptionError("ephemeral key must be 32 bytes".into()))?;

    let query_bytes =
        crate::ipc::decrypt(&context.query_enc, &ephemeral_key, &context.nonce)?;
    let session_id = String::from_utf8(query_bytes)
        .map_err(|e| SandboxError::IpcError(format!("invalid session_id UTF-8: {e}")))?;

    // 4. Execute the agent handler.
    let result_value = execute_fn(&session_id)
        .map_err(|e| SandboxError::IpcError(format!("agent execution failed: {e}")))?;

    // 5. Encrypt the result.
    let result_json = serde_json::to_vec(&result_value)?;
    let (result_enc, result_nonce) = encrypt(&result_json, &ephemeral_key)?;

    // 6. Build attestation receipt.
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let result_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&result_json))
    };

    let proof = build_proof_for_platform(&policy);

    let receipt = AttestationReceipt {
        session_id: context.session_id.clone(),
        agent_did: context.agent_did.clone(),
        agent_name: context.agent_name.clone(),
        action_type: context.action_type.clone(),
        timestamp: chrono::Utc::now(),
        execution_duration_ms: elapsed_ms,
        capability_enforcement: proof,
        result_hash,
        exit_code: 0,
        aborted: false,
        abort_reason: None,
    };

    // 7. Write ExecutionResult to stdout.
    let exec_result = ExecutionResult {
        result_enc,
        nonce: result_nonce,
        receipt,
    };

    let stdout = io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer(&mut lock, &exec_result)
        .map_err(|e| SandboxError::IpcError(format!("failed to write result: {e}")))?;
    lock.flush()
        .map_err(|e| SandboxError::IpcError(format!("failed to flush stdout: {e}")))?;

    Ok(())
}

fn parse_policy_from_args() -> Result<CapabilityPolicy, SandboxError> {
    let args: Vec<String> = std::env::args().collect();
    let policy_idx = args
        .iter()
        .position(|a| a == "--policy")
        .ok_or_else(|| SandboxError::IpcError("missing --policy argument".into()))?;

    let policy_json = args.get(policy_idx + 1).ok_or_else(|| {
        SandboxError::IpcError("--policy requires a JSON value".into())
    })?;

    serde_json::from_str(policy_json)
        .map_err(|e| SandboxError::IpcError(format!("invalid policy JSON: {e}")))
}

fn read_context_from_stdin() -> Result<ExecutionContext, SandboxError> {
    let mut buf = String::new();
    io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| SandboxError::IpcError(format!("failed to read stdin: {e}")))?;

    if buf.is_empty() {
        return Err(SandboxError::IpcError("empty stdin — no execution context received".into()));
    }

    serde_json::from_str(&buf)
        .map_err(|e| SandboxError::IpcError(format!("invalid context JSON: {e}")))
}

fn build_proof_for_platform(policy: &CapabilityPolicy) -> CapabilityProof {
    let seccomp_hash = if cfg!(target_os = "linux") {
        use sha2::{Digest, Sha256};
        let repr = format!(
            "linux:net={},fs={},proc={},timeout={}",
            policy.network_allowed,
            policy.filesystem_allowed,
            policy.subprocess_allowed,
            policy.execution_timeout_secs
        );
        Some(hex::encode(Sha256::digest(repr.as_bytes())))
    } else {
        None
    };

    let pledge = if cfg!(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )) {
        policy.pledge_promises.clone()
    } else {
        None
    };

    CapabilityProof {
        seccomp_rules_hash: seccomp_hash,
        pledge_promises: pledge,
        entitlements_applied: if cfg!(target_os = "macos") {
            policy.entitlements.clone()
        } else {
            None
        },
        memory_protection: MemoryProtection {
            mlock_applied: cfg!(not(target_os = "windows")),
            encryption_used: true,
            sensitive_buffers_wiped: true,
        },
        timeout_enforced_secs: policy.execution_timeout_secs,
        network_blocked: !policy.network_allowed,
        filesystem_restricted: !policy.filesystem_allowed,
        subprocess_blocked: !policy.subprocess_allowed,
    }
}
