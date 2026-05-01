# pap-sandbox: Secure Agent Execution with OS Capability Enforcement

Process spawner with OS-level isolation and cryptographic attestation. Agents run in restricted child processes with enforced capability boundaries (seccomp, pledge, entitlements, job objects). Every execution produces a co-signed receipt proving what constraints were applied.

## Why It Exists

Agents executing in Papillon's process space can access any resource the process can reach—network, filesystem, environment variables. If the agent is compromised or malicious, there's no containment boundary. **pap-sandbox** creates that boundary using OS primitives:

- **Linux**: seccomp-bpf filters block restricted syscalls
- **BSD**: pledge(2) revokes OS capabilities
- **macOS**: Entitlements restrict framework access
- **Windows**: Job Objects limit resource access

The result: even if an agent is compromised, OS constraints prevent it from accessing the network, modifying files, or spawning subprocesses—whatever the policy restricts.

Every execution is cryptographically attested: the `AttestationReceipt` proves "this agent ran under these exact constraints, signed by the principal."

## Quick Start

Add to your Cargo.toml:

```toml
[dependencies]
pap-sandbox = { path = "../../crates/pap-sandbox" }
tokio = { version = "1", features = ["full"] }
```

Basic usage in a PAP Phase 4 (execute) handler:

```rust
use pap_sandbox::{CapabilityPolicy, SandboxedHandlerWrapper};
use std::sync::Arc;

// Wrap your existing agent handler with sandbox enforcement
let policy = CapabilityPolicy {
    execution_timeout_secs: 30,
    network_allowed: false,
    filesystem_allowed: false,
    subprocess_allowed: false,
    ..Default::default()
};

let sandboxed = SandboxedHandlerWrapper::new(
    Arc::new(my_handler),
    Arc::new(my_spawner),
    policy,
    true,  // sandbox_enabled
    "did:key:z6Mk...",
    "MyAgent",
    "schema:SearchAction",
);

// Use sandboxed exactly like the original handler
let result = sandboxed.execute(session_id)?;

// Execution happened in isolation with verified constraints
```

## Core Types

### `AgentSpawner` (Platform Abstraction)

```rust
pub trait AgentSpawner: Send + Sync {
    async fn spawn(
        &self,
        agent_did: &str,
        policy: CapabilityPolicy,
        context: ExecutionContext,
    ) -> Result<ExecutionHandle>;

    async fn poll_state(&self, handle: &ExecutionHandle) 
        -> Result<ExecutionState>;

    async fn terminate(&self, handle: &ExecutionHandle, reason: &str) 
        -> Result<()>;

    async fn collect_result(&self, handle: &ExecutionHandle) 
        -> Result<(ExecutionResult, AttestationReceipt)>;
}
```

Implement this trait for custom spawning logic. Default implementations provided for each OS.

### `CapabilityPolicy`

Defines what the agent is allowed to do:

```rust
pub struct CapabilityPolicy {
    pub execution_timeout_secs: u64,
    pub network_allowed: bool,
    pub filesystem_allowed: bool,
    pub subprocess_allowed: bool,
    // Platform-specific fields:
    pub seccomp_rules: Option<String>,        // Linux
    pub pledge_promises: Option<String>,      // BSD
    pub entitlements: Option<Vec<String>>,    // macOS
}
```

Policies follow a three-tier cascade:
1. **Agent-specific override** (highest priority)
2. **Category default** (fallback)
3. **Global default** (hardcoded minimums)

```rust
let policy = CapabilityPolicy::resolve(
    Some(agent_override),
    "external-api",
    global_default,
);
```

### `ExecutionState`

Tracks agent execution:

```rust
pub enum ExecutionState {
    Pending,
    Running { pid: u32, elapsed_ms: u64 },
    Completed { exit_code: i32 },
    TimedOut,
    Killed { reason: String },
}
```

### `AttestationReceipt`

Cryptographic proof of execution constraints:

```rust
pub struct AttestationReceipt {
    pub session_id: String,
    pub agent_did: String,
    pub action_type: String,
    pub timestamp: DateTime<Utc>,
    pub execution_duration_ms: u64,
    pub capability_enforcement: CapabilityProof,
    pub result_hash: String,  // Per PAP spec: hash only, not value
    pub exit_code: i32,
}

pub struct CapabilityProof {
    pub seccomp_rules_hash: Option<String>,
    pub pledge_promises: Option<String>,
    pub entitlements_applied: Option<Vec<String>>,
    pub memory_protection: MemoryProtection,
    pub timeout_enforced_secs: u64,
}

pub struct MemoryProtection {
    pub mlock_applied: bool,
    pub encryption_used: bool,
    pub sensitive_buffers_wiped: bool,
}
```

Principal co-signs the receipt during PAP Phase 5:

```rust
let mut receipt = receipt_from_execution;
principal.co_sign_receipt(&mut receipt)?;
// receipt now contains cryptographic proof of constraints
```

### `ExecutionContext` (Encrypted IPC)

Sensitive data (query, disclosure, session token) is encrypted before transmission to sandbox:

```rust
pub struct ExecutionContext {
    pub query_enc: Vec<u8>,
    pub disclosure_enc: Vec<u8>,
    pub session_token_enc: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ephemeral_public_key: Vec<u8>,
    pub agent_did: String,
    pub agent_name: String,
    pub action_type: String,
    pub session_id: String,
}
```

Child process decrypts only when needed, re-encrypts result before sending back.

## Integration Pattern

### In Papillon: Phase 4 (Execute)

Replace direct handler invocation with sandboxed spawn:

```rust
// Before:
let result = handler.execute(session_id)?;

// After:
let context = ExecutionContext {
    query_enc: encrypt(&query, &ephemeral_key)?,
    disclosure_enc: encrypt(&disclosure, &ephemeral_key)?,
    session_token_enc: encrypt(&token, &ephemeral_key)?,
    nonce: nonce.to_vec(),
    ephemeral_public_key: ephemeral_key.to_vec(),
    agent_did: agent_did.clone(),
    agent_name: agent_name.clone(),
    action_type: action_type.clone(),
    session_id: session_id.to_string(),
};

// Resolve policy via cascade
let policy = CapabilityPolicy::resolve(
    db.get_agent_policy(&agent_did)?,
    agent_category,
    global_default,
);

// Spawn sandboxed execution
let handle = spawner.spawn(&agent_did, policy, context).await?;

// Poll until completion or timeout
loop {
    match spawner.poll_state(&handle).await? {
        ExecutionState::Completed { .. } => break,
        ExecutionState::TimedOut => {
            spawner.terminate(&handle, "timeout").await?;
            return Err(TransportError::ServerError("execution timed out"));
        }
        ExecutionState::Running { elapsed_ms, .. } if elapsed_ms > policy.execution_timeout_secs * 1000 => {
            spawner.terminate(&handle, "policy timeout").await?;
        }
        _ => tokio::time::sleep(Duration::from_millis(50)).await,
    }
}

// Collect result and receipt
let (exec_result, receipt) = spawner.collect_result(&handle).await?;
let result = serde_json::from_slice(&decrypt(&exec_result.result_enc, &ephemeral_key, &exec_result.nonce)?)?;
```

### In Phase 5 (Co-Sign Receipt)

The receipt includes capability proof:

```rust
let mut tx_receipt = TransactionReceipt::new(
    session_id,
    agent_did,
    action_type,
    result_hash,  // Hash only, per PAP spec
);

// Embed capability proof from attestation receipt
tx_receipt.capability_enforcement = Some(receipt.capability_enforcement);

// Principal co-signs
principal.co_sign_receipt(&mut tx_receipt)?;
// tx_receipt.signature now proves: "I authorized this agent to execute under these constraints"
```

## Testing

### Unit Tests (Policy Cascade)

```rust
#[test]
fn policy_cascade_agent_override() {
    let global = CapabilityPolicy {
        execution_timeout_secs: 60,
        network_allowed: false,
        ..Default::default()
    };

    let agent_override = CapabilityPolicy {
        execution_timeout_secs: 30,
        ..Default::default()
    };

    let resolved = CapabilityPolicy::resolve(
        Some(agent_override),
        "external-api",
        global,
    );

    assert_eq!(resolved.execution_timeout_secs, 30);  // agent override wins
    assert!(!resolved.network_allowed);  // inherited from global
}
```

### Integration Tests (Full Spawn Cycle)

```rust
#[tokio::test]
async fn spawn_execute_collect_receipt() {
    let policy = CapabilityPolicy::default();
    let spawner = platform::new_spawner().unwrap();

    let context = ExecutionContext { /* ... */ };
    let handle = spawner.spawn("did:key:z6Mk...", policy, context).await.unwrap();

    // Poll to completion
    loop {
        match spawner.poll_state(&handle).await.unwrap() {
            ExecutionState::Completed { .. } => break,
            _ => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }

    // Verify receipt includes capability proof
    let (_, receipt) = spawner.collect_result(&handle).await.unwrap();
    assert!(receipt.capability_enforcement.timeout_enforced_secs > 0);
    #[cfg(target_os = "linux")]
    assert!(receipt.capability_enforcement.seccomp_rules_hash.is_some());
}
```

### Platform-Specific Tests

Run with `--lib --test-threads=1` to avoid resource contention:

```bash
# Linux: verify seccomp enforcement
cargo test test_seccomp_socket_block -- --nocapture

# BSD: verify pledge enforcement  
cargo test test_pledge_filesystem_block -- --nocapture

# macOS: verify entitlements applied
cargo test test_entitlements_network_block -- --nocapture

# Windows: verify job object limits
cargo test test_job_objects_cpu_limit -- --nocapture
```

## Performance

Sandbox execution introduces process spawning overhead:

- **Process spawn** is the dominant cost—OS-dependent (Linux ~5-10ms, varies by hardware)
- **Capability enforcement** (seccomp, pledge, entitlements) is loaded at spawn time, not per-syscall
- **Encryption/decryption** of execution context uses AES-256-GCM (fast, hardware-accelerated on modern CPUs)
- **Policy evaluation** is O(1)—cascade resolution is a simple fallback chain

The actual overhead depends heavily on OS and hardware. Measure on your target platform before tuning. Process spawning dominates; other operations are negligible compared to typical agent execution time.

For mission-critical latency paths, sandbox can be disabled per-agent via policy (trusted internal agents, etc.). Tradeoff: no isolation, but attestation receipts still include this fact for audit visibility.

## Security Model

### Threat Model: What It Prevents

- **Filesystem exfiltration**: Child process can't read outside allowed paths
- **Network exfiltration**: Socket syscalls blocked (Linux), capabilities revoked (BSD)
- **Privilege escalation**: Child drops capabilities, can't regain them
- **Resource exhaustion**: CPU/memory limits enforced
- **Subprocess chain attacks**: Subprocess spawning blocked
- **Timing attacks on sensitive data**: Only applicable with specific kernel versions

### What It Doesn't Prevent

- **Payload injection**: Malicious input to agent logic isn't caught by sandbox (but blast radius is constrained)
- **Side-channel attacks**: Speculative execution exploits may still work
- **Algorithm bugs**: Logical bugs in agent code still produce wrong results
- **Timing analysis**: Side-channel information leaks aren't prevented (depends on kernel hardening)

### Attestation as Audit Trail

Every execution is cryptographically bound to constraints:

```rust
// Extract from receipt
let proof = &receipt.capability_enforcement;

// Verify enforcement happened
assert_eq!(proof.timeout_enforced_secs, 30);
assert!(proof.seccomp_rules_hash.is_some());  // Linux
assert!(proof.mlock_applied);  // Memory stayed in RAM

// Verify principal authorized it
assert!(verify_signature(
    &receipt.signature,
    &principal_did,
    &receipt.body_for_signing(),
));
```

Auditable: "Show me all executions of agent X under policy Y signed by principal Z, with seccomp rules hash matching H."

## Platform Support

| Platform | Status | Isolation | Notes |
|----------|--------|-----------|-------|
| **Linux** | ✅ Production | seccomp-bpf | BPF filters (deny-list + allowlist) |
| **BSD** | ✅ Production | pledge(2) | Simpler capability model, covers most use cases |
| **macOS** | ✅ Production | Entitlements + SIP | Security settings depend on user configuration |
| **Windows** | ✅ Production | Job Objects | Resource limits, process isolation |

Fallback: If sandbox fails to initialize, agent runs unsandboxed but receipt includes warning for audit visibility.

---

**See also:**
- [PAP Sandbox Integration Guide](../../docs/pap-sandbox-guide.md)
- [PAP Specification](../../docs/specification.md)
- [Papillon Canvas Lifecycle](../../docs/CANVAS_SPEC.md)
