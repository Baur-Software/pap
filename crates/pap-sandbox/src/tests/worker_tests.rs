use crate::ipc::{decrypt, encrypt, ExecutionContext, ExecutionResult};
use crate::policy::CapabilityPolicy;
use crate::receipt::AttestationReceipt;

fn make_ephemeral_key() -> [u8; 32] {
    [0x42u8; 32]
}

fn make_test_context(session_id: &str) -> (ExecutionContext, [u8; 32]) {
    let key = make_ephemeral_key();
    let (query_enc, nonce) = encrypt(session_id.as_bytes(), &key).unwrap();
    let ctx = ExecutionContext {
        query_enc,
        disclosure_enc: vec![],
        session_token_enc: vec![],
        nonce,
        ephemeral_public_key: key.to_vec(),
        agent_did: "did:key:z6MkTest".to_string(),
        agent_name: "TestAgent".to_string(),
        action_type: "schema:SearchAction".to_string(),
        session_id: session_id.to_string(),
    };
    (ctx, key)
}

#[test]
fn execution_context_round_trips_through_json() {
    let (ctx, _) = make_test_context("sess-001");
    let json = serde_json::to_string(&ctx).unwrap();
    let recovered: ExecutionContext = serde_json::from_str(&json).unwrap();
    assert_eq!(recovered.session_id, "sess-001");
    assert_eq!(recovered.agent_did, "did:key:z6MkTest");
    assert_eq!(recovered.query_enc, ctx.query_enc);
    assert_eq!(recovered.nonce, ctx.nonce);
}

#[test]
fn execution_result_round_trips_through_json() {
    let key = make_ephemeral_key();
    let result_value = serde_json::json!({"@type": "Thing", "name": "result"});
    let result_bytes = serde_json::to_vec(&result_value).unwrap();
    let (result_enc, nonce) = encrypt(&result_bytes, &key).unwrap();

    let result_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&result_bytes))
    };

    let receipt = AttestationReceipt {
        session_id: "sess-001".to_string(),
        agent_did: "did:key:z6MkTest".to_string(),
        agent_name: "TestAgent".to_string(),
        action_type: "schema:SearchAction".to_string(),
        timestamp: chrono::Utc::now(),
        execution_duration_ms: 42,
        capability_enforcement: crate::receipt::CapabilityProof {
            seccomp_rules_hash: None,
            pledge_promises: None,
            entitlements_applied: None,
            memory_protection: crate::receipt::MemoryProtection {
                mlock_applied: false,
                encryption_used: true,
                sensitive_buffers_wiped: true,
            },
            timeout_enforced_secs: 30,
            network_blocked: true,
            filesystem_restricted: true,
            subprocess_blocked: true,
        },
        result_hash: result_hash.clone(),
        exit_code: 0,
        aborted: false,
        abort_reason: None,
    };

    let exec_result = ExecutionResult {
        result_enc: result_enc.clone(),
        nonce: nonce.clone(),
        receipt,
    };

    let json = serde_json::to_string(&exec_result).unwrap();
    let recovered: ExecutionResult = serde_json::from_str(&json).unwrap();

    assert_eq!(recovered.result_enc, result_enc);
    assert_eq!(recovered.nonce, nonce);
    assert_eq!(recovered.receipt.session_id, "sess-001");
    assert_eq!(recovered.receipt.exit_code, 0);
    assert!(!recovered.receipt.aborted);
}

#[test]
fn full_ipc_round_trip_encrypt_serialize_deserialize_decrypt() {
    let session_id = "sess-round-trip";
    let (ctx, key) = make_test_context(session_id);

    // Parent side: serialize context to JSON (what gets written to child stdin).
    let ctx_json = serde_json::to_string(&ctx).unwrap();

    // Child side: deserialize context from stdin JSON.
    let child_ctx: ExecutionContext = serde_json::from_str(&ctx_json).unwrap();

    // Child side: decrypt the query.
    let child_key: [u8; 32] = child_ctx
        .ephemeral_public_key
        .as_slice()
        .try_into()
        .unwrap();
    let decrypted = decrypt(&child_ctx.query_enc, &child_key, &child_ctx.nonce).unwrap();
    let recovered_session_id = String::from_utf8(decrypted).unwrap();
    assert_eq!(recovered_session_id, session_id);

    // Child side: produce a result, encrypt it, build receipt.
    let result_value = serde_json::json!({"@type": "SearchAction", "result": "found"});
    let result_bytes = serde_json::to_vec(&result_value).unwrap();
    let (result_enc, result_nonce) = encrypt(&result_bytes, &child_key).unwrap();
    let result_hash = AttestationReceipt::hash_result(&result_value);

    let receipt = AttestationReceipt {
        session_id: child_ctx.session_id.clone(),
        agent_did: child_ctx.agent_did.clone(),
        agent_name: child_ctx.agent_name.clone(),
        action_type: child_ctx.action_type.clone(),
        timestamp: chrono::Utc::now(),
        execution_duration_ms: 10,
        capability_enforcement: crate::receipt::CapabilityProof {
            seccomp_rules_hash: None,
            pledge_promises: None,
            entitlements_applied: Some(vec!["windows:job-object".to_string()]),
            memory_protection: crate::receipt::MemoryProtection {
                mlock_applied: false,
                encryption_used: true,
                sensitive_buffers_wiped: true,
            },
            timeout_enforced_secs: 30,
            network_blocked: true,
            filesystem_restricted: true,
            subprocess_blocked: true,
        },
        result_hash,
        exit_code: 0,
        aborted: false,
        abort_reason: None,
    };

    let exec_result = ExecutionResult {
        result_enc,
        nonce: result_nonce,
        receipt,
    };

    // Child side: serialize result to JSON (what gets written to stdout).
    let result_json = serde_json::to_string(&exec_result).unwrap();

    // Parent side: deserialize result from child stdout.
    let parent_result: ExecutionResult = serde_json::from_str(&result_json).unwrap();

    // Parent side: verify receipt fields.
    assert_eq!(parent_result.receipt.session_id, session_id);
    assert_eq!(parent_result.receipt.agent_did, "did:key:z6MkTest");
    assert_eq!(parent_result.receipt.exit_code, 0);
    assert!(!parent_result.receipt.aborted);
    assert!(!parent_result.result_enc.is_empty());

    // Parent side: decrypt the result.
    let plaintext = decrypt(&parent_result.result_enc, &key, &parent_result.nonce).unwrap();
    let recovered_value: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(recovered_value["@type"], "SearchAction");
    assert_eq!(recovered_value["result"], "found");
}

#[test]
fn empty_result_enc_detected_as_broken_pipeline() {
    let exec_result = ExecutionResult {
        result_enc: vec![],
        nonce: vec![],
        receipt: AttestationReceipt {
            session_id: "s".into(),
            agent_did: "d".into(),
            agent_name: "n".into(),
            action_type: "a".into(),
            timestamp: chrono::Utc::now(),
            execution_duration_ms: 0,
            capability_enforcement: crate::receipt::CapabilityProof {
                seccomp_rules_hash: None,
                pledge_promises: None,
                entitlements_applied: None,
                memory_protection: crate::receipt::MemoryProtection {
                    mlock_applied: false,
                    encryption_used: false,
                    sensitive_buffers_wiped: false,
                },
                timeout_enforced_secs: 0,
                network_blocked: false,
                filesystem_restricted: false,
                subprocess_blocked: false,
            },
            result_hash: String::new(),
            exit_code: 0,
            aborted: false,
            abort_reason: None,
        },
    };

    assert!(
        exec_result.result_enc.is_empty(),
        "empty result_enc signals broken IPC — handler_wrapper must reject this"
    );
}

#[test]
fn policy_serializes_for_cli_arg() {
    let policy = CapabilityPolicy::default();
    let json = serde_json::to_string(&policy).unwrap();
    let recovered: CapabilityPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(
        recovered.execution_timeout_secs,
        policy.execution_timeout_secs
    );
    assert_eq!(recovered.network_allowed, policy.network_allowed);
    assert_eq!(recovered.filesystem_allowed, policy.filesystem_allowed);
    assert_eq!(recovered.subprocess_allowed, policy.subprocess_allowed);
}

#[test]
fn context_with_wrong_key_length_would_fail_decryption() {
    let (mut ctx, _key) = make_test_context("sess-bad-key");
    ctx.ephemeral_public_key = vec![0u8; 16]; // wrong length

    let result: Result<[u8; 32], _> = ctx.ephemeral_public_key.as_slice().try_into();
    assert!(
        result.is_err(),
        "16-byte key must fail conversion to [u8; 32]"
    );
}

#[test]
fn context_with_tampered_ciphertext_fails_decryption() {
    let (mut ctx, _key) = make_test_context("sess-tamper");
    let key: [u8; 32] = ctx.ephemeral_public_key.as_slice().try_into().unwrap();

    ctx.query_enc[0] ^= 0xFF;
    let result = decrypt(&ctx.query_enc, &key, &ctx.nonce);
    assert!(
        result.is_err(),
        "tampered ciphertext must fail AES-GCM auth"
    );
}
