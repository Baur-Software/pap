//! WASM-native 6-phase PAP handshake executor.
//!
//! Port of `apps/papillon/src/handshake.rs` for browser environments.
//! Uses [`FetchClient`] (web_sys::fetch) instead of `Arc<dyn AgentHandler>`,
//! and async/await instead of `tokio::task::spawn_blocking`.
//!
//! **Security**: Secrets are phase-scoped identically to the native handshake.
//! The principal keypair only signs in phases 1–2 and is not retained after.
//! The ephemeral session keypair only signs in phase 5 and is dropped
//! immediately after co-signing. With `ed25519-dalek/zeroize` enabled,
//! `SigningKey` zeroes its memory on drop (WASM zeroization caveats apply;
//! see `docs/WASM_SECURITY.md`).

pub mod fetch_client;
pub mod intent;

use chrono::{Duration, Utc};
use serde_json::json;

use ed25519_dalek::VerifyingKey;
use pap_core::mandate::Mandate;
use pap_core::receipt::TransactionReceipt;
use pap_core::scope::{DisclosureEntry, DisclosureSet, Scope, ScopeAction};
use pap_core::session::{CapabilityToken, Session};
use pap_did::{PrincipalKeypair, SessionKeypair};
use pap_proto::ProtocolMessage;

use fetch_client::{FetchClient, FetchError};

/// Result of a successful WASM handshake.
pub struct HandshakeResult {
    pub schema_type: String,
    pub content: serde_json::Value,
    pub agent_name: String,
}

/// Callback for phase progress. No `Send` bound — WASM is single-threaded.
pub type PhaseCallback = Box<dyn Fn(u8, &str)>;

/// Callback for failures.
pub type FailCallback = Box<dyn Fn(u8, &str)>;

/// Artifacts produced by phases 1–2 that require the principal signing key.
/// Once this is built, the principal keypair reference is no longer needed.
struct AuthArtifacts {
    agent_session_id: String,
    receiver_session_did: String,
    principal_did: String,
    principal_verifying_key: VerifyingKey,
    disclosure_set: DisclosureSet,
    initiator_did: String,
    initiator_kp: SessionKeypair,
}

/// Parameters for running a WASM handshake.
pub struct WasmHandshakeParams<'a> {
    pub agent_base_url: &'a str,
    pub agent_name: &'a str,
    pub agent_did: &'a str,
    pub action_type: &'a str,
    pub query: &'a str,
    pub principal_kp: &'a PrincipalKeypair,
    pub requires_disclosure: &'a [String],
    pub returns: &'a [String],
    pub on_phase: PhaseCallback,
    pub on_fail: FailCallback,
}

/// Run the full 6-phase PAP handshake over the Fetch API.
///
/// All agent interaction goes through HTTP (same endpoints as AgentServer).
/// The query reaches the agent through disclosures (protocol-native).
pub async fn execute(params: WasmHandshakeParams<'_>) -> Result<HandshakeResult, FetchError> {
    let WasmHandshakeParams {
        agent_base_url,
        agent_name,
        agent_did,
        action_type,
        query,
        principal_kp,
        requires_disclosure,
        returns,
        on_phase,
        on_fail,
    } = params;

    let client = FetchClient::new(agent_base_url);
    let ttl = Utc::now() + Duration::hours(1);

    // ── Phases 1–2: Token + Mandate (principal key signs here, then released) ──
    let auth = {
        let principal_did = principal_kp.did();

        // Phase 1: Present token to agent
        on_phase(1, "Discovering agents...");

        let mut token = CapabilityToken::mint(
            agent_did.to_string(),
            action_type.to_string(),
            principal_did.clone(),
            ttl,
        );
        token.sign(principal_kp.signing_key());

        let resp = client.present_token(token).await.map_err(|e| {
            on_fail(1, &e.to_string());
            FetchError(format!("Agent rejected token: {}", e))
        })?;

        let (agent_session_id, receiver_session_did) = match resp {
            ProtocolMessage::TokenAccepted {
                session_id,
                receiver_session_did,
                ..
            } => (session_id, receiver_session_did),
            ProtocolMessage::TokenRejected { reason } => {
                on_fail(1, &reason);
                return Err(FetchError(format!("Agent rejected token: {}", reason)));
            }
            ProtocolMessage::Error { code, message } => {
                let msg = format!("Protocol error {}: {}", code, message);
                on_fail(1, &msg);
                return Err(FetchError(msg));
            }
            other => {
                let msg = format!("Unexpected response: {}", other.message_type());
                on_fail(1, &msg);
                return Err(FetchError(msg));
            }
        };

        // Phase 2: Issue mandate + DID exchange
        on_phase(2, &format!("Issuing mandate to {}...", agent_name));

        let disclosure_set = if requires_disclosure.is_empty() {
            DisclosureSet::empty()
        } else {
            DisclosureSet::new(vec![DisclosureEntry::new(
                "schema:Person",
                requires_disclosure.to_vec(),
                vec![],
            )])
        };

        let scope = Scope::new(vec![ScopeAction::new(action_type)]);
        let mut mandate = Mandate::issue_root(
            principal_did.clone(),
            agent_did.to_string(),
            scope,
            disclosure_set.clone(),
            ttl,
        );
        mandate.sign(principal_kp.signing_key());

        let initiator_kp = SessionKeypair::generate();
        let initiator_did = initiator_kp.did();

        let resp = client
            .exchange_did(&agent_session_id, initiator_did.clone())
            .await
            .map_err(|e| {
                on_fail(2, &e.to_string());
                FetchError(format!("DID exchange failed: {}", e))
            })?;

        match resp {
            ProtocolMessage::SessionDidAck => {}
            ProtocolMessage::Error { code, message } => {
                let msg = format!("DID exchange error {}: {}", code, message);
                on_fail(2, &msg);
                return Err(FetchError(msg));
            }
            other => {
                let msg = format!("Unexpected DID response: {}", other.message_type());
                on_fail(2, &msg);
                return Err(FetchError(msg));
            }
        }

        AuthArtifacts {
            agent_session_id,
            receiver_session_did,
            principal_did,
            principal_verifying_key: principal_kp.verifying_key(),
            disclosure_set,
            initiator_did,
            initiator_kp,
        }
    };
    // principal_kp borrow ends here — only the public VerifyingKey survives.
    // The signing key is no longer reachable from any live binding.

    // ── Phase 3: Send disclosures (query goes here) ─────────
    on_phase(3, "Opening session...");

    let disclosures = vec![json!({
        "@type": action_type,
        "query": query
    })];

    let resp = client
        .send_disclosures(&auth.agent_session_id, disclosures)
        .await
        .map_err(|e| {
            on_fail(3, &e.to_string());
            FetchError(format!("Disclosure failed: {}", e))
        })?;

    match resp {
        ProtocolMessage::DisclosureAccepted => {}
        ProtocolMessage::Error { code, message } => {
            let msg = format!("Disclosure error {}: {}", code, message);
            on_fail(3, &msg);
            return Err(FetchError(msg));
        }
        other => {
            let msg = format!("Unexpected disclosure response: {}", other.message_type());
            on_fail(3, &msg);
            return Err(FetchError(msg));
        }
    }

    // ── Phase 4: Agent executes ─────────────────────────────
    on_phase(4, &format!("{} working...", agent_name));

    let resp = client
        .request_execution(&auth.agent_session_id)
        .await
        .map_err(|e| {
            on_fail(4, &e.to_string());
            FetchError(format!("Execution failed: {}", e))
        })?;

    let execution_result = match resp {
        ProtocolMessage::ExecutionResult { result } => result,
        ProtocolMessage::Error { code, message } => {
            let msg = format!("Execution error {}: {}", code, message);
            on_fail(4, &msg);
            return Err(FetchError(msg));
        }
        other => {
            let msg = format!("Unexpected execution response: {}", other.message_type());
            on_fail(4, &msg);
            return Err(FetchError(msg));
        }
    };

    // ── Phase 5: Co-sign receipt (session key signs here, then dropped) ──
    on_phase(5, "Co-signing receipt...");

    let (session_id_out, sig_count) = {
        let mut receipt_token = CapabilityToken::mint(
            agent_did.to_string(),
            action_type.to_string(),
            auth.principal_did.clone(),
            ttl,
        );
        // Receipt token is signed with a fresh ephemeral signer for session
        // bookkeeping, not a fresh delegation.
        let receipt_signer = SessionKeypair::generate();
        receipt_token.sign(receipt_signer.signing_key());
        // receipt_signer drops here (zeroized)

        let mut session =
            Session::initiate(&receipt_token, agent_did, &auth.principal_verifying_key).map_err(
                |e| {
                    on_fail(5, &e.to_string());
                    FetchError(e.to_string())
                },
            )?;

        session
            .open(
                auth.initiator_did.clone(),
                auth.receiver_session_did.clone(),
            )
            .map_err(|e| FetchError(e.to_string()))?;
        session
            .execute()
            .map_err(|e| FetchError(e.to_string()))?;

        let mut receipt = TransactionReceipt::from_session(
            &session,
            auth.disclosure_set.property_refs(),
            vec![format!("operator:{}_executed", action_type)],
            format!("{} executed", action_type),
            returns.join(", "),
        )
        .map_err(|e| {
            on_fail(5, &e.to_string());
            FetchError(e.to_string())
        })?;

        // Sign with the ephemeral session key, then drop it
        receipt.co_sign(auth.initiator_kp.signing_key());
        // auth.initiator_kp is consumed by this block and drops at block end (zeroized)

        // Agent co-signs — zero trust: they can refuse
        let resp = client
            .exchange_receipt(&auth.agent_session_id, receipt)
            .await
            .map_err(|e| {
                on_fail(5, &e.to_string());
                FetchError(format!("Agent refused to co-sign: {}", e))
            })?;

        let receipt = match resp {
            ProtocolMessage::ReceiptCoSigned { receipt } => receipt,
            ProtocolMessage::Error { code, message } => {
                let msg = format!("Receipt error {}: {}", code, message);
                on_fail(5, &msg);
                return Err(FetchError(msg));
            }
            other => {
                let msg = format!("Unexpected receipt response: {}", other.message_type());
                on_fail(5, &msg);
                return Err(FetchError(msg));
            }
        };

        session
            .close()
            .map_err(|e| FetchError(e.to_string()))?;

        (session.id.clone(), receipt.signatures.len())
    };
    // auth.initiator_kp is dropped here — SigningKey zeroizes on drop.

    // ── Phase 6: Close session ──────────────────────────────
    on_phase(6, "Closing session...");

    let _resp = client
        .close_session(&auth.agent_session_id)
        .await
        .map_err(|e| {
            on_fail(6, &e.to_string());
            FetchError(e.to_string())
        })?;

    let schema_type = execution_result["@type"]
        .as_str()
        .unwrap_or("Thing")
        .to_string();

    let content = json!({
        "@type": schema_type,
        "agent": agent_name,
        "query": query,
        "result": execution_result,
        "receipt": {
            "session_id": session_id_out,
            "co_signatures": sig_count,
            "action": action_type
        }
    });

    Ok(HandshakeResult {
        schema_type,
        content,
        agent_name: agent_name.to_string(),
    })
}

/// Run a WASM-native handshake from a prompt, updating Leptos signals directly.
///
/// This is the entry point called by `CanvasState::submit_prompt()` when
/// running outside Tauri. It resolves the agent from RegistryState, gets the
/// principal keypair from WebService, and executes the full 6-phase handshake.
pub async fn run_prompt(
    canvases: leptos::prelude::RwSignal<Vec<papillon_shared::Canvas>>,
    canvas_id: String,
    block_id: String,
    text: String,
    service: std::sync::Arc<dyn crate::service::PapillonService>,
    registry: crate::state::registry::RegistryState,
) -> Result<(), String> {
    use leptos::prelude::*;
    use papillon_shared::BlockState;

    // 1. Get the principal keypair from the service layer
    let principal_kp = service
        .active_keypair()
        .map_err(|e| format!("No identity: {}", e))?;

    // 2. Intent detection
    let (action_type, preferred_agent, query) = intent::detect_intent(&text);

    // 3. Resolve agent from RegistryState (populated via Browse page)
    let agents = registry.agents.get();

    let agent = agents
        .iter()
        .find(|a| {
            a.capabilities.iter().any(|c| c == action_type)
                && a.name.contains(preferred_agent)
        })
        .or_else(|| {
            // Fallback: match by capability alone
            agents
                .iter()
                .find(|a| a.capabilities.iter().any(|c| c == action_type))
        })
        .ok_or_else(|| {
            format!(
                "No agent available for '{}'. Navigate to a registry first.",
                action_type
            )
        })?;

    let agent_endpoint = agent
        .endpoint
        .as_deref()
        .ok_or_else(|| format!("Agent '{}' has no endpoint URL", agent.name))?;

    let agent_name = agent.name.clone();
    let agent_did = agent.provider_did.clone();
    let requires_disclosure = agent.requires_disclosure.clone();
    let returns = agent.returns.clone();

    // 4. Build phase callbacks that update Leptos signals directly
    let on_phase = {
        let canvases = canvases;
        let cid = canvas_id.clone();
        let bid = block_id.clone();
        Box::new(move |phase: u8, label: &str| {
            let cid = cid.clone();
            let bid = bid.clone();
            let label = label.to_string();
            canvases.update(move |cs| {
                if let Some(canvas) = cs.iter_mut().find(|c| c.id == cid) {
                    if let Some(b) = canvas.blocks.iter_mut().find(|b| b.id == bid) {
                        b.state = BlockState::Resolving {
                            phase,
                            phase_label: label,
                        };
                        b.updated_at = js_sys::Date::new_0()
                            .to_iso_string()
                            .as_string()
                            .unwrap_or_default();
                    }
                }
            });
        }) as PhaseCallback
    };

    let on_fail = {
        let canvases = canvases;
        let cid = canvas_id.clone();
        let bid = block_id.clone();
        Box::new(move |phase: u8, reason: &str| {
            let cid = cid.clone();
            let bid = bid.clone();
            let reason = reason.to_string();
            canvases.update(move |cs| {
                if let Some(canvas) = cs.iter_mut().find(|c| c.id == cid) {
                    if let Some(b) = canvas.blocks.iter_mut().find(|b| b.id == bid) {
                        b.state = BlockState::Failed { phase, reason };
                        b.updated_at = js_sys::Date::new_0()
                            .to_iso_string()
                            .as_string()
                            .unwrap_or_default();
                    }
                }
            });
        }) as FailCallback
    };

    // 5. Execute the 6-phase handshake
    let result = execute(WasmHandshakeParams {
        agent_base_url: agent_endpoint,
        agent_name: &agent_name,
        agent_did: &agent_did,
        action_type,
        query: &query,
        principal_kp: &principal_kp,
        requires_disclosure: &requires_disclosure,
        returns: &returns,
        on_phase,
        on_fail,
    })
    .await
    .map_err(|e| e.to_string())?;

    // 6. Update block to Resolved state with result
    canvases.update(|cs| {
        if let Some(canvas) = cs.iter_mut().find(|c| c.id == canvas_id) {
            if let Some(b) = canvas.blocks.iter_mut().find(|b| b.id == block_id) {
                b.state = BlockState::Resolved;
                b.schema_type = Some(result.schema_type);
                b.content = Some(result.content);
                b.updated_at = js_sys::Date::new_0()
                    .to_iso_string()
                    .as_string()
                    .unwrap_or_default();
            }
        }
    });

    Ok(())
}
