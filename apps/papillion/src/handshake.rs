//! Drives the 6-phase PAP handshake against an AgentHandler.
//!
//! The orchestrator treats agents as untrusted — all communication flows
//! through the AgentHandler trait, never through type-specific backdoors.
//! Query data is passed via handle_disclosure (protocol-native).

use std::sync::Arc;

use chrono::{Duration, Utc};
use serde_json::json;

use pap_core::mandate::Mandate;
use pap_core::receipt::TransactionReceipt;
use pap_core::scope::{DisclosureEntry, DisclosureSet, Scope, ScopeAction};
use pap_core::session::{CapabilityToken, Session};
use pap_did::{PrincipalKeypair, SessionKeypair};
use pap_transport::AgentHandler;

use crate::error::PapillionError;

/// Result of a successful handshake.
pub struct HandshakeResult {
    pub schema_type: String,
    pub content: serde_json::Value,
    pub agent_name: String,
}

/// Callback for phase progress. (phase_number, label)
pub type PhaseCallback = Box<dyn Fn(u8, &str) + Send>;

/// Callback for failures. (phase_number, reason)
pub type FailCallback = Box<dyn Fn(u8, &str) + Send>;

/// Run the full 6-phase PAP handshake.
///
/// All agent interaction goes through the handler trait — no downcasting,
/// no type-specific methods. The query reaches the agent through disclosures.
pub async fn execute(
    handler: Arc<dyn AgentHandler>,
    agent_name: &str,
    agent_did: &str,
    action_type: &str,
    query: &str,
    principal_kp: &PrincipalKeypair,
    requires_disclosure: &[String],
    returns: &[String],
    on_phase: PhaseCallback,
    on_fail: FailCallback,
) -> Result<HandshakeResult, PapillionError> {
    let principal_did = principal_kp.did();
    let ttl = Utc::now() + Duration::hours(1);

    // ── Phase 1: Present token to agent ─────────────────────
    on_phase(1, "Discovering agents...");

    let mut token = CapabilityToken::mint(
        agent_did.to_string(),
        action_type.to_string(),
        principal_did.clone(),
        ttl,
    );
    token.sign(principal_kp.signing_key());

    let (agent_session_id, receiver_session_did) =
        handler.handle_token(token).map_err(|e| {
            on_fail(1, &e.to_string());
            PapillionError::from(format!("Agent rejected token: {}", e))
        })?;

    // ── Phase 2: Issue mandate + DID exchange ───────────────
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

    handler
        .handle_did_exchange(&agent_session_id, &initiator_did)
        .map_err(|e| {
            on_fail(2, &e.to_string());
            PapillionError::from(format!("DID exchange failed: {}", e))
        })?;

    // ── Phase 3: Send disclosures (query goes here) ─────────
    on_phase(3, "Opening session...");

    let disclosures = vec![json!({
        "@type": action_type,
        "query": query
    })];

    handler
        .handle_disclosure(&agent_session_id, disclosures)
        .map_err(|e| {
            on_fail(3, &e.to_string());
            PapillionError::from(format!("Disclosure failed: {}", e))
        })?;

    // ── Phase 4: Agent executes ─────────────────────────────
    on_phase(4, &format!("{} working...", agent_name));

    let handler_clone = handler.clone();
    let sid = agent_session_id.clone();
    let execution_result = tokio::task::spawn_blocking(move || {
        handler_clone.execute(&sid)
    })
    .await
    .map_err(|e| {
        on_fail(4, &e.to_string());
        PapillionError::from(format!("Execution task panicked: {}", e))
    })?
    .map_err(|e| {
        on_fail(4, &e.to_string());
        PapillionError::from(e.to_string())
    })?;

    // ── Phase 5: Co-sign receipt ────────────────────────────
    on_phase(5, "Co-signing receipt...");

    // Build receipt from an in-memory session (for structure)
    let mut receipt_token = CapabilityToken::mint(
        agent_did.to_string(),
        action_type.to_string(),
        principal_did.clone(),
        ttl,
    );
    receipt_token.sign(principal_kp.signing_key());

    let mut session =
        Session::initiate(&receipt_token, agent_did, &principal_kp.verifying_key())
            .map_err(|e| {
                on_fail(5, &e.to_string());
                PapillionError::from(e.to_string())
            })?;

    session.open(initiator_did, receiver_session_did).map_err(|e| PapillionError::from(e.to_string()))?;
    session.execute().map_err(|e| PapillionError::from(e.to_string()))?;

    let mut receipt = TransactionReceipt::from_session(
        &session,
        disclosure_set.property_refs(),
        vec![format!("operator:{}_executed", action_type)],
        format!("{} executed", action_type),
        returns.join(", "),
    )
    .map_err(|e| {
        on_fail(5, &e.to_string());
        PapillionError::from(e.to_string())
    })?;

    receipt.co_sign(initiator_kp.signing_key());

    // Agent co-signs — zero trust: they can refuse
    let receipt = handler.co_sign_receipt(receipt).map_err(|e| {
        on_fail(5, &e.to_string());
        PapillionError::from(format!("Agent refused to co-sign: {}", e))
    })?;

    // ── Phase 6: Close session ──────────────────────────────
    on_phase(6, "Closing session...");

    handler.handle_close(&agent_session_id).map_err(|e| {
        on_fail(6, &e.to_string());
        PapillionError::from(e.to_string())
    })?;

    session.close().map_err(|e| PapillionError::from(e.to_string()))?;

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
            "session_id": session.id,
            "co_signatures": receipt.signatures.len(),
            "action": action_type
        }
    });

    Ok(HandshakeResult {
        schema_type,
        content,
        agent_name: agent_name.to_string(),
    })
}
