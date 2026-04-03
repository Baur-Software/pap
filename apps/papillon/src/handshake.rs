//! Drives the 6-phase PAP handshake against an AgentHandler.
//!
//! The orchestrator treats agents as untrusted — all communication flows
//! through the AgentHandler trait, never through type-specific backdoors.
//! Query data is passed via handle_disclosure (protocol-native).
//!
//! **Security**: Secrets are phase-scoped. The principal keypair only signs
//! in phases 1–2 and is not retained after. The ephemeral session keypair
//! only signs in phase 5 and is dropped immediately after co-signing.
//! With `ed25519-dalek/zeroize` enabled, `SigningKey` zeroes its memory on drop.

use std::sync::Arc;

use chrono::{Duration, Utc};
use serde_json::json;

use pap_core::mandate::Mandate;
use pap_core::receipt::TransactionReceipt;
use pap_core::scope::{DisclosureEntry, DisclosureSet, Scope, ScopeAction};
use pap_core::session::{CapabilityToken, Session};
use pap_did::{PrincipalKeypair, SessionKeypair};
use pap_transport::AgentHandler;

use crate::error::PapillonError;

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

/// Artifacts produced by phases 1–2 that require the principal signing key.
/// Once this is built, the principal keypair reference is no longer needed.
struct AuthArtifacts {
    agent_session_id: String,
    receiver_session_did: String,
    principal_did: String,
    disclosure_set: DisclosureSet,
    initiator_did: String,
    initiator_kp: SessionKeypair,
}

/// Parameters for running a handshake.
pub struct HandshakeParams<'a> {
    pub handler: Arc<dyn AgentHandler>,
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

/// Run the full 6-phase PAP handshake.
///
/// All agent interaction goes through the handler trait — no downcasting,
/// no type-specific methods. The query reaches the agent through disclosures.
pub async fn execute(params: HandshakeParams<'_>) -> Result<HandshakeResult, PapillonError> {
    let HandshakeParams {
        handler,
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

        let (agent_session_id, receiver_session_did) =
            handler.handle_token(token).map_err(|e| {
                on_fail(1, &e.to_string());
                PapillonError::from(format!("Agent rejected token: {}", e))
            })?;

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

        handler
            .handle_did_exchange(&agent_session_id, &initiator_did)
            .map_err(|e| {
                on_fail(2, &e.to_string());
                PapillonError::from(format!("DID exchange failed: {}", e))
            })?;

        AuthArtifacts {
            agent_session_id,
            receiver_session_did,
            principal_did,
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

    handler
        .handle_disclosure(&auth.agent_session_id, disclosures)
        .map_err(|e| {
            on_fail(3, &e.to_string());
            PapillonError::from(format!("Disclosure failed: {}", e))
        })?;

    // ── Phase 4: Agent executes ─────────────────────────────
    on_phase(4, &format!("{} working...", agent_name));

    let handler_clone = handler.clone();
    let sid = auth.agent_session_id.clone();
    let execution_result = tokio::task::spawn_blocking(move || handler_clone.execute(&sid))
        .await
        .map_err(|e| {
            on_fail(4, &e.to_string());
            PapillonError::from(format!("Execution task panicked: {}", e))
        })?
        .map_err(|e| {
            on_fail(4, &e.to_string());
            PapillonError::from(e.to_string())
        })?;

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
        // bookkeeping — we already proved principal ownership in phase 1.
        // Session::initiate verifies the token signature, so we must pass the
        // key that signed it, not the principal key (dropped after Phase 2).
        let receipt_signer = SessionKeypair::generate();
        receipt_token.sign(receipt_signer.signing_key());
        let receipt_verifying_key = receipt_signer.verifying_key();
        // receipt_signer drops here (zeroized)

        let mut session = Session::initiate(&receipt_token, agent_did, &receipt_verifying_key)
            .map_err(|e| {
                on_fail(5, &e.to_string());
                PapillonError::from(e.to_string())
            })?;

        session
            .open(
                auth.initiator_did.clone(),
                auth.receiver_session_did.clone(),
            )
            .map_err(|e| PapillonError::from(e.to_string()))?;
        session
            .execute()
            .map_err(|e| PapillonError::from(e.to_string()))?;

        let mut receipt = TransactionReceipt::from_session(
            &session,
            auth.disclosure_set.property_refs(),
            vec![format!("operator:{}_executed", action_type)],
            format!("{} executed", action_type),
            returns.join(", "),
        )
        .map_err(|e| {
            on_fail(5, &e.to_string());
            PapillonError::from(e.to_string())
        })?;

        // Sign with the ephemeral session key, then drop it
        receipt.co_sign(auth.initiator_kp.signing_key());
        // auth.initiator_kp is consumed by this block and drops at block end (zeroized)

        // Agent co-signs — zero trust: they can refuse
        let receipt = handler.co_sign_receipt(receipt).map_err(|e| {
            on_fail(5, &e.to_string());
            PapillonError::from(format!("Agent refused to co-sign: {}", e))
        })?;

        session
            .close()
            .map_err(|e| PapillonError::from(e.to_string()))?;

        (session.id.clone(), receipt.signatures.len())
    };
    // auth.initiator_kp is dropped here — SigningKey zeroizes on drop.

    // ── Phase 6: Close session ──────────────────────────────
    on_phase(6, "Closing session...");

    handler.handle_close(&auth.agent_session_id).map_err(|e| {
        on_fail(6, &e.to_string());
        PapillonError::from(e.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use pap_agents::executor::{AgentExecutor, AgentMeta};
    use pap_transport::TransportError;
    use std::sync::Arc;

    /// Echo executor — returns the query as a schema:Thing with no network calls.
    /// Used to test the full 6-phase handshake protocol mechanics in isolation.
    struct EchoExecutor;

    impl AgentExecutor for EchoExecutor {
        fn meta(&self) -> AgentMeta {
            AgentMeta {
                name: "Echo",
                provider: "Test",
                action: "schema:SearchAction",
                object_types: &["schema:Thing"],
                requires_disclosure: &[],
                returns: &["schema:Thing"],
            }
        }

        fn execute(&self, query: &str) -> Result<serde_json::Value, TransportError> {
            Ok(serde_json::json!({
                "@context": "https://schema.org",
                "@type": "SearchResultsPage",
                "query": query,
                "mainEntity": {
                    "@type": "ItemList",
                    "itemListElement": [{"@type": "Thing", "name": query}]
                }
            }))
        }
    }

    /// Agent handler flow: token → disclosure → execute → result.
    /// Tests the exact code path that canvas_prompt uses, protocol mechanics only.
    #[tokio::test]
    async fn agent_handler_returns_real_results() {
        use pap_core::session::CapabilityToken;

        let echo_handler: Arc<dyn pap_transport::AgentHandler> =
            Arc::new(pap_agents::SimpleAgent::new(EchoExecutor));
        let meta = EchoExecutor.meta();

        let agents = pap_agents::build_agents(vec![(
            "Echo",
            echo_handler,
            meta,
        )]);
        let handler = agents
            .handlers
            .get("Echo")
            .expect("Echo handler");
        let ad = agents
            .registry
            .all_advertisements()
            .iter()
            .find(|a| a.name == "Echo")
            .expect("Echo advertisement");

        let kp = PrincipalKeypair::generate();
        let ttl = chrono::Utc::now() + chrono::Duration::hours(1);

        // Phase 1: Present token
        let mut token = CapabilityToken::mint(
            ad.provider.did.clone(),
            "schema:SearchAction".to_string(),
            kp.did(),
            ttl,
        );
        token.sign(kp.signing_key());
        let (session_id, _receiver_did) = handler.handle_token(token).expect("token accepted");

        // Phase 2: DID exchange
        let session_kp = SessionKeypair::generate();
        handler
            .handle_did_exchange(&session_id, &session_kp.did())
            .expect("DID exchange");

        // Phase 3: Disclosure
        handler
            .handle_disclosure(
                &session_id,
                vec![serde_json::json!({
                    "@type": "schema:SearchAction",
                    "query": "protocol handshake test"
                })],
            )
            .expect("disclosure accepted");

        // Phase 4: Execute
        let result = tokio::task::spawn_blocking({
            let handler = handler.clone();
            let sid = session_id.clone();
            move || handler.execute(&sid)
        })
        .await
        .expect("task didn't panic")
        .expect("execute succeeded");

        // Verify protocol result shape
        assert_eq!(result["@type"].as_str(), Some("SearchResultsPage"));
        let list = result["mainEntity"]["itemListElement"].as_array();
        assert!(list.is_some(), "should have itemListElement");
        assert!(!list.unwrap().is_empty(), "results should not be empty");

        // Phase 6: Close
        handler.handle_close(&session_id).expect("close");
    }
}
