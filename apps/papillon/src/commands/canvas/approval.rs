use chrono::Utc;
use tauri::{AppHandle, Emitter, State};

use crate::challenge_store::SignedChallenge;
use crate::error::PapillonError;
use crate::state::AppState;
use papillon_shared::{AgentCandidate, BlockEvent, BlockState, BlockUpdate, IntentPlan, PreferenceEngine};

use super::super::orchestrator::hash_agent_did;
use super::execution::process_prompt;
use super::helpers::maybe_auto_generate_template;
use super::intent::classify_intent;
use super::resolution::resolve_top_agents;

/// Two-phase canvas prompt: plan first (emit `AwaitingApproval`), then wait for
/// principal approval before running the full handshake.
///
/// If `auto_approve_zero_disclosure` is enabled in the orchestrator config and the
/// resolved agent requires no disclosure fields, the gate is skipped and the
/// handshake runs immediately.
#[tauri::command]
pub async fn canvas_plan_prompt(
    app: AppHandle,
    state: State<'_, AppState>,
    _canvas_id: String,
    prompt_id: String,
    block_id: String,
    text: String,
) -> Result<serde_json::Value, PapillonError> {
    // Classify intent once — result is reused for plan-building and handshake.
    let (action_type, preferred, query) = classify_intent(&app, &state, &block_id, &text).await;

    // Early-exit for dataset discovery — routes to multi-agent fan-out coordinator
    if action_type == "schema:DatasetAction" {
        return crate::commands::dataset_discovery::canvas_discover_datasets(
            app, state, _canvas_id, prompt_id, block_id, text,
        )
        .await;
    }

    // Resolve top-3 candidates.
    let candidates_resolved = resolve_top_agents(&state, &action_type, &preferred, &[], 3).await?;

    // Primary agent is the top-scored candidate.
    let primary = &candidates_resolved[0];

    // Union of requires_disclosure across all candidates (dedup, insertion order).
    let mut union_disclosure: Vec<String> = Vec::new();
    for c in &candidates_resolved {
        for prop in &c.requires_disclosure {
            if !union_disclosure.contains(prop) {
                union_disclosure.push(prop.clone());
            }
        }
    }

    let approval_request_id = uuid::Uuid::new_v4().to_string();

    let mandate_ttl_hours = {
        let cfg = state
            .orchestrator_config
            .read()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        cfg.mandate_ttl_hours
    };

    let candidates: Vec<AgentCandidate> = candidates_resolved
        .iter()
        .map(|r| AgentCandidate {
            name: r.name.clone(),
            did: r.did.clone(),
            requires_disclosure: r.requires_disclosure.clone(),
            returns: r.returns.clone(),
        })
        .collect();

    let plan = IntentPlan {
        action: action_type.to_string(),
        selected_agent_name: primary.name.clone(),
        selected_agent_did: Some(primary.did.clone()),
        requires_disclosure: union_disclosure,
        returns: primary.returns.clone(),
        approval_request_id: approval_request_id.clone(),
        ttl_hours: mandate_ttl_hours as u32,
        candidates,
    };

    // Extract owned primary identity strings before any await points to avoid
    // holding a borrow across the oneshot receiver.await below.
    let primary_did = primary.did.clone();
    let primary_name = primary.name.clone();

    // Check auto-approve shortcut: if configured and no disclosure required, skip the gate.
    let auto_approve = {
        let config = state
            .orchestrator_config
            .read()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        config.auto_approve_zero_disclosure
    } && plan.requires_disclosure.is_empty();

    // Widen: also skip the gate when the principal has already approved these
    // exact scopes for this (action, schema) pair in a prior session.
    let schema_type_for_pref = plan.returns.first().map(String::as_str).unwrap_or("");
    let auto_approve = auto_approve
        || PreferenceEngine::new(state.db.as_ref()).has_approved_scopes(
            &action_type,
            schema_type_for_pref,
            &plan.requires_disclosure,
        );

    if auto_approve {
        // Run directly without emitting AwaitingApproval.
        let (schema_type, content, preference_guided, agent_did, retention_warning) =
            process_prompt(
                &app,
                &state,
                &prompt_id,
                &block_id,
                &action_type,
                &preferred,
                &query,
            )
            .await?;
        maybe_auto_generate_template(&state, &schema_type, &content);
        let now = Utc::now().to_rfc3339();
        let mandate_expires_at =
            Some((Utc::now() + chrono::Duration::hours(mandate_ttl_hours as i64)).to_rfc3339());
        let _ = app.emit(
            "block_resolved",
            BlockEvent {
                block: BlockUpdate {
                    id: block_id.clone(),
                    prompt_id,
                    prompt_text: Some(text),
                    state: BlockState::Resolved,
                    schema_type: Some(schema_type),
                    content: Some(content),
                    agent_did: Some(agent_did),
                    mandate_expires_at,
                    preference_guided,
                    created_at: now.clone(),
                    updated_at: now,
                    retention_warning,
                },
            },
        );
        return Ok(serde_json::json!({ "status": "ok", "block_id": block_id }));
    }

    // Emit the AwaitingApproval block so the frontend can render the approval UI.
    let now = Utc::now().to_rfc3339();
    let _ = app.emit(
        "block_updated",
        BlockEvent {
            block: BlockUpdate {
                id: block_id.clone(),
                prompt_id: prompt_id.clone(),
                prompt_text: Some(text.clone()),
                state: BlockState::AwaitingApproval { plan: plan.clone() },
                schema_type: None,
                content: None,
                agent_did: None,
                mandate_expires_at: None,
                preference_guided: false,
                created_at: now.clone(),
                updated_at: now,
                retention_warning: None,
            },
        },
    );

    // Create the oneshot channel and store the sender in the approval_gates map.
    let (sender, receiver) = tokio::sync::oneshot::channel::<bool>();
    {
        let mut gates = state.approval_gates.write().await;
        gates.insert(approval_request_id.clone(), sender);
    }

    // Block until the principal approves or rejects (or the sender is dropped).
    let approved = receiver.await.unwrap_or(false);

    if approved {
        // Persist the approval so future identical requests skip the gate.
        PreferenceEngine::new(state.db.as_ref()).save_approved_scopes(
            &action_type,
            schema_type_for_pref,
            &hash_agent_did(&primary_did),
            &primary_name,
            &plan.requires_disclosure,
        );

        // Run the full handshake.
        let (schema_type, content, preference_guided, agent_did, retention_warning) =
            process_prompt(
                &app,
                &state,
                &prompt_id,
                &block_id,
                &action_type,
                &preferred,
                &query,
            )
            .await?;
        maybe_auto_generate_template(&state, &schema_type, &content);
        let now = Utc::now().to_rfc3339();
        let mandate_expires_at =
            Some((Utc::now() + chrono::Duration::hours(mandate_ttl_hours as i64)).to_rfc3339());
        let _ = app.emit(
            "block_resolved",
            BlockEvent {
                block: BlockUpdate {
                    id: block_id.clone(),
                    prompt_id,
                    prompt_text: Some(text),
                    state: BlockState::Resolved,
                    schema_type: Some(schema_type),
                    content: Some(content),
                    agent_did: Some(agent_did),
                    mandate_expires_at,
                    preference_guided,
                    created_at: now.clone(),
                    updated_at: now,
                    retention_warning,
                },
            },
        );
        Ok(serde_json::json!({ "status": "ok", "block_id": block_id }))
    } else {
        // Principal rejected — emit a Failed block.
        let now = Utc::now().to_rfc3339();
        let _ = app.emit(
            "block_resolved",
            BlockEvent {
                block: BlockUpdate {
                    id: block_id.clone(),
                    prompt_id,
                    prompt_text: Some(text),
                    state: BlockState::Failed {
                        phase: 0,
                        reason: "Rejected by principal".to_string(),
                    },
                    schema_type: None,
                    content: None,
                    agent_did: None,
                    mandate_expires_at: None,
                    preference_guided: false,
                    created_at: now.clone(),
                    updated_at: now,
                    retention_warning: None,
                },
            },
        );
        Ok(serde_json::json!({ "status": "rejected", "block_id": block_id }))
    }
}

/// Resolve a pending approval gate created by `canvas_plan_prompt`.
///
/// Sends `approved` (true/false) through the oneshot channel, which unblocks
/// the waiting `canvas_plan_prompt` command and either proceeds with the
/// handshake or emits a Failed block.
///
/// **Challenge requirement**: `signed_challenge` must contain a valid
/// [`SignedChallenge`] obtained from [`get_identity_challenge`] and signed with
/// the current principal's keypair. This prevents a compromised frontend page
/// (e.g. a malicious `pap://` link) from silently approving data-disclosing
/// mandates on behalf of the principal.
#[tauri::command]
pub async fn canvas_approve_block(
    approval_request_id: String,
    approved: bool,
    signed_challenge: SignedChallenge,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // Verify the principal signed this approval before acting on it.
    {
        let signer_lock = state.signer.read().map_err(|e| e.to_string())?;

        let signer = signer_lock
            .as_ref()
            .ok_or_else(|| "no principal identity to authorize approval against".to_string())?;

        state
            .identity_challenges
            .take_and_verify(&signed_challenge, &signer.verifying_key())
            .map_err(|e| format!("authorization failed: {e}"))?;
    }

    let sender = {
        let mut gates = state.approval_gates.write().await;
        gates.remove(&approval_request_id)
    };
    if let Some(sender) = sender {
        let _ = sender.send(approved);
        Ok(())
    } else {
        Err(format!(
            "No approval gate found for {}",
            approval_request_id
        ))
    }
}
