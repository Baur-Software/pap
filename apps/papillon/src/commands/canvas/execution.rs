use chrono::Utc;
use tauri::{AppHandle, Emitter, State};

use pap_did::PrincipalKeypair;

use crate::error::PapillonError;
use crate::handshake;
use crate::state::AppState;
use papillon_shared::{BlockEvent, BlockState, BlockUpdate, PreferenceEngine};

use super::super::orchestrator::hash_agent_did;
use super::resolution::resolve_agent;

/// Quick quality assessment of a handshake result (0.0 to 1.0).
/// Evaluates content richness without requiring an Episode record.
pub(crate) fn assess_handshake_quality(result: &handshake::HandshakeResult) -> f64 {
    let content = &result.content;
    let payload = content.get("result");
    match payload {
        None => 0.3,
        Some(serde_json::Value::Null) => 0.2,
        Some(serde_json::Value::String(s)) if s.is_empty() => 0.3,
        Some(serde_json::Value::String(s)) if s.len() < 20 => 0.5,
        Some(serde_json::Value::Object(map)) if map.is_empty() => 0.3,
        Some(serde_json::Value::Array(arr)) if arr.is_empty() => 0.3,
        Some(serde_json::Value::Array(arr)) if arr.len() < 3 => 0.6,
        Some(serde_json::Value::Object(map)) => {
            let fields = map.len();
            match fields {
                0 => 0.3,
                1..=2 => 0.6,
                3..=5 => 0.8,
                _ => 1.0,
            }
        }
        _ => 0.8,
    }
}

/// Discover agent, resolve handler, run handshake, and apply reflection.
/// Callers must pre-classify intent via `classify_intent` before calling this.
pub(crate) async fn process_prompt(
    app: &AppHandle,
    state: &State<'_, AppState>,
    prompt_id: &str,
    block_id: &str,
    action_type: &str,
    preferred: &str,
    query: &str,
) -> Result<(String, serde_json::Value, bool, String), PapillonError> {
    process_prompt_inner(
        app,
        state,
        prompt_id,
        block_id,
        action_type,
        preferred,
        query,
        &[],
        0,
    )
    .await
}

/// Inner implementation with exclusion list and retry budget for reflection.
/// Uses `Box::pin` for the recursive async call required by the reflection gate.
///
/// Returns `(schema_type, content, preference_guided, agent_did)` where `preference_guided`
/// is `true` when the PreferenceEngine had meaningful history that influenced
/// agent selection, and `agent_did` is the DID of the resolved agent.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub(crate) fn process_prompt_inner<'a>(
    app: &'a AppHandle,
    state: &'a State<'a, AppState>,
    prompt_id: &'a str,
    block_id: &'a str,
    action_type: &'a str,
    preferred: &'a str,
    query: &'a str,
    exclude_agents: &'a [String],
    retry_count: u8,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<(String, serde_json::Value, bool, String), PapillonError>,
            > + Send
            + 'a,
    >,
> {
    Box::pin(async move {
        let resolved = resolve_agent(state, action_type, preferred, exclude_agents).await?;
        // Capture agent DID before the handshake so it can be threaded into block_resolved.
        let agent_did = resolved.did.clone();

        // Derive schema type from agent's declared returns (first element).
        let schema_hint = resolved.returns.first().cloned().unwrap_or_default();
        let agent_did_hash = hash_agent_did(&resolved.did);

        // Check guidance BEFORE recording — so the badge reflects pre-selection history,
        // not the selection we're about to record (which would fire on the tip-over episode).
        let engine = PreferenceEngine::new(state.db.as_ref());
        let preference_guided = engine.is_preference_guided(action_type, &schema_hint);
        engine.record_agent_selected(action_type, &schema_hint, &agent_did_hash, &resolved.name);

        // Get principal keypair
        let principal_kp = {
            let seed_guard = state.principal_seed.read().unwrap();
            let seed = seed_guard
                .as_ref()
                .ok_or_else(|| PapillonError::from("No identity configured"))?;
            PrincipalKeypair::from_bytes(seed)
                .map_err(|e| PapillonError::from(format!("Failed to load keypair: {}", e)))?
        };

        // Phase progress callbacks emit Tauri events.
        // Thread the computed preference_guided flag so the frontend can show
        // the "based on your preferences" badge during intermediate states too.
        let bid = block_id.to_string();
        let pid = prompt_id.to_string();
        let app_phase = app.clone();
        let on_phase: handshake::PhaseCallback = Box::new(move |phase, label| {
            let now = Utc::now().to_rfc3339();
            let block = BlockUpdate {
                id: bid.clone(),
                prompt_id: pid.clone(),
                prompt_text: None,
                state: BlockState::Resolving {
                    phase,
                    phase_label: label.into(),
                },
                schema_type: None,
                content: None,
                agent_did: None,
                mandate_expires_at: None,
                preference_guided,
                created_at: now.clone(),
                updated_at: now,
            };
            let _ = app_phase.emit("block_updated", BlockEvent { block });
        });

        let bid2 = block_id.to_string();
        let pid2 = prompt_id.to_string();
        let app_fail = app.clone();
        let on_fail: handshake::FailCallback = Box::new(move |phase, reason| {
            let now = Utc::now().to_rfc3339();
            let block = BlockUpdate {
                id: bid2.clone(),
                prompt_id: pid2.clone(),
                prompt_text: None,
                state: BlockState::Failed {
                    phase,
                    reason: reason.into(),
                },
                schema_type: None,
                content: None,
                agent_did: None,
                mandate_expires_at: None,
                preference_guided,
                created_at: now.clone(),
                updated_at: now,
            };
            let _ = app_fail.emit("block_resolved", BlockEvent { block });
        });

        let result = handshake::execute(handshake::HandshakeParams {
            handler: resolved.handler,
            agent_name: &resolved.name,
            agent_did: &resolved.did,
            action_type,
            query,
            principal_kp: &principal_kp,
            requires_disclosure: &resolved.requires_disclosure,
            returns: &resolved.returns,
            on_phase,
            on_fail,
        })
        .await?;

        // Reflection gate: if quality is low and we haven't retried yet,
        // try the next-best agent.
        let quality = assess_handshake_quality(&result);
        if quality < 0.5 && retry_count == 0 {
            let mut new_exclude = exclude_agents.to_vec();
            new_exclude.push(resolved.name.clone());

            // Check if an alternative agent exists before retrying
            if resolve_agent(state, action_type, preferred, &new_exclude)
                .await
                .is_ok()
            {
                // Emit a "reflecting" phase event
                let now = Utc::now().to_rfc3339();
                let _ = app.emit(
                    "block_updated",
                    BlockEvent {
                        block: BlockUpdate {
                            id: block_id.to_string(),
                            prompt_id: prompt_id.to_string(),
                            prompt_text: None,
                            state: BlockState::Resolving {
                                phase: 7,
                                phase_label: "Reflecting — trying alternative agent...".into(),
                            },
                            schema_type: None,
                            content: None,
                            agent_did: None,
                            mandate_expires_at: None,
                            preference_guided,
                            created_at: now.clone(),
                            updated_at: now,
                        },
                    },
                );

                return process_prompt_inner(
                    app,
                    state,
                    prompt_id,
                    block_id,
                    action_type,
                    preferred,
                    query,
                    &new_exclude,
                    retry_count + 1,
                )
                .await;
            }
        }

        // Record outcome after the quality gate — success only when quality is acceptable.
        // If we retried (returned early above), this line is never reached for the bad attempt.
        PreferenceEngine::new(state.db.as_ref()).record_outcome(
            action_type,
            &schema_hint,
            &agent_did_hash,
            quality >= 0.5,
        );

        Ok((
            result.schema_type,
            result.content,
            preference_guided,
            agent_did,
        ))
    })
}
