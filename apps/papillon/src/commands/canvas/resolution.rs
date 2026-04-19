use std::sync::Arc;

use tauri::State;

use pap_federation::{build_pinned_client, PapUrl};
use pap_transport::{AgentHandler, RemoteAgentHandler};

use crate::db::prelude::DatabaseOps;
use crate::error::PapillonError;
use crate::state::AppState;
use papillon_shared::PreferenceEngine;

use super::super::orchestrator::hash_agent_did;

/// Result of agent resolution from registries.
pub(crate) struct ResolvedAgent {
    pub name: String,
    pub did: String,
    pub handler: Arc<dyn AgentHandler>,
    pub requires_disclosure: Vec<String>,
    pub returns: Vec<String>,
}

/// Score an agent candidate using profile history and local preference signals.
/// Higher is better.  The score combines:
/// - `AgentProfile` EMA statistics (success_rate, avg_quality)
/// - `PreferenceEngine` schema-type-aware preference score
/// - A keyword-match bonus for the intent-matched agent name
/// - Model-substrate signals: local agents that can use the user's configured LLM
///   are boosted; remote agents missing an API token are penalised
///
/// Preference score contributes up to 30% of the total when the engine has
/// enough history (≥ 3 sessions).  EMA statistics contribute 40% each on top.
#[allow(clippy::too_many_arguments)]
fn score_agent(
    db: &crate::db::Database,
    agent_did: &str,
    preferred_name: &str,
    agent_name: &str,
    action_type: &str,
    schema_type: &str,
    agent_def: Option<&pap_agents::DynamicAgentDef>,
    inference_substrate: &papillon_shared::LlmProvider,
) -> f64 {
    let agent_did_hash = hash_agent_did(agent_did);

    // Preference engine score (0.0 on cold start, up to 1.0 with history)
    let engine = PreferenceEngine::new(db);
    let pref_score = engine.preference_score(action_type, schema_type, &agent_did_hash);

    // Keyword match bonus
    let keyword_bonus = if agent_name == preferred_name {
        1.0
    } else {
        0.0
    };

    // ── Model-substrate / source signals ─────────────────────────────────
    let mut substrate_delta: f64 = 0.0;

    if let Some(def) = agent_def {
        // Agents without an external HTTP endpoint run locally via the LLM substrate.
        if def.endpoint.is_none() {
            // Any configured LLM substrate (not None) means this agent can run.
            if !matches!(inference_substrate, papillon_shared::LlmProvider::None) {
                substrate_delta += 0.4;
            }
            // Fully on-device BuiltIn model — most private, highest bonus.
            if matches!(
                inference_substrate,
                papillon_shared::LlmProvider::BuiltIn { .. }
            ) {
                substrate_delta += 0.2;
            }
        } else if let Some(endpoint) = &def.endpoint {
            // Agent has an external endpoint — check if it needs auth and has a token.
            let needs_auth = endpoint.headers.contains_key("Authorization");
            if needs_auth {
                let api_token_set = db
                    .get_agent_settings(&agent_did_hash)
                    .ok()
                    .and_then(|settings| settings.get("api_token").map(|s| !s.value.is_empty()))
                    .unwrap_or(false);
                if !api_token_set {
                    // Would fail — deprioritize.
                    substrate_delta -= 0.3;
                }
            }
        }

        // Source bonus/penalty.
        match def.source {
            pap_agents::DynamicAgentSource::Catalog => {
                substrate_delta += 0.1;
            }
            pap_agents::DynamicAgentSource::Generated => {
                substrate_delta -= 0.1;
            }
            _ => {}
        }
    } else {
        // No local def found — treat as federated/remote agent.
        substrate_delta -= 0.1;
    }

    let base_score = match db.get_agent_profile(&agent_did_hash).ok().flatten() {
        Some(profile) if profile.episode_count >= 3 => {
            // 35% success_rate + 35% avg_quality + 20% preference + 10% keyword
            let base = 0.35 * profile.success_rate + 0.35 * profile.avg_quality;
            base + 0.20 * pref_score + 0.10 * keyword_bonus
        }
        Some(_) => {
            // Too few EMA episodes — lean on preference + keyword
            if pref_score > 0.0 {
                0.40 + 0.30 * pref_score + 0.10 * keyword_bonus
            } else if agent_name == preferred_name {
                0.7
            } else {
                0.5
            }
        }
        None => {
            // No EMA history — preference engine + keyword fallback
            if pref_score > 0.0 {
                0.30 + 0.40 * pref_score + 0.10 * keyword_bonus
            } else if agent_name == preferred_name {
                0.6
            } else {
                0.4
            }
        }
    };

    base_score + substrate_delta
}

/// Resolve an agent by action type: discover from registries, build handler.
/// Applies memory-informed scoring to rank candidates.
/// `exclude_agents` filters out agents by name (used by reflection retries).
pub(crate) async fn resolve_agent(
    state: &State<'_, AppState>,
    action_type: &str,
    preferred_name: &str,
    exclude_agents: &[String],
) -> Result<ResolvedAgent, PapillonError> {
    // Load all local agent defs once for model-substrate / source scoring.
    // Keyed by agent DID so we can look up quickly per candidate.
    let agent_defs: std::collections::HashMap<String, pap_agents::DynamicAgentDef> = state
        .db
        .load_all_agents()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|d| d.agent_did.clone().map(|did| (did, d)))
        .collect();

    // Read inference substrate from the orchestrator config for substrate scoring.
    let inference_substrate = {
        let cfg = state.orchestrator_config.read().unwrap();
        cfg.inference_substrate.clone()
    };

    // Discover agent — try local registry first, then remote registries.
    let (agent_name, agent_did, requires_disclosure, returns, source_url) = {
        let local = state
            .local_registry
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        // Use query_local (not query_local_satisfiable) for local agents:
        // local agents run on the user's device and are trusted. Disclosure
        // filtering is meaningful for remote/federated agents, not local ones.
        let candidates = local.query_local(action_type);

        // Filter out excluded agents, then score the rest
        let eligible: Vec<_> = candidates
            .iter()
            .filter(|a| !exclude_agents.contains(&a.name))
            .collect();

        let best = if eligible.is_empty() {
            None
        } else {
            let mut scored: Vec<_> = eligible
                .iter()
                .map(|a| {
                    // Use first returns type as schema hint for preference scoring
                    let schema_hint = a.returns.first().map(|s| s.as_str()).unwrap_or("");
                    let agent_def = agent_defs.get(&a.provider.did);
                    let s = score_agent(
                        &state.db,
                        &a.provider.did,
                        preferred_name,
                        &a.name,
                        action_type,
                        schema_hint,
                        agent_def,
                        &inference_substrate,
                    );
                    (*a, s)
                })
                .collect();
            scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            scored.first().map(|(a, _)| *a)
        };

        if let Some(agent) = best {
            (
                agent.name.clone(),
                agent.provider.did.clone(),
                agent.requires_disclosure.clone(),
                agent.returns.clone(),
                None, // local — no source URL
            )
        } else {
            // Not found locally — search synced remote registries
            drop(local);
            let registries = state
                .registries
                .read()
                .map_err(|e| PapillonError::from(e.to_string()))?;

            let mut found = None;
            for (url, registry) in registries.iter() {
                let remote_candidates = registry.query_local_satisfiable(action_type, &[]);
                let eligible: Vec<_> = remote_candidates
                    .iter()
                    .filter(|a| !exclude_agents.contains(&a.name))
                    .collect();

                let best = if eligible.is_empty() {
                    None
                } else {
                    let mut scored: Vec<_> = eligible
                        .iter()
                        .map(|a| {
                            let schema_hint = a.returns.first().map(|s| s.as_str()).unwrap_or("");
                            // Remote/federated agents won't be in the local agent_defs map.
                            let agent_def = agent_defs.get(&a.provider.did);
                            let s = score_agent(
                                &state.db,
                                &a.provider.did,
                                preferred_name,
                                &a.name,
                                action_type,
                                schema_hint,
                                agent_def,
                                &inference_substrate,
                            );
                            (*a, s)
                        })
                        .collect();
                    scored
                        .sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
                    scored.first().map(|(a, _)| *a)
                };

                if let Some(agent) = best {
                    found = Some((
                        agent.name.clone(),
                        agent.provider.did.clone(),
                        agent.requires_disclosure.clone(),
                        agent.returns.clone(),
                        Some(url.clone()),
                    ));
                    break;
                }
            }

            found.ok_or_else(|| PapillonError::from(format!("No agent for {}", action_type)))?
        }
    };

    // Resolve handler — local handler or remote proxy over TLS.
    let handler: Arc<dyn AgentHandler> = if let Some(h) = state.local_agents.get(&agent_name) {
        h.clone()
    } else if let Some(ref pap_url) = source_url {
        let parsed = PapUrl::parse(pap_url).map_err(|e| PapillonError::from(e.to_string()))?;
        let endpoint = parsed.https_endpoint();

        let fingerprint = {
            let local = state
                .local_registry
                .lock()
                .map_err(|e| PapillonError::from(e.to_string()))?;
            local
                .peers()
                .iter()
                .find(|p| p.endpoint.trim_end_matches('/') == endpoint.trim_end_matches('/'))
                .and_then(|p| p.cert_fingerprint.clone())
        };

        let slug = agent_name.to_lowercase().replace(' ', "-");
        let base_url = format!("{}/agents/{}", endpoint, slug);

        if let Some(fp) = fingerprint {
            let http_client =
                build_pinned_client(&[fp]).map_err(|e| PapillonError::from(e.to_string()))?;
            Arc::new(RemoteAgentHandler::with_client(&base_url, http_client))
        } else {
            return Err(PapillonError::from(format!(
                "No cert fingerprint for peer {} — navigate to it first",
                endpoint
            )));
        }
    } else {
        return Err(PapillonError::from(format!(
            "No handler for {}",
            agent_name
        )));
    };

    Ok(ResolvedAgent {
        name: agent_name,
        did: agent_did,
        handler,
        requires_disclosure,
        returns,
    })
}
