use chrono::Utc;
use tauri::{AppHandle, Emitter, State};

use crate::db::prelude::DatabaseOps;
use crate::handshake;
use crate::state::AppState;
use papillon_shared::{BlockEvent, BlockState, BlockUpdate};

use pap_did::PrincipalKeypair;

use super::resolution::resolve_agent;
use super::INTENT_CONFIDENCE_THRESHOLD;

/// Map an NLU label to a schema.org action type and preferred agent name.
pub(crate) fn map_label_to_action(label: &str) -> (&'static str, &'static str) {
    match label {
        "weather" => ("schema:CheckAction", "Open-Meteo Weather"),
        "currency-exchange" => ("schema:TradeAction", "Frankfurter Exchange"),
        "dictionary" => ("schema:SearchAction", "Free Dictionary"),
        "code-repository" => ("schema:SearchAction", "GitHub Repos"),
        "book" => ("schema:SearchAction", "Open Library Books"),
        "tech-news" => ("schema:SearchAction", "Hacker News"),
        "academic-paper" => ("schema:SearchAction", "arXiv Papers"),
        "geocode" => ("schema:FindAction", "Nominatim Geocoding"),
        "dataset" => ("schema:DatasetAction", "Dataset Discovery"),
        "music" => ("schema:SearchAction", "MusicBrainz"),
        "film" => ("schema:SearchAction", "Open Movie Database"),
        "job-listing" => ("schema:SearchAction", "Remote OK Jobs"),
        "recipe" => ("schema:SearchAction", "MealDB Recipes"),
        "product" => ("schema:SearchAction", "Open Food Facts"),
        _ => ("schema:SearchAction", "DuckDuckGo Search"),
    }
}

/// Classify intent from a user prompt using federation-native NLU agents.
///
/// Fast path: bare HTTP/HTTPS URLs are routed deterministically to Web Page Reader.
/// All other prompts trigger a silent PAP handshake with a discovered
/// `schema:AnalyzeAction` agent (HuggingFace NLU or on-device LLM classifier).
/// Returns `(action_type, preferred_agent, effective_query)` as owned strings.
///
/// Falls back to `("schema:AskAction", "", raw_text)` when no NLU agent is
/// registered, the handshake fails, or confidence is below the configured threshold.
pub(crate) async fn classify_intent(
    app: &AppHandle,
    state: &State<'_, AppState>,
    block_id: &str,
    text: &str,
) -> (String, String, String) {
    // Level 1: deterministic fast path — bare HTTP/HTTPS URLs → Web Page Reader
    let (action, preferred, query) = papillon_shared::intent::detect_intent(text);
    if action != "schema:AnalyzeAction" {
        return (action.to_owned(), preferred.to_owned(), query);
    }

    // Level 2: BM25 semantic index — ~50µs scoring, no network, no spinner needed.
    // Built from the current canvas's agent DB so it reflects approved agents.
    // agent_name is a hint only; downstream resolve_agent applies disclosure
    // scoring so no agent is forced without proper permission evaluation.
    // Falls through to Level 3 when confidence < INTENT_CONFIDENCE_THRESHOLD or catalog is empty.
    {
        let agents = state.db.load_all_agents().unwrap_or_else(|e| {
            eprintln!("[classify_intent] agent catalog unavailable, skipping BM25: {e}");
            vec![]
        });
        let intent_index = pap_agents::IntentIndex::new(&agents);
        if let Some(m) = intent_index.classify(text, INTENT_CONFIDENCE_THRESHOLD) {
            // Empty string means "no forced agent" — resolve_agent selects
            // the best candidate by disclosure scope and profile history.
            let preferred_agent = m.agent_name.unwrap_or_default();
            return (m.action, preferred_agent, m.cleaned_query);
        }
    }

    // Level 3: federation NLU — emit phase 0 spinner while the slower path runs
    {
        let now = Utc::now().to_rfc3339();
        let _ = app.emit(
            "block_updated",
            BlockEvent {
                block: BlockUpdate {
                    id: block_id.to_string(),
                    prompt_id: String::new(),
                    prompt_text: None,
                    state: BlockState::Resolving {
                        phase: 0,
                        phase_label: "Detecting intent\u{2026}".into(),
                    },
                    schema_type: None,
                    content: None,
                    agent_did: None,
                    mandate_expires_at: None,
                    preference_guided: false,
                    created_at: now.clone(),
                    updated_at: now,
                },
            },
        );
    }

    // Universal fallback: when NLU classification cannot run or is not confident,
    // route to DuckDuckGo web search (no API key, always available) rather than
    // schema:AskAction which requires a local LLM.
    macro_rules! nlu_fallback {
        () => {
            return (
                "schema:SearchAction".to_owned(),
                "DuckDuckGo Search".to_owned(),
                text.to_owned(),
            )
        };
    }

    // Resolve NLU agent — scoring drives priority, no name hint needed
    let Ok(resolved) = resolve_agent(state, "schema:AnalyzeAction", "", &[]).await else {
        nlu_fallback!();
    };

    let principal_kp = {
        let seed_guard = state.principal_seed.read().unwrap_or_else(|e| e.into_inner());
        let Some(seed) = seed_guard.as_ref() else {
            nlu_fallback!();
        };
        match PrincipalKeypair::from_bytes(seed) {
            Ok(kp) => kp,
            Err(_) => nlu_fallback!(),
        }
    };

    let Ok(result) = handshake::execute(handshake::HandshakeParams {
        handler: resolved.handler,
        agent_name: &resolved.name,
        agent_did: &resolved.did,
        action_type: "schema:AnalyzeAction",
        query: text,
        principal_kp: &principal_kp,
        requires_disclosure: &resolved.requires_disclosure,
        returns: &resolved.returns,
        on_phase: Box::new(|_, _| {}),
        on_fail: Box::new(|_, _| {}),
    })
    .await
    else {
        nlu_fallback!();
    };

    let label = result
        .content
        .get("actionType")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let confidence = result
        .content
        .get("confidence")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    // cleanedQuery: produced by LLM classifiers, absent for HuggingFace.
    // When present, the capability agent receives the distilled query.
    let effective_query = result
        .content
        .get("cleanedQuery")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(text)
        .to_owned();

    let threshold = {
        let cfg = state.orchestrator_config.read().unwrap_or_else(|e| e.into_inner());
        cfg.intent_confidence_threshold
    };

    if confidence < threshold || label.is_empty() || label == "question-answer" {
        nlu_fallback!();
    }

    let (action_type, preferred_agent) = map_label_to_action(label);
    (
        action_type.to_owned(),
        preferred_agent.to_owned(),
        effective_query,
    )
}
