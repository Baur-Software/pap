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
///
/// Returns `(action_type, preferred_agent, effective_query, disclosure_context_type)`.
///
/// `disclosure_context_type` is the schema.org type that scopes the SD-JWT disclosure
/// set in Phase 2 of the PAP handshake — e.g. `schema:ExchangeRateSpecification` for
/// currency queries, `schema:GeoCoordinates` for location queries. Derived from the
/// ontology index hit when available; falls back to the resolved agent's `object_types[0]`
/// or `schema:Thing` when neither source has data.
pub(crate) async fn classify_intent(
    app: &AppHandle,
    state: &State<'_, AppState>,
    block_id: &str,
    text: &str,
) -> (String, String, String, String) {
    // Level 1: deterministic fast path — bare HTTP/HTTPS URLs → Web Page Reader
    let (action, preferred, query) = papillon_shared::intent::detect_intent(text);
    if action != "schema:AnalyzeAction" {
        // URL reads operate on WebPage objects — no personal data context.
        return (action.to_owned(), preferred.to_owned(), query, "schema:WebPage".to_owned());
    }

    // Level 2: BM25 token index — ~5µs cache read, no DB access, no spinner.
    // The IntentIndex is pre-built at startup and invalidated on agent mutations
    // via AppState::rebuild_intent_index(). Load the full agent list only when
    // the semantic index (Level 2.5) or context-type derivation needs it.
    let bm25_match = {
        let cache = state
            .intent_index_cache
            .read()
            .unwrap_or_else(|e| e.into_inner());
        cache.classify(text, INTENT_CONFIDENCE_THRESHOLD)
    };

    // Load agents lazily — only needed for context-type derivation or the semantic path.
    let agents = std::sync::OnceLock::new();
    let load_agents = || {
        agents.get_or_init(|| {
            state.db.load_all_agents().unwrap_or_else(|e| {
                eprintln!("[classify_intent] agent catalog unavailable: {e}");
                vec![]
            })
        })
    };

    if let Some(m) = bm25_match {
        let preferred_agent = m.agent_name.unwrap_or_default();
        let ctx = load_agents()
            .iter()
            .find(|a| a.name == preferred_agent)
            .and_then(|a| a.object_types.first().cloned())
            .unwrap_or_else(|| "schema:Thing".to_owned());
        return (m.action, preferred_agent, m.cleaned_query, ctx);
    }

    // Level 2.5: ordvec semantic index — ~5ms, no network.
    // Prefers ontology mode (schema-ontology.tvrq seeded from schema.org) over
    // descriptor mode (embed agent descriptors on startup). Falls through
    // gracefully to Level 3 when neither model file set is present on disk.
    #[cfg(feature = "semantic-index")]
    {
        let catalog = load_agents();
        let sem_idx = pap_agents::SemanticIndex::from_ontology(catalog, None)
            .or_else(|| pap_agents::SemanticIndex::build(catalog, None));
        if let Some(idx) = sem_idx {
            let hits = idx.search(text, 1);
            if let Some(top) = hits.into_iter().next() {
                let ctx = catalog
                    .iter()
                    .find(|a| a.name == top.agent_name)
                    .and_then(|a| a.object_types.first().cloned())
                    .unwrap_or_else(|| "schema:Thing".to_owned());
                return (top.action, top.agent_name, text.to_owned(), ctx);
            }
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
                    retention_warning: None,
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
                "schema:Thing".to_owned(),
            )
        };
    }

    // Resolve NLU agent — scoring drives priority, no name hint needed
    let Ok(resolved) = resolve_agent(state, "schema:AnalyzeAction", "", &[]).await else {
        nlu_fallback!();
    };

    let principal_kp = {
        let seed_guard = state
            .principal_seed
            .read()
            .unwrap_or_else(|e| e.into_inner());
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
        // NLU classification discloses only the query text, not personal data.
        disclosure_context_type: "schema:Text",
        extra_disclosures: std::collections::HashMap::new(),
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
        let cfg = state
            .orchestrator_config
            .read()
            .unwrap_or_else(|e| e.into_inner());
        cfg.intent_confidence_threshold
    };

    if confidence < threshold || label.is_empty() || label == "question-answer" {
        nlu_fallback!();
    }

    let (action_type, preferred_agent) = map_label_to_action(label);
    // NLU path: look up context type from matched agent's object_types.
    let ctx = load_agents()
        .iter()
        .find(|a| a.name == preferred_agent)
        .and_then(|a| a.object_types.first().cloned())
        .unwrap_or_else(|| "schema:Thing".to_owned());
    (
        action_type.to_owned(),
        preferred_agent.to_owned(),
        effective_query,
        ctx,
    )
}
