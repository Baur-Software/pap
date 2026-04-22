use leptos::prelude::*;
use leptos_router::components::A;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use papillon_shared::db::Episode;

// ── Page ────────────────────────────────────────────────────────────────────

#[component]
pub fn ReceiptsPage() -> impl IntoView {
    let episodes: RwSignal<Vec<Episode>> = RwSignal::new(vec![]);
    let loading: RwSignal<bool> = RwSignal::new(true);
    let query: RwSignal<String> = RwSignal::new(String::new());
    let selected_id: RwSignal<Option<String>> = RwSignal::new(None);

    // ── Load episodes on mount ────────────────────────────────────────────
    Effect::new(move || {
        if bridge::tauri_available() {
            spawn_local(async move {
                #[derive(serde::Serialize)]
                struct LimitArgs {
                    limit: Option<usize>,
                }
                if let Ok(eps) = bridge::invoke::<LimitArgs, Vec<Episode>>(
                    "list_recent_episodes",
                    &LimitArgs { limit: Some(200) },
                )
                .await
                {
                    episodes.set(eps);
                }
                loading.set(false);
            });
        } else {
            loading.set(false);
        }
    });

    // ── Filtered list ────────────────────────────────────────────────────
    let filtered = move || {
        let q = query.get().to_lowercase();
        episodes
            .get()
            .into_iter()
            .filter(|ep| {
                if q.is_empty() {
                    return true;
                }
                ep.agent_name.to_lowercase().contains(&q)
                    || ep
                        .query
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&q)
                    || ep
                        .intent_summary
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&q)
                    || ep.action_type.to_lowercase().contains(&q)
                    || ep.outcome.to_lowercase().contains(&q)
            })
            .collect::<Vec<_>>()
    };

    let total_count = move || episodes.get().len();
    let filtered_count = move || filtered().len();
    let success_count = move || {
        episodes
            .get()
            .iter()
            .filter(|e| e.outcome == "success")
            .count()
    };

    // ── Selected episode detail ──────────────────────────────────────────
    let selected_episode = move || {
        let id = selected_id.get()?;
        episodes.get().into_iter().find(|e| e.id == id)
    };

    view! {
        <div class="history-page">
            // ── Header ──────────────────────────────────────────────────
            <div class="history-header">
                <div class="history-header-left">
                    <A href="/" attr:class="history-back-btn" attr:title="Back to canvas" attr:aria-label="Back to canvas">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
                            stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <polyline points="15 18 9 12 15 6"/>
                        </svg>
                    </A>
                    <div class="history-header-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
                            stroke="currentColor" stroke-width="1.8">
                            <polyline points="1 4 1 10 7 10"/>
                            <path d="M3.51 15a9 9 0 1 0 .49-4.5"/>
                            <polyline points="12 7 12 12 15 15"/>
                        </svg>
                    </div>
                    <div>
                        <div class="history-title">"EPISODE HISTORY"</div>
                        <div class="history-subtitle">
                            "Past sessions · Agent interactions · Co-signed receipts"
                        </div>
                    </div>
                </div>
                <div class="history-header-right">
                    <span class="history-stat-badge">
                        {move || format!("{} total", total_count())}
                    </span>
                    <span class="history-stat-badge success">
                        {move || format!("{} succeeded", success_count())}
                    </span>
                </div>
            </div>

            // ── Search bar ───────────────────────────────────────────────
            <div class="history-search-bar">
                <div class="history-search-icon">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
                        stroke="currentColor" stroke-width="2">
                        <circle cx="11" cy="11" r="8"/>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                    </svg>
                </div>
                <input
                    type="text"
                    class="history-search-input"
                    placeholder="Search by query, agent, or action\u{2026}"
                    prop:value=move || query.get()
                    on:input=move |ev| query.set(leptos::prelude::event_target_value(&ev))
                />
                <Show when=move || !query.get().is_empty()>
                    <span class="history-search-count">
                        {move || format!("{} of {}", filtered_count(), total_count())}
                    </span>
                </Show>
            </div>

            // ── Body ─────────────────────────────────────────────────────
            <div class="history-body">
                // ── Episode list ─────────────────────────────────────────
                <div class="history-list">
                    <Show
                        when=move || loading.get()
                        fallback=move || view! {
                            <Show
                                when=move || filtered().is_empty()
                                fallback=move || view! {
                                    <For
                                        each=filtered
                                        key=|ep| ep.id.clone()
                                        children=move |ep| {
                                            let id = ep.id.clone();
                                            let id_click = id.clone();
                                            let is_selected =
                                                move || selected_id.get().as_deref() == Some(&id);
                                            view! {
                                                <EpisodeRow
                                                    episode=ep
                                                    selected=is_selected
                                                    on_select=move || {
                                                        selected_id.set(Some(id_click.clone()))
                                                    }
                                                />
                                            }
                                        }
                                    />
                                }
                            >
                                <div class="history-empty">
                                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none"
                                        stroke="currentColor" stroke-width="1.5"
                                        style="opacity: 0.2; margin-bottom: 10px;">
                                        <polyline points="1 4 1 10 7 10"/>
                                        <path d="M3.51 15a9 9 0 1 0 .49-4.5"/>
                                        <polyline points="12 7 12 12 15 15"/>
                                    </svg>
                                    {move || if query.get().is_empty() {
                                        "No episodes yet. Use the canvas to start interacting with agents."
                                    } else {
                                        "No matches. Try a different search term."
                                    }}
                                </div>
                            </Show>
                        }
                    >
                        <div class="history-loading">"Loading history\u{2026}"</div>
                    </Show>
                </div>

                // ── Detail panel ─────────────────────────────────────────
                <div class="history-detail">
                    <Show
                        when=move || selected_episode().is_some()
                        fallback=|| view! {
                            <div class="history-detail-empty">
                                "Select an episode to view details"
                            </div>
                        }
                    >
                        {move || selected_episode().map(|ep| view! {
                            <EpisodeDetail episode=ep />
                        })}
                    </Show>
                </div>
            </div>
        </div>
    }
}

// ── Episode row (list item) ─────────────────────────────────────────────────

#[component]
fn EpisodeRow(
    episode: Episode,
    selected: impl Fn() -> bool + Send + Sync + 'static,
    on_select: impl Fn() + 'static,
) -> impl IntoView {
    let outcome_class = match episode.outcome.as_str() {
        "success" => "history-outcome success",
        "failure" => "history-outcome failure",
        "rejected" => "history-outcome rejected",
        _ => "history-outcome",
    };
    let outcome_label = match episode.outcome.as_str() {
        "success" => "✓",
        "failure" => "✗",
        "rejected" => "⊘",
        _ => "?",
    };
    let action_label = episode
        .action_type
        .trim_start_matches("schema:")
        .to_string();
    let display_query = episode
        .query
        .clone()
        .or_else(|| episode.intent_summary.clone())
        .unwrap_or_else(|| format!("{} via {}", action_label, episode.agent_name));

    // Truncate display query for the list
    let short_query = if display_query.len() > 80 {
        format!("{}…", &display_query[..77])
    } else {
        display_query.clone()
    };

    // Format timestamp to be readable: drop the T, keep date + time (no subseconds)
    let ts = episode
        .recorded_at
        .replace('T', " ")
        .split('.')
        .next()
        .unwrap_or(&episode.recorded_at)
        .to_string();
    let short_ts = ts.chars().take(16).collect::<String>(); // "YYYY-MM-DD HH:MM"

    let duration_s = if episode.duration_ms > 0 {
        if episode.duration_ms >= 1000 {
            format!("{:.1}s", episode.duration_ms as f64 / 1000.0)
        } else {
            format!("{}ms", episode.duration_ms)
        }
    } else {
        String::new()
    };

    view! {
        <div
            class=move || if selected() { "history-row selected" } else { "history-row" }
            on:click=move |_| on_select()
        >
            <span class=outcome_class title=episode.outcome.clone()>
                {outcome_label}
            </span>
            <div class="history-row-body">
                <div class="history-row-query">{short_query}</div>
                <div class="history-row-meta">
                    <span class="history-row-agent">{episode.agent_name.clone()}</span>
                    <span class="history-row-sep">"·"</span>
                    <span class="history-row-action">{action_label}</span>
                    {if !duration_s.is_empty() {
                        view! {
                            <span class="history-row-sep">"·"</span>
                            <span class="history-row-duration">{duration_s}</span>
                        }.into_any()
                    } else {
                        view! { <span /> }.into_any()
                    }}
                </div>
            </div>
            <span class="history-row-ts">{short_ts}</span>
        </div>
    }
}

// ── Episode detail panel ────────────────────────────────────────────────────

#[component]
fn EpisodeDetail(episode: Episode) -> impl IntoView {
    // Pre-compute all derived strings BEFORE view! so nothing is borrowed inside the macro.
    let action_label = episode
        .action_type
        .trim_start_matches("schema:")
        .to_string();

    let outcome_class: &'static str = match episode.outcome.as_str() {
        "success" => "history-detail-outcome success",
        "failure" => "history-detail-outcome failure",
        "rejected" => "history-detail-outcome rejected",
        _ => "history-detail-outcome",
    };
    let outcome_text: &'static str = match episode.outcome.as_str() {
        "success" => "\u{2713} SUCCESS",
        "failure" => "\u{2717} FAILED",
        _ => "\u{2298} REJECTED",
    };

    let disclosure_refs: Vec<String> =
        serde_json::from_str(&episode.disclosure_refs).unwrap_or_default();
    let has_refs = !disclosure_refs.is_empty();
    // StoredValue lets the For-each closure be Fn (callable multiple times) without moving.
    let refs_stored = StoredValue::new(disclosure_refs);

    let ts = {
        let base = episode.recorded_at.replace('T', " ");
        base.split('.').next().unwrap_or("").to_string()
    };

    let duration_label = if episode.duration_ms > 0 {
        if episode.duration_ms >= 1000 {
            format!("{:.2}s", episode.duration_ms as f64 / 1000.0)
        } else {
            format!("{} ms", episode.duration_ms)
        }
    } else {
        "\u{2014}".to_string()
    };

    let (decay_text, decay_cls): (&'static str, &'static str) =
        match episode.decay_state.as_str() {
            "active" => ("ACTIVE", "decay-active"),
            "degraded" => ("DEGRADED", "decay-degraded"),
            "readonly" => ("READ-ONLY", "decay-readonly"),
            "suspended" => ("SUSPENDED", "decay-suspended"),
            _ => ("UNKNOWN", "decay-unknown"),
        };
    let decay_span_class = format!("history-decay-badge {decay_cls}");

    // Optional text fields — owned Strings
    let query_text: Option<String> = episode.query.clone();
    let intent_text: Option<String> = if episode.query.is_none() {
        episode.intent_summary.clone()
    } else {
        None
    };
    let outcome_detail_text: Option<String> = episode.outcome_detail.clone();
    let result_preview: Option<String> = episode
        .result_json
        .as_deref()
        .map(extract_result_preview);

    let agent_name = episode.agent_name.clone();
    let session_id = episode.receipt_session_id.clone();

    view! {
        <div class="history-detail-card">
            // ── Title ──────────────────────────────────────────────────
            <div class="history-detail-header">
                <span class=outcome_class>{outcome_text}</span>
                <span class=decay_span_class>{decay_text}</span>
            </div>

            // ── User query ─────────────────────────────────────────────
            {query_text.map(|q| view! {
                <div class="history-detail-section">
                    <div class="history-detail-label">"YOUR QUERY"</div>
                    <div class="history-detail-query">{q}</div>
                </div>
            })}

            {intent_text.map(|s| view! {
                <div class="history-detail-section">
                    <div class="history-detail-label">"INTENT"</div>
                    <div class="history-detail-query">{s}</div>
                </div>
            })}

            // ── Agent + action ─────────────────────────────────────────
            <div class="history-detail-grid">
                <div class="history-detail-field">
                    <div class="history-detail-label">"AGENT"</div>
                    <div class="history-detail-value">{agent_name}</div>
                </div>
                <div class="history-detail-field">
                    <div class="history-detail-label">"ACTION"</div>
                    <div class="history-detail-value">{action_label}</div>
                </div>
                <div class="history-detail-field">
                    <div class="history-detail-label">"DURATION"</div>
                    <div class="history-detail-value mono">{duration_label}</div>
                </div>
                <div class="history-detail-field">
                    <div class="history-detail-label">"RECORDED"</div>
                    <div class="history-detail-value mono">{ts}</div>
                </div>
            </div>

            // ── Disclosed properties ───────────────────────────────────
            <Show when=move || has_refs>
                <div class="history-detail-section">
                    <div class="history-detail-label">"DISCLOSED TO AGENT"</div>
                    <div class="history-detail-tags">
                        <For
                            each=move || refs_stored.get_value()
                            key=|p| p.clone()
                            children=|prop| view! {
                                <span class="history-tag disclosed">{prop}</span>
                            }
                        />
                    </div>
                </div>
            </Show>

            // ── Outcome detail ─────────────────────────────────────────
            {outcome_detail_text.map(|d| view! {
                <div class="history-detail-section">
                    <div class="history-detail-label">"DETAIL"</div>
                    <div class="history-detail-note">{d}</div>
                </div>
            })}

            // ── Result preview ─────────────────────────────────────────
            {result_preview.map(|preview| view! {
                <div class="history-detail-section">
                    <div class="history-detail-label">"RESULT PREVIEW"</div>
                    <div class="history-detail-result">{preview}</div>
                </div>
            })}

            // ── Session ID ─────────────────────────────────────────────
            <div class="history-detail-section">
                <div class="history-detail-label">"SESSION ID"</div>
                <div class="history-detail-value mono small">{session_id}</div>
            </div>
        </div>
    }
}

// ── Helper: extract readable text from JSON-LD result ──────────────────────

fn extract_result_preview(json: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return json.chars().take(200).collect();
    };

    // Try common schema.org text fields in priority order
    for key in &["description", "text", "articleBody", "headline", "name"] {
        if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return if trimmed.len() > 280 {
                    format!("{}…", &trimmed[..277])
                } else {
                    trimmed.to_string()
                };
            }
        }
    }
    // Fallback: pretty-print first 280 chars
    let pretty = serde_json::to_string_pretty(&v).unwrap_or_default();
    if pretty.len() > 280 {
        format!("{}…", &pretty[..277])
    } else {
        pretty
    }
}
