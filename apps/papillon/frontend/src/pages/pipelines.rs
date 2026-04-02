use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use papillon_shared::db::Episode;

#[derive(Clone, PartialEq)]
enum DecayFilter {
    All,
    Active,
    Degraded,
    Compressed,
}

#[component]
pub fn PipelinesPage() -> impl IntoView {
    let episodes: RwSignal<Vec<Episode>> = RwSignal::new(vec![]);
    let filter = RwSignal::new(DecayFilter::All);
    let loading = RwSignal::new(true);

    Effect::new(move || {
        if bridge::tauri_available() {
            spawn_local(async move {
                match bridge::invoke_no_args::<Vec<Episode>>("list_episodes").await {
                    Ok(mut eps) => {
                        eps.reverse();
                        episodes.set(eps);
                        loading.set(false);
                    }
                    Err(_) => {
                        loading.set(false);
                    }
                }
            });
        } else {
            loading.set(false);
        }
    });

    let filtered = move || {
        let f = filter.get();
        episodes
            .get()
            .into_iter()
            .filter(|e| match f {
                DecayFilter::All => true,
                DecayFilter::Active => e.decay_state == "Active",
                DecayFilter::Degraded => e.decay_state == "Degraded",
                DecayFilter::Compressed => e.decay_state == "Compressed",
            })
            .collect::<Vec<_>>()
    };

    // Stats computed from all episodes
    let total = move || episodes.get().len();
    let active_count = move || {
        episodes
            .get()
            .iter()
            .filter(|e| e.decay_state == "Active")
            .count()
    };
    let degraded_count = move || {
        episodes
            .get()
            .iter()
            .filter(|e| e.decay_state == "Degraded")
            .count()
    };
    let compressed_count = move || {
        episodes
            .get()
            .iter()
            .filter(|e| e.decay_state == "Compressed")
            .count()
    };
    let success_rate = move || {
        let eps = episodes.get();
        if eps.is_empty() {
            return 0u64;
        }
        let ok = eps.iter().filter(|e| e.outcome == "success").count();
        ((ok * 100) / eps.len()) as u64
    };
    let avg_duration = move || {
        let eps = episodes.get();
        if eps.is_empty() {
            return 0i64;
        }
        eps.iter().map(|e| e.duration_ms).sum::<i64>() / eps.len() as i64
    };

    view! {
        <div class="partitions-page">
            // ── Left: Timeline ──────────────────────────────────────────
            <div class="partitions-timeline">
                <div class="partitions-header">
                    <span class="partitions-title">"INTENT_PARTITIONS — SESSION_TIMELINE"</span>
                    <div class="partitions-filters">
                        <button
                            class=move || {
                                if filter.get() == DecayFilter::All {
                                    "partitions-filter-btn active"
                                } else {
                                    "partitions-filter-btn"
                                }
                            }
                            on:click=move |_| filter.set(DecayFilter::All)
                        >
                            "ALL"
                        </button>
                        <button
                            class=move || {
                                if filter.get() == DecayFilter::Active {
                                    "partitions-filter-btn active"
                                } else {
                                    "partitions-filter-btn"
                                }
                            }
                            on:click=move |_| filter.set(DecayFilter::Active)
                        >
                            "ACTIVE"
                        </button>
                        <button
                            class=move || {
                                if filter.get() == DecayFilter::Degraded {
                                    "partitions-filter-btn active"
                                } else {
                                    "partitions-filter-btn"
                                }
                            }
                            on:click=move |_| filter.set(DecayFilter::Degraded)
                        >
                            "DEGRADED"
                        </button>
                        <button
                            class=move || {
                                if filter.get() == DecayFilter::Compressed {
                                    "partitions-filter-btn active"
                                } else {
                                    "partitions-filter-btn"
                                }
                            }
                            on:click=move |_| filter.set(DecayFilter::Compressed)
                        >
                            "COMPRESSED"
                        </button>
                    </div>
                </div>

                <Show when=move || loading.get()>
                    <div class="partitions-loading">"LOADING_PARTITIONS..."</div>
                </Show>

                <Show when=move || !loading.get() && filtered().is_empty()>
                    <div class="partitions-empty">
                        "NO_PARTITIONS_FOUND — run a scenario to create entries"
                    </div>
                </Show>

                <div class="partitions-list">
                    <For
                        each=filtered
                        key=|e| e.id.clone()
                        children=move |ep| {
                            view! { <PartitionCard ep=ep /> }
                        }
                    />
                </div>
            </div>

            // ── Right: Stats panel ──────────────────────────────────────
            <div class="partitions-stats">
                <div class="partitions-stats-title">"PARTITION_STATS"</div>

                <div class="partitions-stat-row">
                    <span class="partitions-stat-label">"TOTAL RUNS"</span>
                    <span class="partitions-stat-value">{total}</span>
                </div>
                <div class="partitions-stat-row">
                    <span class="partitions-stat-label">"ACTIVE"</span>
                    <span class="partitions-stat-value">{active_count}</span>
                </div>
                <div class="partitions-stat-row">
                    <span class="partitions-stat-label">"SUCCESS_RATE"</span>
                    <span class="partitions-stat-value">{move || format!("{}%", success_rate())}</span>
                </div>
                <div class="partitions-stat-row">
                    <span class="partitions-stat-label">"AVG_DURATION"</span>
                    <span class="partitions-stat-value">{move || format!("{}ms", avg_duration())}</span>
                </div>

                <div class="partitions-stat-div" />

                <div class="partitions-stats-title">"DECAY_STATE"</div>

                // Active bar
                <div class="partitions-decay-row">
                    <span class="partitions-decay-label">"Active"</span>
                    <div class="partitions-decay-bar-wrap">
                        <div
                            class="partitions-decay-bar active"
                            style=move || {
                                let t = total();
                                let pct = if t > 0 { active_count() * 100 / t } else { 0 };
                                format!("width: {}%", pct)
                            }
                        />
                    </div>
                    <span class="partitions-decay-count">{active_count}</span>
                </div>

                // Degraded bar
                <div class="partitions-decay-row">
                    <span class="partitions-decay-label">"Degraded"</span>
                    <div class="partitions-decay-bar-wrap">
                        <div
                            class="partitions-decay-bar degraded"
                            style=move || {
                                let t = total();
                                let pct = if t > 0 { degraded_count() * 100 / t } else { 0 };
                                format!("width: {}%", pct)
                            }
                        />
                    </div>
                    <span class="partitions-decay-count">{degraded_count}</span>
                </div>

                // Compressed bar
                <div class="partitions-decay-row">
                    <span class="partitions-decay-label">"Compressed"</span>
                    <div class="partitions-decay-bar-wrap">
                        <div
                            class="partitions-decay-bar compressed"
                            style=move || {
                                let t = total();
                                let pct = if t > 0 { compressed_count() * 100 / t } else { 0 };
                                format!("width: {}%", pct)
                            }
                        />
                    </div>
                    <span class="partitions-decay-count">{compressed_count}</span>
                </div>
            </div>
        </div>
    }
}

#[component]
fn PartitionCard(ep: Episode) -> impl IntoView {
    let is_active = ep.decay_state == "Active";
    let action_display = ep.action_type.trim_start_matches("schema:").to_string();
    let ts_display = if ep.recorded_at.len() >= 10 {
        ep.recorded_at[..10].to_string()
    } else {
        ep.recorded_at.clone()
    };

    let outcome_class = match ep.outcome.as_str() {
        "success" => "partition-outcome-success",
        "failure" => "partition-outcome-failure",
        _ => "partition-outcome-rejected",
    };
    let outcome_label = ep.outcome.to_uppercase();

    let decay_class = match ep.decay_state.as_str() {
        "Active" => "partition-decay-active",
        "Degraded" => "partition-decay-degraded",
        _ => "partition-decay-compressed",
    };
    let decay_label = ep.decay_state.clone();

    let scope_tags: Vec<String> =
        serde_json::from_str::<Vec<String>>(&ep.scope_exercised).unwrap_or_default();
    let scope_display: Vec<String> = scope_tags
        .into_iter()
        .map(|s| s.trim_start_matches("schema:").to_string())
        .collect();

    let agent_name = ep.agent_name.clone();
    let duration_ms = ep.duration_ms;
    let intent_summary = ep.intent_summary.clone();

    view! {
        <div class="partition-card">
            <div class="partition-card-header">
                <span class=if is_active {
                    "partition-live-dot active"
                } else {
                    "partition-live-dot"
                } />
                <span class="partition-type">{action_display}</span>
                <span class="partition-ts">{ts_display}</span>
                <span class=outcome_class>{outcome_label}</span>
            </div>
            <div class="partition-card-body">
                <span class="partition-agent">{agent_name}</span>
                <span class="partition-dur">{duration_ms} "ms"</span>
            </div>
            {intent_summary.map(|summary| view! {
                <p class="partition-summary">"> " {summary}</p>
            })}
            <div class="partition-card-footer">
                {scope_display
                    .into_iter()
                    .map(|tag| {
                        view! { <span class="partition-scope-tag">{tag}</span> }
                    })
                    .collect::<Vec<_>>()}
                <span class=decay_class>{decay_label}</span>
            </div>
        </div>
    }
}
