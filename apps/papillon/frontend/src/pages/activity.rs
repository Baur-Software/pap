use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use papillon_shared::ScenarioRunResult;

#[component]
pub fn ActivityPage() -> impl IntoView {
    let runs = RwSignal::new(Vec::<ScenarioRunResult>::new());

    Effect::new(move || {
        if !bridge::tauri_available() {
            return;
        }
        spawn_local(async move {
            if let Ok(results) =
                bridge::invoke_no_args::<Vec<ScenarioRunResult>>("list_completed_runs").await
            {
                let mut v = results;
                v.reverse();
                runs.set(v);
            }
        });
    });

    let event_count = move || runs.get().len();

    view! {
        <div class="ledger-page">
            <div class="ledger-header">
                <div class="ledger-header-left">
                    <div class="ledger-header-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                            <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
                            <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
                        </svg>
                    </div>
                    <div>
                        <div class="ledger-title">"ACTIVITY LOG"</div>
                        <div class="ledger-subtitle">"Agent interactions &amp; verified receipts"</div>
                    </div>
                </div>
                <div class="ledger-header-right">
                    <span class="ledger-live-badge">
                        <span class="ledger-live-dot" />
                        "LIVE"
                    </span>
                    <span class="ledger-event-count">{move || format!("{} EVENTS", event_count())}</span>
                </div>
            </div>

            <div class="ledger-body">
                <div class="ledger-events">
                    <Show
                        when=move || !runs.get().is_empty()
                        fallback=|| view! {
                            <div class="ledger-empty">
                                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="color: rgba(255,255,255,0.2); margin-bottom: 12px;">
                                    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
                                    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
                                </svg>
                                <div>"No activity yet."</div>
                                <div style="margin-top: 6px; font-size: 11px; opacity: 0.5;">"Ask an agent something to see your interaction history here."</div>
                            </div>
                        }
                    >
                        <For
                            each=move || runs.get()
                            key=|run| run.completed_at.clone()
                            children=move |run| {
                                let agent_name = run.agent_name.clone();
                                let completed_at = run.completed_at.clone();
                                let co_signed = run.receipt.as_ref().map(|r| r.co_signed).unwrap_or(false);
                                let session_id = run.receipt.as_ref().map(|r| r.session_id.clone()).unwrap_or_default();
                                let action = run.receipt.as_ref().map(|r| r.action.clone()).unwrap_or_default();
                                let props = run.receipt.as_ref().map(|r| r.property_refs.clone()).unwrap_or_default();
                                let trust_class = if co_signed { "ledger-trust high" } else { "ledger-trust low" };
                                let trust_label = if co_signed { "TRUST: HIGH" } else { "TRUST: UNVERIFIED" };

                                view! {
                                    <div class="ledger-event-card">
                                        <div class="ledger-event-header">
                                            <div class="ledger-event-icon">
                                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                                    <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
                                                    <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
                                                </svg>
                                            </div>
                                            <span class="ledger-event-type">"AGENT INTERACTION"</span>
                                            {if !session_id.is_empty() {
                                                let short = if session_id.len() > 12 {
                                                    format!("ID: {}...", &session_id[..8])
                                                } else {
                                                    format!("ID: {}", session_id)
                                                };
                                                view! { <span class="ledger-event-id">{short}</span> }.into_any()
                                            } else {
                                                view! { <span /> }.into_any()
                                            }}
                                            <span class="ledger-event-ts">{completed_at}</span>
                                        </div>

                                        <div class="ledger-event-parties">
                                            <div class="ledger-party">
                                                <div class="ledger-party-label">"AGENT"</div>
                                                <div class="ledger-party-name">{agent_name}</div>
                                            </div>
                                            <div class="ledger-party">
                                                <div class="ledger-party-label">"ACTION"</div>
                                                <div class="ledger-party-name">{action.trim_start_matches("schema:").to_string()}</div>
                                            </div>
                                        </div>

                                        {if !props.is_empty() {
                                            view! {
                                                <div class="ledger-event-props">
                                                    <span class="ledger-props-label">"DISCLOSED: "</span>
                                                    {props.iter().map(|p| view! {
                                                        <span class="ledger-prop-tag">{p.clone()}</span>
                                                    }).collect::<Vec<_>>()}
                                                </div>
                                            }.into_any()
                                        } else {
                                            view! { <span /> }.into_any()
                                        }}

                                        <div class="ledger-event-footer">
                                            <span class=trust_class>{trust_label}</span>
                                        </div>
                                    </div>
                                }
                            }
                        />
                    </Show>
                </div>

                <div class="ledger-stats">
                    <div class="ledger-stats-header">"EVENT STATISTICS"</div>
                    <div class="ledger-stat-row">
                        <div class="ledger-stat-label">"TOTAL EVENTS"</div>
                        <div class="ledger-stat-value">{event_count}</div>
                    </div>
                    <div class="ledger-stat-row">
                        <div class="ledger-stat-label">"CO-SIGNED"</div>
                        <div class="ledger-stat-value">{move || runs.get().iter().filter(|r| r.receipt.as_ref().map(|rc| rc.co_signed).unwrap_or(false)).count()}</div>
                    </div>
                    <div class="ledger-stat-row">
                        <div class="ledger-stat-label">"WITH DISCLOSURE"</div>
                        <div class="ledger-stat-value">{move || runs.get().iter().filter(|r| r.receipt.as_ref().map(|rc| !rc.property_refs.is_empty()).unwrap_or(false)).count()}</div>
                    </div>
                </div>
            </div>
        </div>
    }
}
