use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use papillion_shared::ScenarioRunResult;

#[component]
pub fn ActivityPage() -> impl IntoView {
    let runs = RwSignal::new(Vec::<ScenarioRunResult>::new());

    Effect::new(move || {
        spawn_local(async move {
            match bridge::invoke_no_args::<Vec<ScenarioRunResult>>("list_completed_runs").await {
                Ok(results) => runs.set(results),
                Err(e) => {
                    web_sys::console::error_1(&format!("Failed to load runs: {e}").into())
                }
            }
        });
    });

    let runs_reversed = move || {
        let mut v = runs.get();
        v.reverse();
        v
    };

    view! {
        <div>
            <h2 class="page-title">"Activity"</h2>
            <Show
                when=move || !runs.get().is_empty()
                fallback=|| view! {
                    <div class="card">
                        <p style="color: var(--text-secondary);">
                            "No recent activity. Run a scenario to see your session history here."
                        </p>
                    </div>
                }
            >
                <For
                    each=runs_reversed
                    key=|run| run.completed_at.clone()
                    let:run
                >
                    {
                        let agent_name = run.agent_name.clone();
                        let completed_at = run.completed_at.clone();
                        let receipt = run.receipt.clone();
                        let receipt_url = run.receipt_url.clone();
                        view! {
                            <div class="card" style="margin-bottom: 12px;">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                    <strong style="font-size: 14px;">{agent_name}</strong>
                                    <span class="badge badge-success">"Completed"</span>
                                </div>
                                <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 8px;">
                                    {completed_at}
                                </div>
                                {receipt.map(|r| {
                                    let co_sign_label = if r.co_signed { "Yes" } else { "No" };
                                    let disclosed = if r.property_refs.is_empty() {
                                        "None".to_string()
                                    } else {
                                        r.property_refs.join(", ")
                                    };
                                    view! {
                                        <div style="font-size: 12px; padding-top: 8px; border-top: 1px solid var(--border);">
                                            <div style="margin-bottom: 4px;">
                                                <span style="color: var(--text-secondary);">"Session: "</span>
                                                <code>{r.session_id}</code>
                                            </div>
                                            <div style="margin-bottom: 4px;">
                                                <span style="color: var(--text-secondary);">"Action: "</span>
                                                <code>{r.action}</code>
                                            </div>
                                            <div style="margin-bottom: 4px;">
                                                <span style="color: var(--text-secondary);">"Co-signed: "</span>
                                                <span class="badge badge-success">{co_sign_label}</span>
                                                <span style="color: var(--text-secondary); margin-left: 12px;">"Disclosed: "</span>
                                                {disclosed}
                                            </div>
                                        </div>
                                    }
                                })}
                                {receipt_url.map(|u| view! {
                                    <div style="font-size: 12px; margin-top: 4px;">
                                        <span style="color: var(--text-secondary);">"Receipt: "</span>
                                        <code class="receipt-url">{u}</code>
                                    </div>
                                })}
                            </div>
                        }
                    }
                </For>
            </Show>
        </div>
    }
}
