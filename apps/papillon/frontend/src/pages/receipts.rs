use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use papillon_shared::ScenarioRunResult;

#[component]
pub fn ReceiptsPage() -> impl IntoView {
    let runs = RwSignal::new(Vec::<ScenarioRunResult>::new());
    let selected = RwSignal::new(None::<usize>);

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

    let verified_count = move || {
        runs.get()
            .iter()
            .filter(|r| r.receipt.as_ref().map(|rc| rc.co_signed).unwrap_or(false))
            .count()
    };

    view! {
        <div class="receipts-page">
            <div class="receipts-header">
                <div class="receipts-header-left">
                    <div class="receipts-header-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                            <polyline points="14 2 14 8 20 8"/>
                            <line x1="9" y1="15" x2="15" y2="15"/>
                        </svg>
                    </div>
                    <div>
                        <div class="receipts-title">"RECEIPTS & CO-SIGNED OUTCOMES"</div>
                        <div class="receipts-subtitle">"Immutable JSON-LD Ledger \u{2022} Provenance Chain \u{2022} Signature Verification"</div>
                    </div>
                </div>
                <div class="receipts-header-right">
                    <span class="receipts-verified-badge">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                        {move || format!("{} VERIFIED", verified_count())}
                    </span>
                </div>
            </div>

            <div class="receipts-body">
                <div class="receipts-list">
                    <Show
                        when=move || !runs.get().is_empty()
                        fallback=|| view! {
                            <div class="receipts-empty">
                                <p>"No receipts yet."</p>
                                <p style="margin-top: 6px; font-size: 11px; opacity: 0.6;">"Complete a PAP session to generate co-signed receipts."</p>
                            </div>
                        }
                    >
                        <For
                            each=move || runs.get().into_iter().enumerate().collect::<Vec<_>>()
                            key=|(i, _)| *i
                            children=move |(i, run)| {
                                let has_receipt = run.receipt.is_some();
                                let co_signed = run.receipt.as_ref().map(|r| r.co_signed).unwrap_or(false);
                                let agent = run.agent_name.clone();
                                let ts = run.completed_at.clone();
                                let session_id = run.receipt.as_ref().map(|r| {
                                    let id = &r.session_id;
                                    if id.len() > 12 { format!("RCP_{}", &id[..8]) } else { format!("RCP_{}", id) }
                                }).unwrap_or_default();

                                let is_selected = move || selected.get() == Some(i);

                                view! {
                                    <div
                                        class=move || if is_selected() { "receipt-card selected" } else { "receipt-card" }
                                        on:click=move |_| selected.set(Some(i))
                                    >
                                        <div class="receipt-card-top">
                                            {if co_signed {
                                                view! { <span class="receipt-verified-label">"✓ VERIFIED"</span> }.into_any()
                                            } else if has_receipt {
                                                view! { <span class="receipt-pending-label">"◎ PENDING"</span> }.into_any()
                                            } else {
                                                view! { <span class="receipt-unsigned-label">"○ UNSIGNED"</span> }.into_any()
                                            }}
                                            <span class="receipt-id">{session_id}</span>
                                        </div>
                                        <div class="receipt-agent">{agent}</div>
                                        <div class="receipt-ts">{ts}</div>
                                    </div>
                                }
                            }
                        />
                    </Show>
                </div>

                <div class="receipts-detail">
                    {move || {
                        let idx = selected.get();
                        let runs_list = runs.get();
                        match idx.and_then(|i| runs_list.get(i)) {
                            None => view! {
                                <div class="receipts-detail-empty">
                                    <p>"Select a receipt to view details"</p>
                                </div>
                            }.into_any(),
                            Some(run) => {
                                let receipt = run.receipt.clone();
                                let agent = run.agent_name.clone();
                                let ts = run.completed_at.clone();
                                let co_signed = receipt.as_ref().map(|r| r.co_signed).unwrap_or(false);
                                let session_id = receipt.as_ref().map(|r| r.session_id.clone()).unwrap_or_default();
                                let action = receipt.as_ref().map(|r| r.action.clone()).unwrap_or_default();
                                let props = receipt.as_ref().map(|r| r.property_refs.clone()).unwrap_or_default();
                                let short_sid = if session_id.len() > 16 {
                                    format!("{}...{}", &session_id[..8], &session_id[session_id.len()-4..])
                                } else {
                                    session_id.clone()
                                };

                                view! {
                                    <div class="receipt-detail-panel">
                                        <div class="receipt-detail-title">"Receipt "{short_sid.clone()}</div>
                                        <div class="receipt-detail-meta">{agent.clone()}" \u{2022} "{ts.clone()}</div>

                                        <div class="receipt-sig-panel">
                                            <div class="receipt-sig-header">
                                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                                                "SIGNATURE VERIFICATION"
                                                {if co_signed {
                                                    view! { <span class="receipt-all-verified">"✓ ALL VERIFIED"</span> }.into_any()
                                                } else {
                                                    view! { <span /> }.into_any()
                                                }}
                                            </div>
                                            <div class="receipt-sig-cards">
                                                <div class="receipt-sig-card">
                                                    <div class="receipt-sig-role">"PRINCIPAL"</div>
                                                    <div class="receipt-sig-name">"Primary Owner"</div>
                                                    <div class="receipt-sig-key">"LOCAL_KEY"</div>
                                                    {if co_signed {
                                                        view! { <span class="receipt-sig-ok">"✓ VERIFIED"</span> }.into_any()
                                                    } else {
                                                        view! { <span class="receipt-sig-pending">"PENDING"</span> }.into_any()
                                                    }}
                                                </div>
                                                <div class="receipt-sig-card">
                                                    <div class="receipt-sig-role">"AGENT"</div>
                                                    <div class="receipt-sig-name">{agent.clone()}</div>
                                                    <div class="receipt-sig-key">"OPERATOR_KEY"</div>
                                                    {if co_signed {
                                                        view! { <span class="receipt-sig-ok">"✓ VERIFIED"</span> }.into_any()
                                                    } else {
                                                        view! { <span class="receipt-sig-pending">"PENDING"</span> }.into_any()
                                                    }}
                                                </div>
                                            </div>
                                        </div>

                                        <div class="receipt-meta-grid">
                                            <div class="receipt-meta-item">
                                                <div class="receipt-meta-label">"ACTION"</div>
                                                <div class="receipt-meta-value">{action.trim_start_matches("schema:").to_string()}</div>
                                            </div>
                                            <div class="receipt-meta-item">
                                                <div class="receipt-meta-label">"SESSION"</div>
                                                <div class="receipt-meta-value" style="font-size: 11px;">{short_sid}</div>
                                            </div>
                                        </div>

                                        {if !props.is_empty() {
                                            view! {
                                                <div class="receipt-props-section">
                                                    <div class="receipt-meta-label">"DISCLOSED PROPERTIES"</div>
                                                    <div style="display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px;">
                                                        {props.iter().map(|p| view! {
                                                            <span class="agent-cap-tag">{p.clone()}</span>
                                                        }).collect::<Vec<_>>()}
                                                    </div>
                                                </div>
                                            }.into_any()
                                        } else {
                                            view! { <span /> }.into_any()
                                        }}
                                    </div>
                                }.into_any()
                            }
                        }
                    }}
                </div>
            </div>
        </div>
    }
}
