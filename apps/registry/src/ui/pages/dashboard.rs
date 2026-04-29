use leptos::prelude::*;

use crate::ui::api::{self, RegistryStatus, SyncSummaryItem};

#[component]
pub fn DashboardPage() -> impl IntoView {
    let status = Resource::new(|| (), |_| api::get_status());
    let sync_summary = Resource::new(|| (), |_| api::get_sync_summary());

    view! {
        <div class="page">
            <div class="page-header">
                <h1 class="page-title">"Chrysalis Dashboard"</h1>
                <p class="page-subtitle">"Registry overview, inbound pap:// traffic, and federation network health."</p>
            </div>

            <Suspense fallback=|| view! { <div class="loading"><span class="loading-dot">"Loading…"</span></div> }>
                {move || status.get().map(|result| match result {
                    Err(e) => view! {
                        <div class="error-banner">"Failed to load status: " {e.to_string()}</div>
                    }.into_any(),
                    Ok(s) => {
                        let sync = sync_summary.get()
                            .and_then(|r| r.ok())
                            .unwrap_or_default();
                        view! { <DashboardView s=s sync=sync /> }.into_any()
                    }
                })}
            </Suspense>
        </div>
    }
}

#[component]
fn DashboardView(s: RegistryStatus, sync: Vec<SyncSummaryItem>) -> impl IntoView {
    let peer_sub = format!(
        "{} active · {} probationary",
        s.peer_active,
        s.peer_probationary
    );
    let sync_empty = sync.is_empty();

    view! {
        // ── STAT GRID ────────────────────────────────────────────────────────
        <div class="stat-grid" role="region" aria-label="Key metrics">
            <div class="stat-card">
                <div class="stat-label" id="lbl-agents">"Registered Agents"</div>
                <div class="stat-value teal" aria-labelledby="lbl-agents">{s.agent_count}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label" id="lbl-peers">"Federation Peers"</div>
                <div class="stat-value accent" aria-labelledby="lbl-peers">{s.peer_count}</div>
                <div class="stat-sub">{peer_sub}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label" id="lbl-sessions">"pap:// Sessions (1h)"</div>
                <div class="stat-value gold" aria-labelledby="lbl-sessions">"—"</div>
                <div class="stat-sub">"Rolling 60-min window"</div>
            </div>
            <div class="stat-card">
                <div class="stat-label" id="lbl-ver">"Version"</div>
                <div class="stat-value mono" aria-labelledby="lbl-ver">{s.version.clone()}</div>
            </div>
        </div>

        // ── TRAFFIC ──────────────────────────────────────────────────────────
        <h2 class="section-header">"Inbound pap:// Traffic"</h2>
        <div class="two-col">
            <div class="card">
                <div class="card-header">
                    <span class="card-title">"Sessions over time"</span>
                    <span class="card-badge">"last 12h · 1h buckets"</span>
                </div>
                <div class="card-body">
                    <BarChart
                        label="pap:// sessions / hour"
                        color="purple"
                        heights=vec![28,42,36,55,62,50,70,66,80,74,90,100]
                    />
                    <BarChart
                        label="agent queries from clients / hour"
                        color="teal"
                        heights=vec![40,55,44,68,75,60,82,78,92,85,96,100]
                    />
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <span class="card-title">"PAP Handshake Funnel"</span>
                    <span class="card-badge">"last 1h"</span>
                </div>
                <div class="card-body" role="region" aria-label="PAP 6-phase handshake completion rates">
                    <PhaseRow num="①" name="Token Presentation"   pct=100 />
                    <PhaseRow num="②" name="DID Exchange"         pct=99  />
                    <PhaseRow num="③" name="Selective Disclosure" pct=97  />
                    <PhaseRow num="④" name="Agent Execution"      pct=95  />
                    <PhaseRow num="⑤" name="Co-Signed Receipt"    pct=90  />
                    <PhaseRow num="⑥" name="Session Close"        pct=82  />
                    <div class="funnel-footer">
                        <span>"Funnel data available once session counters are instrumented"</span>
                    </div>
                </div>
            </div>
        </div>

        // ── FEDERATION ───────────────────────────────────────────────────────
        <h2 class="section-header">"Federation"</h2>
        <div class="two-col">
            <div class="card">
                <div class="card-header">
                    <span class="card-title">"Peer Sync Activity"</span>
                    <span class="card-badge teal">"ring buffer · last 100/peer"</span>
                </div>
                <div class="card-body">
                    <BarChart
                        label="syncs / hour"
                        color="gold"
                        heights=vec![40,20,80,30,60,50,70,45,90,55,65,75]
                    />
                    <SyncFeed items=sync empty=sync_empty />
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <span class="card-title">"Federation Endpoints"</span>
                    <span class="card-badge gold">"inbound protocol surface"</span>
                </div>
                <div class="card-body">
                    <p style="font-size:12px; color:var(--text-3); margin-bottom:var(--sp-md)">
                        "Other registries and Papillon clients connect at:"
                    </p>
                    <EndpointRow method="GET"  path="/federation/identity"       desc="Node identity & cert" />
                    <EndpointRow method="GET"  path="/federation/query?action=…" desc="Query by Schema.org action" />
                    <EndpointRow method="POST" path="/federation/announce"        desc="Receive agent advertisement" />
                    <EndpointRow method="GET"  path="/federation/peers"           desc="Known peer list" />
                </div>
            </div>
        </div>

        // ── NODE IDENTITY ────────────────────────────────────────────────────
        <h2 class="section-header">"Node Identity"</h2>
        <div class="identity-panel" role="region" aria-label="Node identity information">
            <div class="stat-label">"Node DID"</div>
            <div class="identity-did">{s.did.clone()}</div>
            <div class="identity-row">
                <span>"TLS:"</span>
                <span class="val">{s.cert_fingerprint.clone()}</span>
            </div>
            <div class="identity-row">
                <span>"Public endpoint:"</span>
                <span class="val">{s.endpoint.clone()}</span>
            </div>
        </div>
    }
}

#[component]
fn SyncFeed(items: Vec<SyncSummaryItem>, empty: bool) -> impl IntoView {
    view! {
        <div role="log" aria-label="Recent sync events" aria-live="polite">
            {items.into_iter().take(6).map(|item| {
                let pill_class = if item.outcome == "success" { "log-pill ok" } else { "log-pill err" };
                let extra = format!("+{}", item.merged_count);
                let ts = item.ts.get(11..19).unwrap_or(&item.ts).to_string();
                let did_len = item.peer_did.len();
                let did_short = if did_len > 20 {
                    format!("{}…{}", &item.peer_did[..16], &item.peer_did[did_len - 4..])
                } else {
                    item.peer_did.clone()
                };
                let msg = if let Some(err) = item.error {
                    format!("{did_short} — {err}")
                } else {
                    did_short
                };
                view! {
                    <div class="log-row">
                        <span class="log-ts">{ts}</span>
                        <span class=pill_class>{item.outcome}</span>
                        <span class="log-msg">{msg}</span>
                        <span class="log-extra">{extra}</span>
                    </div>
                }
            }).collect_view()}
            {empty.then(|| view! {
                <p style="font-size:11px; color:var(--text-3); padding-top: var(--sp-sm)">
                    "No sync events yet. Trigger a peer sync to populate this feed."
                </p>
            })}
        </div>
    }
}

#[component]
fn BarChart(label: &'static str, color: &'static str, heights: Vec<u8>) -> impl IntoView {
    view! {
        <div class="mini-chart">
            <div class="mini-chart-label">{label}</div>
            <div class="bar-row" aria-hidden="true">
                {heights.into_iter().map(|h| {
                    view! { <div class=format!("bar {color}") style=format!("height:{}%", h)></div> }
                }).collect_view()}
            </div>
            <div class="chart-x" aria-hidden="true">
                <span>"12h ago"</span><span>"9h"</span><span>"6h"</span><span>"3h"</span><span>"now"</span>
            </div>
        </div>
    }
}

#[component]
fn PhaseRow(num: &'static str, name: &'static str, pct: u8) -> impl IntoView {
    view! {
        <div class="phase-row">
            <span class="phase-num" aria-hidden="true">{num}</span>
            <span class="phase-name">{name}</span>
            <div
                class="phase-bar-track"
                role="progressbar"
                aria-valuenow=pct
                aria-valuemin=0
                aria-valuemax=100
                aria-label=format!("{pct}%")
            >
                <div class="phase-bar-fill" style=format!("width:{}%", pct)></div>
            </div>
            <span class="phase-pct">{format!("{}%", pct)}</span>
        </div>
    }
}

#[component]
fn EndpointRow(method: &'static str, path: &'static str, desc: &'static str) -> impl IntoView {
    let method_class = if method == "GET" { "method get" } else { "method post" };
    view! {
        <div class="endpoint-row">
            <span class=method_class>{method}</span>
            <span class="epath">{path}</span>
            <span class="edesc">{desc}</span>
        </div>
    }
}
