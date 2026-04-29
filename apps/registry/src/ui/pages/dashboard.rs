use leptos::prelude::*;

use crate::ui::api::{
    self, EndpointCounts, RegistryStatus, SyncBuckets, SyncSummaryItem,
};

#[component]
pub fn DashboardPage() -> impl IntoView {
    let status = Resource::new(|| (), |_| api::get_status());
    let sync_summary = Resource::new(|| (), |_| api::get_sync_summary());
    let endpoint_counts = Resource::new(|| (), |_| api::get_endpoint_counts());
    let sync_buckets = Resource::new(|| (), |_| api::get_sync_buckets());

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
                        let sync  = sync_summary.get().and_then(|r| r.ok()).unwrap_or_default();
                        let counts = endpoint_counts.get().and_then(|r| r.ok());
                        let buckets = sync_buckets.get().and_then(|r| r.ok());
                        view! { <DashboardView s=s sync=sync counts=counts buckets=buckets /> }.into_any()
                    }
                })}
            </Suspense>
        </div>
    }
}

#[component]
fn DashboardView(
    s: RegistryStatus,
    sync: Vec<SyncSummaryItem>,
    counts: Option<EndpointCounts>,
    buckets: Option<SyncBuckets>,
) -> impl IntoView {
    let peer_sub = format!(
        "{} active · {} probationary",
        s.peer_active, s.peer_probationary
    );
    let sync_empty = sync.is_empty();

    // Build bar heights (0–100) from real sync bucket counts.
    let sync_bar_heights: Vec<u8> = match &buckets {
        None => vec![0u8; 12],
        Some(b) => {
            let max = b.counts.iter().copied().max().unwrap_or(0);
            b.counts
                .iter()
                .map(|&c| {
                    if max == 0 {
                        0u8
                    } else {
                        ((c as f32 / max as f32) * 100.0).round() as u8
                    }
                })
                .collect()
        }
    };

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
                <div class="stat-label" id="lbl-queries">"Fed. Queries (all-time)"</div>
                {
                    let q = counts.as_ref().map(|c| c.federation_query).unwrap_or(0);
                    view! { <div class="stat-value gold" aria-labelledby="lbl-queries">{format_count(q)}</div> }
                }
            </div>
            <div class="stat-card">
                <div class="stat-label" id="lbl-ver">"Version"</div>
                <div class="stat-value mono" aria-labelledby="lbl-ver">{s.version.clone()}</div>
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
                        label="syncs / hour (last 12 h)"
                        color="gold"
                        heights=sync_bar_heights
                    />
                    <SyncFeed items=sync empty=sync_empty />
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <span class="card-title">"Federation Endpoints"</span>
                    <span class="card-badge gold">"hit counts · all-time"</span>
                </div>
                <div class="card-body">
                    <p style="font-size:12px; color:var(--text-3); margin-bottom:var(--sp-md)">
                        "Other registries and Papillon clients connect at:"
                    </p>
                    {
                        let c = counts.clone().unwrap_or(EndpointCounts {
                            federation_identity: 0,
                            federation_query: 0,
                            federation_announce: 0,
                            federation_peers: 0,
                        });
                        view! {
                            <EndpointRow method="GET"  path="/federation/identity"       desc="Node identity & cert"        hits=c.federation_identity />
                            <EndpointRow method="GET"  path="/federation/query?action=…" desc="Query by Schema.org action"  hits=c.federation_query />
                            <EndpointRow method="POST" path="/federation/announce"        desc="Receive agent advertisement" hits=c.federation_announce />
                            <EndpointRow method="GET"  path="/federation/peers"           desc="Known peer list"            hits=c.federation_peers />
                        }
                    }
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

fn format_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
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
                    let h = h.max(2); // keep bars visible even at zero
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
fn EndpointRow(method: &'static str, path: &'static str, desc: &'static str, hits: u64) -> impl IntoView {
    let method_class = if method == "GET" { "method get" } else { "method post" };
    view! {
        <div class="endpoint-row">
            <span class=method_class>{method}</span>
            <span class="epath">{path}</span>
            <span class="edesc">{desc}</span>
            <span class="hit-count">{format_count(hits)}</span>
        </div>
    }
}
