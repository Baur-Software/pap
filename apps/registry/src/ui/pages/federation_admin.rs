use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::ui::api::{self, RegistryPeer, SyncEvent};

// ── Page root ──────────────────────────────────────────────────────────────

#[component]
pub fn FederationAdminPage() -> impl IntoView {
    let refresh_key = RwSignal::new(0u32);
    let show_add = RwSignal::new(false);
    let banner = RwSignal::new(None::<(String, bool)>); // (message, is_error)

    let peers = Resource::new(move || refresh_key.get(), |_| api::list_peers());

    let reload = move || refresh_key.update(|n| *n += 1);

    view! {
        <div class="page">
            <div class="page-header">
                <div style="display:flex; align-items:center; justify-content:space-between">
                    <div>
                        <h1 class="page-title">"Federation Peer Management"</h1>
                        <p class="page-subtitle">
                            "Add, remove, and sync peer registries. Monitor sync health and event history."
                        </p>
                    </div>
                    <button class="btn btn-primary" on:click=move |_| show_add.set(true)>
                        "+ Add Peer"
                    </button>
                </div>
            </div>

            {move || banner.get().map(|(msg, is_err)| {
                if is_err {
                    view! { <div class="error-banner">{msg}</div> }.into_any()
                } else {
                    view! { <div class="success-banner">{msg}</div> }.into_any()
                }
            })}

            <Suspense fallback=|| view! { <div class="loading">"Loading peers…"</div> }>
                {move || peers.get().map(|result| match result {
                    Err(e) => view! {
                        <div class="error-banner">"Failed to load peers: " {e.to_string()}</div>
                    }.into_any(),
                    Ok(peer_list) => {
                        if peer_list.is_empty() {
                            view! {
                                <div class="empty-state">
                                    <div class="empty-state-icon">"◎"</div>
                                    <div class="empty-state-title">"No federation peers"</div>
                                    <p style="font-size:13px; color: var(--text-3)">
                                        "Add a peer registry to federate agent advertisements across nodes."
                                    </p>
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <div class="peer-list">
                                    {peer_list.into_iter().map(|peer| {
                                        let on_removed = move || {
                                            banner.set(Some(("Peer removed.".into(), false)));
                                            reload();
                                        };
                                        let on_synced = move |msg: String| {
                                            banner.set(Some((msg, false)));
                                            reload();
                                        };
                                        let on_error = move |msg: String| {
                                            banner.set(Some((msg, true)));
                                        };
                                        view! {
                                            <PeerCard
                                                peer=peer
                                                on_removed=on_removed
                                                on_synced=on_synced
                                                on_error=on_error
                                            />
                                        }
                                    }).collect::<Vec<_>>()}
                                </div>
                            }.into_any()
                        }
                    }
                })}
            </Suspense>

            {move || if show_add.get() {
                view! {
                    <AddPeerModal
                        on_close=move || show_add.set(false)
                        on_success=move |(sync_immediately, did): (bool, String)| {
                            show_add.set(false);
                            reload();
                            if sync_immediately {
                                // Trigger a sync after adding the peer.
                                let did = did.clone();
                                spawn_local(async move {
                                    match api::sync_peer(did).await {
                                        Ok(n) => banner.set(Some((
                                            format!("Peer added and synced — {} new agents.", n),
                                            false,
                                        ))),
                                        Err(e) => banner.set(Some((
                                            format!("Peer added, but initial sync failed: {}", e),
                                            true,
                                        ))),
                                    }
                                    refresh_key.update(|n| *n += 1);
                                });
                            } else {
                                banner.set(Some(("Peer added.".into(), false)));
                            }
                        }
                    />
                }.into_any()
            } else {
                view! { <span /> }.into_any()
            }}
        </div>
    }
}

// ── Peer card ─────────────────────────────────────────────────────────────

#[component]
fn PeerCard(
    peer: RegistryPeer,
    #[prop(into)] on_removed: Callback<()>,
    #[prop(into)] on_synced: Callback<String>,
    #[prop(into)] on_error: Callback<String>,
) -> impl IntoView {
    let did = peer.did.clone();
    let endpoint = peer.endpoint.clone();
    let fingerprint = peer.cert_fingerprint.clone();
    let last_sync = peer.last_sync.clone();
    let status = peer.status.clone().unwrap_or_else(|| "Active".into());

    let show_log = RwSignal::new(false);
    let confirm_remove = RwSignal::new(false);

    // ── Health indicator ──────────────────────────────────────────────────
    // Derive health from peer status field (populated via pap-federation PeerStatus).
    let (indicator_color, health_label) = match status.as_str() {
        "Suspended" => ("var(--coral)", "Suspended"),
        "Probationary" => ("var(--gold)", "Probationary"),
        _ => ("var(--teal)", "Active"),
    };

    // Clone did for the two separate move-closures in the view below.
    let did_for_confirm = did.clone();

    // ── Sync action ───────────────────────────────────────────────────────
    let sync_action = Action::new({
        let did = did.clone();
        move |_: &()| {
            let did = did.clone();
            async move { api::sync_peer(did).await }
        }
    });

    Effect::new(move || match sync_action.value().get() {
        Some(Ok(n)) => on_synced.run(format!("Synced {} new agents from peer.", n)),
        Some(Err(e)) => on_error.run(format!("Sync failed: {}", e)),
        None => {}
    });

    // ── Remove action ─────────────────────────────────────────────────────
    let remove_action = Action::new({
        let did = did.clone();
        move |_: &()| {
            let did = did.clone();
            async move { api::remove_peer(did).await }
        }
    });

    Effect::new(move || match remove_action.value().get() {
        Some(Ok(())) => on_removed.run(()),
        Some(Err(e)) => on_error.run(format!("Remove failed: {}", e)),
        None => {}
    });

    view! {
        <div class="peer-row" style="flex-direction: column; align-items: stretch; gap: 0">
            // ── Main row ─────────────────────────────────────────────────
            <div style="display:flex; align-items:center; gap: var(--sp-sm); padding: var(--sp-md)">
                // Health dot
                <div
                    class="peer-indicator"
                    title=health_label
                    style=format!(
                        "background: {}; flex-shrink: 0; width: 8px; height: 8px; border-radius: 50%",
                        indicator_color
                    )
                />
                // Peer info
                <div class="peer-info" style="flex:1; min-width:0">
                    <div class="peer-did">{did.clone()}</div>
                    <div class="peer-endpoint">{endpoint}</div>
                    {fingerprint.map(|fp| view! {
                        <div style="font-size:11px; color: var(--text-3); font-family: var(--font-mono)">
                            "📌 " {fp}
                        </div>
                    })}
                </div>
                // Last sync
                <div class="peer-sync" style="font-size:12px; color: var(--text-2); white-space:nowrap">
                    {last_sync.unwrap_or_else(|| "never synced".into())}
                </div>
                // Actions
                <div style="display:flex; gap: var(--sp-xs); flex-shrink:0">
                    <button
                        class="btn btn-secondary btn-sm"
                        on:click=move |_| show_log.update(|v| *v = !*v)
                        title="Toggle sync event log"
                    >
                        "Events"
                    </button>
                    <button
                        class="btn btn-secondary btn-sm"
                        disabled=move || sync_action.pending().get()
                        on:click=move |_| { sync_action.dispatch(()); }
                    >
                        {move || if sync_action.pending().get() { "Syncing…" } else { "↺ Sync" }}
                    </button>
                    <button
                        class="btn btn-danger btn-sm"
                        disabled=move || remove_action.pending().get()
                        on:click=move |_| confirm_remove.set(true)
                    >
                        "Remove"
                    </button>
                </div>
            </div>

            // ── Sync event log (collapsible) ──────────────────────────────
            {move || if show_log.get() {
                view! {
                    <SyncEventLog peer_did=did.clone() />
                }.into_any()
            } else {
                view! { <span /> }.into_any()
            }}
        </div>

        // ── Confirmation dialog ───────────────────────────────────────────
        {move || if confirm_remove.get() {
            view! {
                <RemoveConfirmModal
                    peer_did=did_for_confirm.clone()
                    on_cancel=move || confirm_remove.set(false)
                    on_confirm=move || {
                        confirm_remove.set(false);
                        remove_action.dispatch(());
                    }
                />
            }.into_any()
        } else {
            view! { <span /> }.into_any()
        }}
    }
}

// ── Sync event log ─────────────────────────────────────────────────────────

#[component]
fn SyncEventLog(peer_did: String) -> impl IntoView {
    let log = Resource::new(move || peer_did.clone(), api::get_peer_sync_log);

    view! {
        <div style="border-top: 1px solid var(--border-subtle); background: var(--bg-2); padding: var(--sp-md)">
            <div style="font-size:11px; font-weight:600; color: var(--text-3); text-transform:uppercase; letter-spacing:.06em; margin-bottom: var(--sp-sm)">
                "Sync Event Log"
            </div>
            <Suspense fallback=|| view! { <div class="loading" style="font-size:12px">"Loading…"</div> }>
                {move || log.get().map(|result| match result {
                    Err(e) => view! {
                        <div style="font-size:12px; color: var(--coral)">"Error: " {e.to_string()}</div>
                    }.into_any(),
                    Ok(events) => {
                        if events.is_empty() {
                            view! {
                                <div style="font-size:12px; color: var(--text-3); font-style:italic">
                                    "No sync events recorded yet."
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <table style="width:100%; border-collapse:collapse; font-size:12px; font-family: var(--font-mono)">
                                    <thead>
                                        <tr style="color: var(--text-3); border-bottom: 1px solid var(--border-subtle)">
                                            <th style="text-align:left; padding: 2px 8px 4px 0; font-weight:500">"Timestamp"</th>
                                            <th style="text-align:left; padding: 2px 8px 4px 0; font-weight:500">"Outcome"</th>
                                            <th style="text-align:right; padding: 2px 0 4px 8px; font-weight:500">"Merged"</th>
                                            <th style="text-align:left; padding: 2px 0 4px 8px; font-weight:500">"Detail"</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {events.into_iter().map(|ev: SyncEvent| {
                                            let color = if ev.outcome == "success" {
                                                "var(--teal)"
                                            } else {
                                                "var(--coral)"
                                            };
                                            let detail = ev.error.clone().unwrap_or_default();
                                            view! {
                                                <tr style="border-bottom: 1px solid var(--border-subtle)">
                                                    <td style="padding: 3px 8px 3px 0; color: var(--text-2)">{ev.ts}</td>
                                                    <td style=format!("padding: 3px 8px 3px 0; color: {}", color)>{ev.outcome}</td>
                                                    <td style="padding: 3px 0 3px 8px; text-align:right; color: var(--text-1)">{ev.merged_count}</td>
                                                    <td style="padding: 3px 0 3px 8px; color: var(--text-3)">{detail}</td>
                                                </tr>
                                            }
                                        }).collect::<Vec<_>>()}
                                    </tbody>
                                </table>
                            }.into_any()
                        }
                    }
                })}
            </Suspense>
        </div>
    }
}

// ── Remove confirmation modal ──────────────────────────────────────────────

#[component]
fn RemoveConfirmModal(
    peer_did: String,
    #[prop(into)] on_cancel: Callback<()>,
    #[prop(into)] on_confirm: Callback<()>,
) -> impl IntoView {
    view! {
        <div class="modal-backdrop">
            <div class="modal">
                <div class="modal-title">"Remove Federation Peer?"</div>
                <p style="font-size:14px; color: var(--text-2); margin: var(--sp-md) 0">
                    "This will remove the peer and stop receiving agent advertisements from it. "
                    "Agents already synced from this peer will remain in the registry."
                </p>
                <div
                    style="font-size:12px; font-family: var(--font-mono); color: var(--text-3);
                           background: var(--bg-2); padding: var(--sp-sm); border-radius: var(--r-sm);
                           word-break:break-all; margin-bottom: var(--sp-md)"
                >
                    {peer_did}
                </div>
                <div class="modal-actions">
                    <button class="btn btn-secondary" on:click=move |_| on_cancel.run(())>
                        "Cancel"
                    </button>
                    <button class="btn btn-danger" on:click=move |_| on_confirm.run(())>
                        "Remove Peer"
                    </button>
                </div>
            </div>
        </div>
    }
}

// ── Add peer modal ─────────────────────────────────────────────────────────

#[component]
fn AddPeerModal(
    #[prop(into)] on_close: Callback<()>,
    #[prop(into)] on_success: Callback<(bool, String)>,
) -> impl IntoView {
    let did_input = RwSignal::new(String::new());
    let endpoint_input = RwSignal::new(String::new());
    let fingerprint_input = RwSignal::new(String::new());
    let sync_after = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);

    let add_action = Action::new(move |args: &(String, String, Option<String>)| {
        let (did, endpoint, fp) = args.clone();
        async move { api::add_peer(did, endpoint, fp).await }
    });

    let submitting = move || add_action.pending().get();

    Effect::new(move || match add_action.value().get() {
        Some(Ok(())) => {
            on_success.run((sync_after.get(), did_input.get()));
        }
        Some(Err(e)) => error.set(Some(e.to_string())),
        None => {}
    });

    let do_submit = move |_| {
        let did = did_input.get().trim().to_string();
        let endpoint = endpoint_input.get().trim().to_string();
        let fingerprint = fingerprint_input.get().trim().to_string();

        if did.is_empty() || endpoint.is_empty() {
            error.set(Some("DID and endpoint are required.".into()));
            return;
        }
        error.set(None);
        let fp = if fingerprint.is_empty() {
            None
        } else {
            Some(fingerprint)
        };
        add_action.dispatch((did, endpoint, fp));
    };

    view! {
        <div class="modal-backdrop">
            <div class="modal">
                <div class="modal-title">"Add Federation Peer"</div>

                <div class="form-group">
                    <label class="form-label">"Peer DID"</label>
                    <input
                        class="form-input"
                        placeholder="did:key:z…"
                        prop:value=move || did_input.get()
                        on:input=move |e| did_input.set(event_target_value(&e))
                    />
                    <div class="form-hint">"The did:key identifier of the peer registry operator."</div>
                </div>

                <div class="form-group">
                    <label class="form-label">"Endpoint URL"</label>
                    <input
                        class="form-input"
                        placeholder="https://registry.example.com:7890"
                        prop:value=move || endpoint_input.get()
                        on:input=move |e| endpoint_input.set(event_target_value(&e))
                    />
                    <div class="form-hint">"The HTTPS endpoint of the peer's federation server."</div>
                </div>

                <div class="form-group">
                    <label class="form-label">"TLS Certificate Fingerprint (optional)"</label>
                    <input
                        class="form-input"
                        placeholder="SHA-256 hex fingerprint for certificate pinning"
                        prop:value=move || fingerprint_input.get()
                        on:input=move |e| fingerprint_input.set(event_target_value(&e))
                    />
                    <div class="form-hint">
                        "Pin the peer's self-signed cert. Leave empty to use TOFU — only for initial bootstrap."
                    </div>
                </div>

                <div class="form-group" style="display:flex; align-items:center; gap: var(--sp-sm)">
                    <input
                        type="checkbox"
                        id="sync-after-add"
                        prop:checked=move || sync_after.get()
                        on:change=move |e| {
                            sync_after.set(event_target_checked(&e));
                        }
                    />
                    <label for="sync-after-add" style="font-size:14px; cursor:pointer">
                        "Sync agents immediately after adding"
                    </label>
                </div>

                {move || error.get().map(|e| view! {
                    <div class="error-banner">{e}</div>
                })}

                <div class="modal-actions">
                    <button class="btn btn-secondary" on:click=move |_| on_close.run(())>
                        "Cancel"
                    </button>
                    <button
                        class="btn btn-primary"
                        disabled=submitting
                        on:click=do_submit
                    >
                        {move || if submitting() { "Adding…" } else { "Add Peer" }}
                    </button>
                </div>
            </div>
        </div>
    }
}
