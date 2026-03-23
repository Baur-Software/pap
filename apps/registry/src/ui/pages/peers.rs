use leptos::prelude::*;

use crate::ui::api::{self, RegistryPeer};

#[component]
pub fn PeersPage() -> impl IntoView {
    let refresh_key = RwSignal::new(0u32);
    let show_add = RwSignal::new(false);
    let sync_msg = RwSignal::new(None::<String>);

    let peers = Resource::new(move || refresh_key.get(), |_| api::list_peers());

    let reload = move || refresh_key.update(|n| *n += 1);

    view! {
        <div class="page">
            <div class="page-header">
                <div style="display:flex; align-items:center; justify-content:space-between">
                    <div>
                        <h1 class="page-title">"Federation Peers"</h1>
                        <p class="page-subtitle">"Peer registries this node federates with."</p>
                    </div>
                    <button class="btn btn-primary" on:click=move |_| show_add.set(true)>
                        "+ Add Peer"
                    </button>
                </div>
            </div>

            {move || sync_msg.get().map(|m| view! {
                <div class="success-banner">{m}</div>
            })}

            <Suspense fallback=|| view! { <div class="loading">"Loading peers…"</div> }>
                {move || peers.get().map(|result| match result {
                    Err(e) => view! {
                        <div class="error-banner">"Error: " {e.to_string()}</div>
                    }.into_any(),
                    Ok(peer_list) => {
                        if peer_list.is_empty() {
                            view! {
                                <div class="empty-state">
                                    <div class="empty-state-icon">"◎"</div>
                                    <div class="empty-state-title">"No peers configured"</div>
                                    <p style="font-size:13px; color: var(--text-3)">
                                        "Add a peer registry to start federating agent advertisements."
                                    </p>
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <div class="peer-list">
                                    {peer_list.into_iter().map(|peer| view! {
                                        <PeerRow
                                            peer=peer
                                            on_remove=move || reload()
                                            on_sync=move |msg| sync_msg.set(Some(msg))
                                        />
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
                        on_success=move || { show_add.set(false); reload(); }
                    />
                }.into_any()
            } else {
                view! { <span /> }.into_any()
            }}
        </div>
    }
}

#[component]
fn PeerRow(
    peer: RegistryPeer,
    #[prop(into)] on_remove: Callback<()>,
    #[prop(into)] on_sync: Callback<String>,
) -> impl IntoView {
    let did = peer.did.clone();
    let endpoint = peer.endpoint.clone();
    let fingerprint = peer.cert_fingerprint.clone();
    let last_sync = peer.last_sync.clone();

    let remove_action = Action::new({
        let did = did.clone();
        move |_: &()| {
            let did = did.clone();
            async move { api::remove_peer(did).await }
        }
    });

    let sync_action = Action::new({
        let did = did.clone();
        move |_: &()| {
            let did = did.clone();
            async move { api::sync_peer(did).await }
        }
    });

    Effect::new(move || match remove_action.value().get() {
        Some(Ok(())) => on_remove.run(()),
        Some(Err(e)) => on_sync.run(format!("Remove failed: {}", e)),
        None => {}
    });

    Effect::new(move || match sync_action.value().get() {
        Some(Ok(n)) => on_sync.run(format!("Synced {} new agents from peer.", n)),
        Some(Err(e)) => on_sync.run(format!("Sync failed: {}", e)),
        None => {}
    });

    view! {
        <div class="peer-row">
            <div class="peer-indicator" />
            <div class="peer-info">
                <div class="peer-did">{did.clone()}</div>
                <div class="peer-endpoint">{endpoint}</div>
                {fingerprint.map(|fp| view! {
                    <div style="font-size:11px; color: var(--text-3); font-family: var(--font-mono)">
                        "📌 " {fp}
                    </div>
                })}
            </div>
            <div class="peer-sync">
                {last_sync.unwrap_or_else(|| "never synced".into())}
            </div>
            <div style="display:flex; gap: var(--sp-xs)">
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
                    on:click=move |_| { remove_action.dispatch(()); }
                >
                    "Remove"
                </button>
            </div>
        </div>
    }
}

#[component]
fn AddPeerModal(
    #[prop(into)] on_close: Callback<()>,
    #[prop(into)] on_success: Callback<()>,
) -> impl IntoView {
    let did_input = RwSignal::new(String::new());
    let endpoint_input = RwSignal::new(String::new());
    let fingerprint_input = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);

    let add_action = Action::new(move |args: &(String, String, Option<String>)| {
        let (did, endpoint, fp) = args.clone();
        async move { api::add_peer(did, endpoint, fp).await }
    });

    Effect::new(move || match add_action.value().get() {
        Some(Ok(())) => on_success.run(()),
        Some(Err(e)) => error.set(Some(e.to_string())),
        None => {}
    });

    let submitting = move || add_action.pending().get();

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
                        placeholder="did:key:z..."
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
                        "Pin the peer's self-signed cert. Leave empty to use TOFU (Trust On First Use) — only for initial bootstrap."
                    </div>
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
