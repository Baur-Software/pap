use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api::{self, AddPeerRequest, RegistryPeer};

#[component]
pub fn PeersPage() -> impl IntoView {
    let peers = RwSignal::new(Vec::<RegistryPeer>::new());
    let error = RwSignal::new(None::<String>);
    let loading = RwSignal::new(true);
    let show_add = RwSignal::new(false);
    let sync_msg = RwSignal::new(None::<String>);

    let reload = move || {
        loading.set(true);
        spawn_local(async move {
            match api::fetch_peers().await {
                Ok(list) => {
                    peers.set(list);
                    error.set(None);
                }
                Err(e) => error.set(Some(e)),
            }
            loading.set(false);
        });
    };

    Effect::new(move || { reload(); });

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

            {move || error.get().map(|e| view! {
                <div class="error-banner">"Error: " {e}</div>
            })}
            {move || sync_msg.get().map(|m| view! {
                <div class="success-banner">{m}</div>
            })}

            {move || if loading.get() {
                view! { <div class="loading">"Loading peers…"</div> }.into_any()
            } else {
                let peer_list = peers.get();
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
                            {peer_list.into_iter().map(|peer| {
                                let did = peer.did.clone();
                                let did_for_remove = did.clone();
                                let did_for_sync = did.clone();
                                let endpoint = peer.endpoint.clone();
                                let fingerprint = peer.cert_fingerprint.clone();
                                let last_sync = peer.last_sync.clone();

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
                                                on:click={
                                                    let did = did_for_sync.clone();
                                                    move |_| {
                                                        let did = did.clone();
                                                        spawn_local(async move {
                                                            match api::sync_peer(&did).await {
                                                                Ok(n) => sync_msg.set(Some(format!("Synced {} new agents from peer.", n))),
                                                                Err(e) => sync_msg.set(Some(format!("Sync failed: {}", e))),
                                                            }
                                                        });
                                                    }
                                                }
                                            >
                                                "↺ Sync"
                                            </button>
                                            <button
                                                class="btn btn-danger btn-sm"
                                                on:click={
                                                    let did = did_for_remove.clone();
                                                    move |_| {
                                                        let did = did.clone();
                                                        spawn_local(async move {
                                                            let _ = api::remove_peer(&did).await;
                                                            reload();
                                                        });
                                                    }
                                                }
                                            >
                                                "Remove"
                                            </button>
                                        </div>
                                    </div>
                                }
                            }).collect::<Vec<_>>()}
                        </div>
                    }.into_any()
                }
            }}

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
fn AddPeerModal(
    #[prop(into)] on_close: Callback<()>,
    #[prop(into)] on_success: Callback<()>,
) -> impl IntoView {
    let did_input = RwSignal::new(String::new());
    let endpoint_input = RwSignal::new(String::new());
    let fingerprint_input = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);
    let submitting = RwSignal::new(false);

    let do_submit = move |_| {
        let did = did_input.get().trim().to_string();
        let endpoint = endpoint_input.get().trim().to_string();
        let fingerprint = fingerprint_input.get().trim().to_string();

        if did.is_empty() || endpoint.is_empty() {
            error.set(Some("DID and endpoint are required.".into()));
            return;
        }
        submitting.set(true);
        error.set(None);

        let req = AddPeerRequest {
            did,
            endpoint,
            cert_fingerprint: if fingerprint.is_empty() { None } else { Some(fingerprint) },
        };

        spawn_local(async move {
            match api::add_peer(&req).await {
                Ok(()) => on_success.run(()),
                Err(e) => {
                    error.set(Some(e));
                    submitting.set(false);
                }
            }
        });
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
                        disabled=move || submitting.get()
                        on:click=do_submit
                    >
                        {move || if submitting.get() { "Adding…" } else { "Add Peer" }}
                    </button>
                </div>
            </div>
        </div>
    }
}
