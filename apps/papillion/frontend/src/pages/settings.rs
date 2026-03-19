use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::state::identity::IdentityState;
use papillion_shared::IdentityInfo;

#[component]
pub fn SettingsPage() -> impl IntoView {
    let identity = expect_context::<IdentityState>();
    let has_identity = move || identity.info.get().is_some();

    view! {
        <div>
            <h2 class="page-title">"Settings"</h2>
            <div class="card">
                <h3 style="font-size: 14px; margin-bottom: 12px;">"Identity"</h3>
                <Show
                    when=has_identity
                    fallback=move || {
                        let identity = identity.clone();
                        view! {
                            <p style="color: var(--text-secondary); margin-bottom: 12px;">
                                "No identity created yet."
                            </p>
                            <button class="btn btn-primary" on:click=move |_| {
                                let identity = identity.clone();
                                spawn_local(async move {
                                    identity.loading.set(true);
                                    match bridge::invoke_no_args::<IdentityInfo>("create_identity").await {
                                        Ok(info) => {
                                            identity.info.set(Some(info));
                                        }
                                        Err(e) => {
                                            web_sys::console::error_1(&format!("Failed to create identity: {e}").into());
                                        }
                                    }
                                    identity.loading.set(false);
                                });
                            }>
                                "Create Identity"
                            </button>
                        }
                    }
                >
                    {move || identity.info.get().map(|info| view! {
                        <div>
                            <div style="margin-bottom: 8px;">
                                <span style="color: var(--text-secondary); font-size: 12px;">"DID: "</span>
                                <code style="font-size: 12px;">{info.did}</code>
                            </div>
                            <div>
                                <span style="color: var(--text-secondary); font-size: 12px;">"Public Key: "</span>
                                <code style="font-size: 12px;">{info.public_key_b64}</code>
                            </div>
                        </div>
                    })}
                </Show>
            </div>
        </div>
    }
}
