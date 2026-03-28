use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

use crate::state::identity::IdentityState;
use crate::state::registry::RegistryState;

#[component]
pub fn DashboardPage() -> impl IntoView {
    let identity = expect_context::<IdentityState>();
    let registry = expect_context::<RegistryState>();
    let navigate = use_navigate();

    let has_identity = move || identity.info.get().is_some();

    let browse_registry = move |_| {
        registry.connect_to("pap://local");
        let nav = navigate.clone();
        nav("/browse", Default::default());
    };

    view! {
        <div class="page">
            <h2 class="page-title">"Dashboard"</h2>

            <div class="card" style="margin-bottom: 16px;">
                <h3 style="font-size: 14px; margin-bottom: 8px;">"Local Agent Registry"</h3>
                <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 12px;">
                    "Browse agents backed by real services: DuckDuckGo search, Wikipedia knowledge, and on-device Mistral AI. Zero disclosure, fully functional."
                </p>
                <button class="btn btn-primary" on:click=browse_registry>
                    "Browse Agents"
                </button>
            </div>

            <Show
                when=has_identity
                fallback=move || view! {
                    <div class="card">
                        <p>"Welcome to Papillon \u{2014} the agentic browser."</p>
                        <p style="color: var(--text-secondary); margin-top: 8px;">
                            "Create an identity in Settings to get started, or browse the local registry above."
                        </p>
                    </div>
                }
            >
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px;">
                    <div class="card">
                        <div style="color: var(--text-secondary); font-size: 12px;">"Connected Registries"</div>
                        <div style="font-size: 24px; font-weight: 600; margin-top: 4px;">"1"</div>
                    </div>
                    <div class="card">
                        <div style="color: var(--text-secondary); font-size: 12px;">"Active Sessions"</div>
                        <div style="font-size: 24px; font-weight: 600; margin-top: 4px;">"0"</div>
                    </div>
                    <div class="card">
                        <div style="color: var(--text-secondary); font-size: 12px;">"Receipts"</div>
                        <div style="font-size: 24px; font-weight: 600; margin-top: 4px;">"0"</div>
                    </div>
                </div>
            </Show>
        </div>
    }
}
