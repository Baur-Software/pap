use leptos::prelude::*;

use crate::state::identity::IdentityState;

#[component]
pub fn DashboardPage() -> impl IntoView {
    let identity = expect_context::<IdentityState>();

    let has_identity = move || identity.info.get().is_some();

    view! {
        <div>
            <h2 class="page-title">"Dashboard"</h2>
            <Show
                when=has_identity
                fallback=move || view! {
                    <div class="card">
                        <p>"Welcome to Papillion — the agentic browser."</p>
                        <p style="color: var(--text-secondary); margin-top: 8px;">
                            "Create an identity in Settings to get started."
                        </p>
                    </div>
                }
            >
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px;">
                    <div class="card">
                        <div style="color: var(--text-secondary); font-size: 12px;">"Connected Registries"</div>
                        <div style="font-size: 24px; font-weight: 600; margin-top: 4px;">"0"</div>
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
