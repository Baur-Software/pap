use leptos::prelude::*;

#[component]
pub fn ActivityPage() -> impl IntoView {
    view! {
        <div>
            <h2 class="page-title">"Activity"</h2>
            <div class="card">
                <p style="color: var(--text-secondary);">
                    "No recent activity. Run a scenario to see your session history and receipts here."
                </p>
            </div>
        </div>
    }
}
