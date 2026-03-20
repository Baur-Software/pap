use leptos::prelude::*;

#[component]
pub fn ReceiptsPage() -> impl IntoView {
    view! {
        <div>
            <h2 class="page-title">"Receipts"</h2>
            <div class="card">
                <p style="color: var(--text-secondary);">"No receipts yet. Complete a session to see the audit trail."</p>
            </div>
        </div>
    }
}
