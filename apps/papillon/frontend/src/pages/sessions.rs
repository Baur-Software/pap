use leptos::prelude::*;

#[component]
pub fn SessionsPage() -> impl IntoView {
    view! {
        <div>
            <h2 class="page-title">"Sessions"</h2>
            <div class="card">
                <p style="color: var(--text-secondary);">"No active sessions. Connect to an agent to start a session."</p>
            </div>
        </div>
    }
}
