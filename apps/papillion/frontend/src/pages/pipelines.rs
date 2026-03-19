use leptos::prelude::*;

#[component]
pub fn PipelinesPage() -> impl IntoView {
    view! {
        <div>
            <h2 class="page-title">"Pipelines"</h2>
            <div class="card">
                <p style="color: var(--text-secondary);">"No pipelines yet. Create one to compose agents into workflows."</p>
            </div>
        </div>
    }
}
