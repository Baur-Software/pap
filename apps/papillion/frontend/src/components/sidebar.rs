use leptos::prelude::*;
use leptos_router::components::A;

use crate::state::identity::IdentityState;

#[component]
pub fn Sidebar() -> impl IntoView {
    let identity = expect_context::<IdentityState>();

    let did_display = move || {
        identity.info.get().map(|i| {
            let did = &i.did;
            if did.len() > 24 {
                format!("{}...{}", &did[..12], &did[did.len()-8..])
            } else {
                did.clone()
            }
        }).unwrap_or_else(|| "No identity".to_string())
    };

    view! {
        <nav class="sidebar">
            <div class="identity-badge">
                <div class="label">"Principal"</div>
                <div class="did">{did_display}</div>
            </div>
            <A href="/" attr:class="nav-item">"Dashboard"</A>
            <A href="/browse" attr:class="nav-item">"Browse Registries"</A>
            <A href="/sessions" attr:class="nav-item">"Sessions"</A>
            <A href="/pipelines" attr:class="nav-item">"Pipelines"</A>
            <A href="/receipts" attr:class="nav-item">"Receipts"</A>
            <A href="/settings" attr:class="nav-item">"Settings"</A>
        </nav>
    }
}
