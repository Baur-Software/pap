use leptos::prelude::*;
use leptos_router::components::A;

use crate::state::identity::IdentityState;
use crate::state::orchestrator::OrchestratorState;
use papillion_shared::OrchestratorStatus;

#[component]
pub fn Sidebar() -> impl IntoView {
    let identity = expect_context::<IdentityState>();
    let orchestrator = expect_context::<OrchestratorState>();

    let did_display = move || {
        identity
            .info
            .get()
            .map(|i| {
                let did = &i.did;
                if did.len() > 24 {
                    format!("{}...{}", &did[..12], &did[did.len() - 8..])
                } else {
                    did.clone()
                }
            })
            .unwrap_or_else(|| "No identity".to_string())
    };

    let status_label = move || match orchestrator.status.get() {
        OrchestratorStatus::Ready => "LLM Connected",
        OrchestratorStatus::Downloading { .. } => "Downloading Model...",
        OrchestratorStatus::Offline => "Offline",
        OrchestratorStatus::Disconnected => "Disconnected",
        OrchestratorStatus::Unconfigured => "Unconfigured",
    };

    let status_class = move || match orchestrator.status.get() {
        OrchestratorStatus::Ready => "status-badge ready",
        OrchestratorStatus::Offline => "status-badge offline",
        _ => "status-badge offline",
    };

    view! {
        <nav class="sidebar">
            <div class="identity-badge">
                <div class="label">"Principal"</div>
                <div class="did">{did_display}</div>
                <div class=status_class>{status_label}</div>
            </div>
            <A href="/" attr:class="nav-item">"Home"</A>
            <A href="/activity" attr:class="nav-item">"Activity"</A>
            <A href="/settings" attr:class="nav-item">"Settings"</A>
        </nav>
    }
}
