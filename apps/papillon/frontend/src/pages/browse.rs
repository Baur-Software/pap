use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

use crate::components::agent_picker_modal::AgentPickerModal;
use papillon_shared::AgentInfo;

/// Browse page — immediately opens the agent picker modal on mount.
/// When the user selects an agent, navigate back to canvas root.
/// When the modal is dismissed without selecting, show a back link.
#[component]
pub fn BrowsePage() -> impl IntoView {
    // Open immediately on mount
    let modal_open: RwSignal<bool> = RwSignal::new(true);

    // Use Leptos router navigation — avoids a full WebView reload that would
    // discard all reactive state (signals, context, in-memory mock state).
    let navigate = use_navigate();

    let on_select = Callback::new(move |_agent: AgentInfo| {
        // NOTE: Phase 3 — navigate to canvas root; agent pre-filling of the intent bar
        // (populating topbar-address-input with pap://<agent.agent_did>) is deferred to Phase 4.
        navigate("/", Default::default());
    });

    view! {
        <AgentPickerModal open=modal_open on_select=on_select />
        // Fallback content shown only when modal is closed without selecting
        <Show when=move || !modal_open.get()>
            <div style="display:flex;align-items:center;justify-content:center;height:60vh;font-size:13px;">
                <a href="/" style="color:var(--purple,#6c5ce7);">"← Back to canvas"</a>
            </div>
        </Show>
    }
}
