use leptos::prelude::*;

use crate::components::agent_picker_modal::AgentPickerModal;
use papillon_shared::AgentInfo;

/// Browse page — immediately opens the agent picker modal on mount.
/// When the user selects an agent, navigate back to canvas root.
/// When the modal is dismissed without selecting, show a back link.
#[component]
pub fn BrowsePage() -> impl IntoView {
    // Open immediately on mount
    let modal_open: RwSignal<bool> = RwSignal::new(true);

    let on_select = Callback::new(move |_agent: AgentInfo| {
        // Modal closed by on_select path — navigate back to canvas
        if let Some(win) = web_sys::window() {
            let _ = win.location().set_href("/");
        }
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
