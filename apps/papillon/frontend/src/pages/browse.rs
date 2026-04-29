use leptos::prelude::*;

use crate::components::agent_picker_modal::AgentPickerModal;
use papillon_shared::AgentInfo;

/// Browse page — immediately opens the agent picker modal.
/// When the user picks an agent, the intent bar is pre-filled with a
/// `pap://` prompt for that agent.
#[component]
pub fn BrowsePage() -> impl IntoView {
    let modal_open: RwSignal<bool> = RwSignal::new(true); // open immediately on mount
    let _selected: RwSignal<Option<AgentInfo>> = RwSignal::new(None);

    let on_select = Callback::new(move |agent: AgentInfo| {
        // Navigate back to canvas — agent selection handled by caller context.
        // For now, record selection and navigate to canvas root.
        _selected.set(Some(agent));
        if let Some(win) = web_sys::window() {
            let _ = win.location().set_href("/");
        }
    });

    view! {
        <AgentPickerModal open=modal_open on_select=on_select />
        // Fallback if modal is dismissed without selecting
        <Show when=move || !modal_open.get()>
            <div style="display:flex;align-items:center;justify-content:center;height:60vh;color:#6b7280;font-size:13px;">
                <a href="/" style="color:var(--purple);">"← Back to canvas"</a>
            </div>
        </Show>
    }
}
