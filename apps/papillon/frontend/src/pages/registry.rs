use leptos::prelude::*;

use crate::components::registry::agent_editor::AgentEditor;
use crate::components::registry::agent_sidebar::AgentSidebar;
use crate::state::registry::RegistryState;

#[component]
pub fn RegistryPage() -> impl IntoView {
    let registry = expect_context::<RegistryState>();
    let agents = registry.agents;

    let active_agent = move || {
        let id = registry.active_agent_id.get()?;
        registry.agents.get().into_iter().find(|a| a.name == id)
    };
    let active_agent_signal = Signal::derive(active_agent);

    let empty_state = move || registry.active_agent_id.get().is_none();

    view! {
        <div style="display: flex; height: 100%; overflow: hidden;">
            <AgentSidebar agents=agents.read_only() />
            <div style="flex: 1; display: flex; flex-direction: column; overflow: hidden;">
                <Show
                    when=move || !empty_state()
                    fallback=|| view! {
                        <div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #334155; font-size: 13px; flex-direction: column; gap: 12px;">
                            <div>"Select an agent or create a new one"</div>
                            <div style="font-size: 11px; color: #1e293b;">"Agents you define here are published into the PAP federation"</div>
                        </div>
                    }
                >
                    <AgentEditor agent=active_agent_signal />
                </Show>
            </div>
        </div>
    }
}
