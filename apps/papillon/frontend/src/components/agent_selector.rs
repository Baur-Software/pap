use leptos::prelude::*;
use papillon_shared::AgentInfo;

/// Multi-select agent picker for a block container.
/// Shows only agents matching the container's SchemaSignature.
#[component]
pub fn AgentSelector(
    /// List of compatible agents (filtered by signature)
    agents: Vec<AgentInfo>,
    /// Currently selected agent names
    selected: RwSignal<Vec<String>>,
) -> impl IntoView {
    let toggle_agent = move |name: String| {
        selected.update(|sel| {
            if sel.contains(&name) {
                sel.retain(|n| n != &name);
            } else {
                sel.push(name);
            }
        });
    };

    view! {
        <div class="agent-selector">
            <div class="agent-selector-header">"Select Agents"</div>
            <div class="agent-selector-list">
                <For
                    each=move || agents.clone()
                    key=|agent| agent.name.clone()
                    children=move |agent| {
                        let agent_name_for_click = agent.name.clone();
                        let agent_name_for_check = agent.name.clone();
                        let agent_name_for_class = agent.name.clone();

                        view! {
                            <button
                                class="agent-selector-item"
                                class:selected=move || selected.get().contains(&agent_name_for_class)
                                on:click=move |_| toggle_agent(agent_name_for_click.clone())
                            >
                                <div class="agent-checkbox">
                                    {move || if selected.get().contains(&agent_name_for_check) { "✓" } else { "" }}
                                </div>
                                <div class="agent-info">
                                    <div class="agent-name">{agent.name.clone()}</div>
                                    <div class="agent-provider">{agent.provider_name.clone()}</div>
                                </div>
                            </button>
                        }
                    }
                />
            </div>
        </div>
    }
}
