use leptos::prelude::*;
use papillon_shared::{AgentCandidate, IntentPlan};

#[component]
pub fn AgentCurationList(
    plan: IntentPlan,
    selected_agents: RwSignal<Vec<String>>,
) -> impl IntoView {
    // Initialize selected agents from plan if not already set
    let initial_selected = plan.candidates
        .iter()
        .filter(|c| Some(&c.did) == plan.selected_agent_did.as_ref())
        .map(|c| c.did.clone())
        .collect::<Vec<_>>();

    if selected_agents.get_untracked().is_empty() && !initial_selected.is_empty() {
        selected_agents.set(initial_selected);
    }

    view! {
        <div class="agent-curation-list">
            <For
                each=move || plan.candidates.clone()
                key=|c| c.did.clone()
                children=move |candidate| {
                    view! {
                        <AgentCurationCard
                            agent=candidate
                            selected=selected_agents.read_only()
                            on_toggle=selected_agents
                        />
                    }
                }
            />
        </div>
    }
}

#[component]
fn AgentCurationCard(
    agent: AgentCandidate,
    selected: ReadSignal<Vec<String>>,
    on_toggle: RwSignal<Vec<String>>,
) -> impl IntoView {
    let agent_did = agent.did.clone();
    let agent_did_for_toggle = agent.did.clone();

    let is_selected = Memo::new(move |_| selected.get().contains(&agent_did));

    // On-device detection (simplified: check if did:key)
    let is_on_device = agent.did.starts_with("did:key:");

    // Truncate DID for display
    let truncated_did = truncate_did(&agent.did);

    view! {
        <div
            class="agent-card"
            class:selected=is_selected
        >
            <label class="agent-card-checkbox-label">
                <input
                    type="checkbox"
                    class="agent-card-checkbox"
                    checked=is_selected
                    on:change=move |_| {
                        on_toggle.update(|list| {
                            if list.contains(&agent_did_for_toggle) {
                                list.retain(|d| d != &agent_did_for_toggle);
                            } else {
                                list.push(agent_did_for_toggle.clone());
                            }
                        });
                    }
                />
                <div class="agent-card-info">
                    <div class="agent-card-header">
                        <span class="agent-card-name">{agent.name.clone()}</span>
                        <Show when=move || is_on_device>
                            <span class="trust-badge on-device">"On-Device"</span>
                        </Show>
                    </div>
                    <span class="agent-card-did">{truncated_did}</span>
                    <div class="agent-card-disclosure">
                        <span class="disclosure-count">
                            {agent.requires_disclosure.len()}
                            " "
                            {if agent.requires_disclosure.len() == 1 { "property" } else { "properties" }}
                        </span>
                    </div>
                </div>
            </label>
        </div>
    }
}

fn truncate_did(did: &str) -> String {
    if did.len() <= 30 {
        return did.to_string();
    }
    format!("{}...{}", &did[..20], &did[did.len() - 8..])
}
