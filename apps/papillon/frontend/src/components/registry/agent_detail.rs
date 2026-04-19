use leptos::prelude::*;

use crate::state::registry::RegistryState;

#[component]
pub fn AgentDetail() -> impl IntoView {
    let registry = expect_context::<RegistryState>();

    let close = move |_| {
        registry.selected_agent.set(None);
    };

    move || {
        registry.selected_agent.get().map(|agent| {
            let name = agent.name.clone();
            let provider_name = agent.provider_name.clone();
            let provider_did = agent.provider_did.clone();
            let caps: Vec<String> = agent.capabilities.clone();
            let returns: Vec<String> = agent.returns.clone();
            let disclosure_text = if agent.requires_disclosure.is_empty() {
                "None (zero-disclosure)".to_string()
            } else {
                agent.requires_disclosure.join(", ")
            };
            let has_disclosure = !agent.requires_disclosure.is_empty();

            view! {
                <div class="agent-detail" style="position: fixed; right: 0; top: var(--header-height); bottom: var(--status-height); width: 400px; background: var(--bg-secondary); border-left: 1px solid var(--border); padding: 20px; overflow-y: auto; z-index: 10;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                        <h3 class="agent-detail-name" style="font-size: 16px;">{name}</h3>
                        <button class="btn" style="background: var(--bg-tertiary); color: var(--text-secondary); padding: 4px 8px;" on:click=close>
                            "X"
                        </button>
                    </div>

                    <div class="card">
                        <h4 style="font-size: 12px; color: var(--text-secondary); margin-bottom: 8px;">"Provider"</h4>
                        <div style="font-size: 13px;">{provider_name}</div>
                        <div style="font-size: 11px; color: var(--text-secondary); font-family: monospace; margin-top: 4px;">
                            {provider_did}
                        </div>
                    </div>

                    <div class="card">
                        <h4 style="font-size: 12px; color: var(--text-secondary); margin-bottom: 8px;">"Capabilities"</h4>
                        {caps.into_iter().map(|cap| view! {
                            <div style="margin-bottom: 4px;">
                                <span class="badge badge-accent">{cap}</span>
                            </div>
                        }).collect::<Vec<_>>()}
                    </div>

                    <div class="card">
                        <h4 style="font-size: 12px; color: var(--text-secondary); margin-bottom: 8px;">"What this agent will see"</h4>
                        <div style={if has_disclosure { "font-size: 12px; color: var(--warning);" } else { "font-size: 12px; color: var(--success);" }}>
                            {disclosure_text}
                        </div>
                    </div>

                    <div class="card">
                        <h4 style="font-size: 12px; color: var(--text-secondary); margin-bottom: 8px;">"Returns"</h4>
                        {returns.into_iter().map(|r| view! {
                            <div style="font-size: 12px; margin-bottom: 4px;">{r}</div>
                        }).collect::<Vec<_>>()}
                    </div>

                    <div style="margin-top: 16px;">
                        <button class="btn btn-primary" style="width: 100%;">
                            "Connect"
                        </button>
                    </div>
                </div>
            }
        })
    }
}
