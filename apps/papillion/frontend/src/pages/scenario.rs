use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

use crate::state::orchestrator::OrchestratorState;

#[component]
pub fn ScenarioPage() -> impl IntoView {
    let orchestrator = expect_context::<OrchestratorState>();
    let navigate = use_navigate();

    let go_back = move |_| {
        let nav = navigate.clone();
        orchestrator.selected_scenario.set(None);
        nav("/", Default::default());
    };

    view! {
        <div>
            <button class="btn" style="margin-bottom: 16px; background: var(--bg-tertiary); color: var(--text-secondary);" on:click=go_back>
                {"\u{2190} Back"}
            </button>

            <Show
                when=move || orchestrator.selected_scenario.get().is_some()
                fallback=move || view! {
                    <div class="card">
                        <p style="color: var(--text-secondary);">"No scenario selected."</p>
                    </div>
                }
            >
                {move || orchestrator.selected_scenario.get().map(|card| {
                    let disclosure = card.requires_disclosure.clone();
                    let returns = card.returns.clone();
                    view! {
                        <div class="card" style="margin-bottom: 16px;">
                            <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                                <span style="font-size: 32px;">{card.icon.clone()}</span>
                                <div>
                                    <h2 style="font-size: 18px; font-weight: 600;">{card.title.clone()}</h2>
                                    <span style="font-size: 12px; color: var(--text-secondary);">{card.agent_name.clone()}</span>
                                </div>
                            </div>
                            <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 16px;">
                                {card.description.clone()}
                            </p>
                            <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">
                                "Action: "
                                <code>{card.action_type.clone()}</code>
                            </div>
                        </div>

                        <div class="card" style="margin-bottom: 16px;">
                            <h3 style="font-size: 14px; margin-bottom: 12px;">"Disclosure Requirements"</h3>
                            {
                                let disc_for_check = disclosure.clone();
                                let disc_for_list = disclosure;
                                view! {
                                    <Show
                                        when=move || disc_for_check.is_empty()
                                        fallback={
                                            let disc = disc_for_list.clone();
                                            move || {
                                                let disc = disc.clone();
                                                view! {
                                                    <ul style="list-style: none; padding: 0;">
                                                        <For
                                                            each=move || disc.clone()
                                                            key=|d| d.clone()
                                                            let:field
                                                        >
                                                            <li style="padding: 4px 0; font-size: 13px;">
                                                                <span class="badge badge-accent" style="margin-right: 8px;">{field}</span>
                                                            </li>
                                                        </For>
                                                    </ul>
                                                }
                                            }
                                        }
                                    >
                                        <p style="color: var(--success); font-size: 13px;">
                                            "None \u{2014} zero disclosure interaction"
                                        </p>
                                    </Show>
                                }
                            }
                        </div>

                        <div class="card" style="margin-bottom: 16px;">
                            <h3 style="font-size: 14px; margin-bottom: 12px;">"Handshake Protocol"</h3>
                            <div class="handshake-stepper">
                                <HandshakeStep number=1 label="Discover agent" />
                                <HandshakeStep number=2 label="Issue mandate" />
                                <HandshakeStep number=3 label="Open session" />
                                <HandshakeStep number=4 label="Exchange data" />
                                <HandshakeStep number=5 label="Co-sign receipt" />
                                <HandshakeStep number=6 label="Close session" />
                            </div>
                        </div>

                        <div class="card">
                            <h3 style="font-size: 14px; margin-bottom: 12px;">"Returns"</h3>
                            <For
                                each=move || returns.clone()
                                key=|r| r.clone()
                                let:ret
                            >
                                <span class="badge badge-success" style="margin-right: 8px;">{ret}</span>
                            </For>
                        </div>
                    }
                })}
            </Show>
        </div>
    }
}

#[component]
fn HandshakeStep(number: u8, label: &'static str) -> impl IntoView {
    view! {
        <div class="handshake-step">
            <div class="handshake-step-number">{number.to_string()}</div>
            <span class="handshake-step-label">{label}</span>
        </div>
    }
}
