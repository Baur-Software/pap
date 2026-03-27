use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::state::orchestrator::OrchestratorState;
use papillon_shared::ScenarioCard;

#[component]
pub fn HomePage() -> impl IntoView {
    let orchestrator = expect_context::<OrchestratorState>();
    let navigate = use_navigate();

    // Load scenarios on mount
    Effect::new(move || {
        let scenarios = orchestrator.scenarios;
        if scenarios.get().is_empty() && bridge::tauri_available() {
            spawn_local(async move {
                if let Ok(cards) =
                    bridge::invoke_no_args::<Vec<ScenarioCard>>("list_scenarios").await
                {
                    scenarios.set(cards);
                }
            });
        }
    });

    view! {
        <div class="page">
            <h2 class="page-title">"What would you like to do?"</h2>
            <div class="scenario-grid">
                <For
                    each=move || orchestrator.scenarios.get()
                    key=|card| card.id.clone()
                    children=move |card| {
                        let nav = navigate.clone();
                        let id = card.id.clone();
                        let orchestrator = orchestrator;
                        let card_for_click = card.clone();
                        view! {
                            <div
                                class="scenario-card"
                                on:click=move |_| {
                                    orchestrator.selected_scenario.set(Some(card_for_click.clone()));
                                    let path = format!("/scenario/{}", id);
                                    nav(&path, Default::default());
                                }
                            >
                                <div class="scenario-icon">{card.icon.clone()}</div>
                                <div class="scenario-info">
                                    <div class="scenario-title">{card.title.clone()}</div>
                                    <div class="scenario-desc">{card.description.clone()}</div>
                                </div>
                                <DisclosureBadge disclosure=card.requires_disclosure.clone() />
                            </div>
                        }
                    }
                />
            </div>
        </div>
    }
}

#[component]
fn DisclosureBadge(disclosure: Vec<String>) -> impl IntoView {
    if disclosure.is_empty() {
        view! {
            <span class="scenario-disclosure zero">"Zero Disclosure"</span>
        }
        .into_any()
    } else {
        let count = disclosure.len();
        let label = if count == 1 {
            "1 field required".to_string()
        } else {
            format!("{count} fields required")
        };
        view! {
            <span class="scenario-disclosure required">{label}</span>
        }
        .into_any()
    }
}
