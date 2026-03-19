use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::state::orchestrator::OrchestratorState;
use papillion_shared::DemoRunResult;

#[component]
pub fn ScenarioPage() -> impl IntoView {
    let orchestrator = expect_context::<OrchestratorState>();
    let navigate = use_navigate();
    let current_step = RwSignal::new(0u8);
    let run_result = RwSignal::new(None::<DemoRunResult>);
    let running = RwSignal::new(false);
    let run_error = RwSignal::new(None::<String>);

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
                    let scenario_id_for_run = card.id.clone();
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
                            <h3 style="font-size: 14px; margin-bottom: 12px;">"PAP Handshake"</h3>
                            <div class="handshake-stepper">
                                <HandshakeStep number=1 label="Discover agent" current_step=current_step result=run_result />
                                <HandshakeStep number=2 label="Issue mandate" current_step=current_step result=run_result />
                                <HandshakeStep number=3 label="Open session" current_step=current_step result=run_result />
                                <HandshakeStep number=4 label="Exchange data" current_step=current_step result=run_result />
                                <HandshakeStep number=5 label="Co-sign receipt" current_step=current_step result=run_result />
                                <HandshakeStep number=6 label="Close session" current_step=current_step result=run_result />
                            </div>

                            <div style="margin-top: 16px;">
                                <button
                                    class="btn btn-run"
                                    disabled={move || running.get() || current_step.get() != 0}
                                    on:click={
                                        let sid = scenario_id_for_run.clone();
                                        move |_| {
                                            let sid = sid.clone();
                                            running.set(true);
                                            run_error.set(None);
                                            current_step.set(1);

                                            spawn_local(async move {
                                                match bridge::invoke::<serde_json::Value, DemoRunResult>(
                                                    "run_demo_scenario",
                                                    &serde_json::json!({ "scenarioId": sid }),
                                                ).await {
                                                    Ok(result) => {
                                                        let result_clone = result.clone();
                                                        let total_steps = result.steps.len() as u8;
                                                        for step_num in 1..=total_steps {
                                                            let cs = current_step;
                                                            let delay = (step_num as i32 - 1) * 300;
                                                            let window = web_sys::window().unwrap();
                                                            let cb = Closure::once(move || {
                                                                cs.set(step_num + 1);
                                                            });
                                                            window.set_timeout_with_callback_and_timeout_and_arguments_0(
                                                                cb.as_ref().unchecked_ref(),
                                                                delay,
                                                            ).ok();
                                                            cb.forget();
                                                        }
                                                        let window = web_sys::window().unwrap();
                                                        let cb = Closure::once(move || {
                                                            run_result.set(Some(result_clone));
                                                            running.set(false);
                                                        });
                                                        window.set_timeout_with_callback_and_timeout_and_arguments_0(
                                                            cb.as_ref().unchecked_ref(),
                                                            (total_steps as i32) * 300,
                                                        ).ok();
                                                        cb.forget();
                                                    }
                                                    Err(e) => {
                                                        run_error.set(Some(e));
                                                        running.set(false);
                                                    }
                                                }
                                            });
                                        }
                                    }
                                >
                                    {move || {
                                        if running.get() {
                                            "Running..."
                                        } else if current_step.get() >= 7 {
                                            "Completed"
                                        } else {
                                            "Run Demo"
                                        }
                                    }}
                                </button>
                                <Show when=move || run_error.get().is_some()>
                                    <p style="color: var(--error); font-size: 12px; margin-top: 8px;">
                                        {move || run_error.get().unwrap_or_default()}
                                    </p>
                                </Show>
                            </div>
                        </div>

                        // Show receipt after completion
                        <Show when=move || run_result.get().is_some()>
                            {move || run_result.get().and_then(|r| r.receipt).map(|receipt| view! {
                                <div class="card" style="margin-bottom: 16px;">
                                    <h3 style="font-size: 14px; margin-bottom: 12px;">"Transaction Receipt"</h3>
                                    <div style="font-size: 12px; margin-bottom: 8px;">
                                        <span style="color: var(--text-secondary);">"Session: "</span>
                                        <code>{receipt.session_id}</code>
                                    </div>
                                    <div style="font-size: 12px; margin-bottom: 8px;">
                                        <span style="color: var(--text-secondary);">"Action: "</span>
                                        <code>{receipt.action}</code>
                                    </div>
                                    <div style="font-size: 12px; margin-bottom: 8px;">
                                        <span style="color: var(--text-secondary);">"Co-signed: "</span>
                                        <span class="badge badge-success">{if receipt.co_signed { "Yes" } else { "No" }}</span>
                                    </div>
                                    <div style="font-size: 12px;">
                                        <span style="color: var(--text-secondary);">"Disclosed: "</span>
                                        {if receipt.property_refs.is_empty() {
                                            "None (zero disclosure)".to_string()
                                        } else {
                                            receipt.property_refs.join(", ")
                                        }}
                                    </div>
                                </div>
                            })}
                        </Show>

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
fn HandshakeStep(
    number: u8,
    label: &'static str,
    current_step: RwSignal<u8>,
    result: RwSignal<Option<DemoRunResult>>,
) -> impl IntoView {
    let status = move || {
        let current = current_step.get();
        if current == 0 {
            "pending"
        } else if number < current {
            "completed"
        } else if number == current {
            "active"
        } else {
            "pending"
        }
    };

    let step_detail = move || {
        if status() == "completed" {
            result.get().and_then(|r| {
                r.steps
                    .iter()
                    .find(|s| s.step_number == number)
                    .and_then(|s| s.detail.clone())
            })
        } else {
            None
        }
    };

    view! {
        <div class=move || format!("handshake-step {}", status())>
            <div class=move || format!("handshake-step-number {}", status())>
                {move || if status() == "completed" {
                    "\u{2713}".to_string()
                } else {
                    number.to_string()
                }}
            </div>
            <div>
                <span class="handshake-step-label">{label}</span>
                <Show when=move || step_detail().is_some()>
                    <div class="step-detail">{move || step_detail().unwrap_or_default()}</div>
                </Show>
            </div>
        </div>
    }
}
