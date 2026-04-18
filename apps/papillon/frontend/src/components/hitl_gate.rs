use leptos::prelude::*;

use crate::state::canvas::CanvasState;

/// Human-in-the-Loop gate — a full-screen critical action barrier.
/// Appears when `canvas_state.hitl_pending` is `Some`.
#[component]
pub fn HitlGate() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    let authorize = move |_| {
        canvas_state.hitl_pending.set(None);
    };

    let reject = move |_| {
        canvas_state.hitl_pending.set(None);
    };

    view! {
        <Show when=move || canvas_state.hitl_pending.get().is_some()>
            {move || {
                let req = canvas_state.hitl_pending.get().unwrap();
                let is_critical = req.risk_level == "CRITICAL";
                view! {
                    <div class="hitl-overlay">
                        <div class="hitl-gate" class:hitl-gate-critical=is_critical>
                            <div class="hitl-header">
                                <span class="hitl-risk-badge" class:hitl-risk-critical=is_critical>
                                    {req.risk_level.clone()}
                                </span>
                                <span class="hitl-title">"HUMAN_GATE_REQUIRED"</span>
                            </div>

                            <div class="hitl-agent-row">
                                <span class="hitl-label">"AGENT"</span>
                                <span class="hitl-value">{req.agent_name.clone()}</span>
                            </div>
                            <div class="hitl-agent-row">
                                <span class="hitl-label">"ACTION"</span>
                                <span class="hitl-value">{
                                    req.action_type.strip_prefix("schema:")
                                        .unwrap_or(&req.action_type)
                                        .to_string()
                                }</span>
                            </div>

                            <div class="hitl-description">{req.description.clone()}</div>

                            {
                                let props_check = req.disclosure_props.clone();
                                let props_render = req.disclosure_props.clone();
                                view! {
                                    <Show when=move || !props_check.is_empty()>
                                        <div class="hitl-disclosure">
                                            <div class="hitl-disclosure-label">"DISCLOSURE_REQUIRED"</div>
                                            <div class="hitl-disclosure-props">
                                                {props_render.iter().map(|p| {
                                                    view! { <span class="hitl-prop-tag">{p.clone()}</span> }
                                                }).collect::<Vec<_>>()}
                                            </div>
                                        </div>
                                    </Show>
                                }
                            }

                            <div class="hitl-actions">
                                <button class="hitl-reject-btn" on:click=reject>
                                    "[ REJECT ]"
                                </button>
                                <button class="hitl-authorize-btn" on:click=authorize>
                                    "[ AUTHORIZE ]"
                                </button>
                            </div>

                            <div class="hitl-footnote">
                                "This action requires your explicit authorization. "
                                "PAP protocol v1 \u{2014} Zero-trust principal gate."
                            </div>
                        </div>
                    </div>
                }
            }}
        </Show>
    }
}
