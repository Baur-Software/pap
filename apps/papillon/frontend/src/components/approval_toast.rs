use leptos::prelude::*;
use crate::state::canvas::CanvasState;

/// Toast notification stack for approval requests.
/// Fixed bottom-right position, animates in from bottom.
#[component]
pub fn ApprovalToastStack() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let hitl_pending = canvas_state.hitl_pending;

    view! {
        <Show when=move || hitl_pending.get().is_some()>
            {move || {
                hitl_pending.get().map(|req| {
                    view! {
                        <ApprovalToast request=req />
                    }
                })
            }}
        </Show>
    }
}

/// Individual approval toast for a single HitL request.
#[component]
fn ApprovalToast(request: crate::state::canvas::HitlRequest) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    // Humanize action type: strip "schema:" prefix and "Action" suffix
    let action_display = humanize_action(&request.action_type);

    // Clone fields needed in closures
    let agent_name = request.agent_name.clone();
    let disclosure_props_len = request.disclosure_props.len();
    let has_disclosure = !request.disclosure_props.is_empty();

    // Quick approve handler
    let quick_approve = move |_| {
        if disclosure_props_len == 0 {
            // Zero-disclosure: approve immediately
            // TODO: wire to canvas_state.approve_block() in Task 18
            leptos::logging::log!("Quick approve: {}", agent_name);
            canvas_state.hitl_pending.set(None);
        } else {
            // Has disclosure: open workflow panel for review
            canvas_state.workflow_panel_open.set(true);
        }
    };

    // Dismiss handler
    let dismiss = move |_| {
        canvas_state.hitl_pending.set(None);
    };

    view! {
        <div class="approval-toast">
            <div class="approval-toast-header">
                <div class="approval-toast-agent">{request.agent_name.clone()}</div>
                <button
                    class="approval-toast-dismiss"
                    on:click=dismiss
                    aria-label="Dismiss"
                >
                    "×"
                </button>
            </div>

            <div class="approval-toast-body">
                <div class="approval-toast-action">
                    {action_display}
                    {move || {
                        if request.risk_level == "HIGH" {
                            view! { <span class="approval-toast-risk high">"HIGH"</span> }.into_any()
                        } else if request.risk_level == "CRITICAL" {
                            view! { <span class="approval-toast-risk critical">"CRITICAL"</span> }.into_any()
                        } else {
                            view! { <></> }.into_any()
                        }
                    }}
                </div>

                <div class="approval-toast-description">
                    {request.description.clone()}
                </div>

                {move || {
                    if !request.disclosure_props.is_empty() {
                        view! {
                            <div class="approval-toast-disclosure">
                                "Requires disclosure: "
                                {request.disclosure_props.join(", ")}
                            </div>
                        }.into_any()
                    } else {
                        view! { <></> }.into_any()
                    }
                }}
            </div>

            <div class="approval-toast-footer">
                {
                    if has_disclosure {
                        // Multi-property disclosure: view details button
                        view! {
                            <button
                                class="approval-toast-button details"
                                on:click=quick_approve
                            >
                                "VIEW DETAILS"
                            </button>
                        }.into_any()
                    } else {
                        // Zero-disclosure: quick approve button
                        view! {
                            <button
                                class="approval-toast-button approve"
                                on:click=quick_approve
                            >
                                "APPROVE"
                            </button>
                        }.into_any()
                    }
                }
            </div>
        </div>
    }
}

/// Strip "schema:" prefix and "Action" suffix from action type strings.
fn humanize_action(action: &str) -> String {
    action
        .trim_start_matches("schema:")
        .trim_end_matches("Action")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn humanize_action_strips_prefix_and_suffix() {
        assert_eq!(humanize_action("schema:SearchAction"), "Search");
        assert_eq!(humanize_action("schema:WriteAction"), "Write");
        assert_eq!(humanize_action("schema:ReadAction"), "Read");
    }

    #[test]
    fn humanize_action_handles_no_prefix() {
        assert_eq!(humanize_action("SearchAction"), "Search");
    }

    #[test]
    fn humanize_action_handles_no_suffix() {
        assert_eq!(humanize_action("schema:Search"), "schema:Search");
    }

    #[test]
    fn humanize_action_handles_plain_string() {
        assert_eq!(humanize_action("search"), "search");
    }
}
