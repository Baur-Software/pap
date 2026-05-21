use leptos::prelude::*;
use papillon_shared::BlockContainer;
use crate::components::{BlockInputPort, BlockOutputPort};

/// Visual container for a multi-agent block with input/output ports.
#[component]
pub fn BlockContainerView(
    container: BlockContainer,
    /// Reactive signal for selected agents (empty = use container.agent_names)
    #[prop(optional)]
    selected_agents: Option<RwSignal<Vec<String>>>,
) -> impl IntoView {
    let selected = selected_agents.unwrap_or_else(|| {
        RwSignal::new(container.agent_names.clone())
    });

    let has_inputs = !container.signature.input_types.is_empty();
    let has_outputs = !container.signature.output_types.is_empty();

    let input_connected = !container.input_connections.is_empty();
    let output_connected = !container.output_connections.is_empty();

    // Clone for closures and prepare all data before view! macro
    let input_types_for_port = container.signature.input_types.clone();
    let output_types_for_port = container.signature.output_types.clone();
    let input_types_for_badges = container.signature.input_types.clone();
    let output_types_for_badges = container.signature.output_types.clone();
    let position_x = container.position.x;
    let position_y = container.position.y;

    // Build type badge views before entering view! macro
    let input_type_views: Vec<_> = input_types_for_badges.iter().map(|t| {
        let type_name = t.strip_prefix("schema:").unwrap_or(t).to_string();
        view! { <div class="type-badge type-input">{type_name}</div> }
    }).collect();

    let output_type_views: Vec<_> = output_types_for_badges.iter().map(|t| {
        let type_name = t.strip_prefix("schema:").unwrap_or(t).to_string();
        view! { <div class="type-badge type-output">{type_name}</div> }
    }).collect();

    let show_no_input = input_types_for_badges.is_empty();
    let has_input_types = !input_types_for_badges.is_empty();

    view! {
        <div
            class="block-container"
            style:left=move || format!("{}px", position_x)
            style:top=move || format!("{}px", position_y)
        >
            {has_inputs.then(|| view! {
                <BlockInputPort
                    types=input_types_for_port.clone()
                    connected=input_connected
                />
            })}

            <div class="block-container-body">
                <div class="block-container-header">
                    {move || {
                        let count = selected.get().len();
                        if count == 0 {
                            "No agents selected".to_string()
                        } else if count == 1 {
                            selected.get()[0].clone()
                        } else {
                            format!("{} agents", count)
                        }
                    }}
                </div>

                <div class="block-container-types">
                    {show_no_input.then(|| view! { <div class="type-badge">"No input"</div> })}
                    {has_input_types.then(|| input_type_views.clone())}
                    <div class="type-arrow">"→"</div>
                    {output_type_views}
                </div>

                <div class="block-agent-count">
                    {move || format!("{} agent(s) selected", selected.get().len())}
                </div>
            </div>

            {has_outputs.then(|| view! {
                <BlockOutputPort
                    types=output_types_for_port.clone()
                    connected=output_connected
                />
            })}
        </div>
    }
}
