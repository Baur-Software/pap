use leptos::prelude::*;

/// Input port displayed on the left side of a block container.
/// Shows schema.org types this block accepts.
#[component]
pub fn BlockInputPort(
    /// Schema.org types this port accepts (e.g., ["schema:Place"])
    types: Vec<String>,
    /// Whether this port has an active connection
    connected: bool,
) -> impl IntoView {
    let type_labels = types.iter()
        .map(|t| t.strip_prefix("schema:").unwrap_or(t))
        .collect::<Vec<_>>()
        .join(", ");

    view! {
        <div class="block-port block-port-input" class:connected=connected>
            <div class="port-circle" />
            <div class="port-label">{type_labels}</div>
        </div>
    }
}

/// Output port displayed on the right side of a block container.
/// Shows schema.org types this block produces.
#[component]
pub fn BlockOutputPort(
    /// Schema.org types this port produces (e.g., ["schema:WeatherForecast"])
    types: Vec<String>,
    /// Whether this port has an active connection
    connected: bool,
) -> impl IntoView {
    let type_labels = types.iter()
        .map(|t| t.strip_prefix("schema:").unwrap_or(t))
        .collect::<Vec<_>>()
        .join(", ");

    view! {
        <div class="block-port block-port-output" class:connected=connected>
            <div class="port-label">{type_labels}</div>
            <div class="port-circle" />
        </div>
    }
}
