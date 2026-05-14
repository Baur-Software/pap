use leptos::prelude::*;
use papillon_shared::IntentPlan;
use std::collections::HashMap;

#[component]
pub fn DisclosureForm(
    plan: IntentPlan,
    selected_agents: ReadSignal<Vec<String>>,
) -> impl IntoView {
    // Form field values stored in local signal
    let (field_values, set_field_values) = create_signal(HashMap::<String, String>::new());

    // Compute union of requires_disclosure from selected agents
    let disclosure_props = create_memo(move |_| {
        let selected = selected_agents.get();
        if selected.is_empty() {
            return Vec::new();
        }

        let mut props = Vec::new();
        for agent in &plan.candidates {
            if selected.contains(&agent.did) {
                for prop in &agent.requires_disclosure {
                    if !props.contains(prop) {
                        props.push(prop.clone());
                    }
                }
            }
        }
        props.sort();
        props
    });

    let agent_count = create_memo(move |_| selected_agents.get().len());

    view! {
        <div class="disclosure-form">
            <div class="disclosure-form-header">
                <span class="disclosure-label">"DISCLOSE"</span>
                <span class="disclosure-count">
                    {move || disclosure_props.get().len()}
                    " "
                    {move || if disclosure_props.get().len() == 1 { "property" } else { "properties" }}
                </span>
            </div>

            <div class="disclosure-form-fields">
                <For
                    each=move || disclosure_props.get()
                    key=|p| p.clone()
                    children=move |prop| {
                        view! {
                            <DisclosureField
                                property=prop
                                field_values=field_values
                                set_field_values=set_field_values
                            />
                        }
                    }
                />
            </div>

            <button
                class="disclosure-approve-button"
                disabled=move || agent_count.get() == 0
            >
                "Disclose & Execute ("
                {move || agent_count.get()}
                " "
                {move || if agent_count.get() == 1 { "agent" } else { "agents" }}
                ")"
            </button>
        </div>
    }
}

#[component]
fn DisclosureField(
    property: String,
    field_values: ReadSignal<HashMap<String, String>>,
    set_field_values: WriteSignal<HashMap<String, String>>,
) -> impl IntoView {
    let prop_clone = property.clone();
    let prop_for_input = property.clone();

    // Infer field type from property name
    let field_type = infer_field_type(&property);

    // Humanize property name
    let label = humanize_property(&property);

    let current_value = create_memo(move |_| {
        field_values
            .get()
            .get(&prop_clone)
            .cloned()
            .unwrap_or_default()
    });

    view! {
        <div class="disclosure-field">
            <label class="disclosure-field-label">{label}</label>
            <input
                type=field_type
                class="disclosure-field-input"
                value=current_value
                on:input=move |ev| {
                    let value = event_target_value(&ev);
                    let prop = prop_for_input.clone();
                    set_field_values.update(|map| {
                        map.insert(prop, value);
                    });
                }
            />
        </div>
    }
}

/// Infer HTML input type from property name
fn infer_field_type(property: &str) -> &'static str {
    let lower = property.to_lowercase();

    if lower.contains("email") {
        "email"
    } else if lower.contains("date") || lower.contains("time") {
        "date"
    } else if lower.contains("url") || lower.contains("website") {
        "url"
    } else if lower.contains("phone") || lower.contains("tel") {
        "tel"
    } else {
        "text"
    }
}

/// Humanize property name: strip "schema:", capitalize, handle dot notation
fn humanize_property(property: &str) -> String {
    // Strip "schema:" prefix
    let without_schema = property.strip_prefix("schema:").unwrap_or(property);

    // Handle dot notation: take last segment
    let last_segment = without_schema.split('.').last().unwrap_or(without_schema);

    // Split camelCase/PascalCase into words
    let mut result = String::new();
    let mut prev_was_lower = false;

    for ch in last_segment.chars() {
        if ch.is_uppercase() && prev_was_lower {
            result.push(' ');
        }
        result.push(ch);
        prev_was_lower = ch.is_lowercase();
    }

    // Capitalize first letter
    if let Some(first) = result.chars().next() {
        first.to_uppercase().collect::<String>() + &result[first.len_utf8()..]
    } else {
        result
    }
}
