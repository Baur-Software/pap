use leptos::prelude::*;
use papillion_shared::types::TemplateConfig;

#[component]
pub fn TemplatePreview(
    template_config: TemplateConfig,
    sample_data: Option<String>,
) -> impl IntoView {
    let sample_input = RwSignal::new(sample_data.unwrap_or_else(|| {
        r#"{
  "@context": "https://schema.org",
  "@type": "FlightReservation",
  "name": "Sample Flight",
  "reservationNumber": "ABC123",
  "reservationStatus": "Confirmed",
  "underName": {
    "@type": "Person",
    "name": "John Doe"
  },
  "reservationFor": {
    "@type": "Flight",
    "flightNumber": "UA100",
    "airline": {
      "@type": "Airline",
      "name": "United Airlines"
    },
    "departureAirport": {
      "@type": "Airport",
      "name": "SFO"
    },
    "arrivalAirport": {
      "@type": "Airport",
      "name": "JFK"
    },
    "departureTime": "2025-03-23T14:30:00",
    "arrivalTime": "2025-03-23T22:30:00"
  }
}"#
            .to_string()
    }));

    let preview_error = RwSignal::new(None::<String>);
    let preview_result = RwSignal::new(String::new());

    let render_preview = move |_| {
        let input = sample_input.get();
        match serde_json::from_str::<serde_json::Value>(&input) {
            Ok(data) => {
                let mut result = String::new();

                // Render layout info
                result.push_str(&format!(
                    "Layout: {} ",
                    template_config.layout.r#type
                ));

                if let Some(cols) = template_config.layout.columns {
                    result.push_str(&format!("({} columns) ", cols));
                }
                if let Some(dir) = &template_config.layout.direction {
                    result.push_str(&format!("({}) ", dir));
                }
                if let Some(spacing) = &template_config.layout.spacing {
                    result.push_str(&format!("(spacing: {})", spacing));
                }
                result.push_str("\n\n");

                // Render fields
                result.push_str("Fields:\n");
                for (i, field) in template_config.fields.iter().enumerate() {
                    result.push_str(&format!(
                        "{}. {} [{}]",
                        i + 1,
                        field
                            .label
                            .as_ref()
                            .unwrap_or(&field.path),
                        field.display
                    ));

                    if let Some(condition) = &field.condition {
                        result.push_str(&format!(" (if {} exists)", condition.field));
                    }
                    result.push('\n');

                    // Try to extract value from data
                    let value = extract_json_path(&data, &field.path);
                    if let Some(v) = value {
                        result.push_str(&format!("  → {}\n", format_value(&v)));
                    } else {
                        result.push_str("  → (not found)\n");
                    }
                }

                preview_result.set(result);
                preview_error.set(None);
            }
            Err(e) => {
                preview_error.set(Some(format!("Invalid sample data: {}", e)));
            }
        }
    };

    // Initial render
    render_preview(());

    view! {
        <div style="display: flex; flex-direction: column; gap: 12px; height: 100%;">
            <div style="flex: 1; display: flex; gap: 12px; overflow-y: auto;">
                // Sample Data Input
                <div style="flex: 1; display: flex; flex-direction: column; gap: 8px;">
                    <label style="font-size: 12px; font-weight: 500; color: var(--text-2);">
                        "Sample JSON-LD Data"
                    </label>
                    <textarea
                        prop:value=move || sample_input.get()
                        on:input=move |ev| sample_input.set(event_target_value(&ev))
                        style="flex: 1; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px; padding: 8px; color: var(--text-1); font-size: 12px; font-family: var(--font-mono); resize: vertical;"
                    />
                    <button
                        class="btn"
                        on:click=render_preview
                        style="padding: 8px 16px; background: var(--purple); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 13px;"
                    >
                        "Render Preview"
                    </button>
                </div>

                // Preview Result
                <div style="flex: 1; display: flex; flex-direction: column; gap: 8px;">
                    <label style="font-size: 12px; font-weight: 500; color: var(--text-2);">
                        "Preview Result"
                    </label>
                    <Show when=move || preview_error.get().is_some()>
                        <div style="background: var(--coral); color: white; padding: 8px; border-radius: 4px; font-size: 12px;">
                            {move || preview_error.get().unwrap_or_default()}
                        </div>
                    </Show>
                    <pre style="flex: 1; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px; padding: 8px; color: var(--text-2); font-size: 12px; font-family: var(--font-mono); margin: 0; overflow-y: auto; white-space: pre-wrap; word-wrap: break-word;">
                        {move || preview_result.get()}
                    </pre>
                </div>
            </div>
        </div>
    }
}

/// Extract a value from JSON using a dot-notation path (e.g., "offers.price", "results.0.title")
fn extract_json_path(data: &serde_json::Value, path: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = data.clone();

    for part in parts {
        if let Ok(index) = part.parse::<usize>() {
            // Array index
            current = current.get(index)?.clone();
        } else {
            // Object key
            current = current.get(part)?.clone();
        }
    }

    if current.is_null() {
        None
    } else {
        Some(current)
    }
}

/// Format a JSON value for display
fn format_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "(null)".to_string(),
        serde_json::Value::Object(_) => "[Object]".to_string(),
        serde_json::Value::Array(_) => "[Array]".to_string(),
    }
}
