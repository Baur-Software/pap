use leptos::prelude::*;
use serde_json::Value;

use super::dispatch_typed_or_generic;
use super::field_classify::{
    camel_to_kebab, classify_field, extract_type, format_datetime, humanize_key,
    sanitize_css_class, scalar_to_string, schema_type_to_css, FieldKind,
};

/// Maximum nesting depth before truncation.
const MAX_DEPTH: u8 = 4;

/// Render any schema.org type generically by walking its fields recursively.
/// Fields are classified by shape (date, price, URL, DID, nested object, list)
/// and given appropriate visual treatment.
pub fn render_generic(schema_type: &str, content: &Value, depth: u8) -> AnyView {
    let type_label = schema_type.to_string();
    let css_type = schema_type_to_css(schema_type);

    let fields = render_fields(content, &css_type, depth);

    view! {
        <div class=format!("typed-generic typed-{}", css_type)>
            <span class="typed-label">{type_label}</span>
            {fields}
        </div>
    }
    .into_any()
}

/// Render all non-@ fields of a JSON object.
fn render_fields(value: &Value, parent_css: &str, depth: u8) -> AnyView {
    if depth > MAX_DEPTH {
        return render_truncated();
    }

    let obj = match value.as_object() {
        Some(o) => o,
        None => return render_scalar_value(value),
    };

    let entries: Vec<_> = obj
        .iter()
        .filter(|(k, _)| !k.starts_with('@'))
        .map(|(key, val)| {
            let kind = classify_field(key, val);
            render_field(key, val, &kind, parent_css, depth)
        })
        .collect();

    view! {
        <div class="typed-fields">{entries}</div>
    }
    .into_any()
}

/// Render a single field based on its classified kind.
fn render_field(key: &str, val: &Value, kind: &FieldKind, parent_css: &str, depth: u8) -> AnyView {
    let css_field = format!(
        "typed-{}-{}",
        parent_css,
        sanitize_css_class(&camel_to_kebab(key))
    );
    let label = humanize_key(key);

    match kind {
        FieldKind::Scalar => {
            let display = scalar_to_string(val);
            view! {
                <div class=format!("typed-field {}", css_field)>
                    <span class="typed-key">{label}</span>
                    <span class="typed-val">{display}</span>
                </div>
            }
            .into_any()
        }

        FieldKind::DateTime => {
            let display = format_datetime(val);
            view! {
                <div class=format!("typed-field typed-field-date {}", css_field)>
                    <span class="typed-key">{label}</span>
                    <span class="typed-val typed-date">{display}</span>
                </div>
            }
            .into_any()
        }

        FieldKind::Price => {
            let display = scalar_to_string(val);
            view! {
                <div class=format!("typed-field typed-field-price {}", css_field)>
                    <span class="typed-key">{label}</span>
                    <span class="typed-val typed-price">{display}</span>
                </div>
            }
            .into_any()
        }

        FieldKind::Url => {
            let display = val.as_str().unwrap_or("-").to_string();
            view! {
                <div class=format!("typed-field typed-field-url {}", css_field)>
                    <span class="typed-key">{label}</span>
                    <span class="typed-val typed-url">{display}</span>
                </div>
            }
            .into_any()
        }

        FieldKind::Did => {
            let full = val.as_str().unwrap_or("-");
            // Truncate long DIDs for display
            let display = if full.len() > 32 {
                format!("{}...{}", &full[..16], &full[full.len() - 8..])
            } else {
                full.to_string()
            };
            view! {
                <div class=format!("typed-field typed-field-did {}", css_field)>
                    <span class="typed-key">{label}</span>
                    <span class="typed-val typed-did" title=full.to_string()>{display}</span>
                </div>
            }
            .into_any()
        }

        FieldKind::TypedObject { schema_type } => {
            let inner = dispatch_typed_or_generic(schema_type, val, depth + 1);
            view! {
                <div class=format!("typed-nested {}", css_field)>
                    {inner}
                </div>
            }
            .into_any()
        }

        FieldKind::List => {
            let items = val.as_array().cloned().unwrap_or_default();
            let capped = items.len() > 50;
            let rendered: Vec<_> = items
                .iter()
                .take(50)
                .map(|item| {
                    if let Some(obj) = item.as_object() {
                        if let Some(t) = extract_type(obj) {
                            return dispatch_typed_or_generic(&t, item, depth + 1);
                        }
                    }
                    render_fields(item, parent_css, depth + 1)
                })
                .collect();
            let more = if capped {
                let remaining = items.len() - 50;
                Some(view! {
                    <span class="typed-truncated">{format!("... {} more items", remaining)}</span>
                })
            } else {
                None
            };
            view! {
                <div class=format!("typed-list {}", css_field)>
                    {rendered}
                    {more}
                </div>
            }
            .into_any()
        }

        FieldKind::Object => {
            let inner = render_fields(val, parent_css, depth + 1);
            view! {
                <div class=format!("typed-nested {}", css_field)>
                    <span class="typed-key">{label}</span>
                    {inner}
                </div>
            }
            .into_any()
        }

        FieldKind::Empty => view! {}.into_any(),
    }
}

fn render_scalar_value(val: &Value) -> AnyView {
    let display = scalar_to_string(val);
    view! {
        <span class="typed-val">{display}</span>
    }
    .into_any()
}

fn render_truncated() -> AnyView {
    view! {
        <span class="typed-truncated">"\u{2026}"</span>
    }
    .into_any()
}
