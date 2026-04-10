use leptos::prelude::*;
use serde_json::Value;
use std::sync::Arc;

use super::field_classify::{
    camel_to_kebab, classify_field, format_datetime, humanize_key, sanitize_css_class,
    scalar_to_string, schema_type_to_css, FieldKind, FormInputType,
};
use super::registry::RendererRegistry;
use super::SettingsActionSink;
use crate::state::canvas::CanvasState;

/// Maximum items rendered per list before showing an overflow indicator.
const LIST_CAP: usize = 50;

/// Maximum total entries to prevent pathological inputs from freezing the UI.
const MAX_ENTRIES: usize = 2_000;

// ── Stream entry types ──────────────────────────────────────────────────────

/// A single renderable element produced by flattening a JSON-LD value tree.
/// Entries are ordered depth-first and carry enough context for independent rendering.
pub struct StreamEntry {
    #[allow(dead_code)]
    pub path: String,
    #[allow(dead_code)]
    pub depth: u16,
    pub kind: EntryKind,
}

/// What a stream entry renders as.
pub enum EntryKind {
    /// Section header for a typed object. If `template_hit` is true, the entry
    /// carries the full Value and children are skipped (the template renders them).
    ///
    /// `schema_types` preserves the full `@type` array from the source JSON-LD.
    /// The first entry is the primary (most-specific) type used for display and
    /// CSS; all entries are tried in order when dispatching to the registry.
    /// This is what makes composite types work: `["FlightReservation", "Reservation"]`
    /// falls back to `Reservation`'s renderer if no specific one is registered.
    TypedObjectHeader {
        schema_types: Vec<String>,
        template_hit: bool,
        content: Option<Value>,
    },
    /// Closing marker for a typed object section.
    TypedObjectFooter {
        #[allow(dead_code)]
        schema_type: String,
    },
    /// Section header for an untyped nested object.
    ObjectHeader { key: String },
    /// Closing marker for an untyped object section.
    ObjectFooter,
    /// Section header for a list.
    ListHeader {
        #[allow(dead_code)]
        key: String,
        #[allow(dead_code)]
        total_items: usize,
        #[allow(dead_code)]
        rendered_items: usize,
    },
    /// Closing marker for a list section.
    ListFooter,
    /// A leaf field — scalar, date, price, URL, or DID.
    Field {
        key: String,
        value: Value,
        field_kind: FieldKind,
        parent_css: String,
    },
    /// Visible indicator that a list was capped.
    ListOverflow { remaining: usize },
}

// ── Work items for the iterative traversal stack ────────────────────────────

enum WorkItem {
    Visit {
        key: String,
        value: Value,
        path: String,
        depth: u16,
        parent_css: String,
    },
    EmitTypedFooter {
        schema_type: String,
    },
    EmitObjectFooter,
    EmitListFooter,
    EmitOverflow {
        remaining: usize,
        depth: u16,
    },
}

// ── Flatten: iterative DFS producing a stream of entries ────────────────────

/// Flatten a JSON-LD value tree into a linear sequence of renderable entries.
/// Uses an explicit stack — no recursion, no depth limit, no silent truncation.
pub fn flatten_to_entries(
    schema_type: &str,
    content: &Value,
    registry: &Arc<RendererRegistry>,
) -> Vec<StreamEntry> {
    let mut entries = Vec::with_capacity(64);
    let mut stack: Vec<WorkItem> = Vec::with_capacity(32);

    // Top-level type list: pull all types from the content's own @type array,
    // falling back to the caller-supplied schema_type. This handles composite
    // roots like { "@type": ["FlightReservation", "Reservation"], ... }.
    let root_types: Vec<String> = content
        .as_object()
        .map(|obj| {
            use super::field_classify::extract_types;
            let mut ts = extract_types(obj);
            if ts.is_empty() {
                ts.push(schema_type.to_string());
            }
            ts
        })
        .unwrap_or_else(|| vec![schema_type.to_string()]);

    // Template check: try each type in order so composite types fall back
    // to the most-specific registered renderer available.
    let template_hit = root_types.iter().any(|t| registry.get(t).is_some());
    if template_hit {
        entries.push(StreamEntry {
            path: String::new(),
            depth: 0,
            kind: EntryKind::TypedObjectHeader {
                schema_types: root_types,
                template_hit: true,
                content: Some(content.clone()),
            },
        });
        return entries;
    }

    // No template — flatten generically using the primary (most-specific) type for CSS.
    let primary_type = root_types
        .first()
        .map(|s| s.as_str())
        .unwrap_or(schema_type);
    let css_type = schema_type_to_css(primary_type);
    entries.push(StreamEntry {
        path: String::new(),
        depth: 0,
        kind: EntryKind::TypedObjectHeader {
            schema_types: root_types,
            template_hit: false,
            content: None,
        },
    });

    // Seed stack with root fields (reversed for correct DFS order)
    if let Some(obj) = content.as_object() {
        stack.push(WorkItem::EmitTypedFooter {
            schema_type: schema_type.to_string(),
        });
        push_object_fields(&mut stack, obj, "", 1, &css_type);
    } else {
        // Bare non-object root value
        entries.push(StreamEntry {
            path: String::new(),
            depth: 1,
            kind: EntryKind::Field {
                key: String::new(),
                value: content.clone(),
                field_kind: classify_field("", content),
                parent_css: css_type,
            },
        });
        entries.push(StreamEntry {
            path: String::new(),
            depth: 0,
            kind: EntryKind::TypedObjectFooter {
                schema_type: schema_type.to_string(),
            },
        });
        return entries;
    }

    // Main loop
    while let Some(item) = stack.pop() {
        if entries.len() >= MAX_ENTRIES {
            entries.push(StreamEntry {
                path: String::new(),
                depth: 0,
                kind: EntryKind::ListOverflow { remaining: 0 },
            });
            break;
        }

        match item {
            WorkItem::EmitTypedFooter { schema_type } => {
                entries.push(StreamEntry {
                    path: String::new(),
                    depth: 0,
                    kind: EntryKind::TypedObjectFooter { schema_type },
                });
            }
            WorkItem::EmitObjectFooter => {
                entries.push(StreamEntry {
                    path: String::new(),
                    depth: 0,
                    kind: EntryKind::ObjectFooter,
                });
            }
            WorkItem::EmitListFooter => {
                entries.push(StreamEntry {
                    path: String::new(),
                    depth: 0,
                    kind: EntryKind::ListFooter,
                });
            }
            WorkItem::EmitOverflow { remaining, depth } => {
                entries.push(StreamEntry {
                    path: String::new(),
                    depth,
                    kind: EntryKind::ListOverflow { remaining },
                });
            }
            WorkItem::Visit {
                key,
                value,
                path,
                depth,
                parent_css,
            } => {
                let kind = classify_field(&key, &value);
                match kind {
                    FieldKind::TypedObject { ref schema_types } => {
                        // Try each type in order — composite types fall back to the
                        // most-specific registered renderer that exists.
                        let hit = schema_types.iter().any(|t| registry.get(t).is_some());
                        let primary = schema_types
                            .first()
                            .map(|s| s.as_str())
                            .unwrap_or_default();
                        if hit {
                            // Template hit — emit as leaf, skip children
                            entries.push(StreamEntry {
                                path: path.clone(),
                                depth,
                                kind: EntryKind::TypedObjectHeader {
                                    schema_types: schema_types.clone(),
                                    template_hit: true,
                                    content: Some(value),
                                },
                            });
                        } else {
                            // No template — flatten children
                            let child_css = schema_type_to_css(primary);
                            entries.push(StreamEntry {
                                path: path.clone(),
                                depth,
                                kind: EntryKind::TypedObjectHeader {
                                    schema_types: schema_types.clone(),
                                    template_hit: false,
                                    content: None,
                                },
                            });
                            stack.push(WorkItem::EmitTypedFooter {
                                schema_type: primary.to_string(),
                            });
                            if let Some(obj) = value.as_object() {
                                push_object_fields(&mut stack, obj, &path, depth + 1, &child_css);
                            }
                        }
                    }
                    FieldKind::Object => {
                        entries.push(StreamEntry {
                            path: path.clone(),
                            depth,
                            kind: EntryKind::ObjectHeader { key: key.clone() },
                        });
                        stack.push(WorkItem::EmitObjectFooter);
                        if let Some(obj) = value.as_object() {
                            push_object_fields(&mut stack, obj, &path, depth + 1, &parent_css);
                        }
                    }
                    FieldKind::List => {
                        let items = value.as_array().cloned().unwrap_or_default();
                        let total = items.len();
                        let capped = total.min(LIST_CAP);

                        entries.push(StreamEntry {
                            path: path.clone(),
                            depth,
                            kind: EntryKind::ListHeader {
                                key: key.clone(),
                                total_items: total,
                                rendered_items: capped,
                            },
                        });

                        // Push in reverse order for correct DFS: footer, overflow, items
                        stack.push(WorkItem::EmitListFooter);
                        if total > LIST_CAP {
                            stack.push(WorkItem::EmitOverflow {
                                remaining: total - LIST_CAP,
                                depth: depth + 1,
                            });
                        }
                        for (i, item) in items.iter().take(capped).enumerate().rev() {
                            stack.push(WorkItem::Visit {
                                key: format!("[{}]", i),
                                value: item.clone(),
                                path: format!("{}[{}]", path, i),
                                depth: depth + 1,
                                parent_css: parent_css.clone(),
                            });
                        }
                    }
                    FieldKind::Scalar
                    | FieldKind::DateTime
                    | FieldKind::Price
                    | FieldKind::ExternalUrl
                    | FieldKind::PapLink
                    | FieldKind::Did
                    | FieldKind::FormField { .. } => {
                        entries.push(StreamEntry {
                            path,
                            depth,
                            kind: EntryKind::Field {
                                key,
                                value,
                                field_kind: kind,
                                parent_css,
                            },
                        });
                    }
                    FieldKind::Empty => {}
                }
            }
        }
    }

    entries
}

/// Push an object's non-@ fields onto the work stack in reverse order.
fn push_object_fields(
    stack: &mut Vec<WorkItem>,
    obj: &serde_json::Map<String, Value>,
    parent_path: &str,
    depth: u16,
    parent_css: &str,
) {
    let fields: Vec<_> = obj.iter().filter(|(k, _)| !k.starts_with('@')).collect();
    for (key, val) in fields.iter().rev() {
        let path = if parent_path.is_empty() {
            key.to_string()
        } else {
            format!("{}.{}", parent_path, key)
        };
        stack.push(WorkItem::Visit {
            key: key.to_string(),
            value: (*val).clone(),
            path,
            depth,
            parent_css: parent_css.to_string(),
        });
    }
}

// ── Render: turn flat entries into Leptos views ─────────────────────────────

/// Render a flat stream of entries into a single Leptos view.
/// Uses a view stack to build nested DOM structure from header/footer pairs.
pub fn render_stream(entries: Vec<StreamEntry>, registry: &Arc<RendererRegistry>) -> AnyView {
    let mut view_stack: Vec<(String, Vec<AnyView>)> = vec![("root".to_string(), Vec::new())];

    for entry in entries {
        match entry.kind {
            EntryKind::TypedObjectHeader {
                ref schema_types,
                template_hit: true,
                ref content,
            } => {
                // Try each schema type in order — composite types dispatch to the
                // first registered renderer, giving specific types priority over general ones.
                let renderer = schema_types.iter().find_map(|t| registry.get(t));
                if let (Some(renderer), Some(val)) = (renderer, content.as_ref()) {
                    let rendered = renderer.render(val);
                    top_children(&mut view_stack).push(rendered);
                }
            }

            EntryKind::TypedObjectHeader {
                ref schema_types,
                template_hit: false,
                ..
            } => {
                let primary = schema_types.first().map(|s| s.as_str()).unwrap_or_default();
                let css_type = schema_type_to_css(primary);
                let css = format!("typed-generic typed-{}", css_type);
                // Show all types in the label for composite objects
                let label = if schema_types.len() > 1 {
                    schema_types.join(" · ")
                } else {
                    primary.to_string()
                };
                view_stack.push((css, Vec::new()));
                top_children(&mut view_stack)
                    .push(view! { <span class="typed-label">{label}</span> }.into_any());
            }

            EntryKind::TypedObjectFooter { .. } => {
                pop_and_wrap(&mut view_stack);
            }

            EntryKind::ObjectHeader { ref key } => {
                let label = humanize_key(key);
                let css = "typed-nested".to_string();
                view_stack.push((css, Vec::new()));
                top_children(&mut view_stack)
                    .push(view! { <span class="typed-key">{label}</span> }.into_any());
            }

            EntryKind::ObjectFooter => {
                pop_and_wrap(&mut view_stack);
            }

            EntryKind::ListHeader { .. } => {
                let css = "typed-list".to_string();
                view_stack.push((css, Vec::new()));
            }

            EntryKind::ListFooter => {
                pop_and_wrap(&mut view_stack);
            }

            EntryKind::Field {
                ref key,
                ref value,
                ref field_kind,
                ref parent_css,
            } => {
                let rendered = render_leaf_field(key, value, field_kind, parent_css);
                top_children(&mut view_stack).push(rendered);
            }

            EntryKind::ListOverflow { remaining } => {
                let text = if remaining == 0 {
                    "Content limit reached".to_string()
                } else {
                    format!("{} more items", remaining)
                };
                top_children(&mut view_stack)
                    .push(view! { <span class="typed-truncated">{text}</span> }.into_any());
            }
        }
    }

    // Collect root children
    let (_, root_children) = view_stack
        .pop()
        .unwrap_or_else(|| ("root".to_string(), Vec::new()));
    view! {
        <div class="typed-fields">{root_children}</div>
    }
    .into_any()
}

/// Pop the top frame, wrap its children in a div, and append to the parent frame.
fn pop_and_wrap(stack: &mut Vec<(String, Vec<AnyView>)>) {
    if stack.len() > 1 {
        let (css, children) = stack.pop().unwrap();
        let wrapped = view! {
            <div class=css>{children}</div>
        }
        .into_any();
        top_children(stack).push(wrapped);
    }
}

/// Get mutable reference to the top frame's children.
fn top_children(stack: &mut [(String, Vec<AnyView>)]) -> &mut Vec<AnyView> {
    &mut stack.last_mut().unwrap().1
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_registry() -> Arc<RendererRegistry> {
        Arc::new(RendererRegistry::new())
    }

    fn registry_with_type(schema_type: &str) -> Arc<RendererRegistry> {
        use papillon_shared::types::{LayoutConfig, Template, TemplateConfig};
        let r = Arc::new(RendererRegistry::new());
        r.load_from_templates(vec![Template {
            id: "t".to_string(),
            template_name: "T".to_string(),
            schema_type: schema_type.to_string(),
            principal_did: None,
            agent_did: None,
            template_config: TemplateConfig {
                version: 1,
                layout: LayoutConfig {
                    r#type: "grid".to_string(),
                    columns: Some(1),
                    direction: None,
                    spacing: None,
                },
                fields: vec![],
            },
            version: 1,
            enabled: true,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            created_by: None,
        }]);
        r
    }

    // ── Match helpers ─────────────────────────────────────────────────────────

    fn is_typed_header(e: &StreamEntry) -> bool {
        matches!(e.kind, EntryKind::TypedObjectHeader { .. })
    }
    fn is_typed_footer(e: &StreamEntry) -> bool {
        matches!(e.kind, EntryKind::TypedObjectFooter { .. })
    }
    fn is_field(e: &StreamEntry) -> bool {
        matches!(e.kind, EntryKind::Field { .. })
    }
    fn is_list_header(e: &StreamEntry) -> bool {
        matches!(e.kind, EntryKind::ListHeader { .. })
    }
    fn is_list_footer(e: &StreamEntry) -> bool {
        matches!(e.kind, EntryKind::ListFooter)
    }
    fn is_list_overflow(e: &StreamEntry) -> bool {
        matches!(e.kind, EntryKind::ListOverflow { .. })
    }

    fn header_types(e: &StreamEntry) -> Vec<String> {
        match &e.kind {
            EntryKind::TypedObjectHeader { schema_types, .. } => schema_types.clone(),
            _ => panic!("expected TypedObjectHeader"),
        }
    }
    fn header_template_hit(e: &StreamEntry) -> bool {
        match &e.kind {
            EntryKind::TypedObjectHeader { template_hit, .. } => *template_hit,
            _ => panic!("expected TypedObjectHeader"),
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn single_field_produces_header_field_footer() {
        let entries = flatten_to_entries("Airport", &serde_json::json!({ "name": "JFK" }), &empty_registry());
        assert_eq!(entries.len(), 3);
        assert!(is_typed_header(&entries[0]));
        assert!(is_field(&entries[1]));
        assert!(is_typed_footer(&entries[2]));
    }

    #[test]
    fn at_prefixed_keys_are_skipped() {
        let entries = flatten_to_entries(
            "Airport",
            &serde_json::json!({ "@type": "Airport", "@context": "https://schema.org", "name": "JFK" }),
            &empty_registry(),
        );
        let field_count = entries.iter().filter(|e| is_field(e)).count();
        assert_eq!(field_count, 1, "@type and @context should be skipped");
    }

    #[test]
    fn no_template_header_has_template_hit_false() {
        let entries = flatten_to_entries(
            "Thing",
            &serde_json::json!({ "title": "hello" }),
            &empty_registry(),
        );
        assert!(!header_template_hit(&entries[0]));
    }

    #[test]
    fn composite_at_type_array_is_preserved_in_header() {
        let entries = flatten_to_entries(
            "FlightReservation",
            &serde_json::json!({
                "@type": ["FlightReservation", "Reservation"],
                "departureAirport": "JFK"
            }),
            &empty_registry(),
        );
        let types = header_types(&entries[0]);
        assert_eq!(types, vec!["FlightReservation", "Reservation"]);
    }

    #[test]
    fn template_hit_produces_single_entry_with_content() {
        let registry = registry_with_type("Recipe");
        let content = serde_json::json!({ "@type": "Recipe", "name": "Pasta" });
        let entries = flatten_to_entries("Recipe", &content, &registry);

        assert_eq!(entries.len(), 1, "template hit short-circuits all children");
        assert!(header_template_hit(&entries[0]));
        assert!(
            matches!(&entries[0].kind, EntryKind::TypedObjectHeader { content: Some(_), .. }),
            "template hit entry must carry the content Value"
        );
    }

    #[test]
    fn composite_type_template_hit_on_second_type() {
        // Only "Reservation" is registered; "FlightReservation" is not.
        // The renderer should still detect a hit because the second type matches.
        let registry = registry_with_type("Reservation");
        let content = serde_json::json!({
            "@type": ["FlightReservation", "Reservation"],
            "departureAirport": "JFK"
        });
        let entries = flatten_to_entries("FlightReservation", &content, &registry);

        assert_eq!(entries.len(), 1, "composite type fallback should also short-circuit");
        assert!(header_template_hit(&entries[0]));
    }

    #[test]
    fn list_field_produces_header_items_footer() {
        let entries = flatten_to_entries(
            "Event",
            &serde_json::json!({ "tags": ["travel", "flights", "booking"] }),
            &empty_registry(),
        );
        let lh_idx = entries.iter().position(|e| is_list_header(e)).expect("ListHeader");
        let lf_idx = entries.iter().position(|e| is_list_footer(e)).expect("ListFooter");
        let field_count = entries[lh_idx + 1..lf_idx].iter().filter(|e| is_field(e)).count();
        assert_eq!(field_count, 3);
    }

    #[test]
    fn list_over_50_items_is_capped_with_overflow() {
        let items: Vec<serde_json::Value> =
            (0..75).map(|i| serde_json::json!(format!("item-{}", i))).collect();
        let entries = flatten_to_entries(
            "Thing",
            &serde_json::json!({ "tags": items }),
            &empty_registry(),
        );

        assert!(entries.iter().any(|e| is_list_overflow(e)), "overflow entry expected");

        let lh_idx = entries.iter().position(|e| is_list_header(e)).unwrap();
        let lf_idx = entries.iter().position(|e| is_list_footer(e)).unwrap();
        let rendered = entries[lh_idx + 1..lf_idx].iter().filter(|e| is_field(e)).count();
        assert_eq!(rendered, 50, "exactly LIST_CAP items rendered");
    }

    #[test]
    fn nested_typed_object_emits_two_headers() {
        let entries = flatten_to_entries(
            "FlightReservation",
            &serde_json::json!({
                "reservationFor": {
                    "@type": "Flight",
                    "flightNumber": "AA100"
                }
            }),
            &empty_registry(),
        );
        let header_count = entries.iter().filter(|e| is_typed_header(e)).count();
        assert_eq!(header_count, 2, "outer + inner TypedObjectHeader");
    }

    #[test]
    fn pvs_object_emits_as_leaf_field_not_recursed() {
        // PropertyValueSpecification objects should be emitted as a single
        // Field entry (FormField kind), not recursed into like TypedObject.
        let content = serde_json::json!({
            "setting": {
                "@type": "PropertyValueSpecification",
                "valueName": "safe_search",
                "name": "Safe Search",
                "defaultValue": true
            }
        });
        let entries = flatten_to_entries("Thing", &content, &empty_registry());
        // Header + Field(FormField) + Footer = 3 entries
        assert_eq!(entries.len(), 3);
        assert!(is_typed_header(&entries[0]));
        assert!(is_field(&entries[1]));
        assert!(is_typed_footer(&entries[2]));
        // Verify it's a FormField kind, not TypedObject
        if let EntryKind::Field { ref field_kind, .. } = entries[1].kind {
            assert!(
                matches!(field_kind, FieldKind::FormField { .. }),
                "PVS should classify as FormField, got {:?}",
                field_kind
            );
        } else {
            panic!("expected Field entry");
        }
    }

    #[test]
    fn fallback_to_caller_type_when_at_type_absent() {
        let entries = flatten_to_entries(
            "CustomType",
            &serde_json::json!({ "name": "no @type key" }),
            &empty_registry(),
        );
        let types = header_types(&entries[0]);
        assert_eq!(types, vec!["CustomType"]);
    }
}

// ── Leaf field rendering ────────────────────────────────────────────────────

/// Render a single leaf field based on its classified kind.
fn render_leaf_field(key: &str, val: &Value, kind: &FieldKind, parent_css: &str) -> AnyView {
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
        FieldKind::ExternalUrl => {
            let display = val.as_str().unwrap_or("-").to_string();
            view! {
                <div class=format!("typed-field typed-field-url {}", css_field)>
                    <span class="typed-key">{label}</span>
                    <span class="typed-val typed-url">{display}</span>
                </div>
            }
            .into_any()
        }
        FieldKind::PapLink => {
            let url = val.as_str().unwrap_or("").to_string();
            // Split scheme from body for visual treatment
            let (scheme, body) = if let Some(rest) = url.strip_prefix("pap+https://") {
                ("pap+https://", rest.to_string())
            } else if let Some(rest) = url.strip_prefix("pap+wss://") {
                ("pap+wss://", rest.to_string())
            } else if let Some(rest) = url.strip_prefix("pap://") {
                ("pap://", rest.to_string())
            } else {
                ("", url.clone())
            };
            let scheme = scheme.to_string();
            let canvas_state = use_context::<CanvasState>();
            let url_for_click = url.clone();
            view! {
                <div class=format!("typed-field typed-field-pap-link {}", css_field)>
                    <span class="typed-key">{label}</span>
                    <button
                        class="pap-link"
                        title=url.clone()
                        on:click=move |_| {
                            // All block-renderer pap:// links are agent-rendered.
                            // Require explicit principal confirmation before dispatch.
                            // submit_agent_link enforces LinkOrigin::Agent so
                            // special authorities (receipt/canvas/settings) are blocked.
                            let url_inner = url_for_click.clone();
                            // Strip control characters from the URL before embedding
                            // it in the confirmation dialog. Without this, an agent
                            // could inject newlines to rewrite the dialog text shown
                            // to the principal.
                            let safe_url: String =
                                url_inner.chars().filter(|c| !c.is_control()).collect();
                            let confirmed = web_sys::window()
                                .and_then(|w| {
                                    w.confirm_with_message(
                                        &format!("Activate PAP link?\n{}", safe_url),
                                    )
                                    .ok()
                                })
                                .unwrap_or(false);
                            if confirmed {
                                if let Some(cs) = canvas_state {
                                    cs.submit_agent_link(url_inner);
                                }
                            }
                        }
                    >
                        <span class="pap-scheme">{scheme}</span>
                        <span class="pap-body">{body}</span>
                    </button>
                </div>
            }
            .into_any()
        }
        FieldKind::Did => {
            let full = val.as_str().unwrap_or("-");
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
        FieldKind::FormField {
            input_type,
            value_name,
        } => render_form_field(val, input_type, value_name, &css_field),
        _ => view! { <span></span> }.into_any(),
    }
}

/// Render a PropertyValueSpecification as an interactive form input.
///
/// The full PVS object is passed as `val`. The input widget is chosen by
/// `FormInputType` (derived from the spec's constraints). When a
/// `SettingsActionSink` context is present, changes emit `SettingsAction`
/// events. When absent, the field renders as read-only display.
fn render_form_field(
    val: &Value,
    input_type: &FormInputType,
    value_name: &str,
    css_field: &str,
) -> AnyView {
    let name = val
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| val.get("valueName").and_then(|v| v.as_str()).unwrap_or("Setting"));
    let description = val
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let current = val
        .get("value")
        .or(val.get("defaultValue"))
        .cloned()
        .unwrap_or(Value::Null);

    let label = name.to_string();
    let css = format!("typed-field typed-field-form {}", css_field);

    // Check if we have an action sink (interactive) or not (read-only)
    let sink = use_context::<SettingsActionSink>();
    let vn = value_name.to_string();

    match input_type {
        FormInputType::Toggle => {
            let checked = current.as_bool().unwrap_or(false);
            let checked_sig = RwSignal::new(checked);
            let vn_change = vn.clone();
            let sink_change = sink.clone();
            view! {
                <div class=css>
                    <label class="typed-form-toggle">
                        <input
                            type="checkbox"
                            prop:checked=move || checked_sig.get()
                            prop:disabled=move || sink_change.is_none()
                            on:change=move |ev| {
                                use web_sys::HtmlInputElement;
                                use wasm_bindgen::JsCast;
                                let new_val = ev.target()
                                    .and_then(|t| t.dyn_into::<HtmlInputElement>().ok())
                                    .map(|el| el.checked())
                                    .unwrap_or(false);
                                checked_sig.set(new_val);
                                if let Some(ref s) = sink {
                                    s.0.run(super::SettingsAction {
                                        target: "papillon".into(),
                                        value_name: vn_change.clone(),
                                        new_value: Value::Bool(new_val),
                                    });
                                }
                            }
                        />
                        <span class="typed-form-label">{label}</span>
                    </label>
                    <p class="typed-form-description">{description}</p>
                </div>
            }
            .into_any()
        }
        FormInputType::Number => {
            let num_val = current.as_f64().unwrap_or(0.0);
            let num_sig = RwSignal::new(num_val);
            let min = val
                .get("minValue")
                .and_then(|v| v.as_f64());
            let max = val
                .get("maxValue")
                .and_then(|v| v.as_f64());
            let step = val
                .get("stepValue")
                .and_then(|v| v.as_f64())
                .unwrap_or(1.0);
            let vn_change = vn.clone();
            let sink_change = sink.clone();
            view! {
                <div class=css>
                    <span class="typed-form-label">{label}</span>
                    <input
                        type="number"
                        prop:value=move || num_sig.get().to_string()
                        prop:disabled=move || sink_change.is_none()
                        min=min.map(|v| v.to_string())
                        max=max.map(|v| v.to_string())
                        step=step.to_string()
                        on:change=move |ev| {
                            let raw = event_target_value(&ev);
                            if let Ok(v) = raw.parse::<f64>() {
                                num_sig.set(v);
                                if let Some(ref s) = sink {
                                    // Prefer integer if step is whole
                                    let json_val = if step.fract() == 0.0 && v.fract() == 0.0 {
                                        serde_json::json!(v as i64)
                                    } else {
                                        serde_json::json!(v)
                                    };
                                    s.0.run(super::SettingsAction {
                                        target: "papillon".into(),
                                        value_name: vn_change.clone(),
                                        new_value: json_val,
                                    });
                                }
                            }
                        }
                    />
                    <p class="typed-form-description">{description}</p>
                </div>
            }
            .into_any()
        }
        FormInputType::Select => {
            let pattern = val
                .get("valuePattern")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let options: Vec<String> = pattern.split('|').map(|s| s.trim().to_string()).collect();
            let current_str = current.as_str().unwrap_or("").to_string();
            let selected = RwSignal::new(current_str);
            let vn_change = vn.clone();
            let sink_change = sink.clone();
            view! {
                <div class=css>
                    <span class="typed-form-label">{label}</span>
                    <select
                        class="typed-form-select"
                        prop:value=move || selected.get()
                        prop:disabled=move || sink_change.is_none()
                        on:change=move |ev| {
                            let new_val = event_target_value(&ev);
                            selected.set(new_val.clone());
                            if let Some(ref s) = sink {
                                s.0.run(super::SettingsAction {
                                    target: "papillon".into(),
                                    value_name: vn_change.clone(),
                                    new_value: Value::String(new_val),
                                });
                            }
                        }
                    >
                        <For
                            each=move || options.clone()
                            key=|opt| opt.clone()
                            children=move |opt: String| {
                                let val = opt.clone();
                                view! { <option value=val>{opt}</option> }
                            }
                        />
                    </select>
                    <p class="typed-form-description">{description}</p>
                </div>
            }
            .into_any()
        }
        FormInputType::Text => {
            let current_str = current.as_str().unwrap_or("").to_string();
            let text_sig = RwSignal::new(current_str);
            let vn_change = vn.clone();
            let sink_change = sink.clone();
            view! {
                <div class=css>
                    <span class="typed-form-label">{label}</span>
                    <input
                        type="text"
                        class="typed-form-text"
                        prop:value=move || text_sig.get()
                        prop:disabled=move || sink_change.is_none()
                        on:change=move |ev| {
                            let new_val = event_target_value(&ev);
                            text_sig.set(new_val.clone());
                            if let Some(ref s) = sink {
                                s.0.run(super::SettingsAction {
                                    target: "papillon".into(),
                                    value_name: vn_change.clone(),
                                    new_value: Value::String(new_val),
                                });
                            }
                        }
                    />
                    <p class="typed-form-description">{description}</p>
                </div>
            }
            .into_any()
        }
    }
}
