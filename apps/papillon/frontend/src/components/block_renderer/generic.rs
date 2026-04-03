use leptos::prelude::*;
use serde_json::Value;
use std::sync::Arc;

use super::field_classify::{
    camel_to_kebab, classify_field, format_datetime, humanize_key, sanitize_css_class,
    scalar_to_string, schema_type_to_css, FieldKind,
};
use super::registry::RendererRegistry;
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
    TypedObjectHeader {
        schema_type: String,
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

    // Top-level template check
    if registry.get(schema_type).is_some() {
        entries.push(StreamEntry {
            path: String::new(),
            depth: 0,
            kind: EntryKind::TypedObjectHeader {
                schema_type: schema_type.to_string(),
                template_hit: true,
                content: Some(content.clone()),
            },
        });
        return entries;
    }

    // No template — flatten generically
    let css_type = schema_type_to_css(schema_type);
    entries.push(StreamEntry {
        path: String::new(),
        depth: 0,
        kind: EntryKind::TypedObjectHeader {
            schema_type: schema_type.to_string(),
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
                    FieldKind::TypedObject { ref schema_type } => {
                        if registry.get(schema_type).is_some() {
                            // Template hit — emit as leaf, skip children
                            entries.push(StreamEntry {
                                path: path.clone(),
                                depth,
                                kind: EntryKind::TypedObjectHeader {
                                    schema_type: schema_type.clone(),
                                    template_hit: true,
                                    content: Some(value),
                                },
                            });
                        } else {
                            // No template — flatten children
                            let child_css = schema_type_to_css(schema_type);
                            entries.push(StreamEntry {
                                path: path.clone(),
                                depth,
                                kind: EntryKind::TypedObjectHeader {
                                    schema_type: schema_type.clone(),
                                    template_hit: false,
                                    content: None,
                                },
                            });
                            stack.push(WorkItem::EmitTypedFooter {
                                schema_type: schema_type.clone(),
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
                    | FieldKind::Did => {
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
                ref schema_type,
                template_hit: true,
                ref content,
            } => {
                if let (Some(renderer), Some(val)) = (registry.get(schema_type), content.as_ref()) {
                    let rendered = renderer.render(val);
                    top_children(&mut view_stack).push(rendered);
                }
            }

            EntryKind::TypedObjectHeader {
                ref schema_type,
                template_hit: false,
                ..
            } => {
                let css_type = schema_type_to_css(schema_type);
                let css = format!("typed-generic typed-{}", css_type);
                let label = schema_type.clone();
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
                            let confirmed = web_sys::window()
                                .and_then(|w| {
                                    w.confirm_with_message(
                                        &format!("Activate PAP link?\n{}", url_inner),
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
        _ => view! { <span></span> }.into_any(),
    }
}
