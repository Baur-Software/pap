use leptos::prelude::*;

use papillion_shared::types::{TemplateConfig, LayoutConfig, FieldMapping, Condition};

#[component]
pub fn TemplateBuilder(
    is_open: RwSignal<bool>,
    on_complete: Callback<TemplateConfig>,
) -> impl IntoView {
    // Layout state
    let layout_type = RwSignal::new("grid".to_string());
    let layout_columns = RwSignal::new(2);
    let layout_direction = RwSignal::new("row".to_string());
    let layout_spacing = RwSignal::new("md".to_string());

    // Fields state
    let fields = RwSignal::new(vec![]);
    let current_field_path = RwSignal::new(String::new());
    let current_field_label = RwSignal::new(String::new());
    let current_field_display = RwSignal::new("text".to_string());
    let current_field_has_condition = RwSignal::new(false);
    let current_field_condition_field = RwSignal::new(String::new());
    let current_field_condition_op = RwSignal::new("exists".to_string());

    // Preview state
    let preview_json = RwSignal::new(String::new());
    let preview_error = RwSignal::new(None::<String>);

    let update_preview = move || {
        let config = TemplateConfig {
            version: 1,
            layout: LayoutConfig {
                r#type: layout_type.get(),
                columns: if layout_type.get() == "grid" {
                    Some(layout_columns.get())
                } else {
                    None
                },
                direction: if layout_type.get() == "flex" {
                    Some(layout_direction.get())
                } else {
                    None
                },
                spacing: Some(layout_spacing.get()),
            },
            fields: fields.get(),
        };

        match serde_json::to_string_pretty(&config) {
            Ok(json) => {
                preview_json.set(json);
                preview_error.set(None);
            }
            Err(e) => {
                preview_error.set(Some(e.to_string()));
            }
        }
    };

    let add_field = move |_| {
        let path = current_field_path.get();
        let label = current_field_label.get();
        let display = current_field_display.get();

        if path.is_empty() {
            preview_error.set(Some("Field path is required".to_string()));
            return;
        }

        let condition = if current_field_has_condition.get() {
            let cond_field = current_field_condition_field.get();
            if cond_field.is_empty() {
                preview_error.set(Some("Condition field is required".to_string()));
                return;
            }
            Some(Condition {
                field: cond_field,
                op: current_field_condition_op.get(),
                value: None,
            })
        } else {
            None
        };

        let field = FieldMapping {
            path,
            label: if label.is_empty() { None } else { Some(label) },
            display,
            condition,
            style: None,
        };

        let mut new_fields = fields.get();
        new_fields.push(field);
        fields.set(new_fields);

        // Clear form
        current_field_path.set(String::new());
        current_field_label.set(String::new());
        current_field_display.set("text".to_string());
        current_field_has_condition.set(false);
        current_field_condition_field.set(String::new());

        update_preview();
    };

    let remove_field = move |index: usize| {
        let mut new_fields = fields.get();
        if index < new_fields.len() {
            new_fields.remove(index);
            fields.set(new_fields);
            update_preview();
        }
    };

    let complete = move |_| {
        let config = TemplateConfig {
            version: 1,
            layout: LayoutConfig {
                r#type: layout_type.get(),
                columns: if layout_type.get() == "grid" {
                    Some(layout_columns.get())
                } else {
                    None
                },
                direction: if layout_type.get() == "flex" {
                    Some(layout_direction.get())
                } else {
                    None
                },
                spacing: Some(layout_spacing.get()),
            },
            fields: fields.get(),
        };

        if let Err(e) = config.validate() {
            preview_error.set(Some(e));
            return;
        }

        on_complete.run(config);
        is_open.set(false);
    };

    view! {
        <Show when=move || is_open.get()>
            <div style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.5); display: flex; align-items: center; justify-content: center; z-index: 1001;">
                <div style="background: var(--bg-1); border: 1px solid var(--border); border-radius: 8px; padding: 20px; max-width: 900px; width: 95%; max-height: 90vh; overflow-y: auto; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15); display: flex; flex-direction: column; gap: 16px;">
                    <h3 style="font-size: 16px; font-weight: 600;">
                        "Template Builder"
                    </h3>

                    <div style="display: flex; gap: 16px;">
                        <div style="flex: 1; display: flex; flex-direction: column; gap: 12px;">
                            <div>
                                <label style="font-size: 12px; font-weight: 500; color: var(--text-2); display: block; margin-bottom: 4px;">
                                    "Layout Type"
                                </label>
                                <select
                                    prop:value=move || layout_type.get()
                                    on:change=move |ev| {
                                        layout_type.set(event_target_value(&ev));
                                        update_preview();
                                    }
                                    style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px; padding: 8px; color: var(--text-1); font-size: 13px;"
                                >
                                    <option value="grid">"Grid"</option>
                                    <option value="flex">"Flex"</option>
                                </select>
                            </div>

                            <Show when=move || layout_type.get() == "grid">
                                <div>
                                    <label style="font-size: 12px; font-weight: 500; color: var(--text-2); display: block; margin-bottom: 4px;">
                                        "Columns"
                                    </label>
                                    <input
                                        type="number"
                                        min="1"
                                        max="12"
                                        prop:value=move || layout_columns.get().to_string()
                                        on:input=move |ev| {
                                            if let Ok(n) = event_target_value(&ev).parse::<i32>() {
                                                layout_columns.set(n);
                                                update_preview();
                                            }
                                        }
                                        style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px; padding: 8px; color: var(--text-1); font-size: 13px;"
                                    />
                                </div>
                            </Show>

                            <Show when=move || layout_type.get() == "flex">
                                <div>
                                    <label style="font-size: 12px; font-weight: 500; color: var(--text-2); display: block; margin-bottom: 4px;">
                                        "Direction"
                                    </label>
                                    <select
                                        prop:value=move || layout_direction.get()
                                        on:change=move |ev| {
                                            layout_direction.set(event_target_value(&ev));
                                            update_preview();
                                        }
                                        style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px; padding: 8px; color: var(--text-1); font-size: 13px;"
                                    >
                                        <option value="row">"Row"</option>
                                        <option value="column">"Column"</option>
                                    </select>
                                </div>
                            </Show>

                            <div>
                                <label style="font-size: 12px; font-weight: 500; color: var(--text-2); display: block; margin-bottom: 4px;">
                                    "Spacing"
                                </label>
                                <select
                                    prop:value=move || layout_spacing.get()
                                    on:change=move |ev| {
                                        layout_spacing.set(event_target_value(&ev));
                                        update_preview();
                                    }
                                    style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px; padding: 8px; color: var(--text-1); font-size: 13px;"
                                >
                                    <option value="sm">"Small"</option>
                                    <option value="md">"Medium"</option>
                                    <option value="lg">"Large"</option>
                                </select>
                            </div>

                            <hr style="border: none; border-top: 1px solid var(--border); margin: 8px 0;" />

                            <h4 style="font-size: 13px; font-weight: 600; margin-top: 8px;">
                                "Add Field"
                            </h4>

                            <div>
                                <label style="font-size: 12px; font-weight: 500; color: var(--text-2); display: block; margin-bottom: 4px;">
                                    "Path (required)"
                                </label>
                                <input
                                    type="text"
                                    placeholder="e.g., name, offers.price, results.0.title"
                                    prop:value=move || current_field_path.get()
                                    on:input=move |ev| current_field_path.set(event_target_value(&ev))
                                    style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px; padding: 8px; color: var(--text-1); font-size: 13px;"
                                />
                            </div>

                            <div>
                                <label style="font-size: 12px; font-weight: 500; color: var(--text-2); display: block; margin-bottom: 4px;">
                                    "Label"
                                </label>
                                <input
                                    type="text"
                                    placeholder="Optional display label"
                                    prop:value=move || current_field_label.get()
                                    on:input=move |ev| current_field_label.set(event_target_value(&ev))
                                    style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px; padding: 8px; color: var(--text-1); font-size: 13px;"
                                />
                            </div>

                            <div>
                                <label style="font-size: 12px; font-weight: 500; color: var(--text-2); display: block; margin-bottom: 4px;">
                                    "Display Type"
                                </label>
                                <select
                                    prop:value=move || current_field_display.get()
                                    on:change=move |ev| current_field_display.set(event_target_value(&ev))
                                    style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px; padding: 8px; color: var(--text-1); font-size: 13px;"
                                >
                                    <option value="text">"Text"</option>
                                    <option value="title">"Title"</option>
                                    <option value="price">"Price"</option>
                                    <option value="date">"Date"</option>
                                    <option value="url">"URL"</option>
                                </select>
                            </div>

                            <div style="display: flex; align-items: center; gap: 8px;">
                                <input
                                    type="checkbox"
                                    checked=move || current_field_has_condition.get()
                                    on:change=move |ev| {
                                        let checked = event_target_checked(&ev);
                                        current_field_has_condition.set(checked);
                                    }
                                    style="cursor: pointer;"
                                />
                                <label style="font-size: 12px; color: var(--text-2); cursor: pointer;">
                                    "Add Condition"
                                </label>
                            </div>

                            <Show when=move || current_field_has_condition.get()>
                                <div style="background: var(--bg-tertiary); padding: 8px; border-radius: 4px; display: flex; flex-direction: column; gap: 8px;">
                                    <div>
                                        <label style="font-size: 11px; font-weight: 500; color: var(--text-2); display: block; margin-bottom: 2px;">
                                            "Condition Field"
                                        </label>
                                        <input
                                            type="text"
                                            placeholder="e.g., offers"
                                            prop:value=move || current_field_condition_field.get()
                                            on:input=move |ev| current_field_condition_field.set(event_target_value(&ev))
                                            style="width: 100%; background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 4px; padding: 6px; color: var(--text-1); font-size: 12px;"
                                        />
                                    </div>

                                    <div>
                                        <label style="font-size: 11px; font-weight: 500; color: var(--text-2); display: block; margin-bottom: 2px;">
                                            "Operator"
                                        </label>
                                        <select
                                            prop:value=move || current_field_condition_op.get()
                                            on:change=move |ev| current_field_condition_op.set(event_target_value(&ev))
                                            style="width: 100%; background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 4px; padding: 6px; color: var(--text-1); font-size: 12px;"
                                        >
                                            <option value="exists">"Exists"</option>
                                            <option value="equals">"Equals"</option>
                                            <option value="contains">"Contains"</option>
                                        </select>
                                    </div>
                                </div>
                            </Show>

                            <button
                                class="btn"
                                on:click=add_field
                                style="padding: 8px 16px; background: var(--teal); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 500; margin-top: 8px;"
                            >
                                "Add Field"
                            </button>
                        </div>

                        <div style="flex: 1; display: flex; flex-direction: column; gap: 12px;">
                            <div>
                                <h4 style="font-size: 13px; font-weight: 600; margin-bottom: 8px;">
                                    "Fields"
                                </h4>
                                <Show
                                    when=move || !fields.get().is_empty()
                                    fallback=|| view! {
                                        <div style="font-size: 12px; color: var(--text-2); text-align: center; padding: 16px; background: var(--bg-tertiary); border-radius: 4px;">
                                            "No fields yet"
                                        </div>
                                    }
                                >
                                    <div style="display: flex; flex-direction: column; gap: 4px;">
                                        <For
                                            each=move || fields.get().into_iter().enumerate()
                                            key=|(i, _)| *i
                                            children=move |(index, field)| {
                                                view! {
                                                    <div style="display: flex; align-items: center; justify-content: space-between; background: var(--bg-tertiary); padding: 8px; border-radius: 4px; font-size: 12px;">
                                                        <div>
                                                            <div style="font-weight: 500;">
                                                                {field.path.clone()}
                                                            </div>
                                                            <div style="color: var(--text-2); font-size: 11px;">
                                                                {field.display.clone()}
                                                            </div>
                                                        </div>
                                                        <button
                                                            class="btn"
                                                            on:click=move |_| remove_field(index)
                                                            style="padding: 4px 8px; background: var(--coral); color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 11px;"
                                                        >
                                                            "Remove"
                                                        </button>
                                                    </div>
                                                }
                                            }
                                        />
                                    </div>
                                </Show>
                            </div>

                            <div>
                                <h4 style="font-size: 13px; font-weight: 600; margin-bottom: 8px;">
                                    "JSON Preview"
                                </h4>
                                <pre style="background: var(--bg-tertiary); padding: 8px; border-radius: 4px; font-size: 11px; overflow-x: auto; margin: 0; color: var(--text-2); font-family: var(--font-mono);">
                                    {move || preview_json.get()}
                                </pre>
                            </div>

                            <Show when=move || preview_error.get().is_some()>
                                <div style="background: var(--coral); color: white; padding: 8px; border-radius: 4px; font-size: 12px;">
                                    {move || preview_error.get().unwrap_or_default()}
                                </div>
                            </Show>
                        </div>
                    </div>

                    <div style="display: flex; gap: 8px; justify-content: flex-end; margin-top: 8px;">
                        <button
                            class="btn"
                            on:click=move |_| is_open.set(false)
                            style="padding: 8px 16px; background: var(--bg-tertiary); color: var(--text-1); border: 1px solid var(--border); border-radius: 8px; cursor: pointer; font-size: 13px;"
                        >
                            "Cancel"
                        </button>
                        <button
                            class="btn"
                            on:click=complete
                            style="padding: 8px 16px; background: var(--purple); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 500;"
                        >
                            "Use This Template"
                        </button>
                    </div>
                </div>
            </div>
        </Show>
    }
}
