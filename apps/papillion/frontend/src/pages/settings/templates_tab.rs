use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::state::templates::TemplatesState;
use papillion_shared::Template;
use papillion_shared::types::{TemplateConfig, LayoutConfig};

#[component]
pub fn TemplatesTab() -> impl IntoView {
    let templates_state = expect_context::<TemplatesState>();

    // Form state for creating new templates
    let new_name = RwSignal::new(String::new());
    let new_schema_type = RwSignal::new(String::new());
    let new_config = RwSignal::new(String::new());

    // UI state
    let create_error = RwSignal::new(None::<String>);
    let create_success = RwSignal::new(false);
    let edit_template_id = RwSignal::new(None::<String>);
    let edit_form_data = RwSignal::new(None::<Template>);
    let edit_name = RwSignal::new(String::new());
    let edit_schema_type = RwSignal::new(String::new());
    let edit_config = RwSignal::new(String::new());
    let edit_error = RwSignal::new(None::<String>);
    let delete_confirm_id = RwSignal::new(None::<String>);
    let delete_error = RwSignal::new(None::<String>);

    // Create template handler
    let handle_create = move |_| {
        create_error.set(None);
        create_success.set(false);

        let name = new_name.get();
        let schema_type = new_schema_type.get();
        let config_str = new_config.get();

        if name.trim().is_empty() || schema_type.trim().is_empty() {
            create_error.set(Some("Name and Schema Type are required".to_string()));
            return;
        }

        // Parse JSON config
        let template_config: TemplateConfig = match serde_json::from_str(&config_str) {
            Ok(cfg) => cfg,
            Err(_) => {
                create_error.set(Some("Invalid JSON in template config".to_string()));
                return;
            }
        };

        let template = Template {
            id: uuid::Uuid::new_v4().to_string(),
            template_name: name.clone(),
            schema_type: schema_type.clone(),
            principal_did: None,
            template_config,
            version: 1,
            enabled: true,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            created_by: None,
        };

        spawn_local(async move {
            match bridge::invoke::<serde_json::Value, ()>(
                "create_template",
                &serde_json::to_value(&template).unwrap(),
            )
            .await
            {
                Ok(_) => {
                    create_success.set(true);
                    new_name.set(String::new());
                    new_schema_type.set(String::new());
                    new_config.set(String::new());

                    // Reload templates
                    if let Ok(global) = bridge::invoke_no_args::<Vec<Template>>("get_global_templates").await
                    {
                        templates_state.global_templates.set(global);
                    }
                }
                Err(e) => {
                    create_error.set(Some(e));
                }
            }
        });
    };

    // Edit template handler
    let handle_edit_open = move |template: Template| {
        edit_form_data.set(Some(template.clone()));
        edit_name.set(template.template_name);
        edit_schema_type.set(template.schema_type);
        edit_config.set(serde_json::to_string_pretty(&template.template_config).unwrap_or_default());
        edit_template_id.set(Some(template.id));
    };

    let handle_edit_save = move |_| {
        edit_error.set(None);

        if let Some(mut template) = edit_form_data.get() {
            let config_str = edit_config.get();
            let template_config: TemplateConfig = match serde_json::from_str(&config_str) {
                Ok(cfg) => cfg,
                Err(_) => {
                    edit_error.set(Some("Invalid JSON in template config".to_string()));
                    return;
                }
            };

            template.template_name = edit_name.get();
            template.schema_type = edit_schema_type.get();
            template.template_config = template_config;
            template.updated_at = chrono::Utc::now().to_rfc3339();

            spawn_local(async move {
                match bridge::invoke::<serde_json::Value, ()>(
                    "update_template",
                    &serde_json::to_value(&template).unwrap(),
                )
                .await
                {
                    Ok(_) => {
                        edit_template_id.set(None);
                        edit_form_data.set(None);

                        // Reload templates
                        if let Ok(global) = bridge::invoke_no_args::<Vec<Template>>("get_global_templates").await
                        {
                            templates_state.global_templates.set(global);
                        }
                    }
                    Err(e) => {
                        edit_error.set(Some(e));
                    }
                }
            });
        }
    };

    let handle_edit_cancel = move |_| {
        edit_template_id.set(None);
        edit_form_data.set(None);
        edit_error.set(None);
    };

    // Delete template handler
    let handle_delete_confirm = move |template_name: String| {
        delete_confirm_id.set(Some(template_name));
    };

    let handle_delete_execute = move |template_name: String| {
        delete_error.set(None);
        spawn_local(async move {
            match bridge::invoke::<serde_json::Value, ()>(
                "delete_template",
                &serde_json::json!({ "template_name": template_name }),
            )
            .await
            {
                Ok(_) => {
                    delete_confirm_id.set(None);

                    // Reload templates
                    if let Ok(global) = bridge::invoke_no_args::<Vec<Template>>("get_global_templates").await
                    {
                        templates_state.global_templates.set(global);
                    }
                }
                Err(e) => {
                    delete_error.set(Some(e));
                }
            }
        });
    };

    // Toggle template enabled state
    let handle_toggle_enabled = move |template_name: String, enabled: bool| {
        spawn_local(async move {
            let _ = bridge::invoke::<serde_json::Value, ()>(
                "set_template_enabled",
                &serde_json::json!({ "template_name": template_name, "enabled": !enabled }),
            )
            .await;

            // Reload templates
            if let Ok(global) = bridge::invoke_no_args::<Vec<Template>>("get_global_templates").await {
                templates_state.global_templates.set(global);
            }
        });
    };

    let all_templates = move || templates_state.all_templates();

    view! {
        <div style="padding: 0;">
            // Create Form
            <div style="background: var(--bg-1); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px;">
                <h3 style="font-size: 14px; font-weight: 600; margin-bottom: 12px;">
                    "Create New Template"
                </h3>

                <div style="display: flex; flex-direction: column; gap: 8px;">
                    <label style="font-size: 12px; font-weight: 500; color: var(--text-2);">
                        "Template Name (required)"
                    </label>
                    <input
                        type="text"
                        placeholder="e.g., My Flight Template"
                        prop:value=move || new_name.get()
                        on:input=move |ev| new_name.set(event_target_value(&ev))
                        style="background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px; padding: 8px; color: var(--text-1); font-size: 13px; font-family: var(--font-body);"
                    />
                </div>

                <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 12px;">
                    <label style="font-size: 12px; font-weight: 500; color: var(--text-2);">
                        "Schema Type (required)"
                    </label>
                    <input
                        type="text"
                        placeholder="e.g., FlightReservation"
                        prop:value=move || new_schema_type.get()
                        on:input=move |ev| new_schema_type.set(event_target_value(&ev))
                        style="background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px; padding: 8px; color: var(--text-1); font-size: 13px; font-family: var(--font-body);"
                    />
                </div>

                <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 12px;">
                    <label style="font-size: 12px; font-weight: 500; color: var(--text-2);">
                        "Template Config (JSON)"
                    </label>
                    <textarea
                        placeholder=r#"{"version":1,"layout":{"type":"grid","columns":2},"fields":[{"path":"name","label":"Name","display":"title"}]}"#
                        prop:value=move || new_config.get()
                        on:input=move |ev| new_config.set(event_target_value(&ev))
                        style="background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px; padding: 8px; color: var(--text-1); font-size: 13px; font-family: var(--font-mono); min-height: 100px; resize: vertical;"
                    />
                </div>

                <Show when=move || create_error.get().is_some()>
                    <div style="font-size: 12px; color: var(--coral); margin-top: 8px;">
                        {move || create_error.get().unwrap_or_default()}
                    </div>
                </Show>

                <Show when=move || create_success.get()>
                    <div style="font-size: 12px; color: var(--teal); margin-top: 8px;">
                        "Template created successfully!"
                    </div>
                </Show>

                <button
                    class="btn btn-primary"
                    on:click=handle_create
                    style="margin-top: 12px; padding: 8px 16px; background: var(--purple); color: white; border-radius: 8px; border: none; cursor: pointer; font-size: 13px; font-weight: 500;"
                >
                    "Create Template"
                </button>
            </div>

            // Templates List
            <div style="background: var(--bg-1); border: 1px solid var(--border); border-radius: 8px; padding: 16px;">
                <h3 style="font-size: 14px; font-weight: 600; margin-bottom: 12px;">
                    "Templates"
                </h3>

                <Show
                    when=move || !all_templates().is_empty()
                    fallback=|| view! {
                        <div style="font-size: 13px; color: var(--text-2); text-align: center; padding: 24px;">
                            "No templates yet"
                        </div>
                    }
                >
                    <For
                        each=all_templates
                        key=|t| t.id.clone()
                        let:template
                    >
                        <div style="display: flex; align-items: center; gap: 12px; padding: 12px; background: var(--bg-tertiary); border-radius: 8px; margin-bottom: 8px; border: 1px solid var(--border);">
                            <div style="flex: 1; min-width: 0;">
                                <div style="font-size: 13px; font-weight: 500; color: var(--text-1);">
                                    {template.template_name.clone()}
                                </div>
                                <div style="font-size: 12px; color: var(--text-2); margin-top: 2px;">
                                    {template.schema_type.clone()}
                                </div>
                            </div>

                            <Show when=move || template.enabled>
                                <span style="font-size: 11px; background: var(--teal); color: white; padding: 2px 8px; border-radius: 4px;">
                                    "Enabled"
                                </span>
                            </Show>
                            <Show when=move || !template.enabled>
                                <span style="font-size: 11px; background: var(--text-3); color: var(--text-2); padding: 2px 8px; border-radius: 4px;">
                                    "Disabled"
                                </span>
                            </Show>

                            <button
                                class="btn"
                                on:click=move |_| handle_edit_open(template.clone())
                                style="padding: 4px 8px; font-size: 11px; background: var(--bg-secondary); color: var(--text-1); border: 1px solid var(--border); border-radius: 4px; cursor: pointer;"
                            >
                                "Edit"
                            </button>

                            <button
                                class="btn"
                                on:click=move |_| handle_toggle_enabled(template.template_name.clone(), template.enabled)
                                style="padding: 4px 8px; font-size: 11px; background: var(--bg-secondary); color: var(--text-1); border: 1px solid var(--border); border-radius: 4px; cursor: pointer;"
                            >
                                {move || if template.enabled { "Disable" } else { "Enable" }}
                            </button>

                            <button
                                class="btn"
                                on:click=move |_| handle_delete_confirm(template.template_name.clone())
                                style="padding: 4px 8px; font-size: 11px; background: var(--coral); color: white; border: none; border-radius: 4px; cursor: pointer;"
                            >
                                "Delete"
                            </button>
                        </div>
                    </For>
                </Show>
            </div>

            // Edit Modal
            <Show when=move || edit_template_id.get().is_some()>
                <div style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.5); display: flex; align-items: center; justify-content: center; z-index: 1000;">
                    <div style="background: var(--bg-1); border: 1px solid var(--border); border-radius: 8px; padding: 20px; max-width: 500px; width: 90%; max-height: 80vh; overflow-y: auto; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);">
                        <h3 style="font-size: 16px; font-weight: 600; margin-bottom: 16px;">
                            "Edit Template"
                        </h3>

                        <div style="display: flex; flex-direction: column; gap: 12px;">
                            <div>
                                <label style="font-size: 12px; font-weight: 500; color: var(--text-2);">
                                    "Template Name"
                                </label>
                                <input
                                    type="text"
                                    prop:value=move || edit_name.get()
                                    on:input=move |ev| edit_name.set(event_target_value(&ev))
                                    style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px; padding: 8px; color: var(--text-1); font-size: 13px; margin-top: 4px; box-sizing: border-box;"
                                />
                            </div>

                            <div>
                                <label style="font-size: 12px; font-weight: 500; color: var(--text-2);">
                                    "Schema Type"
                                </label>
                                <input
                                    type="text"
                                    prop:value=move || edit_schema_type.get()
                                    on:input=move |ev| edit_schema_type.set(event_target_value(&ev))
                                    style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px; padding: 8px; color: var(--text-1); font-size: 13px; margin-top: 4px; box-sizing: border-box;"
                                />
                            </div>

                            <div>
                                <label style="font-size: 12px; font-weight: 500; color: var(--text-2);">
                                    "Template Config (JSON)"
                                </label>
                                <textarea
                                    prop:value=move || edit_config.get()
                                    on:input=move |ev| edit_config.set(event_target_value(&ev))
                                    style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px; padding: 8px; color: var(--text-1); font-size: 13px; font-family: var(--font-mono); min-height: 120px; margin-top: 4px; box-sizing: border-box;"
                                />
                            </div>

                            <Show when=move || edit_error.get().is_some()>
                                <div style="font-size: 12px; color: var(--coral);">
                                    {move || edit_error.get().unwrap_or_default()}
                                </div>
                            </Show>
                        </div>

                        <div style="display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px;">
                            <button
                                class="btn"
                                on:click=handle_edit_cancel
                                style="padding: 8px 16px; background: var(--bg-tertiary); color: var(--text-1); border: 1px solid var(--border); border-radius: 8px; cursor: pointer; font-size: 13px;"
                            >
                                "Cancel"
                            </button>
                            <button
                                class="btn"
                                on:click=handle_edit_save
                                style="padding: 8px 16px; background: var(--purple); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 13px;"
                            >
                                "Save"
                            </button>
                        </div>
                    </div>
                </div>
            </Show>

            // Delete Confirmation Modal
            <Show when=move || delete_confirm_id.get().is_some()>
                <div style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.5); display: flex; align-items: center; justify-content: center; z-index: 1000;">
                    <div style="background: var(--bg-1); border: 1px solid var(--border); border-radius: 8px; padding: 20px; max-width: 400px; width: 90%; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);">
                        <h3 style="font-size: 16px; font-weight: 600; margin-bottom: 8px;">
                            "Delete Template?"
                        </h3>
                        <p style="font-size: 13px; color: var(--text-2); margin-bottom: 16px;">
                            "This action cannot be undone. Are you sure?"
                        </p>

                        <Show when=move || delete_error.get().is_some()>
                            <div style="font-size: 12px; color: var(--coral); margin-bottom: 12px;">
                                {move || delete_error.get().unwrap_or_default()}
                            </div>
                        </Show>

                        <div style="display: flex; gap: 8px; justify-content: flex-end;">
                            <button
                                class="btn"
                                on:click=move |_| delete_confirm_id.set(None)
                                style="padding: 8px 16px; background: var(--bg-tertiary); color: var(--text-1); border: 1px solid var(--border); border-radius: 8px; cursor: pointer; font-size: 13px;"
                            >
                                "Cancel"
                            </button>
                            <button
                                class="btn"
                                on:click=move |_| {
                                    if let Some(id) = delete_confirm_id.get() {
                                        handle_delete_execute(id);
                                    }
                                }
                                style="padding: 8px 16px; background: var(--coral); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 13px;"
                            >
                                "Delete Template"
                            </button>
                        </div>
                    </div>
                </div>
            </Show>
        </div>
    }
}
