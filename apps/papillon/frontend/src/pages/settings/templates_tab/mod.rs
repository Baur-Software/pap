use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::state::templates::TemplatesState;
use papillon_shared::types::TemplateConfig;
use papillon_shared::Template;

mod schema_type_input;
mod template_builder;
mod template_library;

use schema_type_input::SchemaTypeInput;
use template_builder::TemplateBuilder;
use template_library::TemplateLibrary;

#[component]
pub fn TemplatesTab() -> impl IntoView {
    let templates_state = expect_context::<TemplatesState>();

    // Form state for creating new templates
    let new_name = RwSignal::new(String::new());
    let new_schema_type = RwSignal::new(String::new());
    let new_config = RwSignal::new(String::new());
    let new_config_error = RwSignal::new(None::<String>);

    // UI state
    let create_error = RwSignal::new(None::<String>);
    let create_success = RwSignal::new(false);
    let edit_template_id = RwSignal::new(None::<String>);
    let edit_form_data = RwSignal::new(None::<Template>);
    let edit_name = RwSignal::new(String::new());
    let edit_schema_type = RwSignal::new(String::new());
    let edit_config = RwSignal::new(String::new());
    let edit_config_error = RwSignal::new(None::<String>);
    let edit_error = RwSignal::new(None::<String>);
    let delete_confirm_id = RwSignal::new(None::<String>);
    let delete_error = RwSignal::new(None::<String>);

    // Phase 9b: Template Builder UI state
    let builder_open = RwSignal::new(false);

    // Phase 9e: Template Library UI state
    let library_open = RwSignal::new(false);

    // Phase 9d: Bulk operations state
    let selected_templates = RwSignal::new(std::collections::HashSet::<String>::new());
    let bulk_delete_confirm_id = RwSignal::new(None::<String>);

    // Phase 9f: Export/Import state
    let import_error = RwSignal::new(None::<String>);
    let import_success = RwSignal::new(false);

    // Format JSON handler
    let handle_format_json = move |config_signal: RwSignal<String>| {
        let config_str = config_signal.get();
        match serde_json::from_str::<serde_json::Value>(&config_str) {
            Ok(val) => {
                if let Ok(formatted) = serde_json::to_string_pretty(&val) {
                    config_signal.set(formatted);
                    new_config_error.set(None);
                }
            }
            Err(e) => {
                new_config_error.set(Some(format!("Invalid JSON: {}", e)));
            }
        }
    };

    // Minify JSON handler
    let handle_minify_json = move |config_signal: RwSignal<String>| {
        let config_str = config_signal.get();
        match serde_json::from_str::<serde_json::Value>(&config_str) {
            Ok(val) => {
                if let Ok(minified) = serde_json::to_string(&val) {
                    config_signal.set(minified);
                    new_config_error.set(None);
                }
            }
            Err(e) => {
                new_config_error.set(Some(format!("Invalid JSON: {}", e)));
            }
        }
    };

    // Real-time JSON validation on input
    let handle_config_input =
        move |ev: web_sys::Event,
              config_signal: RwSignal<String>,
              error_signal: RwSignal<Option<String>>| {
            let text = event_target_value(&ev);
            config_signal.set(text.clone());

            // Validate JSON
            if text.trim().is_empty() {
                error_signal.set(None);
            } else {
                match serde_json::from_str::<TemplateConfig>(&text) {
                    Ok(_) => error_signal.set(None),
                    Err(e) => {
                        // Extract line/column info from error
                        let error_msg = format!(
                            "Line {}, Column {}: {:?}",
                            e.line(),
                            e.column(),
                            e.classify()
                        );
                        error_signal.set(Some(error_msg));
                    }
                }
            }
        };

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
            Err(e) => {
                create_error.set(Some(format!("Invalid JSON in template config: {}", e)));
                return;
            }
        };

        // Validate template configuration
        if let Err(validation_error) = template_config.validate() {
            create_error.set(Some(validation_error));
            return;
        }

        let template = Template {
            id: uuid::Uuid::new_v4().to_string(),
            template_name: name.clone(),
            schema_type: schema_type.clone(),
            principal_did: None,
            agent_did: None,
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
                &serde_json::json!({ "template": &template }),
            )
            .await
            {
                Ok(_) => {
                    create_success.set(true);
                    new_name.set(String::new());
                    new_schema_type.set(String::new());
                    new_config.set(String::new());

                    // Reload templates
                    if let Ok(global) =
                        bridge::invoke_no_args::<Vec<Template>>("get_global_templates").await
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
        edit_config
            .set(serde_json::to_string_pretty(&template.template_config).unwrap_or_default());
        edit_template_id.set(Some(template.id));
    };

    let handle_edit_save = move |_| {
        edit_error.set(None);

        if let Some(mut template) = edit_form_data.get() {
            let config_str = edit_config.get();
            let template_config: TemplateConfig = match serde_json::from_str(&config_str) {
                Ok(cfg) => cfg,
                Err(e) => {
                    edit_error.set(Some(format!("Invalid JSON in template config: {}", e)));
                    return;
                }
            };

            // Validate template configuration
            if let Err(validation_error) = template_config.validate() {
                edit_error.set(Some(validation_error));
                return;
            }

            template.template_name = edit_name.get();
            template.schema_type = edit_schema_type.get();
            template.template_config = template_config;
            template.updated_at = chrono::Utc::now().to_rfc3339();

            spawn_local(async move {
                match bridge::invoke::<serde_json::Value, ()>(
                    "update_template",
                    &serde_json::json!({ "template": &template }),
                )
                .await
                {
                    Ok(_) => {
                        edit_template_id.set(None);
                        edit_form_data.set(None);

                        // Reload templates
                        if let Ok(global) =
                            bridge::invoke_no_args::<Vec<Template>>("get_global_templates").await
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
                    if let Ok(global) =
                        bridge::invoke_no_args::<Vec<Template>>("get_global_templates").await
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
            if let Ok(global) =
                bridge::invoke_no_args::<Vec<Template>>("get_global_templates").await
            {
                templates_state.global_templates.set(global);
            }
        });
    };

    let all_templates = move || templates_state.all_templates();

    // Registered schema types — derived from global templates, used for type autocomplete
    let registered_types = Signal::derive(move || {
        let mut types: Vec<String> = templates_state
            .global_templates
            .get()
            .into_iter()
            .map(|t| t.schema_type)
            .collect();
        types.sort();
        types.dedup();
        types
    });

    // Handler for builder completion (Phase 9b)
    let handle_builder_complete = move |config: TemplateConfig| {
        if let Ok(json) = serde_json::to_string_pretty(&config) {
            new_config.set(json);
            new_config_error.set(None);
        }
    };

    // Handler for library template selection (Phase 9e)
    let handle_library_select = move |template: template_library::TemplateExample| {
        new_name.set(template.name);
        new_schema_type.set(template.schema_type);
        if let Ok(json) = serde_json::to_string_pretty(&template.config) {
            new_config.set(json);
            new_config_error.set(None);
        }
    };

    // Toggle template selection (Phase 9d)
    let toggle_selection = move |template_name: String| {
        let mut selected = selected_templates.get();
        if selected.contains(&template_name) {
            selected.remove(&template_name);
        } else {
            selected.insert(template_name);
        }
        selected_templates.set(selected);
    };

    // Bulk delete confirm (Phase 9d)
    let handle_bulk_delete_confirm = move |_| {
        let selected = selected_templates.get();
        if !selected.is_empty() {
            bulk_delete_confirm_id.set(Some(format!("{} templates", selected.len())));
        }
    };

    // Bulk delete execute (Phase 9d)
    let handle_bulk_delete_execute = move |_| {
        delete_error.set(None);
        let selected: Vec<String> = selected_templates.get().into_iter().collect();

        spawn_local(async move {
            for template_name in selected {
                let _ = bridge::invoke::<serde_json::Value, ()>(
                    "delete_template",
                    &serde_json::json!({ "template_name": template_name }),
                )
                .await;
            }

            bulk_delete_confirm_id.set(None);
            selected_templates.set(std::collections::HashSet::new());

            // Reload templates
            if let Ok(global) =
                bridge::invoke_no_args::<Vec<Template>>("get_global_templates").await
            {
                templates_state.global_templates.set(global);
            }
        });
    };

    // Bulk enable/disable (Phase 9d)
    let handle_bulk_enable_all = move |_| {
        let selected: Vec<String> = selected_templates.get().into_iter().collect();
        spawn_local(async move {
            for template_name in selected {
                let _ = bridge::invoke::<serde_json::Value, ()>(
                    "set_template_enabled",
                    &serde_json::json!({ "template_name": template_name, "enabled": true }),
                )
                .await;
            }

            if let Ok(global) =
                bridge::invoke_no_args::<Vec<Template>>("get_global_templates").await
            {
                templates_state.global_templates.set(global);
            }
        });
    };

    let handle_bulk_disable_all = move |_| {
        let selected: Vec<String> = selected_templates.get().into_iter().collect();
        spawn_local(async move {
            for template_name in selected {
                let _ = bridge::invoke::<serde_json::Value, ()>(
                    "set_template_enabled",
                    &serde_json::json!({ "template_name": template_name, "enabled": false }),
                )
                .await;
            }

            if let Ok(global) =
                bridge::invoke_no_args::<Vec<Template>>("get_global_templates").await
            {
                templates_state.global_templates.set(global);
            }
        });
    };

    // Export templates (Phase 9f)
    let handle_export = move |_| {
        spawn_local(async move {
            match bridge::invoke_no_args::<String>("export_templates").await {
                Ok(json_str) => {
                    // Trigger file download
                    if let Some(window) = web_sys::window() {
                        if let Some(document) = window.document() {
                            if let Ok(element) = document.create_element("a") {
                                if let Ok(a) = element.dyn_into::<web_sys::HtmlAnchorElement>() {
                                    let arr = js_sys::Array::new();
                                    arr.push(&wasm_bindgen::JsValue::from_str(&json_str));
                                    let blob = web_sys::Blob::new_with_str_sequence(&arr).unwrap();
                                    let url =
                                        web_sys::Url::create_object_url_with_blob(&blob).unwrap();
                                    a.set_href(&url);
                                    a.set_download("papillon-templates.json");
                                    a.click();
                                    web_sys::Url::revoke_object_url(&url).unwrap();
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    import_error.set(Some(format!("Export failed: {}", e)));
                }
            }
        });
    };

    // Import templates (Phase 9f)
    let handle_import_file = move |ev: web_sys::Event| {
        if let Some(input) = ev
            .target()
            .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        {
            if let Some(files) = input.files() {
                if let Some(file) = files.get(0) {
                    spawn_local(async move {
                        match wasm_bindgen_futures::JsFuture::from(file.text()).await {
                            Ok(js_value) => {
                                if let Some(json_str) = js_value.as_string() {
                                    match bridge::invoke::<serde_json::Value, serde_json::Value>(
                                        "import_templates",
                                        &serde_json::json!({ "json_str": json_str }),
                                    )
                                    .await
                                    {
                                        Ok(result) => {
                                            import_success.set(true);
                                            import_error.set(None);

                                            if let Ok(global) =
                                                bridge::invoke_no_args::<Vec<Template>>(
                                                    "get_global_templates",
                                                )
                                                .await
                                            {
                                                templates_state.global_templates.set(global);
                                            }

                                            // Log import result
                                            web_sys::console::log_1(
                                                &format!("Imported: {:?}", result).into(),
                                            );
                                        }
                                        Err(e) => {
                                            import_error.set(Some(e));
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                import_error.set(Some("Failed to read file".to_string()));
                            }
                        }
                    });
                }
            }
        }
    };

    view! {
        <div style="padding: 0;">
            // Create Form (Phase 7 UI Polish)
            <div style="background: var(--bg-1); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 18px;">
                    <h3 style="font-size: 15px; font-weight: 700; color: var(--text-1); margin: 0;">
                        "Create Template"
                    </h3>
                    <div style="display: flex; gap: 8px;">
                        <button
                            class="btn"
                            on:click=move |_| library_open.set(true)
                            title="Choose from pre-built template examples"
                            style="padding: 8px 14px; font-size: 12px; font-weight: 500; background: var(--teal); color: white; border: none; border-radius: 6px; cursor: pointer; transition: all 0.2s ease;"
                        >
                            "📚 Library"
                        </button>
                        <button
                            class="btn"
                            on:click=move |_| builder_open.set(true)
                            title="Visually build a template without writing JSON"
                            style="padding: 8px 14px; font-size: 12px; font-weight: 500; background: var(--purple); color: white; border: none; border-radius: 6px; cursor: pointer; transition: all 0.2s ease;"
                        >
                            "✏️ Builder"
                        </button>
                    </div>
                </div>

                <div style="display: flex; flex-direction: column; gap: 6px;">
                    <label style="font-size: 12px; font-weight: 600; color: var(--text-1); letter-spacing: 0.3px;">
                        "Template Name "
                        <span style="color: var(--coral);">
                            "*"
                        </span>
                    </label>
                    <input
                        type="text"
                        placeholder="Name (e.g., My Flight Template)"
                        prop:value=move || new_name.get()
                        on:input=move |ev| new_name.set(event_target_value(&ev))
                        aria-label="Template name"
                        style="background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 10px; color: var(--text-1); font-size: 13px; font-family: var(--font-body); transition: border-color 0.2s ease;"
                    />
                </div>

                <div style="display: flex; flex-direction: column; gap: 6px;">
                    <label style="font-size: 12px; font-weight: 600; color: var(--text-1); letter-spacing: 0.3px;">
                        "Schema Type "
                        <span style="color: var(--coral);">
                            "*"
                        </span>
                    </label>
                    <SchemaTypeInput value=new_schema_type registered_types=registered_types />
                </div>

                <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 12px;">
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <label style="font-size: 12px; font-weight: 500; color: var(--text-2);">
                            "Template Config (JSON)"
                        </label>
                        <div style="display: flex; gap: 4px;">
                            <button
                                class="btn"
                                on:click=move |_| handle_format_json(new_config)
                                style="padding: 4px 8px; font-size: 11px; background: var(--bg-secondary); color: var(--text-1); border: 1px solid var(--border); border-radius: 4px; cursor: pointer;"
                            >
                                "Format"
                            </button>
                            <button
                                class="btn"
                                on:click=move |_| handle_minify_json(new_config)
                                style="padding: 4px 8px; font-size: 11px; background: var(--bg-secondary); color: var(--text-1); border: 1px solid var(--border); border-radius: 4px; cursor: pointer;"
                            >
                                "Minify"
                            </button>
                        </div>
                    </div>
                    <textarea
                        placeholder=r#"{"version":1,"layout":{"type":"grid","columns":2},"fields":[{"path":"name","label":"Name","display":"title"}]}"#
                        prop:value=move || new_config.get()
                        on:input=move |ev| handle_config_input(ev, new_config, new_config_error)
                        style="background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px; padding: 8px; color: var(--text-1); font-size: 13px; font-family: var(--font-mono); min-height: 100px; resize: vertical;"
                    />
                    <Show when=move || new_config_error.get().is_some()>
                        <div style="font-size: 11px; color: var(--coral);">
                            {move || new_config_error.get().unwrap_or_default()}
                        </div>
                    </Show>
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

            // Templates List with Bulk Operations (Phase 7 UI Polish)
            <div style="background: var(--bg-1); border: 1px solid var(--border); border-radius: 8px; padding: 20px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px;">
                    <h3 style="font-size: 15px; font-weight: 700; color: var(--text-1); margin: 0;">
                        "Templates"
                    </h3>
                    <Show when=move || !selected_templates.get().is_empty()>
                        <div style="display: flex; gap: 8px; align-items: center; font-size: 12px;">
                            <span style="color: var(--text-2);">
                                {move || format!("{} selected", selected_templates.get().len())}
                            </span>
                            <button
                                class="btn"
                                on:click=handle_bulk_enable_all
                                style="padding: 4px 8px; font-size: 11px; background: var(--teal); color: white; border: none; border-radius: 4px; cursor: pointer;"
                            >
                                "Enable All"
                            </button>
                            <button
                                class="btn"
                                on:click=handle_bulk_disable_all
                                style="padding: 4px 8px; font-size: 11px; background: var(--gold); color: black; border: none; border-radius: 4px; cursor: pointer;"
                            >
                                "Disable All"
                            </button>
                            <button
                                class="btn"
                                on:click=handle_bulk_delete_confirm
                                style="padding: 4px 8px; font-size: 11px; background: var(--coral); color: white; border: none; border-radius: 4px; cursor: pointer;"
                            >
                                "Delete All"
                            </button>
                        </div>
                    </Show>
                </div>

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
                        key=|t| format!("{}_{}_{}_{}", t.id, t.schema_type, t.enabled, t.updated_at)
                        children=move |template| {
                            let name_for_check = template.template_name.clone();
                            let name_for_toggle = template.template_name.clone();
                            let name_display = template.template_name.clone();
                            let schema_display = template.schema_type.clone();
                            let enabled = template.enabled;
                            let name_for_enable = template.template_name.clone();
                            let name_for_delete = template.template_name.clone();
                            let template_for_edit = template.clone();
                            view! {
                                <div style="display: flex; align-items: center; gap: 12px; padding: 12px; background: var(--bg-tertiary); border-radius: 8px; margin-bottom: 8px; border: 1px solid var(--border);">
                                    <input
                                        type="checkbox"
                                        checked=move || selected_templates.get().contains(&name_for_check)
                                        on:change=move |_| toggle_selection(name_for_toggle.clone())
                                        style="cursor: pointer;"
                                    />
                                    <div style="flex: 1; min-width: 0;">
                                        <div style="font-size: 13px; font-weight: 500; color: var(--text-1);">
                                            {name_display}
                                        </div>
                                        <div style="font-size: 12px; color: var(--text-2); margin-top: 2px;">
                                            {schema_display}
                                        </div>
                                    </div>

                                    <Show when=move || enabled>
                                        <span style="font-size: 11px; background: var(--teal); color: white; padding: 2px 8px; border-radius: 4px;">
                                            "Enabled"
                                        </span>
                                    </Show>
                                    <Show when=move || !enabled>
                                        <span style="font-size: 11px; background: var(--text-3); color: var(--text-2); padding: 2px 8px; border-radius: 4px;">
                                            "Disabled"
                                        </span>
                                    </Show>

                                    <button
                                        class="btn"
                                        on:click=move |_| handle_edit_open(template_for_edit.clone())
                                        style="padding: 4px 8px; font-size: 11px; background: var(--bg-secondary); color: var(--text-1); border: 1px solid var(--border); border-radius: 4px; cursor: pointer;"
                                    >
                                        "Edit"
                                    </button>

                                    <button
                                        class="btn"
                                        on:click=move |_| handle_toggle_enabled(name_for_enable.clone(), enabled)
                                        style="padding: 4px 8px; font-size: 11px; background: var(--bg-secondary); color: var(--text-1); border: 1px solid var(--border); border-radius: 4px; cursor: pointer;"
                                    >
                                        {move || if enabled { "Disable" } else { "Enable" }}
                                    </button>

                                    <button
                                        class="btn"
                                        on:click=move |_| handle_delete_confirm(name_for_delete.clone())
                                        style="padding: 4px 8px; font-size: 11px; background: var(--coral); color: white; border: none; border-radius: 4px; cursor: pointer;"
                                    >
                                        "Delete"
                                    </button>
                                </div>
                            }
                        }
                    />
                </Show>
            </div>

            // Export/Import Section (Phase 9f)
            <div style="background: var(--bg-1); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px;">
                <h3 style="font-size: 14px; font-weight: 600; margin-bottom: 12px;">
                    "Data Management"
                </h3>

                <div style="display: flex; gap: 12px;">
                    <button
                        class="btn"
                        on:click=handle_export
                        style="padding: 8px 16px; background: var(--purple); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 13px;"
                    >
                        "📥 Export Templates"
                    </button>

                    <input
                        type="file"
                        accept=".json"
                        on:change=handle_import_file
                        style="display: none;"
                        id="template-import-input"
                    />

                    <button
                        class="btn"
                        on:click=move |_| {
                            if let Some(elem) = web_sys::window()
                                .and_then(|w| w.document())
                                .and_then(|d| d.get_element_by_id("template-import-input"))
                                .and_then(|e| e.dyn_into::<web_sys::HtmlInputElement>().ok())
                            {
                                elem.click();
                            }
                        }
                        style="padding: 8px 16px; background: var(--teal); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 13px;"
                    >
                        "📤 Import Templates"
                    </button>
                </div>

                <Show when=move || import_error.get().is_some()>
                    <div style="font-size: 12px; color: var(--coral); margin-top: 8px;">
                        {move || import_error.get().unwrap_or_default()}
                    </div>
                </Show>

                <Show when=move || import_success.get()>
                    <div style="font-size: 12px; color: var(--teal); margin-top: 8px;">
                        "Templates imported successfully!"
                    </div>
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
                                <div style="margin-top: 4px;">
                                    <SchemaTypeInput value=edit_schema_type registered_types=registered_types />
                                </div>
                            </div>

                            <div>
                                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 4px;">
                                    <label style="font-size: 12px; font-weight: 500; color: var(--text-2);">
                                        "Template Config (JSON)"
                                    </label>
                                    <div style="display: flex; gap: 4px;">
                                        <button
                                            class="btn"
                                            on:click=move |_| handle_format_json(edit_config)
                                            style="padding: 4px 8px; font-size: 11px; background: var(--bg-secondary); color: var(--text-1); border: 1px solid var(--border); border-radius: 4px; cursor: pointer;"
                                        >
                                            "Format"
                                        </button>
                                        <button
                                            class="btn"
                                            on:click=move |_| handle_minify_json(edit_config)
                                            style="padding: 4px 8px; font-size: 11px; background: var(--bg-secondary); color: var(--text-1); border: 1px solid var(--border); border-radius: 4px; cursor: pointer;"
                                        >
                                            "Minify"
                                        </button>
                                    </div>
                                </div>
                                <textarea
                                    prop:value=move || edit_config.get()
                                    on:input=move |ev| handle_config_input(ev, edit_config, edit_config_error)
                                    style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 8px; padding: 8px; color: var(--text-1); font-size: 13px; font-family: var(--font-mono); min-height: 120px; margin-top: 4px; box-sizing: border-box;"
                                />
                                <Show when=move || edit_config_error.get().is_some()>
                                    <div style="font-size: 11px; color: var(--coral); margin-top: 4px;">
                                        {move || edit_config_error.get().unwrap_or_default()}
                                    </div>
                                </Show>
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

            // Bulk Delete Confirmation Modal (Phase 9d)
            <Show when=move || bulk_delete_confirm_id.get().is_some()>
                <div style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.5); display: flex; align-items: center; justify-content: center; z-index: 1000;">
                    <div style="background: var(--bg-1); border: 1px solid var(--border); border-radius: 8px; padding: 20px; max-width: 400px; width: 90%; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);">
                        <h3 style="font-size: 16px; font-weight: 600; margin-bottom: 8px;">
                            "Delete Templates?"
                        </h3>
                        <p style="font-size: 13px; color: var(--text-2); margin-bottom: 16px;">
                            {move || format!("Delete {}", bulk_delete_confirm_id.get().unwrap_or_default())}
                            " This action cannot be undone. Are you sure?"
                        </p>

                        <Show when=move || delete_error.get().is_some()>
                            <div style="font-size: 12px; color: var(--coral); margin-bottom: 12px;">
                                {move || delete_error.get().unwrap_or_default()}
                            </div>
                        </Show>

                        <div style="display: flex; gap: 8px; justify-content: flex-end;">
                            <button
                                class="btn"
                                on:click=move |_| bulk_delete_confirm_id.set(None)
                                style="padding: 8px 16px; background: var(--bg-tertiary); color: var(--text-1); border: 1px solid var(--border); border-radius: 8px; cursor: pointer; font-size: 13px;"
                            >
                                "Cancel"
                            </button>
                            <button
                                class="btn"
                                on:click=handle_bulk_delete_execute
                                style="padding: 8px 16px; background: var(--coral); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 13px;"
                            >
                                "Delete Templates"
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

            // Template Builder Modal (Phase 9b)
            <TemplateBuilder
                is_open=builder_open
                on_complete=Callback::new(handle_builder_complete)
                schema_type=new_schema_type
            />

            <TemplateLibrary
                is_open=library_open
                on_select=Callback::new(handle_library_select)
            />
        </div>
    }
}
