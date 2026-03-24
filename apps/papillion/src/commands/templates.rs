use crate::state::AppState;
use papillion_shared::types::Template;
use serde_json::json;

/// Fetch all enabled global templates from the database.
///
/// This command implements zero-trust loading: templates are fetched
/// on every call directly from the database, not cached in AppState.
#[tauri::command]
pub async fn get_global_templates(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<Template>, String> {
    // Fetch enabled global templates from database every call (zero-trust)
    state
        .db
        .list_enabled_templates_for_principal(None)
        .map_err(|e| e.to_string())
}

/// Fetch all enabled templates for a specific profile + global templates.
///
/// Returns both profile-specific templates and global templates combined.
/// This supports per-profile template customization while maintaining
/// access to globally available templates.
#[tauri::command]
pub async fn get_profile_templates(
    state: tauri::State<'_, AppState>,
    principal_did: String,
) -> Result<Vec<Template>, String> {
    // Fetch enabled templates for this principal + global templates
    state
        .db
        .list_enabled_templates_for_principal(Some(&principal_did))
        .map_err(|e| e.to_string())
}

/// Create a new template in the database.
///
/// Requires a complete Template struct with:
/// - Unique template_name
/// - schema_type (e.g., "Recipe", "FlightReservation")
/// - template_config (JSON-LD declarative schema)
/// - Timestamps and metadata
#[tauri::command]
pub async fn create_template(
    state: tauri::State<'_, AppState>,
    template: Template,
) -> Result<(), String> {
    state
        .db
        .insert_template(&template)
        .map_err(|e| e.to_string())
}

/// Update an existing template in the database.
///
/// Updates the template identified by template_name.
/// Modifies: template_config, version, enabled flag, updated_at.
#[tauri::command]
pub async fn update_template(
    state: tauri::State<'_, AppState>,
    template: Template,
) -> Result<(), String> {
    state
        .db
        .update_template(&template)
        .map_err(|e| e.to_string())
}

/// Delete a template from the database by name.
///
/// Permanently removes the template. To disable without deletion,
/// use set_template_enabled() instead.
#[tauri::command]
pub async fn delete_template(
    state: tauri::State<'_, AppState>,
    template_name: String,
) -> Result<(), String> {
    state
        .db
        .delete_template(&template_name)
        .map_err(|e| e.to_string())
}

/// Enable or disable a template without deleting it.
///
/// Disabled templates are not loaded by the renderer registry.
/// This is a soft delete mechanism that preserves the template data.
#[tauri::command]
pub async fn set_template_enabled(
    state: tauri::State<'_, AppState>,
    template_name: String,
    enabled: bool,
) -> Result<(), String> {
    state
        .db
        .set_template_enabled(&template_name, enabled)
        .map_err(|e| e.to_string())
}

/// Export all global templates as JSON string.
///
/// Phase 9f: Returns a JSON string containing all global templates,
/// suitable for saving to a file or sharing with others.
#[tauri::command]
pub async fn export_templates(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let templates = state
        .db
        .list_enabled_templates_for_principal(None)
        .map_err(|e| e.to_string())?;

    serde_json::to_string_pretty(&templates)
        .map_err(|e| format!("Failed to serialize templates: {}", e))
}

/// Import templates from a JSON string.
///
/// Phase 9f: Parses JSON string and creates new templates in the database.
/// Skips templates with duplicate names. Returns count of imported templates.
#[tauri::command]
pub async fn import_templates(
    state: tauri::State<'_, AppState>,
    json_str: String,
) -> Result<serde_json::Value, String> {
    let templates: Vec<Template> =
        serde_json::from_str(&json_str).map_err(|e| format!("Invalid JSON: {}", e))?;

    let mut imported_count = 0;
    let mut skipped_count = 0;

    for template in templates {
        match state.db.insert_template(&template) {
            Ok(()) => imported_count += 1,
            Err(_) => skipped_count += 1, // Skip duplicates
        }
    }

    Ok(json!({
        "imported": imported_count,
        "skipped": skipped_count,
        "total": imported_count + skipped_count
    }))
}
