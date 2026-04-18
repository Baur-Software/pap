use tauri::State;

use crate::db::prelude::DatabaseOps;
use crate::state::AppState;

/// Try to auto-generate and persist a template for the given schema type.
///
/// Only generates when the handshake envelope contains a `"result"` object and
/// no enabled template already covers this schema type. Errors are logged but
/// never propagated — template generation is advisory.
pub(crate) fn maybe_auto_generate_template(
    state: &State<'_, AppState>,
    schema_type: &str,
    content: &serde_json::Value,
) {
    let result_payload = match content.get("result") {
        Some(v) if v.is_object() => v,
        _ => return,
    };

    let has_template = state
        .db
        .has_enabled_template_for_schema_type(schema_type)
        .unwrap_or(true);

    if has_template {
        return;
    }

    let template = papillon_shared::generate_template_from_json_ld(schema_type, result_payload);
    if template.template_config.validate().is_ok() {
        if let Err(e) = state.db.insert_template(&template) {
            eprintln!("Failed to auto-generate template for {schema_type}: {e}");
        }
    }
}
