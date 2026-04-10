//! Settings as vocabulary — Papillon describes its own configuration using
//! schema.org `PropertyValueSpecification` objects. The renderer projects
//! them as form inputs. Agent settings follow the same pattern: the
//! specification comes from the agent's advertisement (via `pap://`),
//! the *values* are local overrides stored in `agent_settings`.

use serde_json::{json, Value};
use tauri::State;

use crate::error::PapillonError;
use crate::state::AppState;
use papillon_shared::db::DatabaseOps;
use papillon_shared::LlmProvider;

/// Return Papillon's own settings as schema.org vocabulary.
///
/// The response is a `SoftwareApplication` with an `ItemList` of
/// `PropertyValueSpecification` entries. The block renderer projects
/// these as interactive form fields — the same renderer used for
/// canvas blocks and agent output.
#[tauri::command]
pub fn get_settings_vocabulary(state: State<'_, AppState>) -> Result<Value, PapillonError> {
    let config = state
        .orchestrator_config
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?;

    Ok(json!({
        "@context": "https://schema.org",
        "@type": "SoftwareApplication",
        "name": "Papillon",
        "softwareVersion": env!("CARGO_PKG_VERSION"),
        "applicationCategory": "Principal Agent Protocol",
        "mainEntity": {
            "@type": "ItemList",
            "name": "Configuration",
            "itemListElement": [
                {
                    "@type": "PropertyValueSpecification",
                    "valueName": "mandate_ttl_hours",
                    "name": "Mandate TTL",
                    "description": "How long agent mandates remain valid (hours)",
                    "value": config.mandate_ttl_hours,
                    "defaultValue": 8,
                    "minValue": 1,
                    "maxValue": 168,
                    "stepValue": 1
                },
                {
                    "@type": "PropertyValueSpecification",
                    "valueName": "auto_approve_zero_disclosure",
                    "name": "Auto-approve zero disclosure",
                    "description": "Skip approval for mandates requiring zero data disclosure",
                    "value": config.auto_approve_zero_disclosure,
                    "defaultValue": true
                },
                {
                    "@type": "PropertyValueSpecification",
                    "valueName": "inference_substrate",
                    "name": "Inference Substrate",
                    "description": "Provider for enhanced reasoning (optional \u{2014} PAP works without it)",
                    "value": serialize_provider(&config.inference_substrate),
                    "defaultValue": "builtin",
                    "valuePattern": "none|builtin|ollama|mistral|huggingface|openai"
                }
            ]
        }
    }))
}

/// Apply a single setting change. Returns the updated vocabulary so the
/// renderer can refresh in one round-trip.
///
/// `target` is `"papillon"` for app-level settings, or an agent DID hash
/// for per-agent overrides stored in `agent_settings`.
#[tauri::command]
pub async fn apply_setting(
    state: State<'_, AppState>,
    target: String,
    value_name: String,
    new_value: Value,
) -> Result<Value, PapillonError> {
    match target.as_str() {
        "papillon" => {
            apply_papillon_setting(&state, &value_name, &new_value)?;
            get_settings_vocabulary(state)
        }
        agent_did_hash => {
            // Store in agent_settings table — local override for
            // any agent, local or remote. The specification comes
            // from the agent's advertisement; the VALUE lives here.
            let json_str = serde_json::to_string(&new_value)
                .map_err(|e| PapillonError::from(e.to_string()))?;
            state
                .db
                .set_agent_setting(agent_did_hash, &value_name, &json_str)
                .map_err(|e| PapillonError::from(e.0))?;
            get_agent_settings_vocabulary(&state, agent_did_hash)
        }
    }
}

/// Return an agent's configurable properties merged with local overrides.
///
/// The specification comes from the agent's `AgentAdvertisement`
/// (reachable via `pap://` on any registry). Local overrides from the
/// `agent_settings` table are merged in as `"value"` fields.
#[tauri::command]
pub fn get_agent_settings_vocabulary(
    state: &State<'_, AppState>,
    agent_did_hash: &str,
) -> Result<Value, PapillonError> {
    // 1. Find the agent's advertisement in local registries
    let (agent_name, mut properties) = {
        let registries = state
            .registries
            .read()
            .map_err(|e| PapillonError::from(e.to_string()))?;

        let mut found_name = String::from("Agent");
        let mut found_props = Vec::new();

        for registry in registries.values() {
            for ad in registry.all_advertisements() {
                // Compare by DID hash since that's what we store
                let hash = crate::commands::orchestrator::hash_agent_did(&ad.provider.did);
                if hash == agent_did_hash {
                    found_name = ad.name.clone();
                    found_props = ad.configurable_properties.clone();
                    break;
                }
            }
            if !found_props.is_empty() {
                break;
            }
        }

        (found_name, found_props)
    };

    // 2. Merge in local overrides from agent_settings table
    let overrides = state
        .db
        .get_agent_settings(agent_did_hash)
        .map_err(|e| PapillonError::from(e.0))?;

    for prop in &mut properties {
        if let Some(name) = prop.get("valueName").and_then(|v| v.as_str()) {
            if let Some(override_json) = overrides.get(name) {
                // Parse the JSON string back to a Value
                if let Ok(val) = serde_json::from_str::<Value>(override_json) {
                    prop.as_object_mut()
                        .map(|obj| obj.insert("value".into(), val));
                }
            }
        }
    }

    Ok(json!({
        "@context": "https://schema.org",
        "@type": "Service",
        "name": agent_name,
        "mainEntity": {
            "@type": "ItemList",
            "name": "Agent Settings",
            "itemListElement": properties
        }
    }))
}

// ── Internal helpers ────────────────────────────────────────────────────

/// Apply a Papillon-level setting and persist to SQLite.
fn apply_papillon_setting(
    state: &State<'_, AppState>,
    value_name: &str,
    new_value: &Value,
) -> Result<(), PapillonError> {
    let mut config = state
        .orchestrator_config
        .write()
        .map_err(|e| PapillonError::from(e.to_string()))?;

    match value_name {
        "mandate_ttl_hours" => {
            if let Some(v) = new_value.as_u64() {
                config.mandate_ttl_hours = v;
            }
        }
        "auto_approve_zero_disclosure" => {
            if let Some(v) = new_value.as_bool() {
                config.auto_approve_zero_disclosure = v;
            }
        }
        "inference_substrate" => {
            if let Some(provider_str) = new_value.as_str() {
                config.inference_substrate = match provider_str {
                    "none" => LlmProvider::None,
                    "builtin" => LlmProvider::BuiltIn {
                        model_id: "gemma-4-e2b".into(),
                    },
                    // For providers requiring configuration (API keys, endpoints),
                    // we only switch to them if they were already configured.
                    // The settings vocabulary Select only changes the provider type;
                    // detailed configuration stays in the LLM provider UI.
                    _ => return Ok(()),
                };
            }
        }
        _ => {
            return Err(PapillonError::from(format!(
                "Unknown Papillon setting: {}",
                value_name
            )));
        }
    }

    // Persist the updated config
    if let Ok(json) = serde_json::to_string(&*config) {
        let _ = state.db.set_setting("orchestrator_config", &json);
    }

    Ok(())
}

/// Serialize an LlmProvider to a vocabulary-friendly string.
fn serialize_provider(provider: &LlmProvider) -> &'static str {
    match provider {
        LlmProvider::None => "none",
        LlmProvider::BuiltIn { .. } => "builtin",
        LlmProvider::Ollama { .. } => "ollama",
        LlmProvider::Mistral { .. } => "mistral",
        LlmProvider::HuggingFace { .. } => "huggingface",
        LlmProvider::OpenAiCompatible { .. } => "openai",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_provider_all_variants() {
        assert_eq!(serialize_provider(&LlmProvider::None), "none");
        assert_eq!(
            serialize_provider(&LlmProvider::BuiltIn {
                model_id: "test".into()
            }),
            "builtin"
        );
        assert_eq!(
            serialize_provider(&LlmProvider::Ollama {
                endpoint: "".into(),
                model: "".into()
            }),
            "ollama"
        );
        assert_eq!(
            serialize_provider(&LlmProvider::Mistral {
                api_key: "".into(),
                model: "".into()
            }),
            "mistral"
        );
        assert_eq!(
            serialize_provider(&LlmProvider::HuggingFace {
                api_token: "".into(),
                model: "".into()
            }),
            "huggingface"
        );
        assert_eq!(
            serialize_provider(&LlmProvider::OpenAiCompatible {
                endpoint: "".into(),
                api_key: "".into(),
                model: "".into()
            }),
            "openai"
        );
    }
}
