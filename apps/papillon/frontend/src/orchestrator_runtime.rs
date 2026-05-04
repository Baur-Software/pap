use papillon_shared::{builtin_model_catalog, BuiltInModelInfo, LlmProvider, OrchestratorConfig, OrchestratorStatus};

pub fn builtin_models_for_runtime(is_tauri: bool) -> Vec<BuiltInModelInfo> {
    let models = builtin_model_catalog();
    if is_tauri {
        models
    } else {
        models
            .into_iter()
            .filter(|model| model.web_compatible)
            .collect()
    }
}

pub fn default_builtin_model_id(is_tauri: bool) -> String {
    builtin_models_for_runtime(is_tauri)
        .into_iter()
        .next()
        .map(|model| model.id)
        .unwrap_or_else(|| "gemma-4-e2b".to_string())
}

pub fn normalize_builtin_model_id(model_id: &str, is_tauri: bool) -> String {
    let models = builtin_models_for_runtime(is_tauri);
    if models.iter().any(|model| model.id == model_id) {
        model_id.to_string()
    } else {
        models
            .into_iter()
            .next()
            .map(|model| model.id)
            .unwrap_or_else(|| "gemma-4-e2b".to_string())
    }
}

pub fn fallback_status_for_config(config: &OrchestratorConfig) -> OrchestratorStatus {
    if matches!(config.inference_substrate, LlmProvider::None) {
        OrchestratorStatus::Unconfigured
    } else {
        OrchestratorStatus::Ready
    }
}
