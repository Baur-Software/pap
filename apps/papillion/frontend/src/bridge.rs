use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::prelude::*;

/// Check whether the Tauri IPC runtime is available.
/// Returns false when running in a plain browser via `trunk serve`.
fn tauri_available() -> bool {
    js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("__TAURI__"))
        .map(|v| !v.is_undefined())
        .unwrap_or(false)
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"], js_name = "invoke")]
    async fn tauri_invoke(cmd: &str, args: JsValue) -> JsValue;
}

/// Call a Tauri command with typed arguments and return type.
/// Returns `Err` when running outside the Tauri webview (browser mode).
pub async fn invoke<A: Serialize, R: DeserializeOwned>(
    command: &str,
    args: &A,
) -> Result<R, String> {
    if !tauri_available() {
        return Err(format!("Tauri runtime not available (command: {command})"));
    }
    let args_js = serde_wasm_bindgen::to_value(args).map_err(|e| e.to_string())?;
    let result = tauri_invoke(command, args_js).await;
    serde_wasm_bindgen::from_value(result).map_err(|e| e.to_string())
}

/// Call a Tauri command with no arguments.
/// Returns `Err` when running outside the Tauri webview (browser mode).
pub async fn invoke_no_args<R: DeserializeOwned>(command: &str) -> Result<R, String> {
    if !tauri_available() {
        return Err(format!("Tauri runtime not available (command: {command})"));
    }
    let empty = serde_wasm_bindgen::to_value(&serde_json::json!({})).map_err(|e| e.to_string())?;
    let result = tauri_invoke(command, empty).await;
    serde_wasm_bindgen::from_value(result).map_err(|e| e.to_string())
}
