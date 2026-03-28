use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch, js_namespace = ["window", "__TAURI__", "core"], js_name = "invoke")]
    async fn tauri_invoke(cmd: &str, args: JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch, js_namespace = ["window", "__TAURI__", "event"], js_name = "listen")]
    async fn tauri_listen(event: &str, handler: &Closure<dyn FnMut(JsValue)>)
        -> Result<JsValue, JsValue>;
}

/// Returns true when running inside Tauri (IPC bridge available).
pub fn tauri_available() -> bool {
    js_sys::Reflect::get(&web_sys::window().unwrap(), &JsValue::from_str("__TAURI__"))
        .map(|v| !v.is_undefined())
        .unwrap_or(false)
}

/// Call a Tauri command with typed arguments and return type.
pub async fn invoke<A: Serialize, R: DeserializeOwned>(
    command: &str,
    args: &A,
) -> Result<R, String> {
    if !tauri_available() {
        return Err("Tauri IPC not available (running outside Tauri shell)".into());
    }
    let args_js = serde_wasm_bindgen::to_value(args).map_err(|e| e.to_string())?;
    let result = tauri_invoke(command, args_js)
        .await
        .map_err(|e| e.as_string().unwrap_or_else(|| format!("{:?}", e)))?;
    serde_wasm_bindgen::from_value(result).map_err(|e| e.to_string())
}

/// Call a Tauri command with no arguments.
pub async fn invoke_no_args<R: DeserializeOwned>(command: &str) -> Result<R, String> {
    if !tauri_available() {
        return Err("Tauri IPC not available (running outside Tauri shell)".into());
    }
    let empty = serde_wasm_bindgen::to_value(&serde_json::json!({})).map_err(|e| e.to_string())?;
    let result = tauri_invoke(command, empty)
        .await
        .map_err(|e| e.as_string().unwrap_or_else(|| format!("{:?}", e)))?;
    serde_wasm_bindgen::from_value(result).map_err(|e| e.to_string())
}

/// Listen for a Tauri event. The callback receives the deserialized payload.
/// The closure is intentionally leaked (lives for app lifetime).
pub fn listen<T: DeserializeOwned + 'static>(event: &str, callback: impl Fn(T) + 'static) {
    if !tauri_available() {
        return;
    }
    let event = event.to_string();
    let closure = Closure::new(move |raw: JsValue| {
        // Tauri event shape: { event: string, payload: T }
        if let Ok(payload_js) = js_sys::Reflect::get(&raw, &JsValue::from_str("payload")) {
            if let Ok(payload) = serde_wasm_bindgen::from_value::<T>(payload_js) {
                callback(payload);
            }
        }
    });
    wasm_bindgen_futures::spawn_local(async move {
        let _ = tauri_listen(&event, &closure).await;
        closure.forget(); // Leak — lives for app lifetime
    });
}
