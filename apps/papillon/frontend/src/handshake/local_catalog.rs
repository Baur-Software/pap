use std::collections::HashMap;

use serde::Deserialize;
use serde_json::{json, Value};

#[cfg(target_arch = "wasm32")]
use papillon_shared::WasmAgentRegistry;
use papillon_shared::WasmDynamicAgentDef;

use super::HandshakeResult;

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn default_response_jsonpath() -> String {
    "$".into()
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn default_timeout_secs() -> u64 {
    5
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
struct LocalEndpointConfig {
    url_template: String,
    method: LocalHttpMethod,
    #[serde(default)]
    headers: HashMap<String, String>,
    body_template: Option<String>,
    #[serde(default = "default_response_jsonpath")]
    response_jsonpath: String,
    response_schema_type: String,
    #[serde(default)]
    response_mapping: HashMap<String, String>,
    #[serde(default = "default_timeout_secs")]
    timeout_secs: u64,
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize, PartialEq)]
enum LocalHttpMethod {
    Get,
    Post,
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
pub(crate) fn decode_endpoint(def: &WasmDynamicAgentDef) -> Option<Value> {
    def.extra.get("endpoint").cloned()
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn execute_local_catalog_agent(
    agent_name: &str,
    query: &str,
) -> Result<HandshakeResult, String> {
    let registry = WasmAgentRegistry::open("papillon-agents")
        .await
        .map_err(|e| format!("Failed to open local catalog: {e}"))?;
    let def = registry
        .defs()
        .iter()
        .find(|def| def.name == agent_name)
        .ok_or_else(|| format!("Built-in agent '{agent_name}' is missing from the local catalog"))?;

    let endpoint_value = decode_endpoint(def)
        .ok_or_else(|| format!("Built-in agent '{agent_name}' has no executable endpoint"))?;
    let endpoint: LocalEndpointConfig = serde_json::from_value(endpoint_value)
        .map_err(|e| format!("Invalid endpoint config for '{agent_name}': {e}"))?;

    let result = fetch_endpoint_result(agent_name, &endpoint, query).await?;
    let schema_type = result["@type"]
        .as_str()
        .unwrap_or(&endpoint.response_schema_type)
        .to_string();

    Ok(HandshakeResult {
        schema_type: schema_type.clone(),
        content: json!({
            "@type": schema_type,
            "agent": agent_name,
            "query": query,
            "result": result,
        }),
        agent_name: agent_name.to_string(),
    })
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn execute_local_catalog_agent(
    agent_name: &str,
    _query: &str,
) -> Result<HandshakeResult, String> {
    Err(format!(
        "Built-in agent '{agent_name}' can only execute in the browser runtime"
    ))
}

#[cfg(target_arch = "wasm32")]
async fn fetch_endpoint_result(
    agent_name: &str,
    endpoint: &LocalEndpointConfig,
    query: &str,
) -> Result<Value, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Request, RequestInit, RequestMode, Response};

    let url = endpoint.url_template.replace("{query}", query);

    let opts = RequestInit::new();
    let method = match endpoint.method {
        LocalHttpMethod::Get => "GET",
        LocalHttpMethod::Post => "POST",
    };
    opts.set_method(method);
    opts.set_mode(RequestMode::Cors);

    if endpoint.timeout_secs > 0 {
        let _ = endpoint.timeout_secs;
    }

    if matches!(endpoint.method, LocalHttpMethod::Post) {
        let escaped_query = json_escape_str(query);
        let body = endpoint
            .body_template
            .as_deref()
            .unwrap_or("{}")
            .replace("{query}", &escaped_query);
        opts.set_body(&wasm_bindgen::JsValue::from_str(&body));
    }

    let request = Request::new_with_str_and_init(&url, &opts)
        .map_err(|e| format!("Failed to create request for '{agent_name}': {e:?}"))?;

    if matches!(endpoint.method, LocalHttpMethod::Post) {
        request
            .headers()
            .set("Content-Type", "application/json")
            .map_err(|e| format!("Failed to set content type: {e:?}"))?;
    }

    for (key, value) in &endpoint.headers {
        if value.contains('{') && value.contains('}') {
            return Err(format!(
                "Built-in agent '{agent_name}' needs additional setup before it can run here"
            ));
        }
        request
            .headers()
            .set(key, value)
            .map_err(|e| format!("Failed to set header '{key}': {e:?}"))?;
    }
    request
        .headers()
        .set("Accept", "application/json")
        .map_err(|e| format!("Failed to set Accept header: {e:?}"))?;

    let window = web_sys::window().ok_or("No browser window available")?;
    let response = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("Network request failed for '{agent_name}': {e:?}"))?;
    let response: Response = response
        .dyn_into()
        .map_err(|_| format!("Response cast failed for '{agent_name}'"))?;

    let text = JsFuture::from(
        response
            .text()
            .map_err(|e| format!("Response body failed for '{agent_name}': {e:?}"))?,
    )
    .await
    .map_err(|e| format!("Response read failed for '{agent_name}': {e:?}"))?
    .as_string()
    .unwrap_or_default();

    let parsed = serde_json::from_str::<Value>(&text).unwrap_or_else(|_| Value::String(text));

    if !response.ok() {
        let message = parsed
            .get("title")
            .or_else(|| parsed.get("message"))
            .or_else(|| parsed.get("error"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("HTTP {} from '{agent_name}'", response.status()));
        return Err(message);
    }

    if !endpoint.response_mapping.is_empty() {
        let mapped = build_mapped_response(
            &parsed,
            &endpoint.response_mapping,
            &endpoint.response_schema_type,
        );
        let field_count = mapped
            .as_object()
            .map(|m| m.keys().filter(|k| !k.starts_with('@')).count())
            .unwrap_or(0);
        if field_count > 0 {
            return Ok(mapped);
        }
    }

    if let Some(extracted) = extract_jsonpath(&parsed, &endpoint.response_jsonpath) {
        return Ok(wrap_extracted_value(
            extracted,
            &endpoint.response_schema_type,
        ));
    }

    Ok(wrap_extracted_value(
        parsed,
        &endpoint.response_schema_type,
    ))
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn build_mapped_response(
    json_body: &Value,
    mapping: &HashMap<String, String>,
    schema_type: &str,
) -> Value {
    let clean_type = schema_type.trim_start_matches("schema:");
    let mut obj = serde_json::Map::new();
    obj.insert("@context".into(), json!("https://schema.org"));
    obj.insert("@type".into(), json!(clean_type));

    for (property, jsonpath) in mapping {
        if let Some(extracted) = extract_jsonpath(json_body, jsonpath) {
            match &extracted {
                Value::Null => continue,
                Value::String(s) if s.is_empty() => continue,
                _ => {
                    obj.insert(property.clone(), extracted);
                }
            }
        }
    }

    Value::Object(obj)
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn wrap_extracted_value(extracted: Value, schema_type: &str) -> Value {
    let clean_type = schema_type.trim_start_matches("schema:");
    match &extracted {
        Value::Object(map) if map.contains_key("@type") => {
            let mut obj = map.clone();
            obj.entry("@context".to_string())
                .or_insert(json!("https://schema.org"));
            Value::Object(obj)
        }
        Value::Object(map) => {
            let mut obj = map.clone();
            obj.insert("@context".into(), json!("https://schema.org"));
            obj.insert("@type".into(), json!(clean_type));
            Value::Object(obj)
        }
        Value::String(_) => json!({
            "@context": "https://schema.org",
            "@type": clean_type,
            "description": extracted,
        }),
        Value::Array(_) => json!({
            "@context": "https://schema.org",
            "@type": clean_type,
            "mainEntity": {
                "@type": "ItemList",
                "itemListElement": extracted,
            }
        }),
        _ => json!({
            "@context": "https://schema.org",
            "@type": clean_type,
            "value": extracted,
        }),
    }
}

fn extract_jsonpath(value: &Value, path: &str) -> Option<Value> {
    let path = path.strip_prefix('$').unwrap_or(path);
    let segments: Vec<&str> = path.split('.').filter(|s| !s.is_empty()).collect();
    let mut current = value.clone();
    for segment in segments {
        if let Some(bracket_pos) = segment.find('[') {
            let field = &segment[..bracket_pos];
            let index_str = segment
                .get(bracket_pos + 1..segment.len().saturating_sub(1))
                .unwrap_or("");
            let index: usize = index_str.parse().ok()?;
            if !field.is_empty() {
                current = current.get(field)?.clone();
            }
            current = current.get(index)?.clone();
        } else {
            current = current.get(segment)?.clone();
        }
    }
    Some(current)
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn json_escape_str(input: &str) -> String {
    serde_json::to_string(input)
        .unwrap_or_else(|_| "\"\"".to_string())
        .trim_matches('"')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_def() -> WasmDynamicAgentDef {
        serde_json::from_value(json!({
            "schema_version": 1,
            "version": "0.1.0",
            "name": "DuckDuckGo Search",
            "provider": "DuckDuckGo",
            "description": "Search",
            "action": "schema:SearchAction",
            "object_types": ["schema:WebPage"],
            "requires_disclosure": [],
            "returns": ["schema:SearchResultsPage"],
            "llm_instructions": "",
            "subagents": [],
            "published_to": [],
            "configurable_properties": [],
            "created_at": "",
            "updated_at": "",
            "endpoint": {
                "url_template": "https://api.duckduckgo.com/?q={query}&format=json",
                "method": "Get",
                "response_jsonpath": "$.AbstractText",
                "response_schema_type": "schema:SearchResultsPage",
                "response_mapping": {
                    "name": "$.Heading",
                    "description": "$.AbstractText"
                }
            }
        }))
        .expect("sample def must deserialize")
    }

    #[test]
    fn decode_endpoint_reads_embedded_endpoint_json() {
        let endpoint = decode_endpoint(&sample_def()).expect("endpoint should exist");
        assert_eq!(endpoint["url_template"], "https://api.duckduckgo.com/?q={query}&format=json");
    }

    #[test]
    fn extract_jsonpath_reads_root_array_segments() {
        let value = json!([{ "label": "weather" }]);
        assert_eq!(
            extract_jsonpath(&value, "$[0].label"),
            Some(json!("weather"))
        );
    }

    #[test]
    fn wrap_extracted_value_builds_schema_object_for_scalars() {
        let wrapped = wrap_extracted_value(json!("San Diego"), "schema:Place");
        assert_eq!(wrapped["@type"], "Place");
        assert_eq!(wrapped["description"], "San Diego");
    }
}
