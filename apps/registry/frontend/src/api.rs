/// Shared data types mirroring the backend API shapes.
/// Kept local to avoid a WASM-incompatible workspace dependency.
use serde::{Deserialize, Serialize};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

// --- Data types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryStatus {
    pub did: String,
    pub endpoint: String,
    pub cert_fingerprint: String,
    pub agent_count: usize,
    pub peer_count: usize,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    #[serde(rename = "@type")]
    pub schema_type: String,
    pub name: String,
    pub did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAdvertisement {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "@type")]
    pub schema_type: String,
    pub name: String,
    pub provider: Provider,
    pub capability: Vec<String>,
    pub object_types: Vec<String>,
    pub requires_disclosure: Vec<String>,
    pub returns: Vec<String>,
    #[serde(default)]
    pub ttl_min: u64,
    pub signed_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Agent paired with its server-computed content hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEntry {
    pub hash: String,
    pub ad: AgentAdvertisement,
}

/// Paginated response from GET /api/agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentListResponse {
    pub items: Vec<AgentEntry>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
    pub total_pages: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryPeer {
    pub did: String,
    pub endpoint: String,
    pub cert_fingerprint: Option<String>,
    pub last_sync: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddPeerRequest {
    pub did: String,
    pub endpoint: String,
    pub cert_fingerprint: Option<String>,
}

// --- HTTP helpers ---

async fn fetch_json<T: for<'de> Deserialize<'de>>(url: &str) -> Result<T, String> {
    let window = web_sys::window().ok_or("no window")?;
    let mut opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::SameOrigin);

    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|e| format!("request error: {:?}", e))?;

    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("fetch error: {:?}", e))?;

    let resp: Response = resp_value.dyn_into().map_err(|_| "not a Response")?;

    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let json = JsFuture::from(resp.json().map_err(|e| format!("json() error: {:?}", e))?)
        .await
        .map_err(|e| format!("json await error: {:?}", e))?;

    serde_wasm_bindgen::from_value(json).map_err(|e| format!("deserialize error: {}", e))
}

async fn post_json<B: Serialize, T: for<'de> Deserialize<'de>>(
    url: &str,
    body: &B,
) -> Result<T, String> {
    let window = web_sys::window().ok_or("no window")?;
    let body_str =
        serde_json::to_string(body).map_err(|e| format!("serialize error: {}", e))?;

    let mut opts = RequestInit::new();
    opts.set_method("POST");
    opts.set_mode(RequestMode::SameOrigin);
    opts.set_body(&JsValue::from_str(&body_str));

    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|e| format!("request error: {:?}", e))?;
    request
        .headers()
        .set("Content-Type", "application/json")
        .map_err(|e| format!("header error: {:?}", e))?;

    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("fetch error: {:?}", e))?;

    let resp: Response = resp_value.dyn_into().map_err(|_| "not a Response")?;

    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let json = JsFuture::from(resp.json().map_err(|e| format!("json() error: {:?}", e))?)
        .await
        .map_err(|e| format!("json await error: {:?}", e))?;

    serde_wasm_bindgen::from_value(json).map_err(|e| format!("deserialize error: {}", e))
}

async fn delete_request(url: &str) -> Result<(), String> {
    let window = web_sys::window().ok_or("no window")?;
    let mut opts = RequestInit::new();
    opts.set_method("DELETE");
    opts.set_mode(RequestMode::SameOrigin);

    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|e| format!("request error: {:?}", e))?;

    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("fetch error: {:?}", e))?;

    let resp: Response = resp_value.dyn_into().map_err(|_| "not a Response")?;

    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }
    Ok(())
}

// --- Public API functions ---

pub async fn fetch_status() -> Result<RegistryStatus, String> {
    fetch_json("/api/status").await
}

pub async fn fetch_agents(
    q: Option<&str>,
    page: u32,
    per_page: u32,
) -> Result<AgentListResponse, String> {
    let mut url = format!("/api/agents?page={}&per_page={}", page, per_page);
    if let Some(q) = q.filter(|s| !s.is_empty()) {
        let encoded = js_sys::encode_uri_component(q);
        url.push_str(&format!("&q={}", encoded));
    }
    fetch_json(&url).await
}

pub async fn remove_agent(hash: &str) -> Result<(), String> {
    let encoded = js_sys::encode_uri_component(hash);
    let url = format!("/api/agents/{}", encoded);
    delete_request(&url).await
}

pub async fn fetch_peers() -> Result<Vec<RegistryPeer>, String> {
    fetch_json("/api/peers").await
}

pub async fn add_peer(req: &AddPeerRequest) -> Result<(), String> {
    let _: serde_json::Value = post_json("/api/peers", req).await?;
    Ok(())
}

pub async fn remove_peer(did: &str) -> Result<(), String> {
    let encoded = js_sys::encode_uri_component(did);
    let url = format!("/api/peers/{}", encoded);
    delete_request(&url).await
}

pub async fn sync_peer(did: &str) -> Result<usize, String> {
    #[derive(Deserialize)]
    struct SyncResult {
        merged: usize,
    }
    let encoded = js_sys::encode_uri_component(did);
    let url = format!("/api/peers/{}/sync", encoded);
    let window = web_sys::window().ok_or("no window")?;
    let mut opts = RequestInit::new();
    opts.set_method("POST");
    opts.set_mode(RequestMode::SameOrigin);
    let request = Request::new_with_str_and_init(&url, &opts)
        .map_err(|e| format!("request error: {:?}", e))?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("fetch error: {:?}", e))?;
    let resp: Response = resp_value.dyn_into().map_err(|_| "not a Response")?;
    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let json = JsFuture::from(resp.json().map_err(|e| format!("json() error: {:?}", e))?)
        .await
        .map_err(|e| format!("json await error: {:?}", e))?;
    let result: SyncResult = serde_wasm_bindgen::from_value(json)
        .map_err(|e| format!("deserialize error: {}", e))?;
    Ok(result.merged)
}
