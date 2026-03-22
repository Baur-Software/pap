use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use pap_federation::peer::RegistryPeer;
use pap_marketplace::AgentAdvertisement;

use crate::state::AppState;

/// Registry status and identity — returned by GET /api/status.
#[derive(Debug, Serialize)]
pub struct RegistryStatus {
    pub did: String,
    pub endpoint: String,
    pub cert_fingerprint: String,
    pub agent_count: usize,
    pub peer_count: usize,
    pub version: &'static str,
}

#[derive(Debug, Deserialize)]
pub struct AddPeerRequest {
    pub did: String,
    pub endpoint: String,
    pub cert_fingerprint: Option<String>,
}

/// Agent advertisement paired with its content hash, as returned by GET /api/agents.
/// The hash is the SHA-256 of the canonical advertisement bytes — the stable ID
/// used to remove agents via DELETE /api/agents/:hash.
#[derive(Debug, Serialize)]
pub struct AgentEntry {
    pub hash: String,
    pub ad: AgentAdvertisement,
}

/// Assemble the admin API router under `/api`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/status", get(get_status))
        .route("/api/agents", get(list_agents))
        .route("/api/agents", post(register_agent))
        .route("/api/agents/:hash", delete(remove_agent))
        .route("/api/peers", get(list_peers))
        .route("/api/peers", post(add_peer))
        .route("/api/peers/:did", delete(remove_peer))
        .route("/api/peers/:did/sync", post(sync_peer))
}

fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

fn auth_error() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": "unauthorized"})),
    )
        .into_response()
}

async fn get_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if !state.is_authorized(extract_bearer(&headers)) {
        return auth_error();
    }
    let registry = state.registry.lock().unwrap();
    Json(RegistryStatus {
        did: state.node_did.clone(),
        endpoint: state.node_endpoint.clone(),
        cert_fingerprint: state.cert_fingerprint.clone(),
        agent_count: registry.len(),
        peer_count: registry.peers().len(),
        version: env!("CARGO_PKG_VERSION"),
    })
    .into_response()
}

async fn list_agents(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if !state.is_authorized(extract_bearer(&headers)) {
        return auth_error();
    }
    let registry = state.registry.lock().unwrap();
    let entries: Vec<AgentEntry> = registry
        .all_advertisements()
        .iter()
        .map(|ad| AgentEntry {
            hash: ad.hash(),
            ad: ad.clone(),
        })
        .collect();
    Json(entries).into_response()
}

async fn register_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(ad): Json<AgentAdvertisement>,
) -> Response {
    if !state.is_authorized(extract_bearer(&headers)) {
        return auth_error();
    }
    let mut registry = state.registry.lock().unwrap();
    match registry.register_local(ad) {
        Ok(()) => (StatusCode::CREATED, Json(serde_json::json!({"ok": true}))).into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn remove_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> Response {
    if !state.is_authorized(extract_bearer(&headers)) {
        return auth_error();
    }
    let mut registry = state.registry.lock().unwrap();
    let removed = registry.remove_by_hash(&hash);
    if removed {
        Json(serde_json::json!({"ok": true})).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "agent not found"})),
        )
            .into_response()
    }
}

async fn list_peers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if !state.is_authorized(extract_bearer(&headers)) {
        return auth_error();
    }
    let registry = state.registry.lock().unwrap();
    Json(registry.peers()).into_response()
}

async fn add_peer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AddPeerRequest>,
) -> Response {
    if !state.is_authorized(extract_bearer(&headers)) {
        return auth_error();
    }
    let peer = match req.cert_fingerprint {
        Some(fp) => RegistryPeer::with_fingerprint(&req.did, &req.endpoint, &fp),
        None => RegistryPeer::new(&req.did, &req.endpoint),
    };
    let mut registry = state.registry.lock().unwrap();
    registry.add_peer(peer);
    (StatusCode::CREATED, Json(serde_json::json!({"ok": true}))).into_response()
}

async fn remove_peer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(did): Path<String>,
) -> Response {
    if !state.is_authorized(extract_bearer(&headers)) {
        return auth_error();
    }
    // URL-decode the DID (colons are valid in path segments but may be encoded)
    let did_decoded = urlencoding_decode(&did);
    let mut registry = state.registry.lock().unwrap();
    let removed = registry.remove_peer(&did_decoded);
    if removed {
        Json(serde_json::json!({"ok": true})).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "peer not found"})),
        )
            .into_response()
    }
}

async fn sync_peer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(did): Path<String>,
) -> Response {
    if !state.is_authorized(extract_bearer(&headers)) {
        return auth_error();
    }
    let did_decoded = urlencoding_decode(&did);
    let endpoint = {
        let registry = state.registry.lock().unwrap();
        registry
            .peers()
            .iter()
            .find(|p| p.did == did_decoded)
            .map(|p| p.endpoint.clone())
    };

    let endpoint = match endpoint {
        Some(e) => e,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "peer not found"})),
            )
                .into_response()
        }
    };

    // Query the peer for all advertisements (using the query-all approach)
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // Self-signed certs for federation
        .build()
        .unwrap();

    match client
        .get(format!("{}/federation/query?action=*", endpoint))
        .send()
        .await
    {
        Ok(resp) => {
            if let Ok(msg) =
                resp.json::<pap_federation::sync::FederationMessage>().await
            {
                if let pap_federation::sync::FederationMessage::QueryResponse {
                    advertisements,
                } = msg
                {
                    let count = {
                        let mut registry = state.registry.lock().unwrap();
                        registry.merge_remote(advertisements)
                    };
                    return Json(serde_json::json!({"ok": true, "merged": count}))
                        .into_response();
                }
            }
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "invalid response from peer"})),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

fn urlencoding_decode(s: &str) -> String {
    // Simple percent-decoding for DID path segments
    percent_decode(s)
}

fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (
                hex_val(bytes[i + 1]),
                hex_val(bytes[i + 2]),
            ) {
                result.push((h * 16 + l) as char);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
