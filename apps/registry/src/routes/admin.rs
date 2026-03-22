use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use pap_federation::peer::RegistryPeer;
use pap_marketplace::AgentAdvertisement;

use crate::db::AgentEntry;
use crate::state::AppState;

// ── Request / response types ──────────────────────────────────────────────────

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

/// Query params for GET /api/agents.
#[derive(Debug, Deserialize)]
pub struct AgentListQuery {
    pub q: Option<String>,
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_per_page")]
    pub per_page: u32,
}
fn default_page() -> u32 { 1 }
fn default_per_page() -> u32 { 20 }

/// Paginated agent list response — replaces the old Vec<AgentEntry>.
#[derive(Debug, Serialize)]
pub struct AgentListResponse {
    pub items: Vec<AgentEntry>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
    pub total_pages: u32,
}

/// Assemble the admin API router under `/api`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/status", get(get_status))
        .route("/api/agents", get(list_agents))
        .route("/api/agents", post(register_agent))
        .route("/api/agents/{hash}", delete(remove_agent))
        .route("/api/peers", get(list_peers))
        .route("/api/peers", post(add_peer))
        .route("/api/peers/{did}", delete(remove_peer))
        .route("/api/peers/{did}/sync", post(sync_peer))
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

/// List agents with server-side search and pagination.
/// GET /api/agents?q=<text>&page=<n>&per_page=<n>
async fn list_agents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<AgentListQuery>,
) -> Response {
    if !state.is_authorized(extract_bearer(&headers)) {
        return auth_error();
    }
    let per_page = params.per_page.clamp(1, 200);
    match state
        .store
        .search_agents(params.q.as_deref(), params.page, per_page)
        .await
    {
        Ok(page) => {
            let total_pages = ((page.total as u32).saturating_add(per_page - 1)) / per_page;
            Json(AgentListResponse {
                items: page.items,
                total: page.total,
                page: page.page,
                per_page: page.per_page,
                total_pages: total_pages.max(1),
            })
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn register_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(ad): Json<AgentAdvertisement>,
) -> Response {
    if !state.is_authorized(extract_bearer(&headers)) {
        return auth_error();
    }
    // Verify Ed25519 signature before storing.
    {
        let registry = state.registry.lock().unwrap();
        if !registry.verify_advertisement(&ad) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "invalid or missing Ed25519 signature — signed_by DID must match the signature"})),
            )
                .into_response();
        }
    }
    // Register in-memory, then write-through to DB.
    // Critical: drop the Mutex guard before any .await.
    let result = {
        let mut registry = state.registry.lock().unwrap();
        registry.register_local(ad.clone())
    };
    match result {
        Ok(()) => {
            let hash = ad.hash();
            if let Err(e) = state.store.insert_agent(&hash, &ad).await {
                tracing::error!("DB write-through failed for agent {hash}: {e}");
            }
            (StatusCode::CREATED, Json(serde_json::json!({"ok": true, "hash": hash})))
                .into_response()
        }
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
    let removed = {
        let mut registry = state.registry.lock().unwrap();
        registry.remove_by_hash(&hash)
    };
    if removed {
        if let Err(e) = state.store.delete_agent(&hash).await {
            tracing::error!("DB delete failed for agent {hash}: {e}");
        }
        Json(serde_json::json!({"ok": true})).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "agent not found"})),
        )
            .into_response()
    }
}

/// List peers — reads from DB so last_sync is always current.
async fn list_peers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if !state.is_authorized(extract_bearer(&headers)) {
        return auth_error();
    }
    match state.store.load_all_peers().await {
        Ok(peers) => Json(peers).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
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
    {
        let mut registry = state.registry.lock().unwrap();
        registry.add_peer(peer.clone());
    }
    if let Err(e) = state.store.upsert_peer(&peer).await {
        tracing::error!("DB write-through failed for peer {}: {e}", peer.did);
    }
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
    let did_decoded = percent_decode(&did);
    let removed = {
        let mut registry = state.registry.lock().unwrap();
        registry.remove_peer(&did_decoded)
    };
    if removed {
        if let Err(e) = state.store.delete_peer(&did_decoded).await {
            tracing::error!("DB delete failed for peer {did_decoded}: {e}");
        }
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
    let did_decoded = percent_decode(&did);
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

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    match client
        .get(format!("{}/federation/query?action=*", endpoint))
        .send()
        .await
    {
        Ok(resp) => {
            if let Ok(msg) = resp.json::<pap_federation::sync::FederationMessage>().await {
                if let pap_federation::sync::FederationMessage::QueryResponse {
                    advertisements,
                } = msg
                {
                    // Snapshot before-hashes, merge, collect new ads for write-through.
                    let new_ads = {
                        let mut registry = state.registry.lock().unwrap();
                        let before: std::collections::HashSet<String> =
                            registry.all_advertisements().iter().map(|a| a.hash()).collect();
                        registry.merge_remote(advertisements);
                        registry
                            .all_advertisements()
                            .iter()
                            .filter(|a| !before.contains(&a.hash()))
                            .cloned()
                            .collect::<Vec<_>>()
                    };

                    let merged = new_ads.len();
                    for ad in &new_ads {
                        let hash = ad.hash();
                        if let Err(e) = state.store.insert_agent(&hash, ad).await {
                            tracing::error!("DB write-through failed for synced agent {hash}: {e}");
                        }
                    }

                    // Update last_sync timestamp in DB.
                    if let Err(e) = state
                        .store
                        .update_peer_sync_time(&did_decoded, chrono::Utc::now())
                        .await
                    {
                        tracing::warn!("Failed to update last_sync for peer {did_decoded}: {e}");
                    }

                    return Json(serde_json::json!({"ok": true, "merged": merged}))
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

fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
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
