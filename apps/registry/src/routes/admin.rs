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

pub fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
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
    // DB first — persist before updating in-memory state.
    let hash = ad.hash();
    if let Err(e) = state.store.insert_agent(&hash, &ad).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }
    {
        let mut registry = state.registry.lock().unwrap();
        let _ = registry.register_local(ad); // duplicate silently ignored
    }
    (StatusCode::CREATED, Json(serde_json::json!({"ok": true, "hash": hash}))).into_response()
}

async fn remove_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> Response {
    if !state.is_authorized(extract_bearer(&headers)) {
        return auth_error();
    }
    // DB first — only remove from memory if persistence succeeds.
    let deleted = match state.store.delete_agent(&hash).await {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    if deleted {
        let mut registry = state.registry.lock().unwrap();
        registry.remove_by_hash(&hash);
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
    // DB first — persist before updating in-memory state.
    if let Err(e) = state.store.upsert_peer(&peer).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }
    {
        let mut registry = state.registry.lock().unwrap();
        registry.add_peer(peer);
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
    // DB first — only remove from memory if persistence succeeds.
    let deleted = match state.store.delete_peer(&did_decoded).await {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    if deleted {
        let mut registry = state.registry.lock().unwrap();
        registry.remove_peer(&did_decoded);
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

    // TODO(C2): validate stored cert_fingerprint against the actual TLS cert presented
    // during handshake. Until fingerprint pinning is implemented, self-signed certs are
    // accepted unconditionally and the stored fingerprint provides no MITM protection.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let resp = match client
        .get(format!("{}/federation/query?action=*", endpoint))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    let msg = match resp.json::<pap_federation::sync::FederationMessage>().await {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("Failed to deserialize federation response from {}: {e}", endpoint);
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("invalid response from peer: {e}")})),
            )
                .into_response();
        }
    };

    match msg {
        pap_federation::sync::FederationMessage::QueryResponse { advertisements } => {
            // Identify new ads without touching the in-memory registry yet.
            let new_ads: Vec<_> = {
                let registry = state.registry.lock().unwrap();
                let existing: std::collections::HashSet<String> =
                    registry.all_advertisements().iter().map(|a| a.hash()).collect();
                advertisements
                    .into_iter()
                    .filter(|ad| !existing.contains(&ad.hash()))
                    .collect()
            };

            // DB first — only merge into memory what was successfully persisted.
            let mut persisted = Vec::with_capacity(new_ads.len());
            for ad in new_ads {
                let hash = ad.hash();
                match state.store.insert_agent(&hash, &ad).await {
                    Ok(()) => persisted.push(ad),
                    Err(e) => tracing::error!("DB write failed for synced agent {hash}: {e}"),
                }
            }

            let merged = persisted.len();
            {
                let mut registry = state.registry.lock().unwrap();
                registry.merge_remote(persisted);
            }

            // Update last_sync timestamp in DB.
            if let Err(e) = state
                .store
                .update_peer_sync_time(&did_decoded, chrono::Utc::now())
                .await
            {
                tracing::warn!("Failed to update last_sync for peer {did_decoded}: {e}");
            }

            Json(serde_json::json!({"ok": true, "merged": merged})).into_response()
        }
        _ => {
            tracing::warn!("Unexpected federation message variant from {}", endpoint);
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "unexpected response type from peer"})),
            )
                .into_response()
        }
    }
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}
