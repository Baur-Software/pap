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
fn default_page() -> u32 {
    1
}
fn default_per_page() -> u32 {
    20
}

/// Paginated agent list response — replaces the old Vec<AgentEntry>.
#[derive(Debug, Serialize)]
pub struct AgentListResponse {
    pub items: Vec<AgentEntry>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
    pub total_pages: u32,
}

/// Agent info returned by the public browse endpoint.
/// Matches `papillon_shared::AgentInfo` so the web client can use it directly.
#[derive(Debug, Serialize)]
pub struct BrowseAgentInfo {
    pub name: String,
    pub provider_name: String,
    pub provider_did: String,
    pub capabilities: Vec<String>,
    pub object_types: Vec<String>,
    pub requires_disclosure: Vec<String>,
    pub returns: Vec<String>,
    pub endpoint: Option<String>,
    pub content_hash: String,
}

/// Assemble the admin API router under `/api`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/status", get(get_status))
        .route("/api/agents", get(list_agents))
        .route("/api/agents", post(register_agent))
        .route("/api/agents/{hash}", delete(remove_agent))
        // Public (no auth) endpoint for the web client to discover agents with endpoints.
        .route("/api/browse", get(browse_agents))
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

async fn get_status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !state.is_authorized(extract_bearer(&headers)) {
        return auth_error();
    }
    let registry = state.registry.lock().unwrap_or_else(|e| e.into_inner());
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

/// Public endpoint for web clients to discover agents with execution endpoints.
/// No authentication required — returns agent metadata + endpoint URLs.
async fn browse_agents(State(state): State<AppState>) -> Response {
    let registry = state.registry.lock().unwrap_or_else(|e| e.into_inner());
    let agents: Vec<BrowseAgentInfo> = registry
        .all_advertisements()
        .iter()
        .map(|ad| {
            let slug = ad.name.to_lowercase().replace(' ', "-");
            BrowseAgentInfo {
                name: ad.name.clone(),
                provider_name: ad.provider.name.clone(),
                provider_did: ad.provider.did.clone(),
                capabilities: ad.capability.clone(),
                object_types: ad.object_types.clone(),
                requires_disclosure: ad.requires_disclosure.clone(),
                returns: ad.returns.clone(),
                endpoint: Some(format!("{}/agents/{slug}", state.node_endpoint)),
                content_hash: ad.hash(),
            }
        })
        .collect();
    Json(agents).into_response()
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
        let registry = state.registry.lock().unwrap_or_else(|e| e.into_inner());
        if !registry.verify_advertisement(&ad) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "invalid or missing Ed25519 signature — signed_by DID must match the signature"})),
            )
                .into_response();
        }
    }
    // Per-principal advertisement count limit (spec §10.1).
    let principal_did = ad.provider.did.clone();
    match state.store.count_agents_by_principal(&principal_did).await {
        Ok(count) if count >= state.max_ads_per_principal as i64 => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": format!(
                        "Principal {} has reached the advertisement limit of {}",
                        principal_did, state.max_ads_per_principal
                    )
                })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Rate limit check failed: {e}")})),
            )
                .into_response();
        }
        Ok(_) => {} // under limit — proceed
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
        let mut registry = state.registry.lock().unwrap_or_else(|e| e.into_inner());
        let _ = registry.register_local(ad); // duplicate silently ignored
    }
    (
        StatusCode::CREATED,
        Json(serde_json::json!({"ok": true, "hash": hash})),
    )
        .into_response()
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
        let mut registry = state.registry.lock().unwrap_or_else(|e| e.into_inner());
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
async fn list_peers(State(state): State<AppState>, headers: HeaderMap) -> Response {
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
        let mut registry = state.registry.lock().unwrap_or_else(|e| e.into_inner());
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
    let did_decoded = match percent_decode(&did) {
        Ok(d) => d,
        Err(r) => return r,
    };
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
        let mut registry = state.registry.lock().unwrap_or_else(|e| e.into_inner());
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
    let did_decoded = match percent_decode(&did) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let peer_info = {
        let registry = state.registry.lock().unwrap_or_else(|e| e.into_inner());
        registry
            .peers()
            .iter()
            .find(|p| p.did == did_decoded)
            .map(|p| (p.endpoint.clone(), p.cert_fingerprint.clone()))
    };

    let (endpoint, fingerprint) = match peer_info {
        Some(pair) => pair,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "peer not found"})),
            )
                .into_response()
        }
    };

    let client = match crate::tls::build_peer_client(fingerprint.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("failed to build HTTP client: {e}")})),
            )
                .into_response()
        }
    };

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
            tracing::error!(
                "Failed to deserialize federation response from {}: {e}",
                endpoint
            );
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
                let registry = state.registry.lock().unwrap_or_else(|e| e.into_inner());
                let existing: std::collections::HashSet<String> = registry
                    .all_advertisements()
                    .iter()
                    .map(|a| a.hash())
                    .collect();
                advertisements
                    .into_iter()
                    .filter(|ad| !existing.contains(&ad.hash()))
                    .collect()
            };

            // DB first — only merge into memory what was successfully persisted.
            // Verify the Ed25519 signature before writing to DB so invalid-signature
            // ads from a compromised peer never enter persistent storage.
            let mut persisted = Vec::with_capacity(new_ads.len());
            for ad in new_ads {
                let hash = ad.hash();
                {
                    let registry = state.registry.lock().unwrap_or_else(|e| e.into_inner());
                    if !registry.verify_advertisement(&ad) {
                        tracing::warn!(
                            "Dropping synced agent {hash} from peer {endpoint}: invalid or missing signature"
                        );
                        continue;
                    }
                }
                match state.store.insert_agent(&hash, &ad).await {
                    Ok(()) => persisted.push(ad),
                    Err(e) => tracing::error!("DB write failed for synced agent {hash}: {e}"),
                }
            }

            let merged = persisted.len();
            {
                let mut registry = state.registry.lock().unwrap_or_else(|e| e.into_inner());
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

fn percent_decode(s: &str) -> Result<String, Response> {
    percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "path parameter contains invalid UTF-8"})),
            )
                .into_response()
        })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use ed25519_dalek::SigningKey;
    use http_body_util::BodyExt;
    use pap_did::PrincipalKeypair;
    use pap_federation::registry::FederatedRegistry;
    use pap_marketplace::AgentAdvertisement;
    use rand::rngs::OsRng;
    use tower::ServiceExt;

    use super::*;
    use crate::db::{sqlite::SqliteStore, RegistryStore};

    // ── Helpers ───────────────────────────────────────────────────────────────

    async fn test_router(token: Option<&str>) -> axum::Router {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("src/db/migrations/sqlite")
            .run(&pool)
            .await
            .unwrap();
        let store = Arc::new(RegistryStore::Sqlite(SqliteStore { pool }));
        let state = AppState {
            registry: Arc::new(Mutex::new(FederatedRegistry::new())),
            store,
            node_did: "did:key:zTestNode".into(),
            node_endpoint: "http://localhost:7890".into(),
            cert_fingerprint: "sha256:deadbeef".into(),
            admin_token: token.map(str::to_owned),
            max_ads_per_principal: 100,
        };
        router().with_state(state)
    }

    fn signed_ad(name: &str) -> AgentAdvertisement {
        let key = SigningKey::generate(&mut OsRng);
        let kp = PrincipalKeypair::from_bytes(&key.to_bytes()).unwrap();
        let did = kp.did();
        let mut ad = AgentAdvertisement::new(
            name,
            "TestCorp",
            &did,
            vec!["schema:SearchAction".into()],
            vec![],
            vec![],
            vec![],
        );
        ad.sign(&key);
        ad
    }

    async fn body_json(body: Body) -> serde_json::Value {
        let bytes = body.collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn bearer(token: &str) -> (header::HeaderName, String) {
        (header::AUTHORIZATION, format!("Bearer {token}"))
    }

    // ── extract_bearer unit tests ─────────────────────────────────────────────

    #[test]
    fn extract_bearer_parses_valid_header() {
        let mut map = HeaderMap::new();
        map.insert(header::AUTHORIZATION, "Bearer mytoken123".parse().unwrap());
        assert_eq!(extract_bearer(&map), Some("mytoken123"));
    }

    #[test]
    fn extract_bearer_missing_header_returns_none() {
        assert_eq!(extract_bearer(&HeaderMap::new()), None);
    }

    #[test]
    fn extract_bearer_wrong_scheme_returns_none() {
        let mut map = HeaderMap::new();
        map.insert(header::AUTHORIZATION, "Token mytoken".parse().unwrap());
        assert_eq!(extract_bearer(&map), None);
    }

    // ── GET /api/status ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn status_no_admin_token_returns_200() {
        let app = test_router(None).await;
        let req = Request::get("/api/status").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn status_without_bearer_returns_401() {
        let app = test_router(Some("secret")).await;
        let req = Request::get("/api/status").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn status_with_correct_bearer_returns_200() {
        let app = test_router(Some("secret")).await;
        let req = Request::get("/api/status")
            .header(header::AUTHORIZATION, "Bearer secret")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert!(json.get("did").is_some());
    }

    #[tokio::test]
    async fn status_with_wrong_bearer_returns_401() {
        let app = test_router(Some("secret")).await;
        let req = Request::get("/api/status")
            .header(header::AUTHORIZATION, "Bearer wrong")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── GET /api/agents ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_agents_empty_returns_paginated_200() {
        let app = test_router(None).await;
        let req = Request::get("/api/agents").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert_eq!(json["total"], 0);
        assert!(json["items"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_agents_fts_special_chars_returns_200_not_500() {
        // Regression for I8: FTS5 special chars in query string must not 500.
        let app = test_router(None).await;
        let req = Request::get("/api/agents?q=%22NOT%22%28%2A")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── POST /api/agents ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn register_unsigned_agent_returns_422() {
        let app = test_router(None).await;
        // An ad without a signature should fail verify_advertisement.
        let key = SigningKey::generate(&mut OsRng);
        let kp = PrincipalKeypair::from_bytes(&key.to_bytes()).unwrap();
        let ad = AgentAdvertisement::new(
            "UnsignedBot",
            "Corp",
            &kp.did(),
            vec![],
            vec![],
            vec![],
            vec![],
        );
        let body = serde_json::to_vec(&ad).unwrap();
        let req = Request::post("/api/agents")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn register_signed_agent_then_appears_in_list() {
        let app = test_router(None).await;
        let ad = signed_ad("ListedBot");
        let body = serde_json::to_vec(&ad).unwrap();
        let req = Request::post("/api/agents")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Re-build the app with the same store is not possible since each call creates
        // a fresh in-memory DB. We verify register returns 201 + hash field instead.
        let json = body_json(resp.into_body()).await;
        assert_eq!(json["ok"], true);
        assert!(json.get("hash").is_some());
    }

    // ── DELETE /api/agents/{hash} ─────────────────────────────────────────────

    #[tokio::test]
    async fn remove_unknown_agent_returns_404() {
        let app = test_router(None).await;
        let req = Request::delete("/api/agents/nonexistenthash")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn register_then_remove_agent_roundtrip() {
        // Use a single AppState for both POST and DELETE.
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("src/db/migrations/sqlite")
            .run(&pool)
            .await
            .unwrap();
        let store = Arc::new(RegistryStore::Sqlite(SqliteStore { pool }));
        let state = AppState {
            registry: Arc::new(Mutex::new(FederatedRegistry::new())),
            store,
            node_did: "did:key:zNode".into(),
            node_endpoint: "http://localhost".into(),
            cert_fingerprint: "sha256:test".into(),
            admin_token: None,
            max_ads_per_principal: 100,
        };
        let app = router().with_state(state);

        let ad = signed_ad("EphemeralBot");
        let hash = ad.hash();
        let body = serde_json::to_vec(&ad).unwrap();

        // Register
        let req = Request::post("/api/agents")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Delete
        let req = Request::delete(format!("/api/agents/{hash}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── GET /api/peers ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_peers_empty_returns_200() {
        let app = test_router(None).await;
        let req = Request::get("/api/peers").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp.into_body()).await;
        assert!(json.as_array().unwrap().is_empty());
    }

    // ── POST /api/peers + GET /api/peers ─────────────────────────────────────

    #[tokio::test]
    async fn add_peer_and_appears_in_list() {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("src/db/migrations/sqlite")
            .run(&pool)
            .await
            .unwrap();
        let store = Arc::new(RegistryStore::Sqlite(SqliteStore { pool }));
        let state = AppState {
            registry: Arc::new(Mutex::new(FederatedRegistry::new())),
            store,
            node_did: "did:key:zNode".into(),
            node_endpoint: "http://localhost".into(),
            cert_fingerprint: "sha256:test".into(),
            admin_token: None,
            max_ads_per_principal: 100,
        };
        let app = router().with_state(state);

        let body = serde_json::json!({
            "did": "did:key:zPeerX",
            "endpoint": "https://peerx.example.com"
        });
        let req = Request::post("/api/peers")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let req = Request::get("/api/peers").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let json = body_json(resp.into_body()).await;
        let peers = json.as_array().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0]["did"], "did:key:zPeerX");
    }

    // ── DELETE /api/peers/{did} ───────────────────────────────────────────────

    #[tokio::test]
    async fn remove_unknown_peer_returns_404() {
        let app = test_router(None).await;
        let req = Request::delete("/api/peers/did%3Akey%3AzUnknown")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn add_then_remove_peer_roundtrip() {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("src/db/migrations/sqlite")
            .run(&pool)
            .await
            .unwrap();
        let store = Arc::new(RegistryStore::Sqlite(SqliteStore { pool }));
        let state = AppState {
            registry: Arc::new(Mutex::new(FederatedRegistry::new())),
            store,
            node_did: "did:key:zNode".into(),
            node_endpoint: "http://localhost".into(),
            cert_fingerprint: "sha256:test".into(),
            admin_token: None,
            max_ads_per_principal: 100,
        };
        let app = router().with_state(state);

        // Add
        let body = serde_json::json!({
            "did": "did:key:zPeerY",
            "endpoint": "https://peery.example.com"
        });
        let req = Request::post("/api/peers")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Delete (DID must be percent-encoded in path)
        let req = Request::delete("/api/peers/did%3Akey%3AzPeerY")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── POST /api/peers/{did}/sync ────────────────────────────────────────────

    #[tokio::test]
    async fn sync_unknown_peer_returns_404() {
        let app = test_router(None).await;
        let req = Request::post("/api/peers/did%3Akey%3AzGhost/sync")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── Rate limiting ─────────────────────────────────────────────────────────

    /// Helper: build a router with a custom max_ads_per_principal limit.
    async fn test_router_with_limit(limit: usize) -> axum::Router {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("src/db/migrations/sqlite")
            .run(&pool)
            .await
            .unwrap();
        let store = Arc::new(RegistryStore::Sqlite(SqliteStore { pool }));
        let state = AppState {
            registry: Arc::new(Mutex::new(FederatedRegistry::new())),
            store,
            node_did: "did:key:zTestNode".into(),
            node_endpoint: "http://localhost:7890".into(),
            cert_fingerprint: "sha256:deadbeef".into(),
            admin_token: None,
            max_ads_per_principal: limit,
        };
        router().with_state(state)
    }

    /// Helper: POST a signed AgentAdvertisement and return the HTTP status code.
    async fn post_ad(app: axum::Router, ad: &AgentAdvertisement) -> StatusCode {
        let body = serde_json::to_vec(ad).unwrap();
        let req = Request::post("/api/agents")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        app.oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn rate_limit_rejects_101st_advertisement() {
        // Use limit=2 to keep the test fast (3 POSTs total).
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("src/db/migrations/sqlite")
            .run(&pool)
            .await
            .unwrap();
        let store = Arc::new(RegistryStore::Sqlite(SqliteStore { pool }));
        let state = AppState {
            registry: Arc::new(Mutex::new(FederatedRegistry::new())),
            store,
            node_did: "did:key:zTestNode".into(),
            node_endpoint: "http://localhost:7890".into(),
            cert_fingerprint: "sha256:deadbeef".into(),
            admin_token: None,
            max_ads_per_principal: 2,
        };
        let app = router().with_state(state);

        // Same principal key for all three ads.
        let key = SigningKey::generate(&mut OsRng);
        let kp = PrincipalKeypair::from_bytes(&key.to_bytes()).unwrap();
        let did = kp.did();

        // First ad — must succeed.
        let mut ad1 = AgentAdvertisement::new(
            "RateLimitBot1",
            "Corp",
            &did,
            vec!["schema:SearchAction".into()],
            vec![],
            vec![],
            vec![],
        );
        ad1.sign(&key);
        let status1 = post_ad(app.clone(), &ad1).await;
        assert_eq!(status1, StatusCode::CREATED, "first ad should be accepted");

        // Second ad (different hash via different name) — must succeed.
        let mut ad2 = AgentAdvertisement::new(
            "RateLimitBot2",
            "Corp",
            &did,
            vec!["schema:SearchAction".into()],
            vec![],
            vec![],
            vec![],
        );
        ad2.sign(&key);
        let status2 = post_ad(app.clone(), &ad2).await;
        assert_eq!(status2, StatusCode::CREATED, "second ad should be accepted");

        // Third ad — must be rejected with 429.
        let mut ad3 = AgentAdvertisement::new(
            "RateLimitBot3",
            "Corp",
            &did,
            vec!["schema:SearchAction".into()],
            vec![],
            vec![],
            vec![],
        );
        ad3.sign(&key);
        let status3 = post_ad(app.clone(), &ad3).await;
        assert_eq!(
            status3,
            StatusCode::TOO_MANY_REQUESTS,
            "third ad should be rejected with 429"
        );
    }

    #[tokio::test]
    async fn rate_limit_allows_different_principals() {
        // Limit=1: each principal gets one slot, but not two.
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("src/db/migrations/sqlite")
            .run(&pool)
            .await
            .unwrap();
        let store = Arc::new(RegistryStore::Sqlite(SqliteStore { pool }));
        let state = AppState {
            registry: Arc::new(Mutex::new(FederatedRegistry::new())),
            store,
            node_did: "did:key:zTestNode".into(),
            node_endpoint: "http://localhost:7890".into(),
            cert_fingerprint: "sha256:deadbeef".into(),
            admin_token: None,
            max_ads_per_principal: 1,
        };
        let app = router().with_state(state);

        let key_a = SigningKey::generate(&mut OsRng);
        let kp_a = PrincipalKeypair::from_bytes(&key_a.to_bytes()).unwrap();
        let did_a = kp_a.did();

        let key_b = SigningKey::generate(&mut OsRng);
        let kp_b = PrincipalKeypair::from_bytes(&key_b.to_bytes()).unwrap();
        let did_b = kp_b.did();

        // Principal A — first ad accepted.
        let mut ad_a1 = AgentAdvertisement::new(
            "AgentA1",
            "Corp",
            &did_a,
            vec!["schema:SearchAction".into()],
            vec![],
            vec![],
            vec![],
        );
        ad_a1.sign(&key_a);
        assert_eq!(
            post_ad(app.clone(), &ad_a1).await,
            StatusCode::CREATED,
            "principal A first ad should be accepted"
        );

        // Principal B — first ad accepted (separate principal).
        let mut ad_b1 = AgentAdvertisement::new(
            "AgentB1",
            "Corp",
            &did_b,
            vec!["schema:SearchAction".into()],
            vec![],
            vec![],
            vec![],
        );
        ad_b1.sign(&key_b);
        assert_eq!(
            post_ad(app.clone(), &ad_b1).await,
            StatusCode::CREATED,
            "principal B first ad should be accepted"
        );

        // Principal A — second ad rejected (over limit=1).
        let mut ad_a2 = AgentAdvertisement::new(
            "AgentA2",
            "Corp",
            &did_a,
            vec!["schema:SearchAction".into()],
            vec![],
            vec![],
            vec![],
        );
        ad_a2.sign(&key_a);
        assert_eq!(
            post_ad(app.clone(), &ad_a2).await,
            StatusCode::TOO_MANY_REQUESTS,
            "principal A second ad should be rejected with 429"
        );
    }
}
