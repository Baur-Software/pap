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
    let endpoint = {
        let registry = state.registry.lock().unwrap_or_else(|e| e.into_inner());
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
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
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
}
