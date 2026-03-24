use leptos::prelude::*;
use serde::{Deserialize, Serialize};

// ── Shared data types ──────────────────────────────────────────────────────────

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEntry {
    pub hash: String,
    pub ad: AgentAdvertisement,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

// ── Server functions ───────────────────────────────────────────────────────────

#[server]
pub async fn get_status() -> Result<RegistryStatus, ServerFnError> {
    use crate::routes::admin::extract_bearer;
    use crate::state::AppState;
    use axum::http::HeaderMap;
    let headers: HeaderMap = leptos_axum::extract()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("no state"))?;
    if !state.is_authorized(extract_bearer(&headers)) {
        return Err(ServerFnError::new("unauthorized"));
    }
    let (agent_count, peer_count) = {
        let registry = state.registry.lock().unwrap();
        (registry.len(), registry.peers().len())
    };
    Ok(RegistryStatus {
        did: state.node_did.clone(),
        endpoint: state.node_endpoint.clone(),
        cert_fingerprint: state.cert_fingerprint.clone(),
        agent_count,
        peer_count,
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[server]
pub async fn list_agents(
    q: Option<String>,
    page: u32,
    per_page: u32,
) -> Result<AgentListResponse, ServerFnError> {
    use crate::routes::admin::extract_bearer;
    use crate::state::AppState;
    use axum::http::HeaderMap;
    let headers: HeaderMap = leptos_axum::extract()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("no state"))?;
    if !state.is_authorized(extract_bearer(&headers)) {
        return Err(ServerFnError::new("unauthorized"));
    }
    let per_page = per_page.clamp(1, 200);
    let db_page = state
        .store
        .search_agents(q.as_deref().filter(|s| !s.is_empty()), page, per_page)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // JSON round-trip: server AgentEntry (pap_marketplace ad) → wire JSON → ui AgentEntry
    let items_json =
        serde_json::to_string(&db_page.items).map_err(|e| ServerFnError::new(e.to_string()))?;
    let items: Vec<AgentEntry> =
        serde_json::from_str(&items_json).map_err(|e| ServerFnError::new(e.to_string()))?;

    let total_pages = ((db_page.total as u32).saturating_add(per_page - 1))
        .checked_div(per_page)
        .unwrap_or(1)
        .max(1);

    Ok(AgentListResponse {
        items,
        total: db_page.total,
        page: db_page.page,
        per_page: db_page.per_page,
        total_pages,
    })
}

#[server]
pub async fn remove_agent(hash: String) -> Result<(), ServerFnError> {
    use crate::routes::admin::extract_bearer;
    use crate::state::AppState;
    use axum::http::HeaderMap;
    let headers: HeaderMap = leptos_axum::extract()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("no state"))?;
    if !state.is_authorized(extract_bearer(&headers)) {
        return Err(ServerFnError::new("unauthorized"));
    }
    // DB first — only update memory if persistence succeeds.
    let deleted = state
        .store
        .delete_agent(&hash)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    if deleted {
        let mut registry = state.registry.lock().unwrap();
        registry.remove_by_hash(&hash);
        Ok(())
    } else {
        Err(ServerFnError::new("agent not found"))
    }
}

/// Sign an unsigned advertisement JSON with the provided Ed25519 private key.
/// Returns the signed JSON with signature field populated.
#[server]
pub async fn sign_advertisement(
    json: String,
    private_key_b64: String,
) -> Result<String, ServerFnError> {
    use base64::Engine;
    use ed25519_dalek::SigningKey;

    // Decode private key from base64
    let private_key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&private_key_b64)
        .map_err(|e| ServerFnError::new(format!("Invalid private key encoding: {}", e)))?;

    if private_key_bytes.len() != 32 {
        return Err(ServerFnError::new(format!(
            "Private key must be 32 bytes, got {}",
            private_key_bytes.len()
        )));
    }

    let signing_key = SigningKey::from_bytes(private_key_bytes.as_slice().try_into().unwrap());

    // Parse the advertisement JSON
    let mut ad: pap_marketplace::AgentAdvertisement = serde_json::from_str(&json)
        .map_err(|e| ServerFnError::new(format!("Invalid advertisement JSON: {}", e)))?;

    // Sign it
    ad.sign(&signing_key);

    // Return signed JSON
    serde_json::to_string(&ad)
        .map_err(|e| ServerFnError::new(format!("Serialization error: {}", e)))
}

/// Register an agent from raw advertisement JSON. Returns the content hash.
#[server]
pub async fn register_agent_json(json: String) -> Result<String, ServerFnError> {
    use crate::routes::admin::extract_bearer;
    use crate::state::AppState;
    use axum::http::HeaderMap;
    use pap_marketplace::AgentAdvertisement as PapAd;

    let headers: HeaderMap = leptos_axum::extract()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("no state"))?;
    if !state.is_authorized(extract_bearer(&headers)) {
        return Err(ServerFnError::new("unauthorized"));
    }

    let ad: PapAd = serde_json::from_str(&json)
        .map_err(|e| ServerFnError::new(format!("Invalid JSON: {}", e)))?;

    {
        let registry = state.registry.lock().unwrap();
        if !registry.verify_advertisement(&ad) {
            return Err(ServerFnError::new(
                "invalid or missing Ed25519 signature — signed_by DID must match the signature",
            ));
        }
    }

    let hash = ad.hash();
    // DB first — persist before updating in-memory state.
    state
        .store
        .insert_agent(&hash, &ad)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    {
        let mut registry = state.registry.lock().unwrap();
        let _ = registry.register_local(ad); // duplicate is silently ignored
    }
    Ok(hash)
}

#[server]
pub async fn list_peers() -> Result<Vec<RegistryPeer>, ServerFnError> {
    use crate::routes::admin::extract_bearer;
    use crate::state::AppState;
    use axum::http::HeaderMap;
    let headers: HeaderMap = leptos_axum::extract()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("no state"))?;
    if !state.is_authorized(extract_bearer(&headers)) {
        return Err(ServerFnError::new("unauthorized"));
    }
    let peers = state
        .store
        .load_all_peers()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // JSON round-trip: pap_federation::peer::RegistryPeer → ui::api::RegistryPeer
    // last_sync: Option<DateTime<Utc>> → Option<String> via RFC3339 string in JSON
    let json = serde_json::to_string(&peers).map_err(|e| ServerFnError::new(e.to_string()))?;
    serde_json::from_str(&json).map_err(|e| ServerFnError::new(e.to_string()))
}

#[server]
pub async fn add_peer(
    did: String,
    endpoint: String,
    cert_fingerprint: Option<String>,
) -> Result<(), ServerFnError> {
    use crate::routes::admin::extract_bearer;
    use crate::state::AppState;
    use axum::http::HeaderMap;
    use pap_federation::peer::RegistryPeer as FedPeer;

    let headers: HeaderMap = leptos_axum::extract()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("no state"))?;
    if !state.is_authorized(extract_bearer(&headers)) {
        return Err(ServerFnError::new("unauthorized"));
    }
    let peer = match cert_fingerprint {
        Some(fp) => FedPeer::with_fingerprint(&did, &endpoint, &fp),
        None => FedPeer::new(&did, &endpoint),
    };
    // DB first — persist before updating in-memory state.
    state
        .store
        .upsert_peer(&peer)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    {
        let mut registry = state.registry.lock().unwrap();
        registry.add_peer(peer);
    }
    Ok(())
}

#[server]
pub async fn remove_peer(did: String) -> Result<(), ServerFnError> {
    use crate::routes::admin::extract_bearer;
    use crate::state::AppState;
    use axum::http::HeaderMap;

    let headers: HeaderMap = leptos_axum::extract()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("no state"))?;
    if !state.is_authorized(extract_bearer(&headers)) {
        return Err(ServerFnError::new("unauthorized"));
    }
    // DB first — only remove from memory if persistence succeeds.
    let deleted = state
        .store
        .delete_peer(&did)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    if deleted {
        let mut registry = state.registry.lock().unwrap();
        registry.remove_peer(&did);
        Ok(())
    } else {
        Err(ServerFnError::new("peer not found"))
    }
}

#[server]
pub async fn sync_peer(did: String) -> Result<usize, ServerFnError> {
    use crate::routes::admin::extract_bearer;
    use crate::state::AppState;
    use axum::http::HeaderMap;

    let headers: HeaderMap = leptos_axum::extract()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("no state"))?;
    if !state.is_authorized(extract_bearer(&headers)) {
        return Err(ServerFnError::new("unauthorized"));
    }

    let peer_info = {
        let registry = state.registry.lock().unwrap();
        registry
            .peers()
            .iter()
            .find(|p| p.did == did)
            .map(|p| (p.endpoint.clone(), p.cert_fingerprint.clone()))
    };
    let (endpoint, fingerprint) = peer_info.ok_or_else(|| ServerFnError::new("peer not found"))?;

    let client = crate::tls::build_peer_client(fingerprint.as_deref())
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let resp = client
        .get(format!("{}/federation/query?action=*", endpoint))
        .send()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let msg = resp
        .json::<pap_federation::sync::FederationMessage>()
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to deserialize federation response from {}: {e}",
                endpoint
            );
            ServerFnError::new(format!("invalid response from peer: {e}"))
        })?;

    if let pap_federation::sync::FederationMessage::QueryResponse { advertisements } = msg {
        // Identify new ads without touching the in-memory registry yet.
        let new_ads: Vec<_> = {
            let registry = state.registry.lock().unwrap();
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

        if let Err(e) = state
            .store
            .update_peer_sync_time(&did, chrono::Utc::now())
            .await
        {
            tracing::warn!("Failed to update last_sync for peer {did}: {e}");
        }
        Ok(merged)
    } else {
        tracing::warn!("Unexpected federation message variant from {}", endpoint);
        Err(ServerFnError::new("unexpected response type from peer"))
    }
}
