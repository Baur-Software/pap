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
    use crate::state::AppState;
    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("no state"))?;
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
    use crate::state::AppState;
    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("no state"))?;
    let per_page = per_page.clamp(1, 200);
    let db_page = state
        .store
        .search_agents(q.as_deref().filter(|s| !s.is_empty()), page, per_page)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    // JSON round-trip: server AgentEntry (pap_marketplace ad) → wire JSON → ui AgentEntry
    let items_json = serde_json::to_string(&db_page.items)
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let items: Vec<AgentEntry> = serde_json::from_str(&items_json)
        .map_err(|e| ServerFnError::new(e.to_string()))?;

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
    use crate::state::AppState;
    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("no state"))?;
    let removed = {
        let mut registry = state.registry.lock().unwrap();
        registry.remove_by_hash(&hash)
    };
    if removed {
        if let Err(e) = state.store.delete_agent(&hash).await {
            tracing::error!("DB delete failed for agent {hash}: {e}");
        }
        Ok(())
    } else {
        Err(ServerFnError::new("agent not found"))
    }
}

/// Register an agent from raw advertisement JSON. Returns the content hash.
#[server]
pub async fn register_agent_json(json: String) -> Result<String, ServerFnError> {
    use crate::state::AppState;
    use pap_marketplace::AgentAdvertisement as PapAd;

    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("no state"))?;
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
            Ok(hash)
        }
        Err(e) => Err(ServerFnError::new(e.to_string())),
    }
}

#[server]
pub async fn list_peers() -> Result<Vec<RegistryPeer>, ServerFnError> {
    use crate::state::AppState;
    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("no state"))?;
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
    use crate::state::AppState;
    use pap_federation::peer::RegistryPeer as FedPeer;

    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("no state"))?;
    let peer = match cert_fingerprint {
        Some(fp) => FedPeer::with_fingerprint(&did, &endpoint, &fp),
        None => FedPeer::new(&did, &endpoint),
    };
    {
        let mut registry = state.registry.lock().unwrap();
        registry.add_peer(peer.clone());
    }
    if let Err(e) = state.store.upsert_peer(&peer).await {
        tracing::error!("DB write-through failed for peer {}: {e}", peer.did);
    }
    Ok(())
}

#[server]
pub async fn remove_peer(did: String) -> Result<(), ServerFnError> {
    use crate::state::AppState;
    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("no state"))?;
    let removed = {
        let mut registry = state.registry.lock().unwrap();
        registry.remove_peer(&did)
    };
    if removed {
        if let Err(e) = state.store.delete_peer(&did).await {
            tracing::error!("DB delete failed for peer {did}: {e}");
        }
        Ok(())
    } else {
        Err(ServerFnError::new("peer not found"))
    }
}

#[server]
pub async fn sync_peer(did: String) -> Result<usize, ServerFnError> {
    use crate::state::AppState;

    let state = use_context::<AppState>().ok_or_else(|| ServerFnError::new("no state"))?;
    let endpoint = {
        let registry = state.registry.lock().unwrap();
        registry
            .peers()
            .iter()
            .find(|p| p.did == did)
            .map(|p| p.endpoint.clone())
    };
    let endpoint = endpoint.ok_or_else(|| ServerFnError::new("peer not found"))?;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let resp = client
        .get(format!("{}/federation/query?action=*", endpoint))
        .send()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    if let Ok(msg) = resp.json::<pap_federation::sync::FederationMessage>().await {
        if let pap_federation::sync::FederationMessage::QueryResponse { advertisements } = msg {
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
            if let Err(e) = state
                .store
                .update_peer_sync_time(&did, chrono::Utc::now())
                .await
            {
                tracing::warn!("Failed to update last_sync for peer {did}: {e}");
            }
            return Ok(merged);
        }
    }
    Err(ServerFnError::new("invalid response from peer"))
}
