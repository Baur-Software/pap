use tauri::State;

use crate::error::PapillionError;
use crate::state::AppState;
use papillion_shared::{AgentInfo, PeerInfo, RegistryInfo};

use pap_federation::{FederatedRegistry, FederationClient, RegistryPeer};

/// Resolve a pap:// URL to an HTTP endpoint.
fn resolve_url(url: &str) -> String {
    let stripped = url
        .trim()
        .trim_start_matches("pap://")
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    format!("http://{stripped}")
}

/// Convert an AgentAdvertisement to our shared AgentInfo DTO.
fn ad_to_info(ad: &pap_marketplace::AgentAdvertisement) -> AgentInfo {
    AgentInfo {
        name: ad.name.clone(),
        provider_name: ad.provider.name.clone(),
        provider_did: ad.provider.did.clone(),
        capabilities: ad.capability.clone(),
        object_types: ad.object_types.clone(),
        requires_disclosure: ad.requires_disclosure.clone(),
        returns: ad.returns.clone(),
        content_hash: ad.hash(),
        endpoint: None,
    }
}

/// Navigate to a registry URL, create a FederatedRegistry, and discover peers.
#[tauri::command]
pub async fn navigate_registry(
    state: State<'_, AppState>,
    url: String,
) -> Result<RegistryInfo, PapillionError> {
    let endpoint = resolve_url(&url);
    let peer = RegistryPeer::new("unknown", &endpoint);
    let client = FederationClient::new();

    // Discover peers from the registry
    let peers = client.discover_peers(&peer).await.unwrap_or_default();

    // Create a new federated registry and add discovered peers
    let mut registry = FederatedRegistry::new();
    for p in &peers {
        registry.add_peer(p.clone());
    }

    let peer_count = registry.peers().len();
    let agent_count = registry.len();

    let mut registries = state
        .registries
        .write()
        .map_err(|e| PapillionError::from(e.to_string()))?;
    registries.insert(url.clone(), registry);

    Ok(RegistryInfo {
        url,
        agent_count,
        peer_count,
    })
}

/// List all agents in a connected registry.
#[tauri::command]
pub fn list_agents(
    state: State<'_, AppState>,
    registry_url: String,
) -> Result<Vec<AgentInfo>, PapillionError> {
    let registries = state
        .registries
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?;

    let registry = registries
        .get(&registry_url)
        .ok_or_else(|| PapillionError::from("Registry not connected".to_string()))?;

    let agents = registry
        .all_advertisements()
        .iter()
        .map(ad_to_info)
        .collect();

    Ok(agents)
}

/// Search agents by Schema.org action type.
#[tauri::command]
pub fn search_agents(
    state: State<'_, AppState>,
    registry_url: String,
    action: String,
) -> Result<Vec<AgentInfo>, PapillionError> {
    let registries = state
        .registries
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?;

    let registry = registries
        .get(&registry_url)
        .ok_or_else(|| PapillionError::from("Registry not connected".to_string()))?;

    let agents = registry
        .query_local(&action)
        .into_iter()
        .map(ad_to_info)
        .collect();

    Ok(agents)
}

/// Sync agents from a peer for a given action type.
#[tauri::command]
pub async fn sync_agents(
    state: State<'_, AppState>,
    registry_url: String,
    action: String,
) -> Result<RegistryInfo, PapillionError> {
    let endpoint = resolve_url(&registry_url);
    let peer = RegistryPeer::new("unknown", &endpoint);
    let client = FederationClient::new();

    let ads = client
        .sync_action(&peer, &action)
        .await
        .map_err(|e| PapillionError::from(e.to_string()))?;

    let mut registries = state
        .registries
        .write()
        .map_err(|e| PapillionError::from(e.to_string()))?;

    let registry = registries
        .entry(registry_url.clone())
        .or_insert_with(FederatedRegistry::new);

    registry.merge_remote(ads);

    Ok(RegistryInfo {
        url: registry_url,
        agent_count: registry.len(),
        peer_count: registry.peers().len(),
    })
}

/// Discover federation peers from a registry.
#[tauri::command]
pub async fn discover_peers(
    state: State<'_, AppState>,
    registry_url: String,
) -> Result<Vec<PeerInfo>, PapillionError> {
    let endpoint = resolve_url(&registry_url);
    let peer = RegistryPeer::new("unknown", &endpoint);
    let client = FederationClient::new();

    let peers = client
        .discover_peers(&peer)
        .await
        .map_err(|e| PapillionError::from(e.to_string()))?;

    // Also add them to the local registry
    {
        let mut registries = state
            .registries
            .write()
            .map_err(|e| PapillionError::from(e.to_string()))?;

        let registry = registries
            .entry(registry_url)
            .or_insert_with(FederatedRegistry::new);

        for p in &peers {
            registry.add_peer(p.clone());
        }
    }

    Ok(peers
        .into_iter()
        .map(|p| PeerInfo {
            did: p.did,
            endpoint: p.endpoint,
            last_sync: p.last_sync.map(|t| t.to_rfc3339()),
        })
        .collect())
}

/// Add a registry URL to bookmarks.
#[tauri::command]
pub fn add_bookmark(
    state: State<'_, AppState>,
    registry_url: String,
) -> Result<(), PapillionError> {
    let mut bookmarks = state
        .bookmarks
        .write()
        .map_err(|e| PapillionError::from(e.to_string()))?;

    if !bookmarks.contains(&registry_url) {
        bookmarks.push(registry_url);
    }

    Ok(())
}

/// List bookmarked registry URLs.
#[tauri::command]
pub fn list_bookmarks(state: State<'_, AppState>) -> Result<Vec<String>, PapillionError> {
    let bookmarks = state
        .bookmarks
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?;

    Ok(bookmarks.clone())
}
