use tauri::State;

use crate::error::PapillionError;
use crate::state::{AppState, LOCAL_REGISTRY_URL};
use papillion_shared::{AgentInfo, PeerInfo, RegistryInfo};

use pap_did::PrincipalKeypair;
use pap_federation::{
    FederatedRegistry, FederationClient, RegistryPeer, resolve_pap_url,
};
use pap_marketplace::AgentAdvertisement;

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

/// Navigate to a pap:// URL, resolve the peer's identity, and discover peers.
///
/// This is the real PAP protocol flow:
/// 1. Parse the pap:// URL
/// 2. Connect via TLS to the node
/// 3. Call /federation/identity to learn who they are (DID + cert fingerprint)
/// 4. Build a verified RegistryPeer
/// 5. Discover their known peers
#[tauri::command]
pub async fn navigate_registry(
    state: State<'_, AppState>,
    url: String,
) -> Result<RegistryInfo, PapillionError> {
    // Short-circuit for the built-in local registry
    if url.trim() == LOCAL_REGISTRY_URL {
        let registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        return Ok(RegistryInfo {
            url: LOCAL_REGISTRY_URL.to_string(),
            agent_count: registry.len(),
            peer_count: registry.peers().len(),
        });
    }

    // Get known peers for fast-path resolution
    let known_peers: Vec<RegistryPeer> = {
        let registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        registry.peers().to_vec()
    };

    // Resolve the pap:// URL — this verifies the peer's identity
    let resolved = resolve_pap_url(&url, &known_peers)
        .await
        .map_err(|e| PapillionError::from(e.to_string()))?;

    let client = FederationClient::new();

    // Discover peers from the verified peer
    let peers = client
        .discover_peers(&resolved.peer)
        .await
        .unwrap_or_default();

    // Build a registry for this remote connection
    let mut registry = FederatedRegistry::new();
    registry.add_peer(resolved.peer.clone());
    for p in &peers {
        registry.add_peer(p.clone());
    }

    // Also add the verified peer to our local registry's peer list
    {
        let mut local = state
            .local_registry
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        local.add_peer(resolved.peer);
        for p in &peers {
            local.add_peer(p.clone());
        }
    }

    let peer_count = registry.peers().len();
    let agent_count = resolved.identity.agent_count;

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
    if registry_url.trim() == LOCAL_REGISTRY_URL {
        let registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        return Ok(registry.all_advertisements().iter().map(ad_to_info).collect());
    }

    let registries = state
        .registries
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?;

    let registry = registries
        .get(&registry_url)
        .ok_or_else(|| PapillionError::from("Registry not connected".to_string()))?;

    Ok(registry
        .all_advertisements()
        .iter()
        .map(ad_to_info)
        .collect())
}

/// Search agents by Schema.org action type.
#[tauri::command]
pub fn search_agents(
    state: State<'_, AppState>,
    registry_url: String,
    action: String,
) -> Result<Vec<AgentInfo>, PapillionError> {
    if registry_url.trim() == LOCAL_REGISTRY_URL {
        let registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        return Ok(registry
            .query_local(&action)
            .into_iter()
            .map(ad_to_info)
            .collect());
    }

    let registries = state
        .registries
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?;

    let registry = registries
        .get(&registry_url)
        .ok_or_else(|| PapillionError::from("Registry not connected".to_string()))?;

    Ok(registry
        .query_local(&action)
        .into_iter()
        .map(ad_to_info)
        .collect())
}

/// Sync agents from a peer for a given action type.
#[tauri::command]
pub async fn sync_agents(
    state: State<'_, AppState>,
    registry_url: String,
    action: String,
) -> Result<RegistryInfo, PapillionError> {
    if registry_url.trim() == LOCAL_REGISTRY_URL {
        let registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        return Ok(RegistryInfo {
            url: LOCAL_REGISTRY_URL.to_string(),
            agent_count: registry.len(),
            peer_count: registry.peers().len(),
        });
    }

    // Get known peers for resolution
    let known_peers: Vec<RegistryPeer> = {
        let registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        registry.peers().to_vec()
    };

    // Resolve the peer with trust verification
    let resolved = resolve_pap_url(&registry_url, &known_peers)
        .await
        .map_err(|e| PapillionError::from(e.to_string()))?;

    let client = FederationClient::new();
    let ads = client
        .sync_action(&resolved.peer, &action)
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
    if registry_url.trim() == LOCAL_REGISTRY_URL {
        let registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        return Ok(registry
            .peers()
            .iter()
            .map(|p| PeerInfo {
                did: p.did.clone(),
                endpoint: p.endpoint.clone(),
                last_sync: p.last_sync.map(|t| t.to_rfc3339()),
            })
            .collect());
    }

    let known_peers: Vec<RegistryPeer> = {
        let registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        registry.peers().to_vec()
    };

    let resolved = resolve_pap_url(&registry_url, &known_peers)
        .await
        .map_err(|e| PapillionError::from(e.to_string()))?;

    let client = FederationClient::new();
    let peers = client
        .discover_peers(&resolved.peer)
        .await
        .map_err(|e| PapillionError::from(e.to_string()))?;

    // Pin discovered peers in our local registry
    {
        let mut local = state
            .local_registry
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        for p in &peers {
            local.add_peer(p.clone());
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

/// Register a new agent advertisement on this node.
///
/// Generates a fresh keypair, signs the advertisement, and registers it
/// in the local registry. Announces to known peers over TLS.
#[tauri::command]
pub async fn register_agent(
    state: State<'_, AppState>,
    name: String,
    provider_name: String,
    capabilities: Vec<String>,
    object_types: Vec<String>,
    requires_disclosure: Vec<String>,
    returns: Vec<String>,
) -> Result<AgentInfo, PapillionError> {
    let kp = PrincipalKeypair::generate();
    let did = kp.did();

    let mut ad = AgentAdvertisement::new(
        &name,
        &provider_name,
        &did,
        capabilities,
        object_types,
        requires_disclosure,
        returns,
    );
    ad.sign(kp.signing_key());

    let info = ad_to_info(&ad);

    // Register in the shared local registry
    {
        let mut registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        registry
            .register_local(ad.clone())
            .map_err(|e| PapillionError::from(e.to_string()))?;
    }

    // Retain the keypair for handshake co-signing
    {
        let mut keypairs = state
            .agent_keypairs
            .write()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        keypairs.insert(name, kp);
    }

    // Announce to known peers over TLS (best-effort)
    let peers: Vec<RegistryPeer> = {
        let registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        registry.peers().to_vec()
    };

    if !peers.is_empty() {
        let client = FederationClient::new();
        for peer in &peers {
            let _ = client.announce(peer, &ad).await;
        }
    }

    Ok(info)
}

/// Get information about this federation node.
#[tauri::command]
pub fn get_node_info(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, PapillionError> {
    let endpoint = state
        .node_endpoint
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?;
    let fingerprint = state
        .node_cert_fingerprint
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?;
    let registry = state
        .local_registry
        .lock()
        .map_err(|e| PapillionError::from(e.to_string()))?;

    let did = {
        let signer = state
            .signer
            .read()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        match signer.as_ref() {
            Some(s) => s.did(),
            None => "unknown".to_string(),
        }
    };

    Ok(serde_json::json!({
        "did": did,
        "endpoint": *endpoint,
        "port": state.federation_port,
        "cert_fingerprint": *fingerprint,
        "agent_count": registry.len(),
        "peer_count": registry.peers().len(),
    }))
}
