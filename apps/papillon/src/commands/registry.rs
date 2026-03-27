use tauri::State;

use crate::db::prelude::DatabaseOps;
use crate::error::PapillonError;
use crate::state::{AppState, LOCAL_REGISTRY_URL};
use papillon_shared::{AgentInfo, PeerInfo, RegistryInfo};

use pap_did::PrincipalKeypair;
use pap_federation::{FederatedRegistry, FederationClient, PapUrl, RegistryPeer};
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

/// Find a known peer by matching its endpoint to a pap:// URL.
fn find_peer_by_url(peers: &[RegistryPeer], url: &str) -> Option<RegistryPeer> {
    let parsed = PapUrl::parse(url).ok()?;
    let endpoint = parsed.https_endpoint();
    peers
        .iter()
        .find(|p| p.endpoint.trim_end_matches('/') == endpoint.trim_end_matches('/'))
        .cloned()
}

/// Navigate to a pap:// URL, resolve the peer's identity, and discover peers.
///
/// PAP protocol flow:
/// 1. Parse the pap:// URL
/// 2. Check known peers (fast path — already fingerprint-pinned)
/// 3. If unknown, TOFU bootstrap: connect, get identity, record fingerprint
/// 4. Discover their known peers (only those with fingerprints)
///
/// TOFU is a transitional mechanism. DNS-based bootstrap
/// (`_pap.hostname` TXT records) will replace it.
#[tauri::command]
pub async fn navigate_registry(
    state: State<'_, AppState>,
    url: String,
) -> Result<RegistryInfo, PapillonError> {
    // Short-circuit for the built-in local registry
    if url.trim() == LOCAL_REGISTRY_URL {
        let registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        return Ok(RegistryInfo {
            url: LOCAL_REGISTRY_URL.to_string(),
            agent_count: registry.len(),
            peer_count: registry.peers().len(),
        });
    }

    let parsed = PapUrl::parse(&url).map_err(|e| PapillonError::from(e.to_string()))?;
    let endpoint = parsed.https_endpoint();

    // Fast path: check if we already know this peer with a pinned fingerprint
    let known_peers: Vec<RegistryPeer> = {
        let registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        registry.peers().to_vec()
    };

    let (peer, identity) = if let Some(existing) = find_peer_by_url(&known_peers, &url) {
        // Known peer — use fingerprint-pinned client
        let client = FederationClient::pinned(std::slice::from_ref(&existing))
            .map_err(|e| PapillonError::from(e.to_string()))?;
        let identity = client
            .fetch_identity(&endpoint)
            .await
            .map_err(|e| PapillonError::from(e.to_string()))?;
        (existing, identity)
    } else {
        // Unknown peer — TOFU bootstrap (will be replaced by DNS)
        let client = FederationClient::tofu();
        let identity = client
            .fetch_identity(&endpoint)
            .await
            .map_err(|e| PapillonError::from(e.to_string()))?;
        let peer = RegistryPeer::with_fingerprint(
            &identity.did,
            &identity.endpoint,
            &identity.cert_fingerprint,
        );
        (peer, identity)
    };

    // Now use pinned client for peer discovery
    let discovered_peers = match FederationClient::pinned(std::slice::from_ref(&peer)) {
        Ok(pinned) => pinned.discover_peers(&peer).await.unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    // Build a registry for this remote connection
    let mut registry = FederatedRegistry::new();
    registry.add_peer(peer.clone());
    // Only add gossiped peers that have fingerprints
    for p in &discovered_peers {
        if p.cert_fingerprint.is_some() {
            registry.add_peer(p.clone());
        }
    }

    // Pin the verified peer in our local registry
    {
        let mut local = state
            .local_registry
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        local.add_peer(peer);
        for p in &discovered_peers {
            if p.cert_fingerprint.is_some() {
                local.add_peer(p.clone());
            }
        }
    }

    let peer_count = registry.peers().len();
    let agent_count = identity.agent_count;

    let mut registries = state
        .registries
        .write()
        .map_err(|e| PapillonError::from(e.to_string()))?;
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
) -> Result<Vec<AgentInfo>, PapillonError> {
    if registry_url.trim() == LOCAL_REGISTRY_URL {
        let registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        return Ok(registry
            .all_advertisements()
            .iter()
            .map(ad_to_info)
            .collect());
    }

    let registries = state
        .registries
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?;

    let registry = registries
        .get(&registry_url)
        .ok_or_else(|| PapillonError::from("Registry not connected".to_string()))?;

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
) -> Result<Vec<AgentInfo>, PapillonError> {
    if registry_url.trim() == LOCAL_REGISTRY_URL {
        let registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        return Ok(registry
            .query_local(&action)
            .into_iter()
            .map(ad_to_info)
            .collect());
    }

    let registries = state
        .registries
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?;

    let registry = registries
        .get(&registry_url)
        .ok_or_else(|| PapillonError::from("Registry not connected".to_string()))?;

    Ok(registry
        .query_local(&action)
        .into_iter()
        .map(ad_to_info)
        .collect())
}

/// Sync agents from a peer for a given action type.
///
/// Requires the peer to already be known (via `navigate_registry`).
/// Uses fingerprint-pinned TLS for the connection.
#[tauri::command]
pub async fn sync_agents(
    state: State<'_, AppState>,
    registry_url: String,
    action: String,
) -> Result<RegistryInfo, PapillonError> {
    if registry_url.trim() == LOCAL_REGISTRY_URL {
        let registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        return Ok(RegistryInfo {
            url: LOCAL_REGISTRY_URL.to_string(),
            agent_count: registry.len(),
            peer_count: registry.peers().len(),
        });
    }

    // Find the peer by URL — must already be known from navigate_registry
    let peer = {
        let registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        find_peer_by_url(registry.peers(), &registry_url).ok_or_else(|| {
            PapillonError::from("Peer not known — navigate to it first".to_string())
        })?
    };

    let client = FederationClient::pinned(std::slice::from_ref(&peer))
        .map_err(|e| PapillonError::from(e.to_string()))?;
    let ads = client
        .sync_action(&peer, &action)
        .await
        .map_err(|e| PapillonError::from(e.to_string()))?;

    let mut registries = state
        .registries
        .write()
        .map_err(|e| PapillonError::from(e.to_string()))?;

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
///
/// Requires the peer to already be known (via `navigate_registry`).
/// Only adds gossiped peers that include cert fingerprints.
#[tauri::command]
pub async fn discover_peers(
    state: State<'_, AppState>,
    registry_url: String,
) -> Result<Vec<PeerInfo>, PapillonError> {
    if registry_url.trim() == LOCAL_REGISTRY_URL {
        let registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;
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

    // Find the peer by URL — must already be known
    let peer = {
        let registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        find_peer_by_url(registry.peers(), &registry_url).ok_or_else(|| {
            PapillonError::from("Peer not known — navigate to it first".to_string())
        })?
    };

    let client = FederationClient::pinned(std::slice::from_ref(&peer))
        .map_err(|e| PapillonError::from(e.to_string()))?;
    let peers = client
        .discover_peers(&peer)
        .await
        .map_err(|e| PapillonError::from(e.to_string()))?;

    // Only add gossiped peers that have cert fingerprints
    {
        let mut local = state
            .local_registry
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        for p in &peers {
            if p.cert_fingerprint.is_some() {
                local.add_peer(p.clone());
            }
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

/// Add a registry URL to bookmarks and persist to SQLite.
#[tauri::command]
pub fn add_bookmark(
    state: State<'_, AppState>,
    registry_url: String,
) -> Result<Vec<String>, PapillonError> {
    let mut bookmarks = state
        .bookmarks
        .write()
        .map_err(|e| PapillonError::from(e.to_string()))?;

    if !bookmarks.contains(&registry_url) {
        bookmarks.push(registry_url);
    }

    persist_bookmarks(&state.db, &bookmarks)?;
    Ok(bookmarks.clone())
}

/// Remove a registry URL from bookmarks and persist the updated list.
/// The built-in `pap://local` registry cannot be removed.
#[tauri::command]
pub fn remove_bookmark(
    state: State<'_, AppState>,
    registry_url: String,
) -> Result<Vec<String>, PapillonError> {
    if registry_url.trim() == LOCAL_REGISTRY_URL {
        return Err(PapillonError::from(
            "Cannot remove the built-in local registry".to_string(),
        ));
    }

    let mut bookmarks = state
        .bookmarks
        .write()
        .map_err(|e| PapillonError::from(e.to_string()))?;

    bookmarks.retain(|u| u != &registry_url);
    persist_bookmarks(&state.db, &bookmarks)?;
    Ok(bookmarks.clone())
}

/// List bookmarked registry URLs.
#[tauri::command]
pub fn list_bookmarks(state: State<'_, AppState>) -> Result<Vec<String>, PapillonError> {
    let bookmarks = state
        .bookmarks
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?;

    Ok(bookmarks.clone())
}

/// Return the LAN-reachable `pap://` URLs for this node.
/// These are computed at startup and exclude loopback addresses.
#[tauri::command]
pub fn get_node_addresses(state: State<'_, AppState>) -> Result<Vec<String>, PapillonError> {
    let urls = state
        .local_pap_urls
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    Ok(urls.clone())
}

/// Serialize bookmarks (excluding pap://local) and write to the settings table.
fn persist_bookmarks(db: &crate::db::Database, bookmarks: &[String]) -> Result<(), PapillonError> {
    // Don't persist the built-in local entry — it is always re-added on startup
    let to_persist: Vec<&String> = bookmarks
        .iter()
        .filter(|u| u.as_str() != LOCAL_REGISTRY_URL)
        .collect();
    let json = serde_json::to_string(&to_persist)
        .map_err(|e| PapillonError::from(format!("bookmark serialization: {e}")))?;
    db.set_setting("registry_bookmarks", &json)
        .map_err(|e| PapillonError::from(e.0))
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
) -> Result<AgentInfo, PapillonError> {
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
            .map_err(|e| PapillonError::from(e.to_string()))?;
        registry
            .register_local(ad.clone())
            .map_err(|e| PapillonError::from(e.to_string()))?;
    }

    // Retain the keypair for handshake co-signing
    {
        let mut keypairs = state
            .agent_keypairs
            .write()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        keypairs.insert(name, kp);
    }

    // Announce to known peers over pinned TLS (best-effort)
    let peers: Vec<RegistryPeer> = {
        let registry = state
            .local_registry
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        registry.peers().to_vec()
    };

    // Only announce to peers with fingerprints (verified connections)
    let pinned_peers: Vec<_> = peers
        .iter()
        .filter(|p| p.cert_fingerprint.is_some())
        .cloned()
        .collect();
    if !pinned_peers.is_empty() {
        if let Ok(client) = FederationClient::pinned(&pinned_peers) {
            for peer in &pinned_peers {
                let _ = client.announce(peer, &ad).await;
            }
        }
    }

    Ok(info)
}

/// Get information about this federation node.
#[tauri::command]
pub fn get_node_info(state: State<'_, AppState>) -> Result<serde_json::Value, PapillonError> {
    let endpoint = state
        .node_endpoint
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    let fingerprint = state
        .node_cert_fingerprint
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    let registry = state
        .local_registry
        .lock()
        .map_err(|e| PapillonError::from(e.to_string()))?;

    let did = {
        let signer = state.signer.read().unwrap();
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
