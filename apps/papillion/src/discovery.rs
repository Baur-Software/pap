//! Background auto-discovery loop for the federation network.
//!
//! Periodically contacts known peers over TLS to:
//! - Discover new peers via gossip (peer exchange)
//! - Sync agent advertisements for common action types
//!
//! This is the heartbeat of the federation — it keeps the registry
//! up to date without manual intervention.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use pap_federation::{FederatedRegistry, FederationClient};

/// How often to run the discovery loop.
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(5 * 60); // 5 minutes

/// Common action types to auto-sync from peers.
const SYNC_ACTIONS: &[&str] = &[
    "schema:SearchAction",
    "schema:AskAction",
];

/// Run the background discovery loop.
///
/// This should be spawned on a tokio task at app startup.
/// It runs indefinitely, contacting known peers at regular intervals.
pub async fn run_discovery_loop(registry: Arc<Mutex<FederatedRegistry>>) {
    // Initial delay — let the server start up first
    tokio::time::sleep(Duration::from_secs(30)).await;

    loop {
        run_discovery_round(&registry).await;
        tokio::time::sleep(DISCOVERY_INTERVAL).await;
    }
}

/// Execute a single discovery round.
async fn run_discovery_round(registry: &Arc<Mutex<FederatedRegistry>>) {
    let peers = {
        let reg = match registry.lock() {
            Ok(r) => r,
            Err(_) => return,
        };
        reg.peers().to_vec()
    };

    if peers.is_empty() {
        return;
    }

    let client = FederationClient::new();

    for peer in &peers {
        // 1. Gossip — discover new peers from this peer
        if let Ok(new_peers) = client.discover_peers(peer).await {
            let mut reg = match registry.lock() {
                Ok(r) => r,
                Err(_) => continue,
            };
            for p in new_peers {
                reg.add_peer(p);
            }
        }

        // 2. Sync — pull agent advertisements for common actions
        for action in SYNC_ACTIONS {
            if let Ok(ads) = client.sync_action(peer, action).await {
                let mut reg = match registry.lock() {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                reg.merge_remote(ads);
            }
        }
    }
}
