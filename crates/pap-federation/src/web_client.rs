//! Browser-native federation client using the Fetch API.
//!
//! This is the WASM counterpart of [`FederationClient`](crate::sync::FederationClient).
//! It speaks the same wire protocol (JSON `FederationMessage` over the same
//! REST endpoints) but uses `web_sys::fetch()` instead of reqwest.
//!
//! Browser limitations vs native:
//! - No TLS certificate pinning (the browser manages TLS)
//! - No mDNS/UDP peer discovery (use `pap+https://` URLs)
//! - Federation servers must serve CORS headers
//!
//! Use `pap+https://` URLs to reach federation endpoints from a browser.

use pap_marketplace::AgentAdvertisement;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

use crate::error::FederationError;
use crate::peer::{NodeIdentityResponse, RegistryPeer};
use crate::sync::FederationMessage;

/// Browser-native federation client using the Fetch API.
///
/// Mirrors `FederationClient` endpoint-by-endpoint:
/// - GET  /federation/identity
/// - GET  /federation/query?action=...
/// - POST /federation/announce
/// - GET  /federation/peers
///
/// Takes HTTPS endpoint URLs directly (not `RegistryPeer` references)
/// since browser clients can't do TLS fingerprint pinning.
pub struct FetchFederationClient;

impl FetchFederationClient {
    /// Query a federation endpoint for agents supporting a given action.
    pub async fn sync_action(
        endpoint: &str,
        action: &str,
    ) -> Result<Vec<AgentAdvertisement>, FederationError> {
        let url = format!(
            "{}/federation/query?action={}",
            endpoint.trim_end_matches('/'),
            action
        );

        let msg = fetch_get(&url).await?;

        match msg {
            FederationMessage::QueryResponse { advertisements } => Ok(advertisements),
            _ => Err(FederationError::SyncFailed(
                "unexpected response type".into(),
            )),
        }
    }

    /// Announce a local advertisement to a federation endpoint.
    pub async fn announce(
        endpoint: &str,
        ad: &AgentAdvertisement,
    ) -> Result<bool, FederationError> {
        let url = format!(
            "{}/federation/announce",
            endpoint.trim_end_matches('/')
        );

        let msg = FederationMessage::Announce {
            advertisement: Box::new(ad.clone()),
        };
        let body = serde_json::to_string(&msg)
            .map_err(|e| FederationError::SyncFailed(e.to_string()))?;

        let ack = fetch_post(&url, &body).await?;

        match ack {
            FederationMessage::AnnounceAck { accepted, .. } => Ok(accepted),
            _ => Err(FederationError::SyncFailed("unexpected ack type".into())),
        }
    }

    /// Fetch a node's identity from its `/federation/identity` endpoint.
    pub async fn fetch_identity(
        endpoint: &str,
    ) -> Result<NodeIdentityResponse, FederationError> {
        let url = format!(
            "{}/federation/identity",
            endpoint.trim_end_matches('/')
        );

        let text = fetch_text(&url).await?;

        serde_json::from_str(&text)
            .map_err(|e| FederationError::SyncFailed(format!("identity parse failed: {e}")))
    }

    /// Discover peers known to a federation endpoint.
    pub async fn discover_peers(
        endpoint: &str,
    ) -> Result<Vec<RegistryPeer>, FederationError> {
        let url = format!(
            "{}/federation/peers",
            endpoint.trim_end_matches('/')
        );

        let msg = fetch_get(&url).await?;

        match msg {
            FederationMessage::PeerListResponse { peers } => Ok(peers),
            _ => Err(FederationError::SyncFailed(
                "unexpected response type".into(),
            )),
        }
    }
}

/// GET request, parse response as `FederationMessage`.
async fn fetch_get(url: &str) -> Result<FederationMessage, FederationError> {
    let text = fetch_text(url).await?;
    serde_json::from_str(&text)
        .map_err(|e| FederationError::SyncFailed(format!("JSON parse failed: {e}")))
}

/// POST request with JSON body, parse response as `FederationMessage`.
async fn fetch_post(url: &str, body: &str) -> Result<FederationMessage, FederationError> {
    let opts = RequestInit::new();
    opts.set_method("POST");
    opts.set_mode(RequestMode::Cors);
    opts.set_body(&wasm_bindgen::JsValue::from_str(body));

    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|e| FederationError::PeerUnreachable(format!("{e:?}")))?;

    request
        .headers()
        .set("Content-Type", "application/json")
        .map_err(|e| FederationError::PeerUnreachable(format!("{e:?}")))?;

    let text = execute_fetch(&request).await?;

    serde_json::from_str(&text)
        .map_err(|e| FederationError::SyncFailed(format!("JSON parse failed: {e}")))
}

/// GET request, return raw response text.
async fn fetch_text(url: &str) -> Result<String, FederationError> {
    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|e| FederationError::PeerUnreachable(format!("{e:?}")))?;

    execute_fetch(&request).await
}

/// Execute a fetch request and return the response body as text.
async fn execute_fetch(request: &Request) -> Result<String, FederationError> {
    let window = web_sys::window()
        .ok_or_else(|| FederationError::PeerUnreachable("no window object".into()))?;

    let resp_value = JsFuture::from(window.fetch_with_request(request))
        .await
        .map_err(|e| FederationError::PeerUnreachable(format!("fetch failed: {e:?}")))?;

    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| FederationError::PeerUnreachable("response cast failed".into()))?;

    if !resp.ok() {
        return Err(FederationError::PeerUnreachable(format!(
            "HTTP {}",
            resp.status()
        )));
    }

    let text_promise = resp
        .text()
        .map_err(|e| FederationError::SyncFailed(format!("{e:?}")))?;

    JsFuture::from(text_promise)
        .await
        .map_err(|e| FederationError::SyncFailed(format!("{e:?}")))?
        .as_string()
        .ok_or_else(|| FederationError::SyncFailed("response not a string".into()))
}
