//! Browser-native federation client WASM bindings.
//!
//! Wraps [`pap_federation::FetchFederationClient`] with `#[wasm_bindgen]`
//! so JavaScript/TypeScript code can discover PAP agents via the federation
//! protocol without any native dependencies.
//!
//! # Example (TypeScript)
//! ```ts
//! import init, { WasmFederationClient } from "./pap_wasm.js";
//!
//! await init();
//!
//! const client = new WasmFederationClient("https://registry.example.com");
//!
//! // Query agents for a given Schema.org action
//! const ads = await client.queryAgents("schema:SearchAction");
//! console.log(ads); // Array of AgentAdvertisement objects
//!
//! // Paginated query
//! const page = await client.queryWithCursor("schema:SearchAction", null, 20);
//! // page.advertisements — array of ads
//! // page.next_cursor    — opaque cursor string or null
//!
//! // Fetch registry identity
//! const identity = await client.getIdentity();
//! console.log(identity.did, identity.agent_count);
//! ```

use js_sys::Array;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use pap_federation::web_client::FetchFederationClient;

// ---------------------------------------------------------------------------
// WasmFederationClient
// ---------------------------------------------------------------------------

/// Browser-native PAP federation client.
///
/// Uses the browser `Fetch` API (via `web-sys`) to query federation registry
/// endpoints. No native runtime or TLS-pinning required — the browser manages
/// HTTPS certificate validation.
///
/// Federation servers must emit CORS headers to allow cross-origin requests
/// from browser agents. The reference server (`FederationServer`) includes
/// CORS middleware by default.
#[wasm_bindgen]
pub struct WasmFederationClient {
    /// Base URL of the registry endpoint, e.g. `"https://registry.example.com"`.
    registry_url: String,
}

#[wasm_bindgen]
impl WasmFederationClient {
    /// Create a new federation client pointed at `registry_url`.
    ///
    /// `registry_url` should be the bare HTTPS origin of the registry,
    /// e.g. `"https://registry.example.com"` (no trailing slash needed).
    #[wasm_bindgen(constructor)]
    pub fn new(registry_url: &str) -> WasmFederationClient {
        WasmFederationClient {
            registry_url: registry_url.trim_end_matches('/').to_string(),
        }
    }

    /// Query the registry for agents that support a given Schema.org `action`.
    ///
    /// Returns a `Promise<Array>` — each element is a plain JavaScript object
    /// deserialised from the registry's `AgentAdvertisement` JSON.
    ///
    /// # Example
    /// ```ts
    /// const ads = await client.queryAgents("schema:SearchAction");
    /// // ads[0].name, ads[0].agent_did, ads[0].supported_actions, …
    /// ```
    #[wasm_bindgen(js_name = queryAgents)]
    pub fn query_agents(&self, action: &str) -> js_sys::Promise {
        let endpoint = self.registry_url.clone();
        let action = action.to_string();

        future_to_promise(async move {
            let ads = FetchFederationClient::sync_action(&endpoint, &action)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let arr = Array::new();
            for ad in &ads {
                let json =
                    serde_json::to_string(ad).map_err(|e| JsValue::from_str(&e.to_string()))?;
                let obj = js_sys::JSON::parse(&json)
                    .map_err(|e| JsValue::from_str(&format!("JSON.parse failed: {e:?}")))?;
                arr.push(&obj);
            }
            Ok(arr.into())
        })
    }

    /// Paginated query for agents supporting `action`.
    ///
    /// Returns a `Promise<{ advertisements: Array, next_cursor: string|null }>`.
    ///
    /// The PAP federation wire format does not yet include server-side cursor
    /// support; pagination is implemented client-side by slicing the full
    /// result set. Pass `cursor` as a base-10 numeric string (the starting
    /// offset) or `null` to start from the beginning.
    ///
    /// # Parameters
    /// - `action`    — Schema.org action URI, e.g. `"schema:SearchAction"`.
    /// - `cursor`    — opaque pagination cursor from a previous call, or `null`.
    /// - `page_size` — number of results to return per page (max 200).
    ///
    /// # Example
    /// ```ts
    /// let cursor = null;
    /// do {
    ///   const page = await client.queryWithCursor("schema:SearchAction", cursor, 20);
    ///   process(page.advertisements);
    ///   cursor = page.next_cursor;
    /// } while (cursor !== null);
    /// ```
    #[wasm_bindgen(js_name = queryWithCursor)]
    pub fn query_with_cursor(
        &self,
        action: &str,
        cursor: Option<String>,
        page_size: u32,
    ) -> js_sys::Promise {
        let endpoint = self.registry_url.clone();
        let action = action.to_string();

        future_to_promise(async move {
            let all_ads = FetchFederationClient::sync_action(&endpoint, &action)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            // Resolve the numeric offset from the cursor string.
            let offset: usize = cursor
                .as_deref()
                .and_then(|c| c.parse::<usize>().ok())
                .unwrap_or(0);

            let page_size = (page_size as usize).clamp(1, 200);
            let slice = &all_ads[offset.min(all_ads.len())..];
            let page: Vec<_> = slice.iter().take(page_size).collect();
            let next_offset = offset + page.len();
            let has_more = next_offset < all_ads.len();

            // Build advertisements array.
            let arr = Array::new();
            for ad in &page {
                let json =
                    serde_json::to_string(ad).map_err(|e| JsValue::from_str(&e.to_string()))?;
                let obj = js_sys::JSON::parse(&json)
                    .map_err(|e| JsValue::from_str(&format!("JSON.parse failed: {e:?}")))?;
                arr.push(&obj);
            }

            // Build result object: { advertisements, next_cursor }.
            let result = js_sys::Object::new();
            js_sys::Reflect::set(&result, &JsValue::from_str("advertisements"), &arr)
                .map_err(|e| JsValue::from_str(&format!("reflect set failed: {e:?}")))?;

            let next_cursor = if has_more {
                JsValue::from_str(&next_offset.to_string())
            } else {
                JsValue::NULL
            };
            js_sys::Reflect::set(&result, &JsValue::from_str("next_cursor"), &next_cursor)
                .map_err(|e| JsValue::from_str(&format!("reflect set failed: {e:?}")))?;

            Ok(result.into())
        })
    }

    /// Fetch the registry's identity document from `GET /federation/identity`.
    ///
    /// Returns a `Promise<{ did, endpoint, cert_fingerprint, agent_count, peer_count }>`.
    ///
    /// Use this to verify you are talking to the expected registry node before
    /// trusting the query results.
    ///
    /// # Example
    /// ```ts
    /// const id = await client.getIdentity();
    /// console.log(id.did);          // "did:key:z…"
    /// console.log(id.agent_count);  // 305
    /// ```
    #[wasm_bindgen(js_name = getIdentity)]
    pub fn get_identity(&self) -> js_sys::Promise {
        let endpoint = self.registry_url.clone();

        future_to_promise(async move {
            let identity = FetchFederationClient::fetch_identity(&endpoint)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let json =
                serde_json::to_string(&identity).map_err(|e| JsValue::from_str(&e.to_string()))?;
            let obj = js_sys::JSON::parse(&json)
                .map_err(|e| JsValue::from_str(&format!("JSON.parse failed: {e:?}")))?;

            Ok(obj)
        })
    }

    /// Fetch the list of known peers from `GET /federation/peers`.
    ///
    /// Returns a `Promise<Array>` — each element is a plain JavaScript object
    /// deserialised from a `RegistryPeer` JSON.
    ///
    /// Useful for building a local peer map for multi-hop discovery.
    #[wasm_bindgen(js_name = discoverPeers)]
    pub fn discover_peers(&self) -> js_sys::Promise {
        let endpoint = self.registry_url.clone();

        future_to_promise(async move {
            let peers = FetchFederationClient::discover_peers(&endpoint)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

            let arr = Array::new();
            for peer in &peers {
                let json =
                    serde_json::to_string(peer).map_err(|e| JsValue::from_str(&e.to_string()))?;
                let obj = js_sys::JSON::parse(&json)
                    .map_err(|e| JsValue::from_str(&format!("JSON.parse failed: {e:?}")))?;
                arr.push(&obj);
            }
            Ok(arr.into())
        })
    }

    /// Returns the registry URL this client was constructed with.
    #[wasm_bindgen(js_name = registryUrl)]
    pub fn registry_url(&self) -> String {
        self.registry_url.clone()
    }
}
