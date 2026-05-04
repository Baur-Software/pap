use leptos::prelude::*;
use papillon_shared::{AgentInfo, RegistryInfo};
use wasm_bindgen_futures::spawn_local;

use crate::bridge;

#[derive(Clone, Copy)]
pub struct RegistryState {
    pub current_url: RwSignal<String>,
    pub info: RwSignal<Option<RegistryInfo>>,
    pub agents: RwSignal<Vec<AgentInfo>>,
    /// Legacy browse-era selection signal. Now superseded by `active_agent_id` for the editor.
    /// Kept for backward compatibility with reset logic in app.rs; can be removed when app.rs is updated.
    pub selected_agent: RwSignal<Option<AgentInfo>>,
    pub action_filter: RwSignal<String>,
    pub loading: RwSignal<bool>,
    pub error: RwSignal<Option<String>>,
    /// ID (name) of the agent currently open in the editor. None = no agent selected.
    pub active_agent_id: RwSignal<Option<String>>,
    /// When true, shows the peer browser panel instead of the editor.
    /// TODO: wire to RegistryPage toggle when peer browser is re-integrated (out of scope for initial editor)
    pub show_peer_browser: RwSignal<bool>,
}

impl Default for RegistryState {
    fn default() -> Self {
        Self {
            current_url: RwSignal::new(String::new()),
            info: RwSignal::new(None),
            agents: RwSignal::new(Vec::new()),
            selected_agent: RwSignal::new(None),
            action_filter: RwSignal::new(String::new()),
            loading: RwSignal::new(false),
            error: RwSignal::new(None),
            active_agent_id: RwSignal::new(None),
            show_peer_browser: RwSignal::new(false),
        }
    }
}

impl RegistryState {
    /// Connect to a registry by URL — navigates, loads agents, updates signals.
    /// Used by the browse page auto-connect and the quickstart buttons.
    ///
    /// In Tauri mode, uses IPC to the backend. In browser mode, fetches
    /// directly from the registry's `/api/browse` endpoint.
    pub fn connect_to(&self, url: &str) {
        let url = url.to_string();
        self.current_url.set(url.clone());
        self.loading.set(true);
        self.error.set(None);

        let registry = *self;

        if bridge::tauri_available() {
            // Tauri IPC path — backend handles TLS, TOFU, and agent listing.
            spawn_local(async move {
                #[derive(serde::Serialize)]
                struct NavArgs {
                    url: String,
                }
                match bridge::invoke::<NavArgs, RegistryInfo>(
                    "navigate_registry",
                    &NavArgs { url: url.clone() },
                )
                .await
                {
                    Ok(info) => {
                        registry.info.set(Some(info));
                        #[derive(serde::Serialize)]
                        struct ListArgs {
                            registry_url: String,
                        }
                        if let Ok(agents) = bridge::invoke::<ListArgs, Vec<AgentInfo>>(
                            "list_agents",
                            &ListArgs { registry_url: url },
                        )
                        .await
                        {
                            registry.agents.set(agents);
                        }
                    }
                    Err(e) => registry.error.set(Some(e)),
                }
                registry.loading.set(false);
            });
        } else {
            // Browser mode — use the embedded local catalog for pap://local,
            // otherwise fetch directly from a remote registry's HTTP API.
            spawn_local(async move {
                #[cfg(target_arch = "wasm32")]
                if crate::service::web_service::is_local_registry_url(&url) {
                    match crate::service::web_service::load_local_registry_snapshot().await {
                        Ok((info, agents)) => {
                            registry.info.set(Some(info));
                            registry.agents.set(agents);
                        }
                        Err(e) => registry.error.set(Some(e)),
                    }
                    registry.loading.set(false);
                    return;
                }

                match fetch_agents_from_registry(&url).await {
                    Ok(agents) => {
                        registry.info.set(Some(RegistryInfo {
                            url: url.clone(),
                            agent_count: agents.len(),
                            peer_count: 0,
                        }));
                        registry.agents.set(agents);
                    }
                    Err(e) => registry.error.set(Some(e)),
                }
                registry.loading.set(false);
            });
        }
    }
}

/// Fetch agent list from a registry's `/api/browse` endpoint using the Fetch API.
/// Returns `AgentInfo` with endpoint URLs ready for the WASM handshake.
async fn fetch_agents_from_registry(registry_url: &str) -> Result<Vec<AgentInfo>, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Request, RequestInit, RequestMode, Response};

    // Convert PAP URL schemes to HTTP(S) for the API call:
    //   pap+http://  → http://   (dev/local)
    //   pap+https:// → https://  (production)
    //   pap://       → https://  (native transport, TLS underneath)
    let base = if registry_url.starts_with("pap+http://") {
        registry_url.replacen("pap+http://", "http://", 1)
    } else if registry_url.starts_with("pap+https://") {
        registry_url.replacen("pap+https://", "https://", 1)
    } else if registry_url.starts_with("pap://") {
        registry_url.replacen("pap://", "https://", 1)
    } else {
        registry_url.to_string()
    };
    let base = base.trim_end_matches('/');
    let api_url = format!("{base}/api/browse");

    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(&api_url, &opts)
        .map_err(|e| format!("Failed to create request: {:?}", e))?;

    let window = web_sys::window().ok_or("No window object")?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("Fetch failed: {:?}", e))?;
    let resp: Response = resp_value.dyn_into().map_err(|_| "Response cast failed")?;

    if !resp.ok() {
        return Err(format!("Registry returned HTTP {}", resp.status()));
    }

    let json = JsFuture::from(
        resp.json()
            .map_err(|e| format!("JSON parse error: {:?}", e))?,
    )
    .await
    .map_err(|e| format!("JSON await failed: {:?}", e))?;

    let agents: Vec<AgentInfo> =
        serde_wasm_bindgen::from_value(json).map_err(|e| format!("Deserialize failed: {e}"))?;

    Ok(agents)
}
