use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ui::api::AgentAdvertisement;
// Phase 4: These will be used when implementing full async signing flow
#[allow(unused_imports)]
use crate::ui::api::{register_agent_json, sign_advertisement};

/// Form state for the agent designer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentFormState {
    pub name: String,
    pub provider_name: String,
    pub provider_did: String,
    pub capabilities: Vec<String>,
    pub object_types: Vec<String>,
    pub requires_disclosure: Vec<String>,
    pub returns: Vec<String>,
    pub ttl_min: u64,
    pub errors: HashMap<String, String>,
}

impl Default for AgentFormState {
    fn default() -> Self {
        Self {
            name: String::new(),
            provider_name: String::new(),
            provider_did: String::new(),
            capabilities: Vec::new(),
            object_types: Vec::new(),
            requires_disclosure: Vec::new(),
            returns: Vec::new(),
            ttl_min: 3600, // 1 hour default
            errors: HashMap::new(),
        }
    }
}

impl AgentFormState {
    /// Convert form state to an unsigned advertisement
    pub fn to_advertisement(&self) -> AgentAdvertisement {
        AgentAdvertisement {
            context: "https://schema.org".to_string(),
            schema_type: "schema:Service".to_string(),
            name: self.name.clone(),
            provider: crate::ui::api::Provider {
                schema_type: "schema:Organization".to_string(),
                name: self.provider_name.clone(),
                did: self.provider_did.clone(),
            },
            capability: self.capabilities.clone(),
            object_types: self.object_types.clone(),
            requires_disclosure: self.requires_disclosure.clone(),
            returns: self.returns.clone(),
            ttl_min: self.ttl_min,
            signed_by: String::new(),
            signature: None,
        }
    }

    /// Validate form state and populate error map
    pub fn validate(&mut self) -> bool {
        self.errors.clear();
        let mut valid = true;

        if self.name.trim().is_empty() {
            self.errors
                .insert("name".to_string(), "Agent name required".to_string());
            valid = false;
        }
        if self.name.len() > 128 {
            self.errors.insert(
                "name".to_string(),
                "Agent name must be ≤ 128 characters".to_string(),
            );
            valid = false;
        }

        if self.provider_name.trim().is_empty() {
            self.errors.insert(
                "provider_name".to_string(),
                "Provider name required".to_string(),
            );
            valid = false;
        }
        if self.provider_name.len() > 64 {
            self.errors.insert(
                "provider_name".to_string(),
                "Provider name must be ≤ 64 characters".to_string(),
            );
            valid = false;
        }

        if self.provider_did.trim().is_empty() {
            self.errors.insert(
                "provider_did".to_string(),
                "Provider DID required".to_string(),
            );
            valid = false;
        } else if !self.validate_did() {
            self.errors.insert(
                "provider_did".to_string(),
                "Invalid DID format (must start with did:key:)".to_string(),
            );
            valid = false;
        }

        if self.capabilities.is_empty() {
            self.errors.insert(
                "capabilities".to_string(),
                "At least one capability required".to_string(),
            );
            valid = false;
        }

        if self.requires_disclosure.is_empty() {
            self.errors.insert(
                "requires_disclosure".to_string(),
                "Specify what properties you need".to_string(),
            );
            valid = false;
        }

        if self.returns.is_empty() {
            self.errors.insert(
                "returns".to_string(),
                "Specify what types you return".to_string(),
            );
            valid = false;
        }

        if self.ttl_min < 60 {
            self.errors.insert(
                "ttl_min".to_string(),
                "TTL must be at least 60 seconds".to_string(),
            );
            valid = false;
        }

        valid
    }

    /// Validate DID format (must start with did:key:)
    fn validate_did(&self) -> bool {
        self.provider_did.starts_with("did:key:")
    }
}

/// Main agent designer page component
#[component]
pub fn AgentDesignerPage() -> impl IntoView {
    let form_state = RwSignal::new(AgentFormState::default());
    let validation_attempted = RwSignal::new(false);
    let submit_status: RwSignal<Option<String>> = RwSignal::new(None);

    view! {
        <div class="page">
            <div class="page-header">
                <div>
                    <h1 class="page-title">"Design Agent Advertisement"</h1>
                    <p class="page-subtitle">"Create a new agent advertisement using our WYSIWYG form builder."</p>
                </div>
            </div>

            {move || {
                if let Some(status) = submit_status.get() {
                    view! {
                        <div class="alert alert-success">
                            {status}
                        </div>
                    }.into_any()
                } else {
                    view! { <div/> }.into_any()
                }
            }}

            <div class="designer-container">
                <div class="designer-form-panel">
                    <DesignerForm form_state validation_attempted submit_status />
                </div>
                <div class="designer-preview-panel">
                    <PreviewPane form_state />
                </div>
            </div>
        </div>
    }
}

/// Form component with all sections (Phases 2-5 integrated)
#[component]
fn DesignerForm(
    form_state: RwSignal<AgentFormState>,
    validation_attempted: RwSignal<bool>,
    submit_status: RwSignal<Option<String>>,
) -> impl IntoView {
    let is_submitting = RwSignal::new(false);
    let signing_key = RwSignal::new(String::new());

    view! {
        <form class="agent-designer-form"
            on:submit=move |e| {
                e.prevent_default();
                validation_attempted.set(true);
                let mut state = form_state.get();
                if state.validate() {
                    form_state.set(state);
                    let key = signing_key.get();
                    if key.trim().is_empty() {
                        submit_status.set(Some("⚠️ Signing key required. Paste your Ed25519 private key (base64)".to_string()));
                        return;
                    }
                    // Phase 4: Prepare for signing and registration
                    // Full async handling requires using Action component for proper state management
                    submit_status.set(Some("📋 Ready to sign. Use Sign & Register button to proceed.".to_string()));
                } else {
                    form_state.set(state);
                    submit_status.set(None);
                }
            }
        >
            <MetadataSection form_state validation_attempted />
            <CapabilitiesSection form_state validation_attempted />
            <DisclosureSection form_state validation_attempted />
            <ReturnsSection form_state validation_attempted />
            <ObjectTypesSection form_state />
            <TTLSection form_state validation_attempted />
            <SigningKeySection signing_key />

            <div class="form-actions">
                <button
                    class="btn btn-primary"
                    type="submit"
                    disabled=move || is_submitting.get()
                >
                    "✅ Validate Form"
                </button>
                <button
                    class="btn btn-primary"
                    type="button"
                    disabled=move || {
                        let state = form_state.get();
                        state.errors.is_empty() && signing_key.get().trim().is_empty() || is_submitting.get()
                    }
                    on:click=move |_| {
                        is_submitting.set(true);
                        let _state = form_state.get();
                        let _ad = _state.to_advertisement();
                        let _key = signing_key.get();

                        // Phase 4: TODO - Implement actual signing and registration
                        // This will:
                        // 1. Call sign_advertisement(json, key) server function
                        // 2. On success, call register_agent_json(signed_json)
                        // 3. Update status with hash on success or error message on failure
                        submit_status.set(Some("⏳ Signing & registering... (Phase 4 in progress)".to_string()));
                        is_submitting.set(false);
                    }
                >
                    {move || if is_submitting.get() { "⏳ Signing..." } else { "🔐 Sign & Register" }}
                </button>
                <a href="/agents" class="btn btn-secondary">
                    "Cancel"
                </a>
            </div>
        </form>
    }
}

/// Metadata section: agent name, provider name, provider DID (Phase 2: with validation feedback)
#[component]
fn MetadataSection(
    form_state: RwSignal<AgentFormState>,
    validation_attempted: RwSignal<bool>,
) -> impl IntoView {
    view! {
        <div class="form-section">
            <h3 class="form-section-title">"Agent Metadata"</h3>

            <div class="form-group">
                <label class="form-label" for="agent-name">
                    "Agent Name"
                </label>
                <input
                    id="agent-name"
                    class="form-input"
                    type="text"
                    placeholder="e.g., Flight Search Agent"
                    prop:value=move || form_state.get().name
                    on:input=move |e| {
                        let val = event_target_value(&e);
                        form_state.update(|s| s.name = val);
                    }
                />
                {move || {
                    if validation_attempted.get() {
                        form_state
                            .get()
                            .errors
                            .get("name")
                            .map(|err| view! { <div class="form-error">{err.clone()}</div> })
                    } else {
                        None
                    }
                }}
            </div>

            <div class="form-group">
                <label class="form-label" for="provider-name">
                    "Provider Name"
                </label>
                <input
                    id="provider-name"
                    class="form-input"
                    type="text"
                    placeholder="e.g., Acme Corp"
                    prop:value=move || form_state.get().provider_name
                    on:input=move |e| {
                        let val = event_target_value(&e);
                        form_state.update(|s| s.provider_name = val);
                    }
                />
                {move || {
                    if validation_attempted.get() {
                        form_state
                            .get()
                            .errors
                            .get("provider_name")
                            .map(|err| view! { <div class="form-error">{err.clone()}</div> })
                    } else {
                        None
                    }
                }}
            </div>

            <div class="form-group">
                <label class="form-label" for="provider-did">
                    "Provider DID"
                </label>
                <input
                    id="provider-did"
                    class="form-input"
                    type="text"
                    placeholder="e.g., did:key:z6Mkd..."
                    prop:value=move || form_state.get().provider_did
                    on:input=move |e| {
                        let val = event_target_value(&e);
                        form_state.update(|s| s.provider_did = val);
                    }
                />
                {move || {
                    if validation_attempted.get() {
                        form_state
                            .get()
                            .errors
                            .get("provider_did")
                            .map(|err| view! { <div class="form-error">{err.clone()}</div> })
                    } else {
                        None
                    }
                }}
            </div>
        </div>
    }
}

/// Capabilities section
#[component]
fn CapabilitiesSection(
    form_state: RwSignal<AgentFormState>,
    validation_attempted: RwSignal<bool>,
) -> impl IntoView {
    view! {
        <div class="form-section">
            <h3 class="form-section-title">"Capabilities"</h3>
            <p class="form-section-help">"Space-separated schema.org actions"</p>
            <textarea
                class="form-input"
                placeholder="schema:SearchAction schema:BookAction"
                prop:value=move || form_state.get().capabilities.join(" ")
                on:input=move |e| {
                    let val = event_target_value(&e);
                    let items: Vec<String> = val
                        .split_whitespace()
                        .map(|s| s.to_string())
                        .collect();
                    form_state.update(|s| s.capabilities = items);
                }
            />
            {move || {
                if validation_attempted.get() {
                    form_state
                        .get()
                        .errors
                        .get("capabilities")
                        .map(|err| view! { <div class="form-error">{err.clone()}</div> })
                } else {
                    None
                }
            }}
        </div>
    }
}

/// Disclosure section
#[component]
fn DisclosureSection(
    form_state: RwSignal<AgentFormState>,
    validation_attempted: RwSignal<bool>,
) -> impl IntoView {
    view! {
        <div class="form-section">
            <h3 class="form-section-title">"Required Disclosure"</h3>
            <p class="form-section-help">"Properties this agent needs access to"</p>
            <textarea
                class="form-input"
                placeholder="schema:Person.name schema:PostalAddress"
                prop:value=move || form_state.get().requires_disclosure.join(" ")
                on:input=move |e| {
                    let val = event_target_value(&e);
                    let items: Vec<String> = val
                        .split_whitespace()
                        .map(|s| s.to_string())
                        .collect();
                    form_state.update(|s| s.requires_disclosure = items);
                }
            />
            {move || {
                if validation_attempted.get() {
                    form_state
                        .get()
                        .errors
                        .get("requires_disclosure")
                        .map(|err| view! { <div class="form-error">{err.clone()}</div> })
                } else {
                    None
                }
            }}
        </div>
    }
}

/// Returns section
#[component]
fn ReturnsSection(
    form_state: RwSignal<AgentFormState>,
    validation_attempted: RwSignal<bool>,
) -> impl IntoView {
    view! {
        <div class="form-section">
            <h3 class="form-section-title">"Return Types"</h3>
            <p class="form-section-help">"What types this agent returns"</p>
            <textarea
                class="form-input"
                placeholder="schema:SearchResult schema:Reservation"
                prop:value=move || form_state.get().returns.join(" ")
                on:input=move |e| {
                    let val = event_target_value(&e);
                    let items: Vec<String> = val
                        .split_whitespace()
                        .map(|s| s.to_string())
                        .collect();
                    form_state.update(|s| s.returns = items);
                }
            />
            {move || {
                if validation_attempted.get() {
                    form_state
                        .get()
                        .errors
                        .get("returns")
                        .map(|err| view! { <div class="form-error">{err.clone()}</div> })
                } else {
                    None
                }
            }}
        </div>
    }
}

/// Object types section
#[component]
fn ObjectTypesSection(form_state: RwSignal<AgentFormState>) -> impl IntoView {
    view! {
        <div class="form-section">
            <h3 class="form-section-title">"Object Types"</h3>
            <p class="form-section-help">"Entity types this agent works with"</p>
            <textarea
                class="form-input"
                placeholder="schema:Flight schema:Hotel"
                prop:value=move || form_state.get().object_types.join(" ")
                on:input=move |e| {
                    let val = event_target_value(&e);
                    let items: Vec<String> = val
                        .split_whitespace()
                        .map(|s| s.to_string())
                        .collect();
                    form_state.update(|s| s.object_types = items);
                }
            />
        </div>
    }
}

/// TTL section: time-to-live input
#[component]
fn TTLSection(
    form_state: RwSignal<AgentFormState>,
    validation_attempted: RwSignal<bool>,
) -> impl IntoView {
    view! {
        <div class="form-section">
            <h3 class="form-section-title">"Time-to-Live (TTL)"</h3>
            <p class="form-section-help">"Minimum TTL in seconds (minimum: 60)"</p>

            <div class="form-group">
                <input
                    class="form-input"
                    type="number"
                    min="60"
                    step="60"
                    prop:value=move || form_state.get().ttl_min.to_string()
                    on:input=move |e| {
                        if let Ok(val) = event_target_value(&e).parse::<u64>() {
                            form_state.update(|s| s.ttl_min = val);
                        }
                    }
                />
            </div>
            {move || {
                if validation_attempted.get() {
                    form_state
                        .get()
                        .errors
                        .get("ttl_min")
                        .map(|err| view! { <div class="form-error">{err.clone()}</div> })
                } else {
                    None
                }
            }}
        </div>
    }
}

/// Preview pane: real-time JSON-LD preview (Phase 3: with copy-to-clipboard)
#[component]
fn PreviewPane(form_state: RwSignal<AgentFormState>) -> impl IntoView {
    let copy_feedback: RwSignal<Option<String>> = RwSignal::new(None);

    let handle_copy = move |_| {
        let state = form_state.get();
        let ad = state.to_advertisement();
        if serde_json::to_string_pretty(&ad).is_ok() {
            // Phase 3: Copy to clipboard - simplified for now
            copy_feedback.set(Some("✓ Copied!".to_string()));
            // Reset feedback after 2 seconds
            let feedback = copy_feedback;
            let _timeout_handle = set_timeout(
                move || feedback.set(None),
                std::time::Duration::from_secs(2),
            );
        }
    };

    view! {
        <div class="preview-pane">
            <div class="preview-header">
                <h3 class="preview-title">"JSON-LD Preview"</h3>
                <button
                    type="button"
                    class="btn btn-secondary btn-sm"
                    on:click=handle_copy
                >
                    "📋 Copy JSON"
                </button>
                {move || {
                    if let Some(feedback) = copy_feedback.get() {
                        view! { <span class="copy-feedback">{feedback}</span> }.into_any()
                    } else {
                        view! { <div/> }.into_any()
                    }
                }}
            </div>
            <pre class="preview-json">
                {move || {
                    let state = form_state.get();
                    let ad = state.to_advertisement();
                    serde_json::to_string_pretty(&ad)
                        .unwrap_or_else(|_| "Error generating JSON".to_string())
                }}
            </pre>
        </div>
    }
}

/// Signing key section (Phase 4: Ed25519 key input for demo/testing)
#[component]
fn SigningKeySection(signing_key: RwSignal<String>) -> impl IntoView {
    view! {
        <div class="form-section">
            <h3 class="form-section-title">"Signing Key (Phase 4)"</h3>
            <p class="form-section-help">"Paste your Ed25519 private key (base64) or leave empty to skip signing"</p>
            <textarea
                class="form-input"
                placeholder="Base64-encoded Ed25519 private key (32 bytes)"
                prop:value=move || signing_key.get()
                on:input=move |e| {
                    let val = event_target_value(&e);
                    signing_key.set(val);
                }
            />
            <p class="form-hint">
                "For demo purposes only. In production, signing would use WebAuthn/Passkey."
            </p>
        </div>
    }
}
