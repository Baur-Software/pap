use leptos::prelude::*;
use papillon_shared::{AgentInfo, AgentLifecycle};
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::state::registry::RegistryState;

#[component]
pub fn JsonLdPanel(agent: Signal<Option<AgentInfo>>) -> impl IntoView {
    let registry = expect_context::<RegistryState>();

    let preview = move || {
        agent.get().map(|a| {
            let action = a.capabilities.first().cloned().unwrap_or_default();
            let returns = a.returns.first().cloned().unwrap_or_default();
            let did = a.agent_did.clone().unwrap_or_else(|| "did:key:\u{2026}".to_string());
            serde_json::json!({
                "@context": "https://schema.org",
                "@type": action,
                "name": a.name,
                "provider": {
                    "@type": "Organization",
                    "name": a.provider_name
                },
                "result": { "@type": returns },
                "did": did
            })
            .to_string()
        })
        .unwrap_or_default()
    };

    let lifecycle = move || agent.get().map(|a| a.lifecycle).unwrap_or(AgentLifecycle::Draft);

    let action_label = move || match lifecycle() {
        AgentLifecycle::Draft => "Sign & Publish",
        AgentLifecycle::Published => "Unpublish",
        AgentLifecycle::Unpublished => "Re-publish",
    };

    let action_style = move || match lifecycle() {
        AgentLifecycle::Draft | AgentLifecycle::Unpublished =>
            "font-size: 11px; font-weight: 600; padding: 5px 14px; background: #6c5ce7; color: #fff; border: none; border-radius: 6px; cursor: pointer;",
        AgentLifecycle::Published =>
            "font-size: 11px; font-weight: 600; padding: 5px 14px; background: transparent; color: #f87171; border: 1px solid rgba(248,113,113,0.3); border-radius: 6px; cursor: pointer;",
    };

    let on_action = move |_| {
        let agent_did = match agent.get().and_then(|a| a.agent_did.clone()) {
            Some(did) if !did.is_empty() => did,
            _ => {
                registry
                    .error
                    .set(Some("Agent has no DID — save the agent first to generate one.".into()));
                return;
            }
        };
        let lc = lifecycle();

        spawn_local(async move {
            #[derive(serde::Serialize)]
            struct AgentDidArg {
                agent_did: String,
            }
            let cmd = match lc {
                AgentLifecycle::Draft | AgentLifecycle::Unpublished => "sign_and_publish_local",
                AgentLifecycle::Published => "unpublish_local",
            };
            match bridge::invoke::<AgentDidArg, AgentInfo>(cmd, &AgentDidArg { agent_did }).await {
                Ok(_) => {
                    match bridge::invoke_no_args::<Vec<AgentInfo>>("list_local_agents").await {
                        Ok(agents) => registry.agents.set(agents),
                        Err(e) => registry.error.set(Some(format!("Transition succeeded but refresh failed: {e}"))),
                    }
                }
                Err(e) => registry.error.set(Some(e)),
            }
        });
    };

    view! {
        <div style="height: 200px; border-top: 1px solid var(--border); background: #0a0a12; display: flex; flex-direction: column; flex-shrink: 0;">
            <div style="display: flex; align-items: center; gap: 10px; padding: 0 16px; height: 36px; border-bottom: 1px solid var(--border); flex-shrink: 0;">
                <span style="font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-secondary);">"JSON-LD Advertisement"</span>
                <div style="margin-left: auto; display: flex; gap: 8px;">
                    <button style=action_style on:click=on_action>
                        {action_label}
                    </button>
                </div>
            </div>
            <div style="flex: 1; overflow-y: auto; padding: 12px 16px; font-family: 'JetBrains Mono', monospace; font-size: 11px; line-height: 1.7; color: #475569; white-space: pre-wrap;">
                {preview}
            </div>
        </div>
    }
}
