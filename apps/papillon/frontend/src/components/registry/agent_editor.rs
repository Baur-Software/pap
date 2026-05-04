use leptos::prelude::*;
use papillon_shared::{AgentInfo, AgentLifecycle, ExecutionTarget};

use crate::components::registry::json_ld_panel::JsonLdPanel;

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Input,
    Returns,
    Disclosure,
    Endpoint,
    Settings,
}

#[component]
pub fn AgentEditor(agent: Signal<Option<AgentInfo>>) -> impl IntoView {
    let active_tab = RwSignal::new(Tab::Input);

    let agent_name = move || agent.get().map(|a| a.name.clone()).unwrap_or_default();
    let lifecycle = move || agent.get().map(|a| a.lifecycle.clone()).unwrap_or(AgentLifecycle::Draft);

    let lifecycle_label = move || match lifecycle() {
        AgentLifecycle::Draft => "Draft",
        AgentLifecycle::Published => "Published",
        AgentLifecycle::Unpublished => "Unpublished",
    };
    let lifecycle_style = move || match lifecycle() {
        AgentLifecycle::Draft =>
            "font-size: 10px; font-weight: 600; padding: 4px 10px; border-radius: 20px; background: rgba(100,116,139,0.12); color: #64748b; border: 1px solid #1e293b;",
        AgentLifecycle::Published =>
            "font-size: 10px; font-weight: 600; padding: 4px 10px; border-radius: 20px; background: rgba(108,92,231,0.15); color: #a78bfa; border: 1px solid rgba(108,92,231,0.3);",
        AgentLifecycle::Unpublished =>
            "font-size: 10px; font-weight: 600; padding: 4px 10px; border-radius: 20px; background: rgba(239,68,68,0.1); color: #f87171; border: 1px solid rgba(239,68,68,0.2);",
    };

    view! {
        <div style="flex: 1; display: flex; flex-direction: column; overflow: hidden;">
            // Agent bar
            <div style="padding: 12px 20px; border-bottom: 1px solid var(--border); background: var(--bg-secondary); display: flex; align-items: center; gap: 10px; flex-shrink: 0;">
                <ActionSelector agent=agent />
                <input
                    style="flex: 1; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 6px 12px; font-size: 14px; font-weight: 600; color: var(--text-primary);"
                    prop:value=agent_name
                    placeholder="Agent name\u{2026}"
                />
                <span style=lifecycle_style>{lifecycle_label}</span>
            </div>

            // Tabs
            <div style="display: flex; border-bottom: 1px solid var(--border); background: var(--bg-secondary); padding: 0 20px; flex-shrink: 0;">
                <TabButton tab=Tab::Input active_tab=active_tab label="Input" />
                <TabButton tab=Tab::Returns active_tab=active_tab label="Returns" />
                <TabButton tab=Tab::Disclosure active_tab=active_tab label="Disclosure" />
                <TabButton tab=Tab::Endpoint active_tab=active_tab label="Endpoint" />
                <TabButton tab=Tab::Settings active_tab=active_tab label="Settings" />
            </div>

            // Tab content
            <div style="flex: 1; overflow-y: auto; padding: 20px;">
                {move || match active_tab.get() {
                    Tab::Input => view! { <InputTab agent=agent /> }.into_any(),
                    Tab::Returns => view! { <ReturnsTab agent=agent /> }.into_any(),
                    Tab::Disclosure => view! { <DisclosureTab agent=agent /> }.into_any(),
                    Tab::Endpoint => view! { <EndpointTab agent=agent /> }.into_any(),
                    Tab::Settings => view! { <SettingsTab agent=agent /> }.into_any(),
                }}
            </div>

            <JsonLdPanel agent=agent />
        </div>
    }
}

#[component]
fn TabButton(tab: Tab, active_tab: RwSignal<Tab>, label: &'static str) -> impl IntoView {
    let is_active = move || active_tab.get() == tab;
    view! {
        <div
            style=move || format!(
                "font-size: 12px; padding: 10px 14px; cursor: pointer; color: {}; border-bottom: 2px solid {};",
                if is_active() { "#a78bfa" } else { "#334155" },
                if is_active() { "#6c5ce7" } else { "transparent" }
            )
            on:click=move |_| active_tab.set(tab)
        >
            {label}
        </div>
    }
}

#[component]
fn ActionSelector(agent: Signal<Option<AgentInfo>>) -> impl IntoView {
    let action = move || {
        agent
            .get()
            .and_then(|a| a.capabilities.first().cloned())
            .map(|s| papillon_shared::schema_phrase(&s))
            .unwrap_or_else(|| "Action".to_string())
    };
    view! {
        <select style="background: rgba(108,92,231,0.12); border: 1px solid rgba(108,92,231,0.25); border-radius: 6px; padding: 6px 10px; font-size: 12px; font-weight: 600; color: #a78bfa; cursor: pointer;">
            <option>{action}</option>
            <option>"Search"</option>
            <option>"Book"</option>
            <option>"Buy"</option>
            <option>"Reserve"</option>
            <option>"Review"</option>
            <option>"Create"</option>
            <option>"Find"</option>
        </select>
    }
}

#[component]
fn InputTab(agent: Signal<Option<AgentInfo>>) -> impl IntoView {
    let props = move || agent.get().map(|a| a.capabilities.clone()).unwrap_or_default();
    view! {
        <div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
                <span style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: #334155;">"Input Properties"</span>
                <button style="font-size: 10px; padding: 4px 10px; border-radius: 5px; background: rgba(255,255,255,0.04); color: #64748b; border: 1px solid var(--border); cursor: pointer;">
                    "+ Add Property"
                </button>
            </div>
            {move || props().into_iter().map(|p| {
                let phrase = papillon_shared::schema_phrase(&p);
                view! {
                    <div style="display: flex; gap: 8px; align-items: center; padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.04);">
                        <input
                            style="flex: 2; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 5px; padding: 5px 8px; font-size: 12px; color: #94a3b8;"
                            prop:value=phrase
                        />
                        <select style="flex: 1; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 5px; padding: 5px 8px; font-size: 12px; color: #7dd3fc;">
                            <option>"String"</option>
                            <option>"Number"</option>
                            <option>"Boolean"</option>
                            <option>"Enum"</option>
                            <option>"Date"</option>
                            <option>"URL"</option>
                        </select>
                        <span style="color: #1e293b; cursor: pointer; padding: 4px 6px;">{"×"}</span>
                    </div>
                }
            }).collect::<Vec<_>>()}
        </div>
    }
}

#[component]
fn ReturnsTab(agent: Signal<Option<AgentInfo>>) -> impl IntoView {
    let returns = move || agent.get().map(|a| a.returns.clone()).unwrap_or_default();
    view! {
        <div>
            <div style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: #334155; margin-bottom: 14px;">"Return Types"</div>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                {move || returns().into_iter().map(|r| {
                    let phrase = papillon_shared::schema_phrase(&r);
                    view! {
                        <span style="font-size: 12px; padding: 4px 10px; border-radius: 10px; background: rgba(167,139,250,0.08); color: #a78bfa; border: 1px solid rgba(167,139,250,0.2);">
                            {phrase}
                        </span>
                    }
                }).collect::<Vec<_>>()}
                <span style="font-size: 12px; padding: 4px 10px; border-radius: 10px; background: rgba(255,255,255,0.04); color: #334155; border: 1px solid var(--border); cursor: pointer;">
                    "+ Add type"
                </span>
            </div>
        </div>
    }
}

#[component]
fn DisclosureTab(agent: Signal<Option<AgentInfo>>) -> impl IntoView {
    let disclosure = move || agent.get().map(|a| a.requires_disclosure.clone()).unwrap_or_default();
    view! {
        <div>
            <div style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: #334155; margin-bottom: 14px;">"Disclosure Requirements"</div>
            {move || {
                let items = disclosure();
                if items.is_empty() {
                    view! {
                        <div style="font-size: 13px; color: #22c55e;">"No disclosure required \u{2014} zero-disclosure agent"</div>
                    }.into_any()
                } else {
                    view! {
                        <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                            {items.into_iter().map(|d| view! {
                                <span style="font-size: 12px; padding: 4px 10px; border-radius: 10px; background: rgba(245,158,11,0.08); color: #f59e0b; border: 1px solid rgba(245,158,11,0.2);">
                                    {d}
                                </span>
                            }).collect::<Vec<_>>()}
                        </div>
                    }.into_any()
                }
            }}
        </div>
    }
}

#[component]
fn EndpointTab(agent: Signal<Option<AgentInfo>>) -> impl IntoView {
    let endpoint_url = move || agent.get().and_then(|a| a.endpoint).unwrap_or_default();
    let exec_badge = move || {
        agent.get().map(|a| match &a.execution_target {
            ExecutionTarget::Remote(_) => ("Remote", "rgba(56,189,248,0.1)", "#7dd3fc", "rgba(56,189,248,0.2)"),
            ExecutionTarget::Local(_) => ("Local", "rgba(52,211,153,0.1)", "#6ee7b7", "rgba(52,211,153,0.2)"),
            ExecutionTarget::SubAgent(_) => ("Sub-agent", "rgba(251,191,36,0.1)", "#fcd34d", "rgba(251,191,36,0.2)"),
            ExecutionTarget::None => ("None", "rgba(100,116,139,0.1)", "#94a3b8", "rgba(100,116,139,0.2)"),
        })
    };
    view! {
        <div>
            <div style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: #334155; margin-bottom: 14px;">"Execution Target"</div>
            <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 8px;">
                <select style="background: rgba(52,211,153,0.1); border: 1px solid rgba(52,211,153,0.2); border-radius: 6px; padding: 7px 10px; font-size: 11px; font-weight: 700; color: #6ee7b7; cursor: pointer;">
                    <option>"GET"</option>
                    <option>"POST"</option>
                    <option>"PUT"</option>
                    <option>"DELETE"</option>
                </select>
                <input
                    style="flex: 1; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 7px 12px; font-size: 12px; color: #94a3b8; font-family: monospace;"
                    prop:value=endpoint_url
                    placeholder="https://api.example.com/endpoint"
                />
                {move || exec_badge().map(|(label, bg, color, border)| view! {
                    <span style=format!("font-size: 10px; font-weight: 600; padding: 4px 8px; border-radius: 10px; background: {bg}; color: {color}; border: 1px solid {border};")>
                        {label}
                    </span>
                })}
            </div>
            <div style="font-size: 11px; color: #1e293b;">"Badge derived from URL scheme: https:// = Remote \u{00b7} file:// = Local \u{00b7} did: or pap:// = Sub-agent"</div>
        </div>
    }
}

#[component]
fn SettingsTab(agent: Signal<Option<AgentInfo>>) -> impl IntoView {
    let provider = move || agent.get().map(|a| a.provider_name.clone()).unwrap_or_default();
    view! {
        <div style="display: flex; flex-direction: column; gap: 14px;">
            <div>
                <div style="font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #475569; margin-bottom: 6px;">"Provider Name"</div>
                <input
                    style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 7px 12px; font-size: 13px; color: #94a3b8;"
                    prop:value=provider
                />
            </div>
            <div>
                <div style="font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #475569; margin-bottom: 6px;">
                    "Description"
                    <span style="color: #334155; margin-left: 6px; font-size: 9px;">"(overrides derived verb phrase when present)"</span>
                </div>
                <textarea style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 7px 12px; font-size: 13px; color: #94a3b8; resize: vertical; min-height: 60px;" />
            </div>
            <div>
                <div style="font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #475569; margin-bottom: 6px;">"LLM Instructions"</div>
                <textarea style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 7px 12px; font-size: 12px; color: #94a3b8; resize: vertical; min-height: 80px; font-family: monospace;" />
            </div>
        </div>
    }
}
