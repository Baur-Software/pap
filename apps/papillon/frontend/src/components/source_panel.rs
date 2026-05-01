use leptos::prelude::*;
use papillon_shared::{AgentInfo, BlockState, CanvasBlock};

use crate::state::canvas::CanvasState;
use crate::state::registry::RegistryState;
use crate::state::templates::TemplatesState;

/// Side-panel with two tabs: **Blocks** (resolved/outcome/note blocks as
/// draggable chips) and **Agents** (browsable agent catalog with search and
/// disclosure filter).
///
/// - The Blocks tab preserves the existing chip behaviour (click to insert
///   `{{block:ID}}`, drag to compose, reshape via template picker).
/// - The Agents tab reads from `RegistryState.agents`, supports text search
///   and a "Zero Disclosure Only" toggle, and creates Ghost blocks on click.
#[component]
pub fn SourcePanel() -> impl IntoView {
    let active_tab: RwSignal<&'static str> = RwSignal::new("blocks");

    view! {
        <div class="source-panel">
            <div class="source-panel-tabs" role="tablist">
                <button
                    class="source-tab"
                    class:source-tab--active=move || active_tab.get() == "blocks"
                    role="tab"
                    on:click=move |_| active_tab.set("blocks")
                >
                    "Blocks"
                </button>
                <button
                    class="source-tab"
                    class:source-tab--active=move || active_tab.get() == "agents"
                    role="tab"
                    on:click=move |_| active_tab.set("agents")
                >
                    "Agents"
                </button>
            </div>
            <Show when=move || active_tab.get() == "blocks">
                <BlocksTab />
            </Show>
            <Show when=move || active_tab.get() == "agents">
                <AgentsTab />
            </Show>
        </div>
    }
}

// ── Blocks Tab ──────────────────────────────────────────────────────────────

/// Original resolved-blocks chip list, extracted into its own component.
#[component]
fn BlocksTab() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    let resolved_blocks = move || {
        canvas_state
            .current_canvas()
            .map(|c| {
                c.blocks
                    .into_iter()
                    .filter(|b| {
                        matches!(
                            b.state,
                            BlockState::Resolved
                                | BlockState::Outcome { .. }
                                | BlockState::Note { .. }
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };

    view! {
        <div class="source-panel-blocks-tab">
            <div class="source-panel-header">
                <span class="source-panel-title">"Sources"</span>
                <span class="source-count">{move || resolved_blocks().len()}</span>
            </div>
            <div class="source-chips">
                <For
                    each=resolved_blocks
                    key=|b| b.id.clone()
                    children=|block| view! { <SourceChip block=block /> }
                />
            </div>
        </div>
    }
}

// ── Agents Tab ──────────────────────────────────────────────────────────────

/// Browsable agent catalog with text search and disclosure filter.
#[component]
fn AgentsTab() -> impl IntoView {
    let registry = expect_context::<RegistryState>();

    let search_query: RwSignal<String> = RwSignal::new(String::new());
    let zero_disclosure_only: RwSignal<bool> = RwSignal::new(false);

    // Derive filtered agent list as a reactive closure.
    // We use a closure instead of Memo because AgentInfo does not implement
    // PartialEq (required by Memo).
    let filtered_agents = move || {
        let agents = registry.agents.get();
        let query = search_query.get().to_lowercase();
        let zd_only = zero_disclosure_only.get();

        agents
            .into_iter()
            .filter(|a| {
                // Zero-disclosure filter
                if zd_only && !a.requires_disclosure.is_empty() {
                    return false;
                }
                // Text search (name + capabilities + category, case-insensitive)
                if !query.is_empty() {
                    let name_match = a.name.to_lowercase().contains(&query);
                    let cap_match = a.capabilities.iter().any(|c| c.to_lowercase().contains(&query));
                    let cat_match = a.category.to_lowercase().contains(&query);
                    if !(name_match || cap_match || cat_match) {
                        return false;
                    }
                }
                true
            })
            .collect::<Vec<AgentInfo>>()
    };

    let agent_count = move || {
        let agents = registry.agents.get();
        let query = search_query.get().to_lowercase();
        let zd_only = zero_disclosure_only.get();

        agents
            .iter()
            .filter(|a| {
                if zd_only && !a.requires_disclosure.is_empty() {
                    return false;
                }
                if !query.is_empty() {
                    let name_match = a.name.to_lowercase().contains(&query);
                    let cap_match = a.capabilities.iter().any(|c| c.to_lowercase().contains(&query));
                    let cat_match = a.category.to_lowercase().contains(&query);
                    if !(name_match || cap_match || cat_match) {
                        return false;
                    }
                }
                true
            })
            .count()
    };

    view! {
        <div class="source-panel-agents-tab">
            <div class="agents-filter-bar">
                <input
                    class="agents-search-input"
                    type="text"
                    placeholder="Search agents..."
                    prop:value=move || search_query.get()
                    on:input=move |e| search_query.set(event_target_value(&e))
                />
                <label class="agents-disclosure-toggle">
                    <input
                        type="checkbox"
                        prop:checked=move || zero_disclosure_only.get()
                        on:change=move |e| {
                            let checked = event_target_checked(&e);
                            zero_disclosure_only.set(checked);
                        }
                    />
                    <span class="agents-disclosure-toggle-label">"Zero Disclosure"</span>
                </label>
            </div>
            <div class="agents-list-header">
                <span class="source-panel-title">"Agents"</span>
                <span class="source-count">{agent_count}</span>
            </div>
            <div class="agents-list">
                <For
                    each=filtered_agents
                    key=|a| format!("{}-{}", a.name, a.content_hash)
                    children=|agent| view! { <AgentCard agent=agent /> }
                />
            </div>
        </div>
    }
}

/// Helper to extract a checkbox's checked state from a change event.
fn event_target_checked(e: &leptos::ev::Event) -> bool {
    use wasm_bindgen::JsCast;
    e.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|el| el.checked())
        .unwrap_or(false)
}

// ── Agent Card ──────────────────────────────────────────────────────────────

/// Compact agent card for the Sources panel Agents tab.
/// Shows name, category, capabilities, disclosure badges, and trust indicator.
/// Click to create a Ghost block on the active canvas.
#[component]
fn AgentCard(agent: AgentInfo) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let agent_for_click = agent.clone();

    let name = agent.name.clone();
    let category = agent.category.clone();
    let is_local = agent.endpoint.is_none();

    let capabilities: Vec<String> = agent
        .capabilities
        .iter()
        .take(3) // Show at most 3 to keep cards compact
        .map(|c| c.trim_start_matches("schema:").to_string())
        .collect();
    let remaining_caps = if agent.capabilities.len() > 3 {
        Some(format!("+{}", agent.capabilities.len() - 3))
    } else {
        None
    };

    let zero_disclosure = agent.requires_disclosure.is_empty();
    let disclosure_props: Vec<String> = agent
        .requires_disclosure
        .iter()
        .take(3)
        .cloned()
        .collect();

    let on_click = move |_| {
        canvas_state.create_ghost_block(&agent_for_click);
    };

    view! {
        <div class="agent-card" on:click=on_click>
            <div class="agent-card-header">
                <span class="agent-card-name">{name}</span>
                {if !category.is_empty() {
                    view! { <span class="agent-card-category">{category}</span> }.into_any()
                } else {
                    view! { <span></span> }.into_any()
                }}
            </div>
            <div class="agent-card-capabilities">
                {capabilities.into_iter().map(|cap| view! {
                    <span class="agent-card-cap-badge">{cap}</span>
                }).collect::<Vec<_>>()}
                {remaining_caps.map(|r| view! {
                    <span class="agent-card-cap-badge agent-card-cap-overflow">{r}</span>
                })}
            </div>
            <div class="agent-card-footer">
                <div class="agent-card-disclosure">
                    {if zero_disclosure {
                        view! { <span class="agent-card-disclosure-badge agent-card-disclosure--zero">"Zero Disclosure"</span> }.into_any()
                    } else {
                        view! {
                            <span class="agent-card-disclosure-badges">
                                {disclosure_props.into_iter().map(|p| view! {
                                    <span class="agent-card-disclosure-badge agent-card-disclosure--required">{p}</span>
                                }).collect::<Vec<_>>()}
                            </span>
                        }.into_any()
                    }}
                </div>
                <span class=if is_local { "agent-card-trust agent-card-trust--local" } else { "agent-card-trust agent-card-trust--federated" }>
                    {if is_local { "Local" } else { "Federated" }}
                </span>
            </div>
        </div>
    }
}

// ── Source Chip (existing) ──────────────────────────────────────────────────

/// A single chip representing one resolved block.
#[component]
fn SourceChip(block: CanvasBlock) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let templates_state = expect_context::<TemplatesState>();

    let block_id = block.id.clone();
    let block_id_for_drag = block_id.clone();
    let block_id_for_reshape = block_id.clone();

    // For Note blocks show the note title with a pencil prefix.
    // For agent blocks extract the agent name from the JSON-LD envelope.
    let is_note = matches!(&block.state, BlockState::Note { .. });
    let agent_name = if is_note {
        block.content
            .as_ref()
            .and_then(|c| c.get("title").and_then(|t| t.as_str()))
            .map(|t| format!("\u{270f} {}", t))
            .unwrap_or_else(|| "\u{270f} Note".to_string())
    } else {
        block
            .content
            .as_ref()
            .and_then(|c| c.get("agent").and_then(|a| a.as_str()))
            .unwrap_or_else(|| {
                if block_id.len() > 8 {
                    &block_id[..8]
                } else {
                    &block_id
                }
            })
            .to_string()
    };

    let schema_type = block
        .schema_type
        .clone()
        .unwrap_or_default()
        .trim_start_matches("schema:")
        .to_string();

    let has_schema = !schema_type.is_empty();

    // The text/plain payload dropped onto the address bar.
    let drag_ref_text = format!("{{{{block:{}}}}}", block_id_for_drag);

    let (show_reshape, set_show_reshape) = signal(false);
    let (selected_template, set_selected_template) = signal(String::new());

    let on_chip_click = {
        let block_id = block_id.clone();
        let cs = canvas_state;
        move |_| cs.insert_block_ref(block_id.clone())
    };

    // TTL badge decay class derived from mandate_expires_at (mirrors the
    // logic in BlockRenderer so styling stays consistent).
    let ttl_badge = block.mandate_expires_at.as_ref().map(|expires| {
        let now_ms = js_sys::Date::now();
        let exp_ms =
            js_sys::Date::new(&wasm_bindgen::JsValue::from_str(expires)).get_time();
        let remaining_ms = exp_ms - now_ms;
        let decay_class = if remaining_ms < 0.0 {
            "source-chip-ttl decay-readonly"
        } else if remaining_ms < 600_000.0 {
            "source-chip-ttl decay-degraded"
        } else {
            "source-chip-ttl decay-active"
        };
        decay_class
    });

    view! {
        <div
            class="source-chip"
            draggable="true"
            on:dragstart=move |e: web_sys::DragEvent| {
                if let Some(dt) = e.data_transfer() {
                    let _ = dt.set_data("text/plain", &drag_ref_text);
                }
            }
        >
            <div class="source-chip-main" on:click=on_chip_click>
                <span class="source-chip-agent">{agent_name}</span>
                {if has_schema {
                    view! { <span class="source-chip-type">{schema_type}</span> }.into_any()
                } else {
                    view! { <span></span> }.into_any()
                }}
                {ttl_badge.map(|cls| view! { <span class=cls>"\u{25cf}"</span> }.into_any())}
            </div>
            <button
                class="source-chip-reshape"
                title="Reshape: apply a different template to this block"
                on:click=move |e: leptos::ev::MouseEvent| {
                    e.stop_propagation();
                    set_show_reshape.update(|v| *v = !*v);
                }
            >
                "\u{27f3}"
            </button>

            // Reshape picker — visible only when the user clicks the button.
            <Show when=move || show_reshape.get()>
                <div class="reshape-picker">
                    <select
                        on:change=move |e| {
                            set_selected_template.set(event_target_value(&e));
                        }
                    >
                        <option value="">"\u{2014} choose template \u{2014}"</option>
                        {move || {
                            templates_state
                                .all_templates()
                                .into_iter()
                                .map(|t| {
                                    let name = t.template_name.clone();
                                    let name2 = name.clone();
                                    view! {
                                        <option value={name}>{name2}</option>
                                    }
                                })
                                .collect::<Vec<_>>()
                        }}
                    </select>
                    <button
                        class="reshape-picker-apply"
                        on:click={
                            let block_id2 = block_id_for_reshape.clone();
                            let cs2 = canvas_state;
                            move |_| {
                                let tpl = selected_template.get();
                                if !tpl.is_empty() {
                                    cs2.reshape_block_template(block_id2.clone(), tpl);
                                    set_show_reshape.set(false);
                                }
                            }
                        }
                    >
                        "Apply"
                    </button>
                </div>
            </Show>
        </div>
    }
}
