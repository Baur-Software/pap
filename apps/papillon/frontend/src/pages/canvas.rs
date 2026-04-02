use leptos::prelude::*;
use leptos::{ev, html};
use leptos_router::hooks::use_navigate;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

use crate::components::block_renderer::BlockRenderer;
use crate::state::canvas::{CanvasState, HitlRequest};
use crate::state::orchestrator::OrchestratorState;
use papillon_shared::OrchestratorStatus;

/// Try-it-now prompts that match real intent rules in `papillon_shared::intent`.
const QUICK_PROMPTS: &[&str] = &[
    "search for Rust programming",
    "weather in Tokyo",
    "define ephemeral",
    "paper on zero-knowledge proofs",
    "tell me about photosynthesis",
    "convert 100 USD to EUR",
];

/// Agent capabilities shown as clickable tiles on the new-tab canvas.
/// Each entry is (label, example_prompt).
const AGENT_TILES: &[(&str, &str)] = &[
    ("Web Search", "search for "),
    ("Wikipedia", "tell me about "),
    ("Weather", "weather in "),
    ("Dictionary", "define "),
    ("Currency", "convert 100 USD to EUR"),
    ("Countries", "country "),
    ("Research Papers", "paper on "),
    ("GitHub Repos", "github "),
    ("Books", "book about "),
    ("Hacker News", "hacker news "),
    ("Geocoding", "where is "),
    ("Web Reader", "https://"),
    ("AI Chat", "explain "),
];

#[component]
pub fn CanvasPage() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    let blocks = move || {
        canvas_state
            .current_canvas()
            .map(|c| c.blocks)
            .unwrap_or_default()
    };

    let has_blocks = move || !blocks().is_empty();

    // Group blocks by semantic links for rendering
    let grouped_blocks = move || {
        let all_blocks = blocks();
        let mut rendered: Vec<BlockGroup> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for block in &all_blocks {
            if seen.contains(&block.id) {
                continue;
            }
            seen.insert(block.id.clone());

            if block.linked_block_ids.is_empty() {
                rendered.push(BlockGroup::Single(block.clone()));
            } else {
                let mut group = vec![block.clone()];
                for linked_id in &block.linked_block_ids {
                    if !seen.contains(linked_id) {
                        if let Some(linked) = all_blocks.iter().find(|b| b.id == *linked_id) {
                            seen.insert(linked.id.clone());
                            group.push(linked.clone());
                        }
                    }
                }
                rendered.push(BlockGroup::Linked(group));
            }
        }
        rendered
    };

    let left_collapsed = RwSignal::new(false);
    let right_collapsed = RwSignal::new(false);

    let toggle_left = move |_| left_collapsed.set(!left_collapsed.get_untracked());
    let toggle_right = move |_| right_collapsed.set(!right_collapsed.get_untracked());

    view! {
        // HitL gate overlay — shown above everything when a gate is pending
        <HitlGate />

        <div class="canvas-workspace">
            // Left: Intent & Memory panel (collapsible)
            <div class="canvas-intent-panel" class:collapsed=left_collapsed>
                <div class="canvas-panel-header">
                    <span class="canvas-panel-label">"INTENT_MEMORY"</span>
                    <button class="canvas-panel-toggle" on:click=toggle_left>{move || if left_collapsed.get() { "▶" } else { "◀" }}</button>
                </div>
                <div class="canvas-panel-body">
                    <IntentPanel />
                </div>
            </div>

            // Center: main canvas (unchanged content)
            <div class="canvas-viewport">
                <div class="canvas-area">
                    <Show when=has_blocks fallback=move || view! {
                        <NewTabCanvas />
                    }>
                        <div class="canvas-blocks">
                            <For
                                each=grouped_blocks
                                key=|g| match g {
                                    BlockGroup::Single(b) => format!("{}@{}", b.id, b.updated_at),
                                    BlockGroup::Linked(bs) => bs.iter().map(|b| format!("{}@{}", b.id, b.updated_at)).collect::<Vec<_>>().join("-"),
                                }
                                children=move |group| {
                                    match group {
                                        BlockGroup::Single(block) => {
                                            view! { <BlockRenderer block=block /> }.into_any()
                                        }
                                        BlockGroup::Linked(blocks) => {
                                            view! {
                                                <div class="block-group">
                                                    {blocks.into_iter().map(|block| {
                                                        view! { <BlockRenderer block=block /> }
                                                    }).collect::<Vec<_>>()}
                                                </div>
                                            }.into_any()
                                        }
                                    }
                                }
                            />
                        </div>
                        <InlinePrompt />
                    </Show>
                </div>
            </div>

            // Right: Negotiation Ledger panel (collapsible)
            <div class="canvas-ledger-panel" class:collapsed=right_collapsed>
                <div class="canvas-panel-header">
                    <button class="canvas-panel-toggle" on:click=toggle_right>{move || if right_collapsed.get() { "◀" } else { "▶" }}</button>
                    <span class="canvas-panel-label">"NEGOTIATION_LEDGER"</span>
                </div>
                <div class="canvas-panel-body">
                    <CanvasLedger />
                </div>
            </div>
        </div>
    }
}

/// Left panel: shows session context from CanvasState and OrchestratorState.
#[component]
fn IntentPanel() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let orchestrator = expect_context::<OrchestratorState>();

    let session_id = move || {
        canvas_state.current_canvas()
            .map(|c| c.id.chars().take(12).collect::<String>())
            .unwrap_or_else(|| "NO_SESSION".to_string())
    };

    let block_count = move || {
        canvas_state.current_canvas()
            .map(|c| c.blocks.len())
            .unwrap_or(0)
    };

    let llm_status = move || {
        match orchestrator.status.get() {
            OrchestratorStatus::Ready => "SUBSTRATE_READY",
            OrchestratorStatus::Unconfigured => "NOT_CONFIGURED",
            OrchestratorStatus::Disconnected => "DISCONNECTED",
            _ => "UNKNOWN",
        }
    };

    view! {
        <div class="intent-section">
            <div class="intent-section-label">"SESSION"</div>
            <div class="intent-kv">
                <span class="intent-key">"ID"</span>
                <span class="intent-val">{session_id}</span>
            </div>
            <div class="intent-kv">
                <span class="intent-key">"BLOCKS"</span>
                <span class="intent-val">{block_count}</span>
            </div>
        </div>
        <div class="intent-divider" />
        <div class="intent-section">
            <div class="intent-section-label">"SUBSTRATE"</div>
            <div class="intent-kv">
                <span class="intent-key">"LLM"</span>
                <span class="intent-val intent-val-status">{llm_status}</span>
            </div>
        </div>
        <div class="intent-divider" />
        <div class="intent-section">
            <div class="intent-section-label">"SCOPE"</div>
            <div class="intent-hint">"No active mandate"</div>
            <div class="intent-hint">"Agents run zero-disclosure by default"</div>
        </div>
    }
}

/// Right panel: shows recent canvas blocks as ledger entries.
#[component]
fn CanvasLedger() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    let recent_blocks = move || {
        canvas_state.current_canvas()
            .map(|c| {
                let mut blocks = c.blocks;
                blocks.reverse();
                blocks.truncate(8);
                blocks
            })
            .unwrap_or_default()
    };

    view! {
        <Show when=move || recent_blocks().is_empty()>
            <div class="canvas-ledger-empty">"AWAITING_EVENTS"</div>
        </Show>
        <div class="canvas-ledger-entries">
            <For
                each=recent_blocks
                key=|b| b.id.clone()
                children=move |block| {
                    let action = block.schema_type.clone()
                        .unwrap_or_else(|| "Event".to_string());
                    let action_display = action.strip_prefix("schema:").unwrap_or(&action).to_string();
                    let ts = block.updated_at.chars().take(16).collect::<String>();
                    let is_failed = matches!(block.state, papillon_shared::BlockState::Failed { .. });
                    let outcome_class = if is_failed {
                        "canvas-ledger-entry canvas-ledger-entry-error"
                    } else {
                        "canvas-ledger-entry canvas-ledger-entry-ok"
                    };
                    view! {
                        <div class=outcome_class>
                            <span class="canvas-ledger-type">{action_display}</span>
                            <span class="canvas-ledger-ts">{ts}</span>
                        </div>
                    }
                }
            />
        </div>
    }
}

/// The empty canvas — like a new tab page in a browser.
/// Shows the prompt bar, available agents, and quick-start actions.
#[component]
fn NewTabCanvas() -> impl IntoView {
    let orchestrator = expect_context::<OrchestratorState>();
    let navigate = use_navigate();

    let is_unconfigured =
        move || matches!(orchestrator.status.get(), OrchestratorStatus::Unconfigured);
    let is_disconnected =
        move || matches!(orchestrator.status.get(), OrchestratorStatus::Disconnected);

    let nav = navigate.clone();
    let go_browse = move |_| {
        let n = nav.clone();
        n("/browse", Default::default());
    };

    view! {
        <div class="canvas-empty">
            <div class="newtab-hero">
                <img src="/logo.png" alt="" class="newtab-logo" />
                <p class="newtab-tagline">
                    "The browser for the agent web"
                </p>
            </div>

            <p class="inspiration-line">"Search the web, check the weather, or explore knowledge \u{2014} all through privacy-preserving agents."</p>

            <Show when=is_disconnected>
                <div class="canvas-prompt-setup">
                    <p>"Configure an LLM provider to unlock on-device AI capabilities."</p>
                    <a href="/settings" class="newtab-link">"Open Settings"</a>
                </div>
            </Show>

            <Show when=move || !is_disconnected()>
                <InlinePrompt />
            </Show>

            <Show when=is_unconfigured>
                <div class="newtab-setup-hint">
                    "On-device AI not configured yet \u{2014} "
                    "search, weather, wiki, and 10 more agents work without it. "
                    <a href="/settings" class="newtab-link">"Set up AI"</a>
                </div>
            </Show>

            <div class="agent-capabilities">
                <div class="capabilities-label">"Agents available now"</div>
                <AgentTiles />
            </div>

            <div class="newtab-footer">
                <button class="newtab-action" on:click=go_browse>
                    "Browse Registries"
                </button>
                <span class="newtab-hint">
                    {"\u{2318}K new canvas"}
                </span>
            </div>
        </div>
    }
}

/// Grid of clickable agent capability tiles.
/// Each tile populates the prompt input with an example query via signal.
#[component]
fn AgentTiles() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    view! {
        <div class="capabilities-grid">
            {AGENT_TILES.iter().map(|&(label, example)| {
                let cs = canvas_state;
                let ex = example.to_string();
                view! {
                    <button
                        class="capability-chip"
                        on:click=move |_| {
                            cs.prefill_prompt.set(Some(ex.clone()));
                            cs.focus_prompt.set(cs.focus_prompt.get_untracked() + 1);
                        }
                    >
                        {label}
                    </button>
                }
            }).collect::<Vec<_>>()}
        </div>
    }
}

/// Prompt input embedded directly in the canvas — the address bar of the agent web.
#[component]
fn InlinePrompt() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let input_ref = NodeRef::<html::Input>::new();
    let input_value = RwSignal::new(String::new());

    let submit = move || {
        let text = input_value.get();
        if text.trim().is_empty() {
            return;
        }
        canvas_state.submit_prompt(text.clone());
        input_value.set(String::new());
    };

    let on_keydown = move |e: ev::KeyboardEvent| {
        if e.key() == "Enter" {
            submit();
        }
    };

    let click_suggestion = move |text: &'static str| {
        input_value.set(text.to_string());
        if let Some(el) = input_ref.get() {
            let _ = el.focus();
        }
    };

    // Pick up prefill values from agent tile clicks
    Effect::new(move || {
        if let Some(text) = canvas_state.prefill_prompt.get() {
            input_value.set(text);
            canvas_state.prefill_prompt.set(None);
        }
    });

    // Focus the input on mount and whenever focus_prompt is bumped (e.g. ⌘K).
    // Capture the DOM element eagerly in the reactive context (still alive)
    // so the setTimeout callback doesn't access a disposed NodeRef.
    Effect::new(move || {
        let _ = canvas_state.focus_prompt.get(); // subscribe to signal
        let el_opt = input_ref.get();
        let cb = Closure::once(move || {
            if let Some(el) = el_opt {
                let _ = el.focus();
            }
        });
        let window = web_sys::window().unwrap();
        let _ = window
            .set_timeout_with_callback_and_timeout_and_arguments_0(cb.as_ref().unchecked_ref(), 50);
        cb.forget();
    });

    view! {
        <div class="canvas-prompt">
            <span class="palette-label">"What do you want to build?"</span>
            <input
                node_ref=input_ref
                class="palette-input"
                type="text"
                placeholder="Search agents, ask a question, or enter a pap:// address\u{2026}"
                prop:value=move || input_value.get()
                on:input=move |e| {
                    input_value.set(event_target_value(&e));
                }
                on:keydown=on_keydown
            />
            <Show when=move || input_value.get().is_empty()>
                <div class="palette-suggestions">
                    {QUICK_PROMPTS.iter().map(|&text| {
                        let t = text;
                        view! {
                            <button
                                class="palette-suggestion"
                                on:click=move |_| click_suggestion(t)
                            >
                                {t}
                            </button>
                        }
                    }).collect::<Vec<_>>()}
                </div>
            </Show>
        </div>
    }
}

/// Human-in-the-Loop gate — a full-screen critical action barrier.
/// Appears when `canvas_state.hitl_pending` is `Some`.
#[component]
fn HitlGate() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    let authorize = move |_| {
        canvas_state.hitl_pending.set(None);
        // Future: send approval signal back to the protocol layer
    };

    let reject = move |_| {
        canvas_state.hitl_pending.set(None);
        // Future: send rejection signal back to the protocol layer
    };

    view! {
        <Show when=move || canvas_state.hitl_pending.get().is_some()>
            {move || {
                let req = canvas_state.hitl_pending.get().unwrap();
                let is_critical = req.risk_level == "CRITICAL";
                view! {
                    <div class="hitl-overlay">
                        <div class="hitl-gate" class:hitl-gate-critical=is_critical>
                            <div class="hitl-header">
                                <span class="hitl-risk-badge" class:hitl-risk-critical=is_critical>
                                    {req.risk_level.clone()}
                                </span>
                                <span class="hitl-title">"HUMAN_GATE_REQUIRED"</span>
                            </div>

                            <div class="hitl-agent-row">
                                <span class="hitl-label">"AGENT"</span>
                                <span class="hitl-value">{req.agent_name.clone()}</span>
                            </div>
                            <div class="hitl-agent-row">
                                <span class="hitl-label">"ACTION"</span>
                                <span class="hitl-value">{
                                    req.action_type.strip_prefix("schema:")
                                        .unwrap_or(&req.action_type)
                                        .to_string()
                                }</span>
                            </div>

                            <div class="hitl-description">{req.description.clone()}</div>

                            <Show when=move || !req.disclosure_props.is_empty()>
                                <div class="hitl-disclosure">
                                    <div class="hitl-disclosure-label">"DISCLOSURE_REQUIRED"</div>
                                    <div class="hitl-disclosure-props">
                                        {req.disclosure_props.iter().map(|p| {
                                            view! { <span class="hitl-prop-tag">{p.clone()}</span> }
                                        }).collect::<Vec<_>>()}
                                    </div>
                                </div>
                            </Show>

                            <div class="hitl-actions">
                                <button class="hitl-reject-btn" on:click=reject>
                                    "[ REJECT ]"
                                </button>
                                <button class="hitl-authorize-btn" on:click=authorize>
                                    "[ AUTHORIZE ]"
                                </button>
                            </div>

                            <div class="hitl-footnote">
                                "This action requires your explicit authorization. "
                                "PAP protocol v1 \u{2014} Zero-trust principal gate."
                            </div>
                        </div>
                    </div>
                }
            }}
        </Show>
    }
}

#[derive(Clone)]
enum BlockGroup {
    Single(papillon_shared::CanvasBlock),
    Linked(Vec<papillon_shared::CanvasBlock>),
}
