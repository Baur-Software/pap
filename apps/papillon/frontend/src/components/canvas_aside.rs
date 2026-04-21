use leptos::prelude::*;
use papillon_shared::OrchestratorStatus;

use crate::components::canvas_chat_thread::CanvasChatThread;
use crate::state::canvas::CanvasState;
use crate::state::orchestrator::OrchestratorState;

#[derive(Clone, Copy, PartialEq)]
enum AsideMode {
    None,
    Plan,
    Auto,
}

/// Collapsible right aside for the canvas front face.
/// Contains:
/// - First-run tip explaining Papillon (dismissible, persisted to localStorage)
/// - Plan / Auto mode buttons (only when LLM is configured)
/// - Conversation / chat history via `CanvasChatThread`
///
/// The aside starts collapsed (`open` defaults to `false`). It exposes an X
/// close button to collapse itself. A topbar toggle was planned but was omitted
/// because `use_context::<RwSignal<bool>>()` is ambiguous — both `show_settings`
/// (provided in app root) and `aside_open` (provided in CanvasPage) share the
/// same type. The innermost context wins, but this is fragile across pages.
/// A future refactor should introduce a dedicated `AsideOpen(RwSignal<bool>)`
/// newtype to eliminate the ambiguity.
#[component]
pub fn CanvasAside(open: RwSignal<bool>) -> impl IntoView {
    let orchestrator = expect_context::<OrchestratorState>();
    let canvas_state = expect_context::<CanvasState>();
    let mode: RwSignal<AsideMode> = RwSignal::new(AsideMode::None);

    // Show tip until dismissed — persisted in localStorage under "papillon_aside_tip_dismissed"
    let show_tip = RwSignal::new({
        web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
            .and_then(|s| s.get_item("papillon_aside_tip_dismissed").ok().flatten())
            .is_none()
    });

    let dismiss_tip = move |_: leptos::ev::MouseEvent| {
        show_tip.set(false);
        if let Some(storage) = web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
        {
            let _ = storage.set_item("papillon_aside_tip_dismissed", "1");
        }
    };

    let has_llm = move || matches!(orchestrator.status.get(), OrchestratorStatus::Ready);

    let has_messages = move || {
        let active_id = canvas_state.current_canvas_id.get();
        canvas_state
            .canvas_messages
            .get()
            .iter()
            .any(|m| active_id.as_deref() == Some(m.canvas_id.as_str()))
    };

    view! {
        <div
            class="canvas-aside"
            class:collapsed=move || !open.get()
        >
            <div class="canvas-aside-header">
                <span class="canvas-aside-title">"CANVAS"</span>
                <button
                    class="canvas-aside-close"
                    on:click=move |_| open.set(false)
                    aria-label="Close aside"
                >"\u{00d7}"</button>
            </div>

            <div class="canvas-aside-body">
                // First-run tip
                <Show when=move || show_tip.get()>
                    <div class="canvas-aside-tip">
                        "Papillon is an intent browser. Type what you want to know or do — it finds and runs the right agent on your behalf, with your explicit approval over what data is shared."
                        <button class="canvas-aside-tip-dismiss" on:click=dismiss_tip>
                            "Got it, dismiss"
                        </button>
                    </div>
                </Show>

                // Plan / Auto mode (only when LLM is available)
                <Show when=has_llm>
                    <div class="canvas-aside-modes">
                        <div class="canvas-aside-mode-label">"AI MODE"</div>
                        <button
                            class="canvas-aside-mode-btn"
                            class:active=move || mode.get() == AsideMode::Plan
                            on:click=move |_| {
                                mode.update(|m| {
                                    *m = if *m == AsideMode::Plan { AsideMode::None } else { AsideMode::Plan };
                                });
                            }
                            title="Collect context on which agents to add and how properties connect, then present a plan."
                        >
                            "\u{1f4cb} Plan mode"
                        </button>
                        <button
                            class="canvas-aside-mode-btn"
                            class:active=move || mode.get() == AsideMode::Auto
                            on:click=move |_| {
                                mode.update(|m| {
                                    *m = if *m == AsideMode::Auto { AsideMode::None } else { AsideMode::Auto };
                                });
                            }
                            title="Immediately add advertised agent blocks and run automatically."
                        >
                            "\u{26a1} Auto mode"
                        </button>
                    </div>
                </Show>

                // Chat history (only when messages exist for the active canvas)
                <Show when=has_messages>
                    <div class="canvas-aside-chat-label">"CONVERSATION"</div>
                    <CanvasChatThread />
                </Show>
            </div>
        </div>
    }
}
