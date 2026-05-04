use leptos::prelude::*;

use crate::state::canvas::{filter_messages_by_canvas, CanvasState};

/// Chat thread component — shows conversation messages and a simple input.
#[component]
pub fn CanvasChatThread(#[prop(optional)] compact: bool) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    // Only show messages belonging to the currently active canvas.
    let active_messages = move || {
        let active_id = canvas_state.current_canvas_id.get();
        filter_messages_by_canvas(
            &canvas_state.canvas_messages.get(),
            active_id.as_deref(),
        )
    };

    view! {
        <div class="canvas-chat-thread" class:compact=compact>
            <Show
                when=move || !active_messages().is_empty()
                fallback=move || view! {
                    <div class="canvas-chat-empty">
                        "No orchestrator activity yet. The next prompt will start a trace."
                    </div>
                }
            >
                <For
                    each=active_messages
                    key=|msg| msg.id.clone()
                    children=move |msg| {
                        let is_user = msg.role == "user";
                        let cls = if is_user { "chat-message-user" } else { "chat-message-assistant" };
                        let content = msg.content.clone();
                        let block_id = msg.block_id.clone();
                        let role_label = if is_user { "You" } else { "Papillon" };
                        view! {
                            <div class=cls>
                                <div class="chat-message-meta">
                                    <span class="chat-message-role">{role_label}</span>
                                    {move || {
                                        if let Some(ref bid) = block_id {
                                            let bid_short = if bid.len() > 8 {
                                                format!("{}...", &bid[..8])
                                            } else {
                                                bid.clone()
                                            };
                                            view! {
                                                <span class="chat-block-link">
                                                    {format!("block:{}", bid_short)}
                                                </span>
                                            }.into_any()
                                        } else {
                                            view! { <span /> }.into_any()
                                        }
                                    }}
                                </div>
                                <div class="chat-message-body">{content}</div>
                            </div>
                        }
                    }
                />
            </Show>
        </div>
    }
}
