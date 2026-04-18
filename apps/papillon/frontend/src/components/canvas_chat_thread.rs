use leptos::prelude::*;

use crate::state::canvas::{filter_messages_by_canvas, CanvasState};

/// Chat thread component — shows conversation messages and a simple input.
#[component]
pub fn CanvasChatThread() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let input_value = RwSignal::new(String::new());

    let on_keydown = move |e: leptos::ev::KeyboardEvent| {
        if e.key() == "Enter" {
            let text = input_value.get();
            let trimmed = text.trim().to_string();
            if !trimmed.is_empty() {
                canvas_state.submit_prompt(trimmed.clone());
                canvas_state.add_message("user", &trimmed, None);
                input_value.set(String::new());
            }
        }
    };

    // Only show messages belonging to the currently active canvas.
    let active_messages = move || {
        let active_id = canvas_state.current_canvas_id.get();
        filter_messages_by_canvas(
            &canvas_state.canvas_messages.get(),
            active_id.as_deref(),
        )
    };

    view! {
        <div class="canvas-chat-thread">
            <For
                each=active_messages
                key=|msg| msg.id.clone()
                children=move |msg| {
                    let is_user = msg.role == "user";
                    let cls = if is_user { "chat-message-user" } else { "chat-message-assistant" };
                    let content = msg.content.clone();
                    let block_id = msg.block_id.clone();
                    view! {
                        <div class=cls>
                            {content}
                            {move || {
                                if !is_user {
                                    if let Some(ref bid) = block_id {
                                        let bid_short = if bid.len() > 8 {
                                            format!("{}...", &bid[..8])
                                        } else {
                                            bid.clone()
                                        };
                                        view! {
                                            <span class="chat-block-link">
                                                {format!(" \u{2192} block:{}", bid_short)}
                                            </span>
                                        }.into_any()
                                    } else {
                                        view! { <span /> }.into_any()
                                    }
                                } else {
                                    view! { <span /> }.into_any()
                                }
                            }}
                        </div>
                    }
                }
            />
        </div>
        <div class="canvas-chat-input">
            <input
                type="text"
                placeholder="Ask anything..."
                prop:value=move || input_value.get()
                on:input=move |e| input_value.set(event_target_value(&e))
                on:keydown=on_keydown
            />
        </div>
    }
}
