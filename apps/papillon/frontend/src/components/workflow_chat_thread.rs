use leptos::prelude::*;
use papillon_shared::types::CanvasMessageRecord;

use crate::state::canvas::CanvasState;

#[component]
pub fn WorkflowChatThread() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let messages = canvas_state.canvas_messages;

    let all_messages = move || messages.get();

    view! {
        <div class="workflow-chat">
            <Show
                when=move || !all_messages().is_empty()
                fallback=|| view! {
                    <div class="workflow-chat-empty">
                        "No messages yet"
                    </div>
                }
            >
                <For
                    each=all_messages
                    key=|m| m.id.clone()
                    children=|msg| {
                        view! { <ChatMessage message=msg /> }
                    }
                />
            </Show>
        </div>
    }
}

#[component]
fn ChatMessage(message: CanvasMessageRecord) -> impl IntoView {
    let is_user = message.role == "user";
    let formatted_time = format_message_time(&message.created_at);

    view! {
        <div
            class="chat-message"
            class:user=is_user
            class:assistant=!is_user
        >
            <div class="chat-message-header">
                <span class="chat-message-role">
                    {if is_user { "You" } else { "Papillon" }}
                </span>
                <span class="chat-message-time">{formatted_time}</span>
            </div>
            <div class="chat-message-content">
                {message.content}
            </div>
        </div>
    }
}

fn format_message_time(timestamp: &str) -> String {
    // Simplified: just show timestamp
    // TODO: Implement relative time formatting
    timestamp.to_string()
}
