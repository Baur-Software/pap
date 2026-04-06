//! Tauri commands for chat — conversation and message persistence.
//!
//! All commands delegate to `EpisodeStore`, which also owns the chat
//! persistence methods. Group room creation is handled here.

use chrono::Utc;
use tauri::State;

use crate::episode_store::EpisodeStore;
use papillon_shared::db::{ChatMessage, Conversation};

/// Build a `Conversation` record for a chat room, stamped with the current time.
fn build_room_conversation(room_id: String, room_name: String) -> Conversation {
    let now = Utc::now().to_rfc3339();
    Conversation {
        id: room_id,
        name: room_name,
        is_group: true,
        created_at: now.clone(),
        updated_at: now,
    }
}

/// List all known conversations, newest first.
#[tauri::command]
pub fn list_conversations(store: State<'_, EpisodeStore>) -> Result<Vec<Conversation>, String> {
    store.list_conversations().map_err(|e| e.message)
}

/// Return up to `limit` messages for a conversation (oldest first).
///
/// `limit` defaults to 100 and is clamped to 500.
#[tauri::command]
pub fn get_chat_history(
    store: State<'_, EpisodeStore>,
    conversation_id: String,
    limit: Option<usize>,
) -> Result<Vec<ChatMessage>, String> {
    let limit = limit.unwrap_or(100).min(500);
    store
        .list_messages(&conversation_id, limit)
        .map_err(|e| e.message)
}

/// Create a new group chat room and persist a conversation record.
///
/// Returns the persisted `Conversation` so the frontend can open it
/// immediately. Issuing CapabilityTokens to member DIDs is handled
/// separately by the orchestrator layer.
#[tauri::command]
pub fn create_group_chat(
    store: State<'_, EpisodeStore>,
    room_name: String,
    room_id: String,
) -> Result<Conversation, String> {
    let conversation = build_room_conversation(room_id, room_name);
    store
        .upsert_conversation(&conversation)
        .map_err(|e| e.message)?;
    Ok(conversation)
}

/// Join an existing room — persist a conversation record for an incoming
/// group chat whose room DID and name are provided by the room owner.
#[tauri::command]
pub fn join_group_chat(
    store: State<'_, EpisodeStore>,
    room_id: String,
    room_name: String,
) -> Result<Conversation, String> {
    let conversation = build_room_conversation(room_id, room_name);
    store
        .upsert_conversation(&conversation)
        .map_err(|e| e.message)?;
    Ok(conversation)
}

/// Persist a single chat message (called by the streaming layer after
/// each `StreamingMessage` is received or sent).
#[tauri::command]
pub fn record_chat_message(
    store: State<'_, EpisodeStore>,
    message: ChatMessage,
) -> Result<(), String> {
    store.insert_message(&message).map_err(|e| e.message)
}

/// Mark a message as delivered.
#[tauri::command]
pub fn mark_message_delivered(
    store: State<'_, EpisodeStore>,
    message_id: String,
) -> Result<(), String> {
    store.mark_delivered(&message_id).map_err(|e| e.message)
}
