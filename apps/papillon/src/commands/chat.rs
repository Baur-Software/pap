//! Tauri commands for chat — conversation and message persistence.
//!
//! All commands delegate to `ChatStore`, following the same pattern as
//! `commands/episodes.rs`. Group room creation is also handled here.

use chrono::Utc;
use tauri::State;

use crate::chat_store::ChatStore;
use papillon_shared::db::{ChatMessage, Conversation};

/// List all known conversations, newest first.
#[tauri::command]
pub fn list_conversations(store: State<'_, ChatStore>) -> Result<Vec<Conversation>, String> {
    store.list_conversations().map_err(|e| e.message)
}

/// Return up to `limit` messages for a conversation (oldest first).
///
/// `limit` defaults to 100 and is clamped to 500.
#[tauri::command]
pub fn get_chat_history(
    store: State<'_, ChatStore>,
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
    store: State<'_, ChatStore>,
    room_name: String,
    room_id: String,
) -> Result<Conversation, String> {
    let now = Utc::now().to_rfc3339();
    let conversation = Conversation {
        id: room_id,
        name: room_name,
        is_group: true,
        created_at: now.clone(),
        updated_at: now,
    };
    store
        .upsert_conversation(&conversation)
        .map_err(|e| e.message)?;
    Ok(conversation)
}

/// Join an existing room — persist a conversation record for an incoming
/// group chat whose room DID and name are provided by the room owner.
#[tauri::command]
pub fn join_group_chat(
    store: State<'_, ChatStore>,
    room_id: String,
    room_name: String,
) -> Result<Conversation, String> {
    let now = Utc::now().to_rfc3339();
    let conversation = Conversation {
        id: room_id,
        name: room_name,
        is_group: true,
        created_at: now.clone(),
        updated_at: now,
    };
    store
        .upsert_conversation(&conversation)
        .map_err(|e| e.message)?;
    Ok(conversation)
}

/// Persist a single chat message (called by the streaming layer after
/// each `StreamingMessage` is received or sent).
#[tauri::command]
pub fn record_chat_message(
    store: State<'_, ChatStore>,
    message: ChatMessage,
) -> Result<(), String> {
    store.insert_message(&message).map_err(|e| e.message)
}

/// Mark a message as delivered.
#[tauri::command]
pub fn mark_message_delivered(
    store: State<'_, ChatStore>,
    message_id: String,
) -> Result<(), String> {
    store.mark_delivered(&message_id).map_err(|e| e.message)
}
