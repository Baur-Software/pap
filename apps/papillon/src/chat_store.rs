//! `ChatStore` — Tauri-managed wrapper for chat persistence.
//!
//! Thin wrapper over `papillon_shared::db::NativeDatabase` following the
//! same pattern as `EpisodeStore`.  Registered as Tauri state; all chat
//! commands delegate through this handle.

use std::path::Path;
use std::sync::Arc;

use crate::db::{prelude::DatabaseOps, Database};
use crate::error::PapillonError;
use papillon_shared::db::{ChatMessage, Conversation};

/// Tauri-managed chat persistence handle.
#[derive(Clone)]
pub struct ChatStore {
    db: Arc<Database>,
}

impl ChatStore {
    /// Open (or create) the database at `app_data_dir/episodes.db`.
    ///
    /// Chat tables are created by the same migration that handles episodes,
    /// so no separate file is needed.
    pub fn open(app_data_dir: &Path) -> Result<Self, PapillonError> {
        let db_path = app_data_dir.join("episodes.db");
        let db = crate::db::open_db(&db_path)?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Create a `ChatStore` backed by an existing `Arc<Database>`.
    ///
    /// Use this when sharing a single database connection with `AppState`.
    pub fn from_db(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Insert or update a conversation record.
    pub fn upsert_conversation(&self, conversation: &Conversation) -> Result<(), PapillonError> {
        self.db
            .upsert_conversation(conversation)
            .map_err(|e| PapillonError::from(e.0))
    }

    /// List all conversations, newest first.
    pub fn list_conversations(&self) -> Result<Vec<Conversation>, PapillonError> {
        self.db
            .list_conversations()
            .map_err(|e| PapillonError::from(e.0))
    }

    /// Persist a chat message.
    pub fn insert_message(&self, message: &ChatMessage) -> Result<(), PapillonError> {
        self.db
            .insert_chat_message(message)
            .map_err(|e| PapillonError::from(e.0))
    }

    /// Mark a message as delivered.
    pub fn mark_delivered(&self, message_id: &str) -> Result<(), PapillonError> {
        self.db
            .mark_message_delivered(message_id)
            .map_err(|e| PapillonError::from(e.0))
    }

    /// Return up to `limit` messages for a conversation, oldest first.
    pub fn list_messages(
        &self,
        conversation_id: &str,
        limit: usize,
    ) -> Result<Vec<ChatMessage>, PapillonError> {
        self.db
            .list_chat_messages(conversation_id, limit)
            .map_err(|e| PapillonError::from(e.0))
    }
}
