//! `EpisodeStore` — Tauri-managed wrapper around the SQLite episode database.
//!
//! This module exposes a thin wrapper over `papillon_shared::db::NativeDatabase`
//! that can be registered as independent Tauri state so the frontend commands have
//! a single, typed handle for episode persistence. The underlying database file is
//! shared with `AppState::db` when the same path is passed; SQLite's own
//! connection-level locking keeps the two handles consistent.
//!
//! # Design
//! - `EpisodeStore::open` opens (or creates) the SQLite file and runs schema
//!   migrations exactly once.
//! - All operations delegate to the `DatabaseOps` trait implementation so the
//!   store is trivially swappable for tests or future WASM ports.

use std::path::Path;
use std::sync::Arc;

use crate::db::{prelude::DatabaseOps, Database, Episode};
use crate::error::PapillonError;
use papillon_shared::db::{ChatMessage, Conversation};

/// Tauri-managed episode persistence handle.
///
/// Wraps an `Arc<Database>` so it can be cheaply cloned across threads and
/// registered with `app.manage()` without taking ownership of the inner
/// connection pool.
#[derive(Clone)]
pub struct EpisodeStore {
    db: Arc<Database>,
}

impl EpisodeStore {
    /// Open (or create) the episode database at `app_data_dir/episodes.db`.
    ///
    /// Runs schema migrations on every open — migrations are idempotent and
    /// add no overhead on subsequent startups.
    pub fn open(app_data_dir: &Path) -> Result<Self, PapillonError> {
        let db_path = app_data_dir.join("episodes.db");
        let db = crate::db::open_db(&db_path)?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Create an `EpisodeStore` backed by an existing `Arc<Database>`.
    ///
    /// Used by `AppState` setup to share a single rusqlite connection with the
    /// rest of the application rather than opening a second file handle.
    pub fn from_db(db: Arc<Database>) -> Self {
        Self { db }
    }

    // ── Delegating accessors ─────────────────────────────────────────────

    /// Persist a completed episode to SQLite.
    pub fn record(&self, episode: &Episode) -> Result<(), PapillonError> {
        self.db
            .insert_episode(episode)
            .map_err(|e| PapillonError::from(e.0))
    }

    /// Return up to `limit` recent episodes, newest first.
    pub fn list_recent(&self, limit: usize) -> Result<Vec<Episode>, PapillonError> {
        self.db
            .list_episodes(None, None, limit, None)
            .map_err(|e| PapillonError::from(e.0))
    }

    /// Look up a single episode by its UUID string.
    ///
    /// Returns `None` when no matching episode exists.
    pub fn get_by_id(&self, id: &str) -> Result<Option<Episode>, PapillonError> {
        // `list_episodes` with a large offset has no per-ID filter, so we fetch
        // a small recent window and scan. For the expected episode volumes
        // (<10 k rows) this is fast; a follow-up ISS-631 will add FTS5 / indexed
        // lookup.
        let episodes = self
            .db
            .list_episodes(None, None, usize::MAX, None)
            .map_err(|e| PapillonError::from(e.0))?;
        Ok(episodes.into_iter().find(|ep| ep.id == id))
    }

    // ── Chat persistence ─────────────────────────────────────────────────

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    fn store() -> EpisodeStore {
        EpisodeStore::from_db(Arc::new(Database::open_memory().expect("in-memory db")))
    }

    fn conv(id: &str) -> Conversation {
        Conversation {
            id: id.to_string(),
            name: format!("Room {id}"),
            is_group: false,
            created_at: "2026-04-01T10:00:00Z".to_string(),
            updated_at: "2026-04-01T10:00:00Z".to_string(),
        }
    }

    fn msg(id: &str, conv_id: &str) -> ChatMessage {
        ChatMessage {
            id: id.to_string(),
            conversation_id: conv_id.to_string(),
            author_did: "did:key:zSender".to_string(),
            content: r#"{"body":{"content":"hi"}}"#.to_string(),
            created_at: "2026-04-01T10:01:00Z".to_string(),
            delivered: false,
        }
    }

    #[test]
    fn upsert_and_list_conversations() {
        let s = store();
        s.upsert_conversation(&conv("c-1")).unwrap();
        s.upsert_conversation(&conv("c-2")).unwrap();
        assert_eq!(s.list_conversations().unwrap().len(), 2);
    }

    #[test]
    fn insert_and_retrieve_messages() {
        let s = store();
        s.upsert_conversation(&conv("c-1")).unwrap();
        s.insert_message(&msg("m-1", "c-1")).unwrap();
        s.insert_message(&msg("m-2", "c-1")).unwrap();
        let msgs = s.list_messages("c-1", 100).unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(!msgs[0].delivered);
    }

    #[test]
    fn mark_delivered_flips_flag() {
        let s = store();
        s.upsert_conversation(&conv("c-1")).unwrap();
        s.insert_message(&msg("m-1", "c-1")).unwrap();
        s.mark_delivered("m-1").unwrap();
        let msgs = s.list_messages("c-1", 100).unwrap();
        assert!(msgs[0].delivered);
    }

    #[test]
    fn list_messages_limit_respected() {
        let s = store();
        s.upsert_conversation(&conv("c-1")).unwrap();
        for i in 0..6_u8 {
            s.insert_message(&msg(&i.to_string(), "c-1")).unwrap();
        }
        assert_eq!(s.list_messages("c-1", 4).unwrap().len(), 4);
    }
}
