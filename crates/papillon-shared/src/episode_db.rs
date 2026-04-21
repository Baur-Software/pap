//! Episode database — a focused rusqlite store for recording agent interaction episodes.
//!
//! An **episode** is the canonical record of a single mandate use: one agent interaction
//! anchored to a co-signed receipt.  This module provides a thin, ergonomic wrapper around
//! a rusqlite `Connection` with full CRUD support and an idempotent migration.
//!
//! # Usage
//!
//! ```rust,no_run
//! # use std::path::Path;
//! # use papillon_shared::episode_db::{EpisodeDb, Episode};
//! let db = EpisodeDb::open(Path::new("/tmp/episodes.sqlite")).unwrap();
//! let ep = Episode {
//!     id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
//!     session_did: "did:key:z6Mk...".to_string(),
//!     agent_did: "did:key:z6Mk...".to_string(),
//!     action: "schema:SearchAction".to_string(),
//!     scope_summary: "{}".to_string(),
//!     started_at: "2026-01-01T00:00:00Z".to_string(),
//!     completed_at: None,
//!     outcome: "success".to_string(),
//!     receipt_hash: None,
//!     principal_did: "did:key:z6Mk...".to_string(),
//! };
//! db.insert_episode(&ep).unwrap();
//! ```

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension, Result as SqlResult};
use serde::{Deserialize, Serialize};

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors that can occur during episode database operations.
#[derive(Debug)]
pub enum EpisodeDbError {
    /// A rusqlite error.
    Sqlite(rusqlite::Error),
    /// A lock-poisoning error (should only occur on panics in another thread).
    Lock(String),
}

impl std::fmt::Display for EpisodeDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EpisodeDbError::Sqlite(e) => write!(f, "sqlite error: {e}"),
            EpisodeDbError::Lock(e) => write!(f, "lock error: {e}"),
        }
    }
}

impl std::error::Error for EpisodeDbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EpisodeDbError::Sqlite(e) => Some(e),
            EpisodeDbError::Lock(_) => None,
        }
    }
}

impl From<rusqlite::Error> for EpisodeDbError {
    fn from(e: rusqlite::Error) -> Self {
        EpisodeDbError::Sqlite(e)
    }
}

/// Convenience alias used throughout this module.
pub type Result<T> = std::result::Result<T, EpisodeDbError>;

// ── Episode data model ────────────────────────────────────────────────────────

/// A single recorded agent interaction anchored to a co-signed receipt.
///
/// Each field directly maps to a column in the `episodes` table.
/// `scope_summary` is stored as a JSON string so callers may encode any
/// structured scope data without coupling the schema to a fixed shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Episode {
    /// UUID v4, primary key.
    pub id: String,

    /// The ephemeral session DID used for this interaction (e.g. `did:key:z6Mk…`).
    /// Ephemeral session DIDs are generated per-session and are intentionally
    /// unlinked from the principal identity.
    pub session_did: String,

    /// The DID of the agent that handled the interaction.
    pub agent_did: String,

    /// The Schema.org action type performed (e.g. `"schema:SearchAction"`).
    pub action: String,

    /// JSON-encoded summary of the scope that was exercised.  Stored as text so
    /// that protocol-level scope structures are not hard-coded into the schema.
    pub scope_summary: String,

    /// ISO 8601 timestamp at which the episode began.
    pub started_at: String,

    /// ISO 8601 timestamp at which the episode completed, or `None` if still
    /// in-flight or if the outcome was a `"timeout"`.
    pub completed_at: Option<String>,

    /// Terminal state of the episode.  Must be one of:
    /// - `"success"` — the agent completed the action and the receipt was co-signed.
    /// - `"failure"` — the agent reported an error or the receipt was refused.
    /// - `"timeout"` — the episode exceeded its TTL without completing.
    pub outcome: String,

    /// SHA-256 hex digest of the co-signed receipt, or `None` if no receipt was
    /// produced (e.g. for `"timeout"` outcomes).
    pub receipt_hash: Option<String>,

    /// The root principal's DID.  This is the human-controlled identity at the
    /// root of the delegation chain.
    pub principal_did: String,
}

// ── Approval record data model ────────────────────────────────────────────────

/// A persisted "always allow" decision from the principal.
///
/// Keyed by `(output_type, input_type, agent_did, principal_did)` so that
/// previously-approved property wire disclosures auto-approve silently on
/// subsequent runs until the record expires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// UUID v4, primary key.
    pub id: String,

    /// The Schema.org output type produced by the agent (e.g. `"schema:FlightReservation"`).
    pub output_type: String,

    /// The Schema.org input type consumed by the agent (e.g. `"schema:LodgingReservation"`).
    pub input_type: String,

    /// The DID of the agent that was approved.
    pub agent_did: String,

    /// The root principal's DID that granted the approval.
    pub principal_did: String,

    /// How many hours this approval is valid for (used when computing `expires_at`).
    pub ttl_hours: i64,

    /// ISO 8601 timestamp at which the approval was granted.
    pub approved_at: String,

    /// ISO 8601 timestamp at which the approval expires.
    pub expires_at: String,
}

// ── Database wrapper ──────────────────────────────────────────────────────────

/// A focused rusqlite wrapper for the episode store.
///
/// The `Mutex<Connection>` ensures the struct can be used safely from multiple
/// threads without requiring an `async` runtime.
pub struct EpisodeDb {
    conn: Mutex<Connection>,
}

impl EpisodeDb {
    // ── Constructors ──────────────────────────────────────────────────────

    /// Open (or create) the database at `path` and run idempotent migrations.
    ///
    /// The parent directory must already exist.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(EpisodeDbError::Sqlite)?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    /// Open an in-memory database.  Primarily intended for unit tests.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(EpisodeDbError::Sqlite)?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    // ── Private helpers ───────────────────────────────────────────────────

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|e| EpisodeDbError::Lock(e.to_string()))
    }

    /// Run all schema migrations.  Safe to call on every startup.
    ///
    /// Structured as two phases so that column-backfills (which SQLite only
    /// supports one-at-a-time and has no `IF NOT EXISTS` guard for) are applied
    /// before the indexes that depend on those columns are created.
    fn migrate(&self) -> Result<()> {
        let conn = self.lock()?;

        // Phase 1 — create tables and pragmas.
        // `CREATE TABLE IF NOT EXISTS` is safe on an existing DB.
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS episodes (
                id            TEXT PRIMARY KEY,
                session_did   TEXT NOT NULL,
                agent_did     TEXT NOT NULL,
                action        TEXT NOT NULL,
                scope_summary TEXT NOT NULL DEFAULT '{}',
                started_at    TEXT NOT NULL,
                completed_at  TEXT,
                outcome       TEXT NOT NULL
                                  CHECK(outcome IN ('success', 'failure', 'timeout')),
                receipt_hash  TEXT,
                principal_did TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS approval_records (
                id            TEXT PRIMARY KEY,
                output_type   TEXT NOT NULL,
                input_type    TEXT NOT NULL,
                agent_did     TEXT NOT NULL,
                principal_did TEXT NOT NULL,
                ttl_hours     INTEGER NOT NULL DEFAULT 24,
                approved_at   TEXT NOT NULL,
                expires_at    TEXT NOT NULL,
                UNIQUE(output_type, input_type, agent_did, principal_did)
            );
            ",
        )
        .map_err(EpisodeDbError::Sqlite)?;

        // Phase 2 — backfill columns that may be absent in databases created
        // before the current schema.  SQLite has no `ADD COLUMN IF NOT EXISTS`
        // so we execute each ALTER separately and treat "duplicate column" as
        // success (error code 1 / SQLITE_ERROR with "duplicate column name").
        //
        // Cover every non-primary-key column so the migration is safe regardless
        // of how old the on-disk DB is.  NOT NULL columns must have a DEFAULT so
        // SQLite can back-fill existing rows.  CHECK constraints are omitted from
        // ALTER TABLE because they are only enforced on new inserts — existing rows
        // are unaffected and new inserts still hit the constraint on the table def.
        let backfills: &[&str] = &[
            "ALTER TABLE episodes ADD COLUMN session_did   TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE episodes ADD COLUMN agent_did     TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE episodes ADD COLUMN action        TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE episodes ADD COLUMN scope_summary TEXT NOT NULL DEFAULT '{}'",
            "ALTER TABLE episodes ADD COLUMN started_at    TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE episodes ADD COLUMN completed_at  TEXT",
            "ALTER TABLE episodes ADD COLUMN outcome       TEXT NOT NULL DEFAULT 'success'",
            "ALTER TABLE episodes ADD COLUMN receipt_hash  TEXT",
            "ALTER TABLE episodes ADD COLUMN principal_did TEXT NOT NULL DEFAULT ''",
        ];
        for sql in backfills {
            match conn.execute(sql, []) {
                Ok(_) => {}
                Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error {
                        code: rusqlite::ffi::ErrorCode::Unknown,
                        ..
                    },
                    Some(ref msg),
                )) if msg.contains("duplicate column") => {
                    // Column already exists — this is the normal case on an up-to-date DB.
                }
                Err(e) => return Err(EpisodeDbError::Sqlite(e)),
            }
        }

        // Phase 3 — indexes.  Now safe because all referenced columns exist.
        conn.execute_batch(
            "
            CREATE INDEX IF NOT EXISTS idx_episodes_agent_did
                ON episodes(agent_did);
            CREATE INDEX IF NOT EXISTS idx_episodes_principal_did
                ON episodes(principal_did);
            CREATE INDEX IF NOT EXISTS idx_episodes_action
                ON episodes(action);
            CREATE INDEX IF NOT EXISTS idx_episodes_started_at
                ON episodes(started_at);
            CREATE INDEX IF NOT EXISTS idx_episodes_outcome
                ON episodes(outcome);

            CREATE INDEX IF NOT EXISTS idx_approval_agent
                ON approval_records(agent_did);
            ",
        )
        .map_err(EpisodeDbError::Sqlite)
    }

    // ── Write operations ──────────────────────────────────────────────────

    /// Persist a new episode.
    ///
    /// Returns `Err` if an episode with the same `id` already exists
    /// (the `id` column is a `PRIMARY KEY`).
    pub fn insert_episode(&self, episode: &Episode) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO episodes (
                id, session_did, agent_did, action, scope_summary,
                started_at, completed_at, outcome, receipt_hash, principal_did
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                episode.id,
                episode.session_did,
                episode.agent_did,
                episode.action,
                episode.scope_summary,
                episode.started_at,
                episode.completed_at,
                episode.outcome,
                episode.receipt_hash,
                episode.principal_did,
            ],
        )
        .map_err(EpisodeDbError::Sqlite)?;
        Ok(())
    }

    // ── Read operations ───────────────────────────────────────────────────

    /// Return the `limit` most-recent episodes ordered by `started_at` descending.
    ///
    /// A `limit` of `0` returns all episodes.
    pub fn list_episodes(&self, limit: usize) -> Result<Vec<Episode>> {
        let conn = self.lock()?;

        let mut stmt = if limit == 0 {
            conn.prepare(
                "SELECT id, session_did, agent_did, action, scope_summary,
                        started_at, completed_at, outcome, receipt_hash, principal_did
                 FROM episodes
                 ORDER BY started_at DESC",
            )
            .map_err(EpisodeDbError::Sqlite)?
        } else {
            conn.prepare(
                "SELECT id, session_did, agent_did, action, scope_summary,
                        started_at, completed_at, outcome, receipt_hash, principal_did
                 FROM episodes
                 ORDER BY started_at DESC
                 LIMIT ?1",
            )
            .map_err(EpisodeDbError::Sqlite)?
        };

        let rows = if limit == 0 {
            stmt.query_map([], row_to_episode)
                .map_err(EpisodeDbError::Sqlite)?
        } else {
            stmt.query_map(params![limit as i64], row_to_episode)
                .map_err(EpisodeDbError::Sqlite)?
        };

        rows.collect::<SqlResult<Vec<_>>>()
            .map_err(EpisodeDbError::Sqlite)
    }

    /// Look up a single episode by its UUID.
    ///
    /// Returns `Ok(None)` when no episode with that `id` exists.
    pub fn get_episode(&self, id: &str) -> Result<Option<Episode>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, session_did, agent_did, action, scope_summary,
                        started_at, completed_at, outcome, receipt_hash, principal_did
                 FROM episodes
                 WHERE id = ?1",
            )
            .map_err(EpisodeDbError::Sqlite)?;

        stmt.query_row(params![id], row_to_episode)
            .optional()
            .map_err(EpisodeDbError::Sqlite)
    }

    // ── Approval record operations ────────────────────────────────────────

    /// Check if a `(output_type, input_type, agent_did, principal_did)` tuple
    /// has a non-expired approval record.
    ///
    /// Returns `Ok(true)` only when a matching record exists **and** its
    /// `expires_at` timestamp is strictly in the future.
    pub fn has_approval(
        &self,
        output_type: &str,
        input_type: &str,
        agent_did: &str,
        principal_did: &str,
    ) -> Result<bool> {
        let conn = self.lock()?;
        let now = chrono::Utc::now().to_rfc3339();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM approval_records \
                 WHERE output_type=?1 AND input_type=?2 AND agent_did=?3 \
                 AND principal_did=?4 AND expires_at > ?5",
                rusqlite::params![output_type, input_type, agent_did, principal_did, now],
                |row| row.get(0),
            )
            .map_err(EpisodeDbError::Sqlite)?;
        Ok(count > 0)
    }

    /// Persist an "always allow" approval.
    ///
    /// Uses `ON CONFLICT … DO UPDATE` (upsert) so that re-approving the same
    /// `(output_type, input_type, agent_did, principal_did)` tuple simply
    /// refreshes the `approved_at` and `expires_at` timestamps without
    /// duplicating the row.
    pub fn store_approval(&self, record: &ApprovalRecord) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO approval_records \
             (id, output_type, input_type, agent_did, principal_did, ttl_hours, approved_at, expires_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8) \
             ON CONFLICT(output_type, input_type, agent_did, principal_did) \
             DO UPDATE SET expires_at=excluded.expires_at, approved_at=excluded.approved_at, ttl_hours=excluded.ttl_hours",
            rusqlite::params![
                record.id,
                record.output_type,
                record.input_type,
                record.agent_did,
                record.principal_did,
                record.ttl_hours,
                record.approved_at,
                record.expires_at,
            ],
        )
        .map_err(EpisodeDbError::Sqlite)?;
        Ok(())
    }

    /// Remove an approval record — called on explicit "Deny" or revocation.
    ///
    /// Silently succeeds when no matching record exists.
    pub fn revoke_approval(
        &self,
        output_type: &str,
        input_type: &str,
        agent_did: &str,
        principal_did: &str,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM approval_records \
             WHERE output_type=?1 AND input_type=?2 AND agent_did=?3 AND principal_did=?4",
            rusqlite::params![output_type, input_type, agent_did, principal_did],
        )
        .map_err(EpisodeDbError::Sqlite)?;
        Ok(())
    }
}

// ── Row mapping ───────────────────────────────────────────────────────────────

/// Map a rusqlite row to an [`Episode`].  Used by both `list_episodes` and
/// `get_episode` so the column ordering is defined in exactly one place.
fn row_to_episode(row: &rusqlite::Row<'_>) -> SqlResult<Episode> {
    Ok(Episode {
        id: row.get(0)?,
        session_did: row.get(1)?,
        agent_did: row.get(2)?,
        action: row.get(3)?,
        scope_summary: row.get(4)?,
        started_at: row.get(5)?,
        completed_at: row.get(6)?,
        outcome: row.get(7)?,
        receipt_hash: row.get(8)?,
        principal_did: row.get(9)?,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Construct a minimal valid episode for use in tests.
    fn make_episode(id: &str, outcome: &str) -> Episode {
        Episode {
            id: id.to_string(),
            session_did: format!("did:key:z6MkSession{id}"),
            agent_did: format!("did:key:z6MkAgent{id}"),
            action: "schema:SearchAction".to_string(),
            scope_summary: r#"{"actions":["schema:SearchAction"]}"#.to_string(),
            started_at: "2026-01-01T10:00:00Z".to_string(),
            completed_at: Some("2026-01-01T10:00:01Z".to_string()),
            outcome: outcome.to_string(),
            receipt_hash: Some(format!(
                "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6{id:0>4}"
            )),
            principal_did: "did:key:z6MkPrincipal".to_string(),
        }
    }

    // ── Migration / open ──────────────────────────────────────────────────

    #[test]
    fn open_in_memory_succeeds() {
        EpisodeDb::open_in_memory().expect("in-memory db should open");
    }

    #[test]
    fn migration_is_idempotent() {
        // Calling migrate() twice (once in open_in_memory, once manually) must
        // not fail.
        let db = EpisodeDb::open_in_memory().expect("open");
        db.migrate().expect("second migrate must not fail");
    }

    #[test]
    fn migration_upgrades_minimal_legacy_db() {
        // Simulate a DB created by an old version that only had (id, session_did).
        // The migration must add all missing columns and indexes without panicking.
        use rusqlite::Connection;
        use std::sync::Mutex;

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE episodes (id TEXT PRIMARY KEY, session_did TEXT NOT NULL);",
        )
        .unwrap();
        let db = EpisodeDb {
            conn: Mutex::new(conn),
        };
        db.migrate()
            .expect("migration must succeed on legacy minimal schema");

        // After migration we must be able to insert and retrieve a full episode.
        let ep = make_episode("legacy-001", "success");
        db.insert_episode(&ep).expect("insert after migration");
        let fetched = db.get_episode("legacy-001").unwrap();
        assert_eq!(fetched.as_ref(), Some(&ep));
    }

    // ── insert_episode ────────────────────────────────────────────────────

    #[test]
    fn insert_episode_round_trips() {
        let db = EpisodeDb::open_in_memory().unwrap();
        let ep = make_episode("0001", "success");
        db.insert_episode(&ep).expect("insert should succeed");

        let fetched = db.get_episode("0001").unwrap();
        assert_eq!(fetched.as_ref(), Some(&ep));
    }

    #[test]
    fn insert_episode_duplicate_id_is_error() {
        let db = EpisodeDb::open_in_memory().unwrap();
        let ep = make_episode("dup1", "success");
        db.insert_episode(&ep).expect("first insert");
        let result = db.insert_episode(&ep);
        assert!(result.is_err(), "inserting duplicate primary key must fail");
    }

    #[test]
    fn insert_episode_invalid_outcome_is_error() {
        let db = EpisodeDb::open_in_memory().unwrap();
        let mut ep = make_episode("bad1", "success");
        ep.outcome = "invalid".to_string();
        let result = db.insert_episode(&ep);
        assert!(
            result.is_err(),
            "outcome CHECK constraint must reject unknown values"
        );
    }

    #[test]
    fn insert_episode_all_outcome_variants() {
        let db = EpisodeDb::open_in_memory().unwrap();
        for (i, outcome) in ["success", "failure", "timeout"].iter().enumerate() {
            let mut ep = make_episode(&format!("{:04}", i), outcome);
            ep.outcome = outcome.to_string();
            db.insert_episode(&ep)
                .unwrap_or_else(|e| panic!("outcome '{outcome}' should be valid: {e}"));
        }
    }

    #[test]
    fn insert_episode_nullable_fields_accept_none() {
        let db = EpisodeDb::open_in_memory().unwrap();
        let ep = Episode {
            id: "null-fields".to_string(),
            session_did: "did:key:z6MkSession".to_string(),
            agent_did: "did:key:z6MkAgent".to_string(),
            action: "schema:BuyAction".to_string(),
            scope_summary: "{}".to_string(),
            started_at: "2026-03-01T08:00:00Z".to_string(),
            completed_at: None,
            outcome: "timeout".to_string(),
            receipt_hash: None,
            principal_did: "did:key:z6MkPrincipal".to_string(),
        };
        db.insert_episode(&ep)
            .expect("nullable fields should be stored");
        let fetched = db.get_episode("null-fields").unwrap().unwrap();
        assert_eq!(fetched.completed_at, None);
        assert_eq!(fetched.receipt_hash, None);
    }

    // ── list_episodes ─────────────────────────────────────────────────────

    #[test]
    fn list_episodes_returns_empty_on_fresh_db() {
        let db = EpisodeDb::open_in_memory().unwrap();
        let episodes = db.list_episodes(10).unwrap();
        assert!(episodes.is_empty(), "fresh db should have no episodes");
    }

    #[test]
    fn list_episodes_limit_is_honoured() {
        let db = EpisodeDb::open_in_memory().unwrap();
        for i in 0..5usize {
            db.insert_episode(&make_episode(&format!("{i:04}"), "success"))
                .unwrap();
        }
        let three = db.list_episodes(3).unwrap();
        assert_eq!(three.len(), 3, "limit=3 must return exactly 3 episodes");
    }

    #[test]
    fn list_episodes_zero_limit_returns_all() {
        let db = EpisodeDb::open_in_memory().unwrap();
        for i in 0..4usize {
            db.insert_episode(&make_episode(&format!("{i:04}"), "success"))
                .unwrap();
        }
        let all = db.list_episodes(0).unwrap();
        assert_eq!(all.len(), 4, "limit=0 must return all episodes");
    }

    #[test]
    fn list_episodes_ordered_by_started_at_desc() {
        let db = EpisodeDb::open_in_memory().unwrap();
        // Insert episodes with deliberate out-of-order timestamps.
        let episodes = vec![
            Episode {
                id: "e1".to_string(),
                started_at: "2026-01-01T10:00:00Z".to_string(),
                ..make_episode("e1", "success")
            },
            Episode {
                id: "e2".to_string(),
                started_at: "2026-01-03T10:00:00Z".to_string(),
                ..make_episode("e2", "success")
            },
            Episode {
                id: "e3".to_string(),
                started_at: "2026-01-02T10:00:00Z".to_string(),
                ..make_episode("e3", "success")
            },
        ];
        for ep in &episodes {
            db.insert_episode(ep).unwrap();
        }
        let listed = db.list_episodes(10).unwrap();
        assert_eq!(listed[0].started_at, "2026-01-03T10:00:00Z");
        assert_eq!(listed[1].started_at, "2026-01-02T10:00:00Z");
        assert_eq!(listed[2].started_at, "2026-01-01T10:00:00Z");
    }

    // ── get_episode ───────────────────────────────────────────────────────

    #[test]
    fn get_episode_returns_none_when_missing() {
        let db = EpisodeDb::open_in_memory().unwrap();
        let result = db.get_episode("nonexistent-id").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn get_episode_returns_correct_record() {
        let db = EpisodeDb::open_in_memory().unwrap();
        let ep_a = make_episode("aaa", "success");
        let ep_b = make_episode("bbb", "failure");
        db.insert_episode(&ep_a).unwrap();
        db.insert_episode(&ep_b).unwrap();

        let fetched_a = db.get_episode("aaa").unwrap();
        let fetched_b = db.get_episode("bbb").unwrap();

        assert_eq!(fetched_a.as_ref(), Some(&ep_a));
        assert_eq!(fetched_b.as_ref(), Some(&ep_b));
    }

    #[test]
    fn get_episode_preserves_all_fields() {
        let db = EpisodeDb::open_in_memory().unwrap();
        let ep = Episode {
            id: "full-fields".to_string(),
            session_did: "did:key:z6MkSess123".to_string(),
            agent_did: "did:key:z6MkAgent456".to_string(),
            action: "schema:ReserveAction".to_string(),
            scope_summary: r#"{"actions":["schema:ReserveAction"],"constraints":{"maxCost":100}}"#
                .to_string(),
            started_at: "2026-02-15T09:30:00Z".to_string(),
            completed_at: Some("2026-02-15T09:30:05Z".to_string()),
            outcome: "failure".to_string(),
            receipt_hash: Some(
                "deadbeef0000000000000000000000000000000000000000000000000000dead".to_string(),
            ),
            principal_did: "did:key:z6MkRoot789".to_string(),
        };
        db.insert_episode(&ep).unwrap();
        let fetched = db.get_episode("full-fields").unwrap().unwrap();

        assert_eq!(fetched.id, ep.id);
        assert_eq!(fetched.session_did, ep.session_did);
        assert_eq!(fetched.agent_did, ep.agent_did);
        assert_eq!(fetched.action, ep.action);
        assert_eq!(fetched.scope_summary, ep.scope_summary);
        assert_eq!(fetched.started_at, ep.started_at);
        assert_eq!(fetched.completed_at, ep.completed_at);
        assert_eq!(fetched.outcome, ep.outcome);
        assert_eq!(fetched.receipt_hash, ep.receipt_hash);
        assert_eq!(fetched.principal_did, ep.principal_did);
    }

    // ── Open-path constructor ─────────────────────────────────────────────

    #[test]
    fn open_path_creates_db_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("episodes.sqlite");
        {
            let db = EpisodeDb::open(&path).expect("open path db");
            db.insert_episode(&make_episode("path-test", "success"))
                .unwrap();
        }
        // Re-open to prove data persists.
        let db2 = EpisodeDb::open(&path).expect("re-open");
        let episodes = db2.list_episodes(10).unwrap();
        assert_eq!(episodes.len(), 1);
        assert_eq!(episodes[0].id, "path-test");
    }

    // ── approval_records ──────────────────────────────────────────────────

    #[test]
    fn approval_record_roundtrip() {
        let db = EpisodeDb::open_in_memory().unwrap();
        let now = chrono::Utc::now();
        let record = ApprovalRecord {
            id: uuid::Uuid::new_v4().to_string(),
            output_type: "schema:FlightReservation".into(),
            input_type: "schema:LodgingReservation".into(),
            agent_did: "did:key:zQ3shtest".into(),
            principal_did: "did:key:zQ3shprincipal".into(),
            ttl_hours: 24,
            approved_at: now.to_rfc3339(),
            expires_at: (now + chrono::Duration::hours(24)).to_rfc3339(),
        };
        db.store_approval(&record).unwrap();
        assert!(db
            .has_approval(
                "schema:FlightReservation",
                "schema:LodgingReservation",
                "did:key:zQ3shtest",
                "did:key:zQ3shprincipal"
            )
            .unwrap());

        // Revoke and verify gone.
        db.revoke_approval(
            "schema:FlightReservation",
            "schema:LodgingReservation",
            "did:key:zQ3shtest",
            "did:key:zQ3shprincipal",
        )
        .unwrap();
        assert!(!db
            .has_approval(
                "schema:FlightReservation",
                "schema:LodgingReservation",
                "did:key:zQ3shtest",
                "did:key:zQ3shprincipal"
            )
            .unwrap());
    }

    #[test]
    fn approval_upsert_refreshes_expiry() {
        let db = EpisodeDb::open_in_memory().unwrap();
        let now = chrono::Utc::now();
        let id = uuid::Uuid::new_v4().to_string();
        let record = ApprovalRecord {
            id: id.clone(),
            output_type: "schema:FlightReservation".into(),
            input_type: "schema:LodgingReservation".into(),
            agent_did: "did:key:zagent".into(),
            principal_did: "did:key:zprincipal".into(),
            ttl_hours: 1,
            approved_at: now.to_rfc3339(),
            expires_at: (now + chrono::Duration::hours(1)).to_rfc3339(),
        };
        db.store_approval(&record).unwrap();

        // Upsert with extended TTL.
        let refreshed = ApprovalRecord {
            id: uuid::Uuid::new_v4().to_string(),
            expires_at: (now + chrono::Duration::hours(48)).to_rfc3339(),
            ..record
        };
        db.store_approval(&refreshed).unwrap();
        // Should still be valid (not expired).
        assert!(db
            .has_approval(
                "schema:FlightReservation",
                "schema:LodgingReservation",
                "did:key:zagent",
                "did:key:zprincipal"
            )
            .unwrap());
    }

    #[test]
    fn expired_approval_not_returned() {
        let db = EpisodeDb::open_in_memory().unwrap();
        let past = chrono::Utc::now() - chrono::Duration::hours(2);
        let record = ApprovalRecord {
            id: uuid::Uuid::new_v4().to_string(),
            output_type: "schema:FlightReservation".into(),
            input_type: "schema:LodgingReservation".into(),
            agent_did: "did:key:zold".into(),
            principal_did: "did:key:zprincipal".into(),
            ttl_hours: 1,
            approved_at: (past - chrono::Duration::hours(1)).to_rfc3339(),
            expires_at: past.to_rfc3339(), // already expired
        };
        db.store_approval(&record).unwrap();
        assert!(!db
            .has_approval(
                "schema:FlightReservation",
                "schema:LodgingReservation",
                "did:key:zold",
                "did:key:zprincipal"
            )
            .unwrap());
    }
}
