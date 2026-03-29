use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};

use crate::error::PapillonError;
use papillon_shared::ProfileMetadata;

/// Dedicated profiles registry database — stores profile metadata and seeds.
///
/// Separate from the main `papillon.db` to enable:
/// - Profile discovery without decrypting individual profiles
/// - Atomic profile list operations
/// - Clean separation between global registry and per-profile content
///
/// Stores profile metadata (id, name, created_at, last_used, active) and each
/// profile's Ed25519 seed (base64url-encoded).
pub struct ProfilesDatabase {
    conn: Mutex<Connection>,
}

impl ProfilesDatabase {
    /// Open (or create) the profiles registry database at the given path and run migrations.
    pub fn open(path: &Path) -> Result<Self, PapillonError> {
        let conn = Connection::open(path)
            .map_err(|e| PapillonError::from(format!("profiles_db open: {e}")))?;

        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }

    /// Run schema migrations. Idempotent — safe to call on every startup.
    fn migrate(&self) -> Result<(), PapillonError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS profiles (
                id              TEXT PRIMARY KEY,
                name            TEXT NOT NULL UNIQUE,
                principal_seed_b64 TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                last_used       TEXT,
                active          INTEGER NOT NULL DEFAULT 0
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_active
                ON profiles(active) WHERE active = 1;
            ",
        )
        .map_err(|e| PapillonError::from(format!("profiles_db migrate: {e}")))?;

        Ok(())
    }

    // ── Profile CRUD ───────────────────────────────────────────

    /// Create a new profile with the given name and seed.
    /// Does NOT automatically set it as active.
    pub fn create_profile(
        &self,
        id: &str,
        name: &str,
        seed_b64: &str,
    ) -> Result<ProfileMetadata, PapillonError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;

        let now = chrono::Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO profiles (id, name, principal_seed_b64, created_at, active)
             VALUES (?1, ?2, ?3, ?4, 0)",
            params![id, name, seed_b64, now],
        )
        .map_err(|e| PapillonError::from(format!("profiles_db create: {e}")))?;

        Ok(ProfileMetadata {
            id: id.to_string(),
            name: name.to_string(),
            created_at: now,
            last_used: None,
            active: false,
        })
    }

    /// List all profiles.
    pub fn list_profiles(&self) -> Result<Vec<ProfileMetadata>, PapillonError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT id, name, created_at, last_used, active
                 FROM profiles ORDER BY created_at ASC",
            )
            .map_err(|e| PapillonError::from(format!("profiles_db prepare: {e}")))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(ProfileMetadata {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    created_at: row.get(2)?,
                    last_used: row.get(3)?,
                    active: row.get::<_, i32>(4)? != 0,
                })
            })
            .map_err(|e| PapillonError::from(format!("profiles_db query: {e}")))?;

        let mut profiles = Vec::new();
        for row in rows {
            profiles.push(row.map_err(|e| PapillonError::from(format!("profiles_db row: {e}")))?);
        }
        Ok(profiles)
    }

    /// Get the active profile (marked with active=1).
    pub fn get_active_profile(&self) -> Result<Option<ProfileMetadata>, PapillonError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT id, name, created_at, last_used, active
                 FROM profiles WHERE active = 1",
            )
            .map_err(|e| PapillonError::from(format!("profiles_db prepare: {e}")))?;

        let mut rows = stmt
            .query_map([], |row| {
                Ok(ProfileMetadata {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    created_at: row.get(2)?,
                    last_used: row.get(3)?,
                    active: row.get::<_, i32>(4)? != 0,
                })
            })
            .map_err(|e| PapillonError::from(format!("profiles_db query: {e}")))?;

        match rows.next() {
            Some(Ok(profile)) => Ok(Some(profile)),
            Some(Err(e)) => Err(PapillonError::from(format!("profiles_db row: {e}"))),
            None => Ok(None),
        }
    }

    /// Get a profile by ID.
    pub fn get_profile(&self, id: &str) -> Result<Option<ProfileMetadata>, PapillonError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT id, name, created_at, last_used, active
                 FROM profiles WHERE id = ?1",
            )
            .map_err(|e| PapillonError::from(format!("profiles_db prepare: {e}")))?;

        let mut rows = stmt
            .query_map(params![id], |row| {
                Ok(ProfileMetadata {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    created_at: row.get(2)?,
                    last_used: row.get(3)?,
                    active: row.get::<_, i32>(4)? != 0,
                })
            })
            .map_err(|e| PapillonError::from(format!("profiles_db query: {e}")))?;

        match rows.next() {
            Some(Ok(profile)) => Ok(Some(profile)),
            Some(Err(e)) => Err(PapillonError::from(format!("profiles_db row: {e}"))),
            None => Ok(None),
        }
    }

    /// Get a profile's seed by ID.
    pub fn get_profile_seed(&self, id: &str) -> Result<Option<String>, PapillonError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;

        let mut stmt = conn
            .prepare("SELECT principal_seed_b64 FROM profiles WHERE id = ?1")
            .map_err(|e| PapillonError::from(format!("profiles_db prepare: {e}")))?;

        let mut rows = stmt
            .query_map(params![id], |row| row.get::<_, String>(0))
            .map_err(|e| PapillonError::from(format!("profiles_db query: {e}")))?;

        match rows.next() {
            Some(Ok(seed)) => Ok(Some(seed)),
            Some(Err(e)) => Err(PapillonError::from(format!("profiles_db row: {e}"))),
            None => Ok(None),
        }
    }

    /// Switch active profile: set given profile to active, all others to inactive.
    /// Returns error if profile doesn't exist.
    pub fn switch_profile(&self, id: &str) -> Result<(), PapillonError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;

        // Begin transaction
        conn.execute("BEGIN TRANSACTION", [])
            .map_err(|e| PapillonError::from(format!("profiles_db begin: {e}")))?;

        // Verify profile exists
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM profiles WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .map_err(|e| PapillonError::from(format!("profiles_db query: {e}")))?;

        if exists == 0 {
            conn.execute("ROLLBACK", [])
                .map_err(|e| PapillonError::from(format!("profiles_db rollback: {e}")))?;
            return Err(PapillonError::from(format!("Profile {id} not found")));
        }

        // Set all to inactive, then set target to active
        conn.execute("UPDATE profiles SET active = 0", [])
            .map_err(|e| PapillonError::from(format!("profiles_db update: {e}")))?;

        conn.execute("UPDATE profiles SET active = 1 WHERE id = ?1", params![id])
            .map_err(|e| PapillonError::from(format!("profiles_db update: {e}")))?;

        // Update last_used timestamp
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE profiles SET last_used = ?1 WHERE id = ?2",
            params![now, id],
        )
        .map_err(|e| PapillonError::from(format!("profiles_db update: {e}")))?;

        // Commit transaction
        conn.execute("COMMIT", [])
            .map_err(|e| PapillonError::from(format!("profiles_db commit: {e}")))?;

        Ok(())
    }

    /// Rename a profile.
    pub fn rename_profile(&self, id: &str, new_name: &str) -> Result<(), PapillonError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;

        conn.execute(
            "UPDATE profiles SET name = ?1 WHERE id = ?2",
            params![new_name, id],
        )
        .map_err(|e| PapillonError::from(format!("profiles_db rename: {e}")))?;

        Ok(())
    }

    /// Delete a profile by ID.
    /// Returns error if it's the last profile or currently active.
    pub fn delete_profile(&self, id: &str) -> Result<(), PapillonError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;

        // Check if it's the active profile
        let is_active: i64 = conn
            .query_row(
                "SELECT active FROM profiles WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .map_err(|e| PapillonError::from(format!("profiles_db query: {e}")))?;

        if is_active != 0 {
            return Err(PapillonError::from(
                "Cannot delete the active profile".to_string(),
            ));
        }

        // Check if it's the last profile
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM profiles", [], |row| row.get(0))
            .map_err(|e| PapillonError::from(format!("profiles_db count: {e}")))?;

        if count <= 1 {
            return Err(PapillonError::from(
                "Cannot delete the last profile".to_string(),
            ));
        }

        // Delete the profile
        conn.execute("DELETE FROM profiles WHERE id = ?1", params![id])
            .map_err(|e| PapillonError::from(format!("profiles_db delete: {e}")))?;

        Ok(())
    }

    /// Update last_used timestamp for a profile.
    pub fn mark_last_used(&self, id: &str) -> Result<(), PapillonError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;

        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE profiles SET last_used = ?1 WHERE id = ?2",
            params![now, id],
        )
        .map_err(|e| PapillonError::from(format!("profiles_db update: {e}")))?;

        Ok(())
    }
}

/// Test-only: in-memory ProfilesDatabase for unit tests across the crate.
#[cfg(test)]
impl ProfilesDatabase {
    pub fn open_memory() -> Result<Self, crate::error::PapillonError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| crate::error::PapillonError::from(format!("profiles_db open: {e}")))?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.migrate()?;
        Ok(db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> ProfilesDatabase {
        ProfilesDatabase::open_memory().expect("in-memory profiles db")
    }

    #[test]
    fn create_and_list_profiles() {
        let db = test_db();
        db.create_profile("p1", "Profile 1", "seed1").unwrap();
        db.create_profile("p2", "Profile 2", "seed2").unwrap();

        let profiles = db.list_profiles().unwrap();
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].name, "Profile 1");
        assert_eq!(profiles[1].name, "Profile 2");
    }

    #[test]
    fn switch_profile_sets_active() {
        let db = test_db();
        db.create_profile("p1", "Profile 1", "seed1").unwrap();
        db.create_profile("p2", "Profile 2", "seed2").unwrap();

        db.switch_profile("p2").unwrap();

        let active = db.get_active_profile().unwrap().unwrap();
        assert_eq!(active.id, "p2");
        assert!(active.active);

        let p1 = db.get_profile("p1").unwrap().unwrap();
        assert!(!p1.active);
    }

    #[test]
    fn get_profile_seed() {
        let db = test_db();
        db.create_profile("p1", "Profile 1", "my_seed_b64").unwrap();

        let seed = db.get_profile_seed("p1").unwrap().unwrap();
        assert_eq!(seed, "my_seed_b64");
    }

    #[test]
    fn rename_profile() {
        let db = test_db();
        db.create_profile("p1", "Old Name", "seed1").unwrap();

        db.rename_profile("p1", "New Name").unwrap();

        let profile = db.get_profile("p1").unwrap().unwrap();
        assert_eq!(profile.name, "New Name");
    }

    #[test]
    fn cannot_delete_active_profile() {
        let db = test_db();
        db.create_profile("p1", "Profile 1", "seed1").unwrap();
        db.create_profile("p2", "Profile 2", "seed2").unwrap();

        db.switch_profile("p1").unwrap();

        let result = db.delete_profile("p1");
        assert!(result.is_err());
    }

    #[test]
    fn cannot_delete_last_profile() {
        let db = test_db();
        db.create_profile("p1", "Profile 1", "seed1").unwrap();

        let result = db.delete_profile("p1");
        assert!(result.is_err());
    }

    #[test]
    fn delete_non_active_profile() {
        let db = test_db();
        db.create_profile("p1", "Profile 1", "seed1").unwrap();
        db.create_profile("p2", "Profile 2", "seed2").unwrap();

        db.switch_profile("p1").unwrap();
        db.delete_profile("p2").unwrap();

        let profiles = db.list_profiles().unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].id, "p1");
    }

    #[test]
    fn unique_profile_name_constraint() {
        let db = test_db();
        db.create_profile("p1", "Duplicate", "seed1").unwrap();

        let result = db.create_profile("p2", "Duplicate", "seed2");
        assert!(result.is_err());
    }

    #[test]
    fn mark_last_used() {
        let db = test_db();
        db.create_profile("p1", "Profile 1", "seed1").unwrap();

        db.mark_last_used("p1").unwrap();

        let profile = db.get_profile("p1").unwrap().unwrap();
        assert!(profile.last_used.is_some());
    }
}
