//! Re-export database types and implementations from papillon-shared.
//!
//! This module provides a backward-compatible interface to the shared database abstraction.
//! Existing code that imports from `crate::db` continues to work without changes.

pub use papillon_shared::db::{AgentProfile, DatabaseOps, DbError, Episode};

// Re-export for convenience
pub use papillon_shared::db::native::NativeDatabase;

// Type alias for backward compatibility
pub type Database = NativeDatabase;

// Prelude: import this for convenient access to trait methods
pub mod prelude {
    pub use papillon_shared::db::DatabaseOps;
}

// PapillonError compatibility layer
use crate::error::PapillonError;

impl From<DbError> for PapillonError {
    fn from(err: DbError) -> Self {
        PapillonError::from(err.0)
    }
}

// Helper functions for opening database
pub fn open_db(path: &std::path::Path) -> Result<Database, PapillonError> {
    NativeDatabase::open(path).map_err(|e| PapillonError::from(e.0))
}
