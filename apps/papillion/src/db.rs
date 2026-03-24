//! Re-export database types and implementations from papillion-shared.
//!
//! This module provides a backward-compatible interface to the shared database abstraction.
//! Existing code that imports from `crate::db` continues to work without changes.

pub use papillion_shared::db::{
    AgentProfile, DatabaseOps, DbError, Episode,
};

// Re-export for convenience
pub use papillion_shared::db::native::NativeDatabase;

// Type alias for backward compatibility
pub type Database = NativeDatabase;

// Prelude: import this for convenient access to trait methods
pub mod prelude {
    pub use papillion_shared::db::DatabaseOps;
}

// PapillionError compatibility layer
use crate::error::PapillionError;

impl From<DbError> for PapillionError {
    fn from(err: DbError) -> Self {
        PapillionError::from(err.0)
    }
}

// Helper functions for opening database
pub fn open_db(path: &std::path::Path) -> Result<Database, PapillionError> {
    NativeDatabase::open(path).map_err(|e| PapillionError::from(e.0))
}

#[cfg(test)]
pub fn open_db_memory() -> Result<Database, PapillionError> {
    NativeDatabase::open_memory().map_err(|e| PapillionError::from(e.0))
}
