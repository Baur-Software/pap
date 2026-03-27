//! Backend-agnostic storage trait for the vault.

use crate::error::VaultError;
use crate::types::{VaultHeader, VaultItem, VaultItemType};

/// Abstraction over vault persistence.
///
/// Implementations handle raw encrypted data only — they never see
/// plaintext secrets. The `Vault` orchestrator is responsible for
/// encryption/decryption using the in-memory vault key.
pub trait VaultStore: Send + Sync {
    /// Load the vault header, or None if no vault has been created.
    fn load_header(&self) -> Result<Option<VaultHeader>, VaultError>;

    /// Persist the vault header (creates or replaces).
    fn save_header(&self, header: &VaultHeader) -> Result<(), VaultError>;

    /// List all encrypted items.
    fn list_items(&self) -> Result<Vec<VaultItem>, VaultError>;

    /// List encrypted items filtered by type.
    fn list_items_by_type(&self, item_type: VaultItemType) -> Result<Vec<VaultItem>, VaultError>;

    /// Retrieve a single encrypted item by ID.
    fn get_item(&self, id: &str) -> Result<Option<VaultItem>, VaultError>;

    /// Insert a new encrypted item.
    fn insert_item(&self, item: &VaultItem) -> Result<(), VaultError>;

    /// Replace an existing encrypted item.
    fn update_item(&self, item: &VaultItem) -> Result<(), VaultError>;

    /// Delete an item by ID.
    fn delete_item(&self, id: &str) -> Result<(), VaultError>;
}
