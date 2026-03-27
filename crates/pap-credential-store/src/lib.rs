//! Encrypted principal credential store for the Principal Agent Protocol.
//!
//! Provides encrypted-at-rest storage for PAP protocol material:
//!
//! - **Principal seeds** — Ed25519 signing key material (the root of trust)
//! - **Continuity tokens** — vendor-encrypted session state (spec section 13.3)
//! - **Verifiable credentials** — W3C VCs issued to the principal
//! - **Notary designations** — M-of-N social recovery mandates (spec section 13.5)
//!
//! # Encryption scheme
//!
//! Two-layer key model:
//! 1. Master password → Argon2id → master key (32 bytes)
//! 2. Master key wraps a random vault key via AES-256-GCM
//! 3. Each item encrypted with the vault key, using item ID as AAD
//!
//! The vault key never touches disk; it exists only in memory while unlocked.
//! Auto-lock zeroizes the key after a configurable timeout.
//!
//! # Usage
//!
//! ```rust,no_run
//! use pap_credential_store::{Vault, SqliteVaultStore, VaultItemData, VaultSigner};
//!
//! // Create a new vault
//! let store = SqliteVaultStore::open(std::path::Path::new("vault.db")).unwrap();
//! let vault = Vault::create(store, "master-password").unwrap();
//!
//! // Store a principal seed
//! let id = vault.add_item(VaultItemData::PrincipalSeed {
//!     name: "Alice".into(),
//!     seed_b64: "base64url-encoded-seed".into(),
//!     did: "did:key:z...".into(),
//! }).unwrap();
//!
//! // Retrieve and use as a signer
//! let seed = vault.get_principal_seed(&id).unwrap();
//! let signer = VaultSigner::from_seed(&seed).unwrap();
//! ```

pub mod crypto;
pub mod error;
pub mod signer;
pub mod store;
pub mod types;
pub mod vault;

#[cfg(feature = "sqlite")]
pub mod sqlite;

pub use error::VaultError;
pub use signer::VaultSigner;
pub use store::VaultStore;
pub use types::{
    EncryptedBlob, KdfParams, SensitiveKey, VaultHeader, VaultItem, VaultItemData,
    VaultItemSummary, VaultItemType,
};
pub use vault::Vault;

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteVaultStore;
