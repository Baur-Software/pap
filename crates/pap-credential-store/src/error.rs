use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault is locked")]
    VaultLocked,

    #[error("vault already exists")]
    VaultAlreadyExists,

    #[error("vault not initialized")]
    VaultNotInitialized,

    #[error("decryption failed: wrong password or corrupted data")]
    DecryptionFailed,

    #[error("item not found: {0}")]
    ItemNotFound(String),

    #[error("invalid key material: {0}")]
    InvalidKeyMaterial(String),

    #[error("storage error: {0}")]
    StorageError(String),

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("kdf error: {0}")]
    KdfError(String),
}
