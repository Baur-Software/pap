use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Authenticated ciphertext produced by AES-256-GCM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// KDF parameters persisted alongside the vault header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB (default 64 MiB = 65536).
    pub m_cost: u32,
    /// Time cost / iterations (default 3).
    pub t_cost: u32,
    /// Parallelism (default 4).
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

/// Single-row vault metadata stored in plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    pub id: String,
    pub version: u32,
    pub kdf_salt: [u8; 32],
    pub kdf_params: KdfParams,
    /// Vault key wrapped (encrypted) with the master key.
    pub encrypted_vault_key: EncryptedBlob,
    pub created_at: DateTime<Utc>,
}

/// Discriminant stored in plaintext for filtering without decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum VaultItemType {
    PrincipalSeed = 0,
    ContinuityToken = 1,
    VerifiableCredential = 2,
    NotaryDesignation = 3,
    ApiCredential = 4,
}

/// Row stored in the vault_items table.
#[derive(Debug, Clone)]
pub struct VaultItem {
    pub id: String,
    pub item_type: VaultItemType,
    pub encrypted_data: EncryptedBlob,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Decrypted item payload — the inner content of each vault item.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum VaultItemData {
    PrincipalSeed {
        name: String,
        /// 32-byte Ed25519 seed, base64url-encoded for JSON safety.
        seed_b64: String,
        did: String,
    },
    ContinuityToken {
        name: String,
        /// Vendor-encrypted opaque blob (base64url).
        token_b64: String,
        vendor_did: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at: Option<DateTime<Utc>>,
    },
    VerifiableCredential {
        name: String,
        credential_json: String,
        issuer_did: String,
    },
    NotaryDesignation {
        name: String,
        /// Serialized RecoveryMandate JSON.
        mandate_json: String,
        threshold: usize,
        notary_count: usize,
    },
    ApiCredential {
        name: String,
        value: String,
    },
}

impl VaultItemData {
    pub fn item_type(&self) -> VaultItemType {
        match self {
            Self::PrincipalSeed { .. } => VaultItemType::PrincipalSeed,
            Self::ContinuityToken { .. } => VaultItemType::ContinuityToken,
            Self::VerifiableCredential { .. } => VaultItemType::VerifiableCredential,
            Self::NotaryDesignation { .. } => VaultItemType::NotaryDesignation,
            Self::ApiCredential { .. } => VaultItemType::ApiCredential,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::PrincipalSeed { name, .. }
            | Self::ContinuityToken { name, .. }
            | Self::VerifiableCredential { name, .. }
            | Self::NotaryDesignation { name, .. }
            | Self::ApiCredential { name, .. } => name,
        }
    }
}

/// Summary returned by list operations (no secrets).
#[derive(Debug, Clone)]
pub struct VaultItemSummary {
    pub id: String,
    pub item_type: VaultItemType,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A 32-byte key that is zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SensitiveKey([u8; 32]);

impl SensitiveKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SensitiveKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SensitiveKey([REDACTED])")
    }
}
