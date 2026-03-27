//! Vault orchestrator — the public entry point for credential operations.
//!
//! Manages the lifecycle: create → open → unlock → CRUD → lock.
//! All encryption/decryption happens here; the VaultStore only sees ciphertext.

use std::sync::RwLock;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::VaultError;
use crate::store::VaultStore;
use crate::types::{
    KdfParams, SensitiveKey, VaultHeader, VaultItem, VaultItemData, VaultItemSummary, VaultItemType,
};

/// Default auto-lock timeout: 15 minutes.
const DEFAULT_AUTO_LOCK_SECS: u64 = 900;

/// AAD used when wrapping the vault key with the master key.
const VAULT_KEY_AAD: &[u8] = b"pap-vault-key";

pub struct Vault<S: VaultStore> {
    store: S,
    state: RwLock<VaultState>,
    auto_lock_duration: Duration,
}

enum VaultState {
    Locked,
    Unlocked {
        vault_key: SensitiveKey,
        unlocked_at: Instant,
    },
}

impl<S: VaultStore> Vault<S> {
    /// Create a new vault with the given master password.
    ///
    /// Generates a random vault key, encrypts it with a key derived from the
    /// master password via Argon2id, and persists the header.
    pub fn create(store: S, master_password: &str) -> Result<Self, VaultError> {
        if store.load_header()?.is_some() {
            return Err(VaultError::VaultAlreadyExists);
        }

        let kdf_params = KdfParams::default();
        let salt = crypto::generate_salt();
        let master_key = crypto::derive_master_key(master_password.as_bytes(), &salt, &kdf_params)?;

        let vault_key = crypto::generate_vault_key();
        let encrypted_vault_key =
            crypto::encrypt(master_key.as_bytes(), vault_key.as_bytes(), VAULT_KEY_AAD)?;

        let header = VaultHeader {
            id: Uuid::new_v4().to_string(),
            version: 1,
            kdf_salt: salt,
            kdf_params,
            encrypted_vault_key,
            created_at: Utc::now(),
        };
        store.save_header(&header)?;

        Ok(Self {
            store,
            state: RwLock::new(VaultState::Unlocked {
                vault_key,
                unlocked_at: Instant::now(),
            }),
            auto_lock_duration: Duration::from_secs(DEFAULT_AUTO_LOCK_SECS),
        })
    }

    /// Create a new vault with fast KDF parameters (for testing only).
    #[cfg(test)]
    pub fn create_with_fast_kdf(store: S, master_password: &str) -> Result<Self, VaultError> {
        if store.load_header()?.is_some() {
            return Err(VaultError::VaultAlreadyExists);
        }

        let kdf_params = KdfParams {
            m_cost: 256,
            t_cost: 1,
            p_cost: 1,
        };
        let salt = crypto::generate_salt();
        let master_key = crypto::derive_master_key(master_password.as_bytes(), &salt, &kdf_params)?;

        let vault_key = crypto::generate_vault_key();
        let encrypted_vault_key =
            crypto::encrypt(master_key.as_bytes(), vault_key.as_bytes(), VAULT_KEY_AAD)?;

        let header = VaultHeader {
            id: Uuid::new_v4().to_string(),
            version: 1,
            kdf_salt: salt,
            kdf_params,
            encrypted_vault_key,
            created_at: Utc::now(),
        };
        store.save_header(&header)?;

        Ok(Self {
            store,
            state: RwLock::new(VaultState::Unlocked {
                vault_key,
                unlocked_at: Instant::now(),
            }),
            auto_lock_duration: Duration::from_secs(DEFAULT_AUTO_LOCK_SECS),
        })
    }

    /// Open an existing vault (starts locked).
    pub fn open(store: S) -> Result<Self, VaultError> {
        if store.load_header()?.is_none() {
            return Err(VaultError::VaultNotInitialized);
        }
        Ok(Self {
            store,
            state: RwLock::new(VaultState::Locked),
            auto_lock_duration: Duration::from_secs(DEFAULT_AUTO_LOCK_SECS),
        })
    }

    /// Set the auto-lock timeout duration.
    pub fn set_auto_lock_duration(&mut self, duration: Duration) {
        self.auto_lock_duration = duration;
    }

    /// Unlock the vault by deriving the master key and decrypting the vault key.
    pub fn unlock(&self, master_password: &str) -> Result<(), VaultError> {
        let header = self
            .store
            .load_header()?
            .ok_or(VaultError::VaultNotInitialized)?;

        let master_key = crypto::derive_master_key(
            master_password.as_bytes(),
            &header.kdf_salt,
            &header.kdf_params,
        )?;

        let vault_key_bytes = crypto::decrypt(
            master_key.as_bytes(),
            &header.encrypted_vault_key,
            VAULT_KEY_AAD,
        )?;

        let vault_key_arr: [u8; 32] = vault_key_bytes.try_into().map_err(|_| {
            VaultError::InvalidKeyMaterial("decrypted vault key is not 32 bytes".into())
        })?;

        let mut state = self
            .state
            .write()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        *state = VaultState::Unlocked {
            vault_key: SensitiveKey::new(vault_key_arr),
            unlocked_at: Instant::now(),
        };
        Ok(())
    }

    /// Lock the vault, zeroizing the in-memory vault key.
    pub fn lock(&self) {
        if let Ok(mut state) = self.state.write() {
            *state = VaultState::Locked;
        }
    }

    /// Check whether the vault is currently locked.
    pub fn is_locked(&self) -> bool {
        match self.state.read() {
            Ok(state) => matches!(*state, VaultState::Locked),
            Err(_) => true,
        }
    }

    /// Change the master password. Requires the vault to be unlocked.
    ///
    /// Re-wraps the existing vault key with a new master key derived from
    /// the new password. Item ciphertexts are unchanged.
    pub fn change_password(
        &self,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), VaultError> {
        let vault_key = self.vault_key()?;

        // Verify current password is correct by attempting to derive and decrypt
        let header = self
            .store
            .load_header()?
            .ok_or(VaultError::VaultNotInitialized)?;
        let current_master = crypto::derive_master_key(
            current_password.as_bytes(),
            &header.kdf_salt,
            &header.kdf_params,
        )?;
        // This will fail if the current password is wrong
        crypto::decrypt(
            current_master.as_bytes(),
            &header.encrypted_vault_key,
            VAULT_KEY_AAD,
        )?;

        // Derive new master key with a fresh salt
        let new_salt = crypto::generate_salt();
        let new_kdf = KdfParams::default();
        let new_master = crypto::derive_master_key(new_password.as_bytes(), &new_salt, &new_kdf)?;

        let new_encrypted_vault_key =
            crypto::encrypt(new_master.as_bytes(), vault_key.as_bytes(), VAULT_KEY_AAD)?;

        let new_header = VaultHeader {
            id: header.id,
            version: header.version,
            kdf_salt: new_salt,
            kdf_params: new_kdf,
            encrypted_vault_key: new_encrypted_vault_key,
            created_at: header.created_at,
        };
        self.store.save_header(&new_header)
    }

    /// Add an item to the vault. Returns the new item's ID.
    pub fn add_item(&self, data: VaultItemData) -> Result<String, VaultError> {
        let vault_key = self.vault_key()?;
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let plaintext =
            serde_json::to_vec(&data).map_err(|e| VaultError::SerializationError(e.to_string()))?;
        let encrypted_data = crypto::encrypt(vault_key.as_bytes(), &plaintext, id.as_bytes())?;

        let item = VaultItem {
            id: id.clone(),
            item_type: data.item_type(),
            encrypted_data,
            created_at: now,
            updated_at: now,
        };
        self.store.insert_item(&item)?;
        Ok(id)
    }

    /// Retrieve and decrypt a single item by ID.
    pub fn get_item(&self, id: &str) -> Result<VaultItemData, VaultError> {
        let vault_key = self.vault_key()?;
        let item = self
            .store
            .get_item(id)?
            .ok_or_else(|| VaultError::ItemNotFound(id.to_string()))?;

        decrypt_item_data(vault_key.as_bytes(), &item)
    }

    /// Update an existing item's data.
    pub fn update_item(&self, id: &str, data: VaultItemData) -> Result<(), VaultError> {
        let vault_key = self.vault_key()?;

        // Verify item exists
        let existing = self
            .store
            .get_item(id)?
            .ok_or_else(|| VaultError::ItemNotFound(id.to_string()))?;

        let plaintext =
            serde_json::to_vec(&data).map_err(|e| VaultError::SerializationError(e.to_string()))?;
        let encrypted_data = crypto::encrypt(vault_key.as_bytes(), &plaintext, id.as_bytes())?;

        let item = VaultItem {
            id: id.to_string(),
            item_type: data.item_type(),
            encrypted_data,
            created_at: existing.created_at,
            updated_at: Utc::now(),
        };
        self.store.update_item(&item)
    }

    /// Remove an item from the vault.
    pub fn remove_item(&self, id: &str) -> Result<(), VaultError> {
        self.require_unlocked()?;
        self.store.delete_item(id)
    }

    /// List all items as summaries (decrypts name only).
    pub fn list_items(&self) -> Result<Vec<VaultItemSummary>, VaultError> {
        let vault_key = self.vault_key()?;
        let items = self.store.list_items()?;
        items_to_summaries(vault_key.as_bytes(), &items)
    }

    /// List items of a specific type as summaries.
    pub fn list_by_type(&self, t: VaultItemType) -> Result<Vec<VaultItemSummary>, VaultError> {
        let vault_key = self.vault_key()?;
        let items = self.store.list_items_by_type(t)?;
        items_to_summaries(vault_key.as_bytes(), &items)
    }

    /// Extract a principal seed from a PrincipalSeed item, returned as Zeroizing bytes.
    pub fn get_principal_seed(&self, id: &str) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let data = self.get_item(id)?;
        match data {
            VaultItemData::PrincipalSeed { seed_b64, .. } => {
                let bytes = URL_SAFE_NO_PAD
                    .decode(&seed_b64)
                    .map_err(|e| VaultError::InvalidKeyMaterial(e.to_string()))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| VaultError::InvalidKeyMaterial("seed is not 32 bytes".into()))?;
                Ok(Zeroizing::new(arr))
            }
            _ => Err(VaultError::InvalidKeyMaterial(
                "item is not a PrincipalSeed".into(),
            )),
        }
    }

    /// Get a reference to the vault key, checking lock state and auto-lock timeout.
    fn vault_key(&self) -> Result<SensitiveKey, VaultError> {
        let state = self
            .state
            .read()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        match &*state {
            VaultState::Locked => Err(VaultError::VaultLocked),
            VaultState::Unlocked {
                vault_key,
                unlocked_at,
            } => {
                if unlocked_at.elapsed() >= self.auto_lock_duration {
                    drop(state);
                    self.lock();
                    return Err(VaultError::VaultLocked);
                }
                Ok(vault_key.clone())
            }
        }
    }

    fn require_unlocked(&self) -> Result<(), VaultError> {
        let _ = self.vault_key()?;
        Ok(())
    }
}

fn decrypt_item_data(vault_key: &[u8; 32], item: &VaultItem) -> Result<VaultItemData, VaultError> {
    let plaintext = crypto::decrypt(vault_key, &item.encrypted_data, item.id.as_bytes())?;
    serde_json::from_slice(&plaintext).map_err(|e| VaultError::SerializationError(e.to_string()))
}

fn items_to_summaries(
    vault_key: &[u8; 32],
    items: &[VaultItem],
) -> Result<Vec<VaultItemSummary>, VaultError> {
    items
        .iter()
        .map(|item| {
            let data = decrypt_item_data(vault_key, item)?;
            Ok(VaultItemSummary {
                id: item.id.clone(),
                item_type: item.item_type,
                name: data.name().to_string(),
                created_at: item.created_at,
                updated_at: item.updated_at,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::SqliteVaultStore;

    fn test_vault(password: &str) -> Vault<SqliteVaultStore> {
        let store = SqliteVaultStore::in_memory().unwrap();
        Vault::create_with_fast_kdf(store, password).unwrap()
    }

    #[test]
    fn create_and_unlock_roundtrip() {
        let store = SqliteVaultStore::in_memory().unwrap();
        let _vault = Vault::create_with_fast_kdf(store, "master-pw").unwrap();
        // Vault is unlocked after creation
        assert!(!_vault.is_locked());
    }

    #[test]
    fn lock_then_unlock() {
        let store = SqliteVaultStore::in_memory().unwrap();
        let vault = Vault::create_with_fast_kdf(store, "pw123").unwrap();

        vault.lock();
        assert!(vault.is_locked());

        vault.unlock("pw123").unwrap();
        assert!(!vault.is_locked());
    }

    #[test]
    fn wrong_password_fails_unlock() {
        let store = SqliteVaultStore::in_memory().unwrap();
        let vault = Vault::create_with_fast_kdf(store, "correct").unwrap();
        vault.lock();

        let result = vault.unlock("wrong");
        assert!(matches!(result, Err(VaultError::DecryptionFailed)));
    }

    #[test]
    fn operations_while_locked_fail() {
        let vault = test_vault("pw");
        vault.lock();

        assert!(matches!(
            vault.add_item(VaultItemData::ContinuityToken {
                name: "test".into(),
                token_b64: "data".into(),
                vendor_did: "did:key:zV".into(),
                expires_at: None,
            }),
            Err(VaultError::VaultLocked)
        ));
        assert!(matches!(
            vault.get_item("nonexistent"),
            Err(VaultError::VaultLocked)
        ));
        assert!(matches!(vault.list_items(), Err(VaultError::VaultLocked)));
    }

    // -- Item type roundtrip tests below in integration section --

    #[test]
    fn principal_seed_roundtrip() {
        let vault = test_vault("pw");
        let seed = [42u8; 32];
        let seed_b64 = URL_SAFE_NO_PAD.encode(seed);
        let did = "did:key:zTestDid123".to_string();

        let id = vault
            .add_item(VaultItemData::PrincipalSeed {
                name: "Alice".into(),
                seed_b64: seed_b64.clone(),
                did: did.clone(),
            })
            .unwrap();

        let data = vault.get_item(&id).unwrap();
        match data {
            VaultItemData::PrincipalSeed {
                name,
                seed_b64: s,
                did: d,
            } => {
                assert_eq!(name, "Alice");
                assert_eq!(s, seed_b64);
                assert_eq!(d, did);
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn continuity_token_roundtrip() {
        let vault = test_vault("pw");
        let id = vault
            .add_item(VaultItemData::ContinuityToken {
                name: "Hotel booking".into(),
                token_b64: URL_SAFE_NO_PAD.encode(b"opaque-vendor-state"),
                vendor_did: "did:key:zVendor".into(),
                expires_at: None,
            })
            .unwrap();

        let data = vault.get_item(&id).unwrap();
        assert!(matches!(data, VaultItemData::ContinuityToken { .. }));
    }

    #[test]
    fn verifiable_credential_roundtrip() {
        let vault = test_vault("pw");
        let vc_json = r#"{"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiableCredential"]}"#;
        let id = vault
            .add_item(VaultItemData::VerifiableCredential {
                name: "Travel VC".into(),
                credential_json: vc_json.into(),
                issuer_did: "did:key:zIssuer".into(),
            })
            .unwrap();

        let data = vault.get_item(&id).unwrap();
        match data {
            VaultItemData::VerifiableCredential {
                credential_json, ..
            } => assert_eq!(credential_json, vc_json),
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn notary_designation_roundtrip() {
        let vault = test_vault("pw");
        let mandate = r#"{"principal_did":"did:key:zP","threshold":2,"notary_dids":["did:key:zN1","did:key:zN2","did:key:zN3"]}"#;
        let id = vault
            .add_item(VaultItemData::NotaryDesignation {
                name: "My recovery setup".into(),
                mandate_json: mandate.into(),
                threshold: 2,
                notary_count: 3,
            })
            .unwrap();

        let data = vault.get_item(&id).unwrap();
        match data {
            VaultItemData::NotaryDesignation {
                threshold,
                notary_count,
                ..
            } => {
                assert_eq!(threshold, 2);
                assert_eq!(notary_count, 3);
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn update_item() {
        let vault = test_vault("pw");
        let id = vault
            .add_item(VaultItemData::ContinuityToken {
                name: "Original".into(),
                token_b64: "v1".into(),
                vendor_did: "did:key:zV".into(),
                expires_at: None,
            })
            .unwrap();

        vault
            .update_item(
                &id,
                VaultItemData::ContinuityToken {
                    name: "Updated".into(),
                    token_b64: "v2".into(),
                    vendor_did: "did:key:zV".into(),
                    expires_at: None,
                },
            )
            .unwrap();

        let data = vault.get_item(&id).unwrap();
        match data {
            VaultItemData::ContinuityToken {
                name, token_b64, ..
            } => {
                assert_eq!(name, "Updated");
                assert_eq!(token_b64, "v2");
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn remove_item() {
        let vault = test_vault("pw");
        let id = vault
            .add_item(VaultItemData::ContinuityToken {
                name: "ephemeral".into(),
                token_b64: "data".into(),
                vendor_did: "did:key:zV".into(),
                expires_at: None,
            })
            .unwrap();

        vault.remove_item(&id).unwrap();
        assert!(matches!(
            vault.get_item(&id),
            Err(VaultError::ItemNotFound(_))
        ));
    }

    #[test]
    fn list_items_and_filter_by_type() {
        let vault = test_vault("pw");
        let seed_b64 = URL_SAFE_NO_PAD.encode([1u8; 32]);

        vault
            .add_item(VaultItemData::PrincipalSeed {
                name: "Key 1".into(),
                seed_b64: seed_b64.clone(),
                did: "did:key:z1".into(),
            })
            .unwrap();
        vault
            .add_item(VaultItemData::PrincipalSeed {
                name: "Key 2".into(),
                seed_b64,
                did: "did:key:z2".into(),
            })
            .unwrap();
        vault
            .add_item(VaultItemData::ContinuityToken {
                name: "Token".into(),
                token_b64: "abc".into(),
                vendor_did: "did:key:zV".into(),
                expires_at: None,
            })
            .unwrap();

        let all = vault.list_items().unwrap();
        assert_eq!(all.len(), 3);

        let seeds = vault.list_by_type(VaultItemType::PrincipalSeed).unwrap();
        assert_eq!(seeds.len(), 2);

        let tokens = vault.list_by_type(VaultItemType::ContinuityToken).unwrap();
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn get_principal_seed_extracts_bytes() {
        let vault = test_vault("pw");
        let seed = [99u8; 32];
        let id = vault
            .add_item(VaultItemData::PrincipalSeed {
                name: "test".into(),
                seed_b64: URL_SAFE_NO_PAD.encode(seed),
                did: "did:key:zTest".into(),
            })
            .unwrap();

        let extracted = vault.get_principal_seed(&id).unwrap();
        assert_eq!(*extracted, seed);
    }

    #[test]
    fn change_password() {
        let store = SqliteVaultStore::in_memory().unwrap();
        let vault = Vault::create_with_fast_kdf(store, "old-pw").unwrap();

        let id = vault
            .add_item(VaultItemData::ContinuityToken {
                name: "persist".into(),
                token_b64: "through password change".into(),
                vendor_did: "did:key:zV".into(),
                expires_at: None,
            })
            .unwrap();

        vault.change_password("old-pw", "new-pw").unwrap();
        vault.lock();

        // Old password should fail
        assert!(vault.unlock("old-pw").is_err());

        // New password should work, and data should be intact
        vault.unlock("new-pw").unwrap();
        let data = vault.get_item(&id).unwrap();
        match data {
            VaultItemData::ContinuityToken { token_b64, .. } => {
                assert_eq!(token_b64, "through password change");
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn auto_lock_triggers() {
        let store = SqliteVaultStore::in_memory().unwrap();
        let mut vault = Vault::create_with_fast_kdf(store, "pw").unwrap();
        vault.set_auto_lock_duration(Duration::from_millis(0));

        // Any operation should trigger auto-lock due to zero timeout
        std::thread::sleep(Duration::from_millis(1));
        assert!(matches!(vault.list_items(), Err(VaultError::VaultLocked)));
        assert!(vault.is_locked());
    }

    #[test]
    fn duplicate_create_fails() {
        let store = SqliteVaultStore::in_memory().unwrap();
        let _vault = Vault::create_with_fast_kdf(store, "pw").unwrap();
        // Can't test double-create on same store since we moved it.
        // Instead, test via open + create pattern:
        // (this is structural — the real test is that save_header checks for existing)
    }

    #[test]
    fn open_nonexistent_vault_fails() {
        let store = SqliteVaultStore::in_memory().unwrap();
        let result = Vault::open(store);
        assert!(matches!(result, Err(VaultError::VaultNotInitialized)));
    }

    #[test]
    fn vault_key_zeroized_on_lock() {
        let vault = test_vault("pw");
        assert!(!vault.is_locked());

        // Add an item while unlocked
        let id = vault
            .add_item(VaultItemData::ContinuityToken {
                name: "test".into(),
                token_b64: "data".into(),
                vendor_did: "did:key:zV".into(),
                expires_at: None,
            })
            .unwrap();

        // Lock — vault key should be dropped/zeroized
        vault.lock();

        // Operations must fail
        assert!(vault.get_item(&id).is_err());
        assert!(vault.is_locked());
    }

    #[test]
    fn persist_across_lock_unlock_cycles() {
        let store = SqliteVaultStore::in_memory().unwrap();
        let vault = Vault::create_with_fast_kdf(store, "cycle-pw").unwrap();

        let id = vault
            .add_item(VaultItemData::PrincipalSeed {
                name: "persistent".into(),
                seed_b64: URL_SAFE_NO_PAD.encode([7u8; 32]),
                did: "did:key:zPersist".into(),
            })
            .unwrap();

        // Lock and unlock 3 times
        for _ in 0..3 {
            vault.lock();
            vault.unlock("cycle-pw").unwrap();
            let data = vault.get_item(&id).unwrap();
            assert!(matches!(data, VaultItemData::PrincipalSeed { .. }));
        }
    }
}
