//! SQLite-backed VaultStore implementation.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::sync::Mutex;

use crate::error::VaultError;
use crate::store::VaultStore;
use crate::types::{EncryptedBlob, KdfParams, VaultHeader, VaultItem, VaultItemType};

pub struct SqliteVaultStore {
    conn: Mutex<Connection>,
}

impl SqliteVaultStore {
    /// Open (or create) a vault database at the given path.
    pub fn open(path: &std::path::Path) -> Result<Self, VaultError> {
        let conn = Connection::open(path).map_err(|e| VaultError::StorageError(e.to_string()))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    /// In-memory vault store for testing.
    #[cfg(any(test, feature = "testing"))]
    pub fn in_memory() -> Result<Self, VaultError> {
        let conn =
            Connection::open_in_memory().map_err(|e| VaultError::StorageError(e.to_string()))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), VaultError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vault_header (
                id           TEXT PRIMARY KEY,
                version      INTEGER NOT NULL DEFAULT 1,
                kdf_salt     BLOB NOT NULL,
                kdf_m_cost   INTEGER NOT NULL,
                kdf_t_cost   INTEGER NOT NULL,
                kdf_p_cost   INTEGER NOT NULL,
                enc_vk_nonce BLOB NOT NULL,
                enc_vk_ct    BLOB NOT NULL,
                created_at   TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vault_items (
                id           TEXT PRIMARY KEY,
                item_type    INTEGER NOT NULL,
                nonce        BLOB NOT NULL,
                ciphertext   BLOB NOT NULL,
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL
            );",
        )
        .map_err(|e| VaultError::StorageError(e.to_string()))
    }
}

impl VaultStore for SqliteVaultStore {
    fn load_header(&self) -> Result<Option<VaultHeader>, VaultError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, version, kdf_salt, kdf_m_cost, kdf_t_cost, kdf_p_cost,
                        enc_vk_nonce, enc_vk_ct, created_at
                 FROM vault_header LIMIT 1",
            )
            .map_err(|e| VaultError::StorageError(e.to_string()))?;

        let mut rows = stmt
            .query_map([], |row| {
                let kdf_salt: Vec<u8> = row.get(2)?;
                let enc_vk_nonce: Vec<u8> = row.get(6)?;
                let enc_vk_ct: Vec<u8> = row.get(7)?;
                let created_at_str: String = row.get(8)?;

                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u32>(1)?,
                    kdf_salt,
                    row.get::<_, u32>(3)?,
                    row.get::<_, u32>(4)?,
                    row.get::<_, u32>(5)?,
                    enc_vk_nonce,
                    enc_vk_ct,
                    created_at_str,
                ))
            })
            .map_err(|e| VaultError::StorageError(e.to_string()))?;

        match rows.next() {
            Some(Ok((
                id,
                version,
                kdf_salt,
                m_cost,
                t_cost,
                p_cost,
                nonce,
                ct,
                created_at_str,
            ))) => {
                let kdf_salt: [u8; 32] = kdf_salt
                    .try_into()
                    .map_err(|_| VaultError::StorageError("invalid kdf_salt length".into()))?;
                let nonce: [u8; 12] = nonce
                    .try_into()
                    .map_err(|_| VaultError::StorageError("invalid nonce length".into()))?;
                let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                    .map_err(|e| VaultError::StorageError(e.to_string()))?
                    .with_timezone(&Utc);

                Ok(Some(VaultHeader {
                    id,
                    version,
                    kdf_salt,
                    kdf_params: KdfParams {
                        m_cost,
                        t_cost,
                        p_cost,
                    },
                    encrypted_vault_key: EncryptedBlob {
                        nonce,
                        ciphertext: ct,
                    },
                    created_at,
                }))
            }
            Some(Err(e)) => Err(VaultError::StorageError(e.to_string())),
            None => Ok(None),
        }
    }

    fn save_header(&self, header: &VaultHeader) -> Result<(), VaultError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO vault_header
             (id, version, kdf_salt, kdf_m_cost, kdf_t_cost, kdf_p_cost,
              enc_vk_nonce, enc_vk_ct, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                header.id,
                header.version,
                header.kdf_salt.as_slice(),
                header.kdf_params.m_cost,
                header.kdf_params.t_cost,
                header.kdf_params.p_cost,
                header.encrypted_vault_key.nonce.as_slice(),
                header.encrypted_vault_key.ciphertext.as_slice(),
                header.created_at.to_rfc3339(),
            ],
        )
        .map_err(|e| VaultError::StorageError(e.to_string()))?;
        Ok(())
    }

    fn list_items(&self) -> Result<Vec<VaultItem>, VaultError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, item_type, nonce, ciphertext, created_at, updated_at FROM vault_items",
            )
            .map_err(|e| VaultError::StorageError(e.to_string()))?;

        let items = stmt
            .query_map([], row_to_vault_item)
            .map_err(|e| VaultError::StorageError(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;

        Ok(items)
    }

    fn list_items_by_type(&self, item_type: VaultItemType) -> Result<Vec<VaultItem>, VaultError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, item_type, nonce, ciphertext, created_at, updated_at
                 FROM vault_items WHERE item_type = ?1",
            )
            .map_err(|e| VaultError::StorageError(e.to_string()))?;

        let items = stmt
            .query_map(params![item_type as u8], row_to_vault_item)
            .map_err(|e| VaultError::StorageError(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;

        Ok(items)
    }

    fn get_item(&self, id: &str) -> Result<Option<VaultItem>, VaultError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, item_type, nonce, ciphertext, created_at, updated_at
                 FROM vault_items WHERE id = ?1",
            )
            .map_err(|e| VaultError::StorageError(e.to_string()))?;

        let mut rows = stmt
            .query_map(params![id], row_to_vault_item)
            .map_err(|e| VaultError::StorageError(e.to_string()))?;

        match rows.next() {
            Some(Ok(item)) => Ok(Some(item)),
            Some(Err(e)) => Err(VaultError::StorageError(e.to_string())),
            None => Ok(None),
        }
    }

    fn insert_item(&self, item: &VaultItem) -> Result<(), VaultError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        conn.execute(
            "INSERT INTO vault_items (id, item_type, nonce, ciphertext, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                item.id,
                item.item_type as u8,
                item.nonce(),
                item.ciphertext(),
                item.created_at.to_rfc3339(),
                item.updated_at.to_rfc3339(),
            ],
        )
        .map_err(|e| VaultError::StorageError(e.to_string()))?;
        Ok(())
    }

    fn update_item(&self, item: &VaultItem) -> Result<(), VaultError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        let changed = conn
            .execute(
                "UPDATE vault_items SET item_type = ?1, nonce = ?2, ciphertext = ?3, updated_at = ?4
                 WHERE id = ?5",
                params![
                    item.item_type as u8,
                    item.nonce(),
                    item.ciphertext(),
                    item.updated_at.to_rfc3339(),
                    item.id,
                ],
            )
            .map_err(|e| VaultError::StorageError(e.to_string()))?;

        if changed == 0 {
            return Err(VaultError::ItemNotFound(item.id.clone()));
        }
        Ok(())
    }

    fn delete_item(&self, id: &str) -> Result<(), VaultError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| VaultError::StorageError(e.to_string()))?;
        let changed = conn
            .execute("DELETE FROM vault_items WHERE id = ?1", params![id])
            .map_err(|e| VaultError::StorageError(e.to_string()))?;

        if changed == 0 {
            return Err(VaultError::ItemNotFound(id.to_string()));
        }
        Ok(())
    }
}

impl VaultItem {
    fn nonce(&self) -> &[u8] {
        &self.encrypted_data.nonce
    }

    fn ciphertext(&self) -> &[u8] {
        &self.encrypted_data.ciphertext
    }
}

fn row_to_vault_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<VaultItem> {
    let id: String = row.get(0)?;
    let type_u8: u8 = row.get(1)?;
    let nonce: Vec<u8> = row.get(2)?;
    let ciphertext: Vec<u8> = row.get(3)?;
    let created_at_str: String = row.get(4)?;
    let updated_at_str: String = row.get(5)?;

    let item_type = match type_u8 {
        0 => VaultItemType::PrincipalSeed,
        1 => VaultItemType::ContinuityToken,
        2 => VaultItemType::VerifiableCredential,
        3 => VaultItemType::NotaryDesignation,
        other => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Integer,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown item type: {other}"),
                )),
            ))
        }
    };

    let nonce_arr: [u8; 12] = nonce.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid nonce length",
            )),
        )
    })?;

    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
        })?;

    Ok(VaultItem {
        id,
        item_type,
        encrypted_data: EncryptedBlob {
            nonce: nonce_arr,
            ciphertext,
        },
        created_at,
        updated_at,
    })
}
