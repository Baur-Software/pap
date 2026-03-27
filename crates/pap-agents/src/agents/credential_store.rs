//! Credential Store agent — local vault operations via PAP protocol.
//!
//! This agent provides mandate-scoped access to the principal's encrypted
//! credential vault. It runs locally (no network calls) and handles storage
//! and retrieval of PAP protocol material: principal seeds, continuity tokens,
//! verifiable credentials, and notary designations.
//!
//! ## Query Format
//!
//! The query is a JSON object with an `"action"` field:
//!
//! - `{"action": "list"}` — list all items (summaries only)
//! - `{"action": "list", "itemType": "PrincipalSeed"}` — list by type
//! - `{"action": "get", "id": "uuid"}` — retrieve a specific item
//! - `{"action": "store", "item": { VaultItemData }}` — store a new item
//! - `{"action": "remove", "id": "uuid"}` — remove an item

use std::sync::Arc;

use pap_credential_store::{Vault, VaultItemData, VaultItemType, VaultStore};
use pap_transport::TransportError;
use serde::Deserialize;
use serde_json::json;

use crate::executor::{AgentExecutor, AgentMeta};

/// Credential store agent backed by an encrypted vault.
///
/// Constructed with a reference to an unlocked `Vault`. The vault's lock
/// state is checked on each operation — if the vault auto-locks between
/// requests, the agent returns an error rather than silently failing.
pub struct CredentialStoreExecutor<S: VaultStore> {
    vault: Arc<Vault<S>>,
}

impl<S: VaultStore> CredentialStoreExecutor<S> {
    pub fn new(vault: Arc<Vault<S>>) -> Self {
        Self { vault }
    }
}

impl<S: VaultStore + 'static> AgentExecutor for CredentialStoreExecutor<S> {
    fn meta(&self) -> AgentMeta {
        AgentMeta {
            name: "Credential Store",
            provider: "PAP Core",
            action: "schema:OrganizeAction",
            object_types: &["schema:DigitalDocument"],
            requires_disclosure: &[],
            returns: &["schema:DigitalDocument"],
        }
    }

    fn execute(&self, query: &str) -> Result<serde_json::Value, TransportError> {
        let cmd: VaultCommand = serde_json::from_str(query)
            .map_err(|e| TransportError::ServerError(format!("invalid query: {e}")))?;

        match cmd {
            VaultCommand::List { item_type } => self.handle_list(item_type),
            VaultCommand::Get { id } => self.handle_get(&id),
            VaultCommand::Store { item } => self.handle_store(item),
            VaultCommand::Remove { id } => self.handle_remove(&id),
        }
    }
}

impl<S: VaultStore> CredentialStoreExecutor<S> {
    fn handle_list(&self, item_type: Option<String>) -> Result<serde_json::Value, TransportError> {
        let summaries = match item_type {
            Some(ref t) => {
                let vt = parse_item_type(t)?;
                self.vault
                    .list_by_type(vt)
                    .map_err(|e| TransportError::ServerError(e.to_string()))?
            }
            None => self
                .vault
                .list_items()
                .map_err(|e| TransportError::ServerError(e.to_string()))?,
        };

        let items: Vec<serde_json::Value> = summaries
            .iter()
            .map(|s| {
                json!({
                    "@type": "DigitalDocument",
                    "identifier": s.id,
                    "name": s.name,
                    "additionalType": format!("{:?}", s.item_type),
                    "dateCreated": s.created_at.to_rfc3339(),
                    "dateModified": s.updated_at.to_rfc3339(),
                })
            })
            .collect();

        Ok(json!({
            "@context": "https://schema.org",
            "@type": "ItemList",
            "numberOfItems": items.len(),
            "itemListElement": items
        }))
    }

    fn handle_get(&self, id: &str) -> Result<serde_json::Value, TransportError> {
        let data = self
            .vault
            .get_item(id)
            .map_err(|e| TransportError::ServerError(e.to_string()))?;

        Ok(match data {
            VaultItemData::PrincipalSeed { name, did, .. } => json!({
                "@context": "https://schema.org",
                "@type": "DigitalDocument",
                "identifier": id,
                "name": name,
                "additionalType": "PrincipalSeed",
                "about": { "@type": "Thing", "identifier": did }
            }),
            VaultItemData::ContinuityToken {
                name,
                vendor_did,
                expires_at,
                ..
            } => json!({
                "@context": "https://schema.org",
                "@type": "DigitalDocument",
                "identifier": id,
                "name": name,
                "additionalType": "ContinuityToken",
                "provider": { "@type": "Organization", "identifier": vendor_did },
                "expires": expires_at.map(|e| e.to_rfc3339()),
            }),
            VaultItemData::VerifiableCredential {
                name,
                credential_json,
                issuer_did,
            } => json!({
                "@context": "https://schema.org",
                "@type": "DigitalDocument",
                "identifier": id,
                "name": name,
                "additionalType": "VerifiableCredential",
                "creator": { "@type": "Organization", "identifier": issuer_did },
                "text": credential_json,
            }),
            VaultItemData::NotaryDesignation {
                name,
                threshold,
                notary_count,
                ..
            } => json!({
                "@context": "https://schema.org",
                "@type": "DigitalDocument",
                "identifier": id,
                "name": name,
                "additionalType": "NotaryDesignation",
                "about": {
                    "threshold": threshold,
                    "notaryCount": notary_count,
                }
            }),
        })
    }

    fn handle_store(&self, item: VaultItemData) -> Result<serde_json::Value, TransportError> {
        let name = item.name().to_string();
        let item_type = format!("{:?}", item.item_type());

        let id = self
            .vault
            .add_item(item)
            .map_err(|e| TransportError::ServerError(e.to_string()))?;

        Ok(json!({
            "@context": "https://schema.org",
            "@type": "DigitalDocument",
            "identifier": id,
            "name": name,
            "additionalType": item_type,
        }))
    }

    fn handle_remove(&self, id: &str) -> Result<serde_json::Value, TransportError> {
        self.vault
            .remove_item(id)
            .map_err(|e| TransportError::ServerError(e.to_string()))?;

        Ok(json!({
            "@context": "https://schema.org",
            "@type": "DeleteAction",
            "object": { "@type": "DigitalDocument", "identifier": id },
        }))
    }
}

fn parse_item_type(s: &str) -> Result<VaultItemType, TransportError> {
    match s {
        "PrincipalSeed" => Ok(VaultItemType::PrincipalSeed),
        "ContinuityToken" => Ok(VaultItemType::ContinuityToken),
        "VerifiableCredential" => Ok(VaultItemType::VerifiableCredential),
        "NotaryDesignation" => Ok(VaultItemType::NotaryDesignation),
        other => Err(TransportError::ServerError(format!(
            "unknown item type: {other}"
        ))),
    }
}

/// Internal command parsed from the query JSON.
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "camelCase")]
enum VaultCommand {
    #[serde(rename = "list")]
    List {
        #[serde(default, rename = "itemType")]
        item_type: Option<String>,
    },
    #[serde(rename = "get")]
    Get { id: String },
    #[serde(rename = "store")]
    Store { item: VaultItemData },
    #[serde(rename = "remove")]
    Remove { id: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use pap_credential_store::SqliteVaultStore;

    fn test_executor() -> CredentialStoreExecutor<SqliteVaultStore> {
        let store = SqliteVaultStore::in_memory().unwrap();
        let vault = Arc::new(Vault::create_with_fast_kdf(store, "test-pw").unwrap());
        CredentialStoreExecutor::new(vault)
    }

    #[test]
    fn meta_is_correct() {
        let exec = test_executor();
        let meta = exec.meta();
        assert_eq!(meta.name, "Credential Store");
        assert_eq!(meta.action, "schema:OrganizeAction");
        assert_eq!(meta.object_types, &["schema:DigitalDocument"]);
    }

    #[test]
    fn store_and_list_roundtrip() {
        let exec = test_executor();

        // Store a continuity token
        let store_query = json!({
            "action": "store",
            "item": {
                "type": "ContinuityToken",
                "name": "Hotel Booking",
                "token_b64": "b3BhcXVlLXZlbmRvci1zdGF0ZQ",
                "vendor_did": "did:key:zVendor"
            }
        });
        let result = exec.execute(&store_query.to_string()).unwrap();
        assert_eq!(result["@type"], "DigitalDocument");
        assert_eq!(result["name"], "Hotel Booking");
        let id = result["identifier"].as_str().unwrap();

        // List all — should have 1 item
        let list_result = exec.execute(r#"{"action":"list"}"#).unwrap();
        assert_eq!(list_result["numberOfItems"], 1);
        assert_eq!(list_result["itemListElement"][0]["identifier"], id);
    }

    #[test]
    fn store_and_get_roundtrip() {
        let exec = test_executor();

        let store_query = json!({
            "action": "store",
            "item": {
                "type": "VerifiableCredential",
                "name": "Travel VC",
                "credential_json": "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"]}",
                "issuer_did": "did:key:zIssuer"
            }
        });
        let result = exec.execute(&store_query.to_string()).unwrap();
        let id = result["identifier"].as_str().unwrap();

        let get_query = json!({"action": "get", "id": id});
        let item = exec.execute(&get_query.to_string()).unwrap();
        assert_eq!(item["name"], "Travel VC");
        assert_eq!(item["additionalType"], "VerifiableCredential");
        assert_eq!(item["creator"]["identifier"], "did:key:zIssuer");
    }

    #[test]
    fn store_and_remove() {
        let exec = test_executor();

        let store_query = json!({
            "action": "store",
            "item": {
                "type": "ContinuityToken",
                "name": "Ephemeral",
                "token_b64": "YWJj",
                "vendor_did": "did:key:zV"
            }
        });
        let result = exec.execute(&store_query.to_string()).unwrap();
        let id = result["identifier"].as_str().unwrap();

        let remove_query = json!({"action": "remove", "id": id});
        let removed = exec.execute(&remove_query.to_string()).unwrap();
        assert_eq!(removed["@type"], "DeleteAction");

        // Verify it's gone
        let get_query = json!({"action": "get", "id": id});
        assert!(exec.execute(&get_query.to_string()).is_err());
    }

    #[test]
    fn list_by_type_filter() {
        let exec = test_executor();

        // Store one of each type
        exec.execute(
            &json!({
                "action": "store",
                "item": {
                    "type": "ContinuityToken",
                    "name": "Token 1",
                    "token_b64": "YWJj",
                    "vendor_did": "did:key:zV"
                }
            })
            .to_string(),
        )
        .unwrap();

        exec.execute(
            &json!({
                "action": "store",
                "item": {
                    "type": "NotaryDesignation",
                    "name": "Recovery 1",
                    "mandate_json": "{}",
                    "threshold": 2,
                    "notary_count": 3
                }
            })
            .to_string(),
        )
        .unwrap();

        // Filter by type
        let tokens = exec
            .execute(r#"{"action":"list","itemType":"ContinuityToken"}"#)
            .unwrap();
        assert_eq!(tokens["numberOfItems"], 1);

        let notaries = exec
            .execute(r#"{"action":"list","itemType":"NotaryDesignation"}"#)
            .unwrap();
        assert_eq!(notaries["numberOfItems"], 1);

        let seeds = exec
            .execute(r#"{"action":"list","itemType":"PrincipalSeed"}"#)
            .unwrap();
        assert_eq!(seeds["numberOfItems"], 0);
    }

    #[test]
    fn invalid_query_returns_error() {
        let exec = test_executor();
        assert!(exec.execute("not json").is_err());
        assert!(exec.execute(r#"{"action":"unknown"}"#).is_err());
    }

    #[test]
    fn vault_locked_returns_error() {
        let store = SqliteVaultStore::in_memory().unwrap();
        let vault = Arc::new(Vault::create_with_fast_kdf(store, "pw").unwrap());
        let exec = CredentialStoreExecutor::new(vault.clone());

        vault.lock();

        let result = exec.execute(r#"{"action":"list"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn principal_seed_get_redacts_seed() {
        let exec = test_executor();

        let result = exec
            .execute(
                &json!({
                    "action": "store",
                    "item": {
                        "type": "PrincipalSeed",
                        "name": "Alice",
                        "seed_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "did": "did:key:zAlice"
                    }
                })
                .to_string(),
            )
            .unwrap();
        let id = result["identifier"].as_str().unwrap();

        let item = exec
            .execute(&json!({"action": "get", "id": id}).to_string())
            .unwrap();
        // Should have DID but NOT the seed
        assert_eq!(item["about"]["identifier"], "did:key:zAlice");
        assert!(item.get("seed_b64").is_none());
        assert!(item["text"].is_null());
    }
}
