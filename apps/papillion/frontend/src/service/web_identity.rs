//! Browser-native identity management backed by IndexedDB.
//!
//! Generates Ed25519 keypairs via `pap-did` (using `crypto.getRandomValues()`
//! for entropy) and persists profile metadata + seeds in IndexedDB.
//!
//! # Storage
//!
//! Profile records are stored in the existing `papillion` IndexedDB under a
//! reserved key (`__profiles__`) in the `db_snapshots` object store. Each
//! record contains the Ed25519 seed encoded as base64url-no-pad, matching
//! the Tauri backend's `ProfilesDatabase` format.
//!
//! # Security
//!
//! - Seeds are stored in **IndexedDB**, not localStorage. IndexedDB is
//!   same-origin isolated and uses structured cloning rather than string-only
//!   storage, making it resistant to XSS exfiltration vectors that target
//!   `document.cookie` or `window.localStorage`.
//!
//! - **WASM linear memory cannot guarantee zeroization** of sensitive key
//!   material. The `zeroize` crate writes zeros on `Drop`, but the WASM GC
//!   may copy memory regions before the destructor runs. See
//!   `docs/WASM_SECURITY.md` for details and mitigations.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use pap_did::PrincipalKeypair;
use papillion_shared::db::idb;
use papillion_shared::{IdentityInfo, ProfileMetadata};
use serde::{Deserialize, Serialize};

/// Reserved IndexedDB key for profile storage — distinct from DID-based
/// per-profile content keys.
const PROFILES_IDB_KEY: &str = "__profiles__";

/// Manages Ed25519 principal identities in IndexedDB for the browser.
pub struct WebIdentityService {
    profiles: Vec<ProfileRecord>,
}

/// Internal record persisted to IndexedDB.
#[derive(Clone, Serialize, Deserialize)]
struct ProfileRecord {
    id: String,
    name: String,
    principal_seed_b64: String,
    created_at: String,
    last_used: Option<String>,
    active: bool,
}

/// Serialized form stored in IndexedDB.
#[derive(Serialize, Deserialize)]
struct ProfilesSnapshot {
    profiles: Vec<ProfileRecord>,
}

impl WebIdentityService {
    /// Create an empty service with no profiles (fallback for init failures).
    pub fn empty() -> Self {
        Self {
            profiles: Vec::new(),
        }
    }

    /// Load profiles from IndexedDB. Call once at startup.
    pub async fn load() -> Result<Self, String> {
        let json = idb::load(PROFILES_IDB_KEY)
            .await
            .map_err(|e| format!("IndexedDB load: {:?}", e))?;

        let profiles = match json {
            Some(data) => {
                let snapshot: ProfilesSnapshot = serde_json::from_str(&data)
                    .map_err(|e| format!("profiles deserialize: {e}"))?;
                snapshot.profiles
            }
            None => Vec::new(),
        };

        Ok(Self { profiles })
    }

    /// Create a new profile with a freshly generated Ed25519 keypair.
    ///
    /// The keypair is generated using `crypto.getRandomValues()` via
    /// `getrandom/js`. The 32-byte seed is stored as base64url-no-pad.
    pub async fn create_profile(&mut self, name: &str) -> Result<ProfileMetadata, String> {
        // Check for duplicate names
        if self.profiles.iter().any(|p| p.name == name) {
            return Err(format!("Profile name '{}' already exists", name));
        }

        let keypair = PrincipalKeypair::generate();
        let seed = keypair.signing_key().to_bytes();
        let seed_b64 = URL_SAFE_NO_PAD.encode(seed);

        let profile_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();

        let record = ProfileRecord {
            id: profile_id.clone(),
            name: name.to_string(),
            principal_seed_b64: seed_b64,
            created_at: now.clone(),
            last_used: None,
            active: false,
        };

        self.profiles.push(record);
        self.persist().await?;

        Ok(ProfileMetadata {
            id: profile_id,
            name: name.to_string(),
            created_at: now,
            last_used: None,
            active: false,
        })
    }

    /// Switch to a profile by ID. Returns the new identity info.
    ///
    /// Sets the target profile as active, all others as inactive.
    /// Updates the `last_used` timestamp.
    pub async fn switch_profile(&mut self, profile_id: &str) -> Result<IdentityInfo, String> {
        let exists = self.profiles.iter().any(|p| p.id == profile_id);
        if !exists {
            return Err(format!("Profile '{}' not found", profile_id));
        }

        let now = chrono::Utc::now().to_rfc3339();
        for p in &mut self.profiles {
            if p.id == profile_id {
                p.active = true;
                p.last_used = Some(now.clone());
            } else {
                p.active = false;
            }
        }

        self.persist().await?;
        self.active_identity_info()
    }

    /// List all profiles (metadata only, no seeds exposed).
    pub fn list_profiles(&self) -> Vec<ProfileMetadata> {
        self.profiles
            .iter()
            .map(|p| ProfileMetadata {
                id: p.id.clone(),
                name: p.name.clone(),
                created_at: p.created_at.clone(),
                last_used: p.last_used.clone(),
                active: p.active,
            })
            .collect()
    }

    /// Get the active profile's identity info (DID + public key).
    pub fn get_identity(&self) -> Option<IdentityInfo> {
        self.active_identity_info().ok()
    }

    /// Get the active profile's principal keypair (with signing key).
    ///
    /// Used by the WASM handshake executor to sign tokens and mandates.
    /// The caller must scope the keypair's lifetime appropriately — see
    /// `handshake::execute()` for the phase-scoped security model.
    pub fn active_keypair(&self) -> Result<PrincipalKeypair, String> {
        let active = self
            .profiles
            .iter()
            .find(|p| p.active)
            .ok_or_else(|| "No active profile".to_string())?;

        let seed_bytes = URL_SAFE_NO_PAD
            .decode(&active.principal_seed_b64)
            .map_err(|e| format!("seed decode: {e}"))?;

        let seed: [u8; 32] = seed_bytes
            .try_into()
            .map_err(|_| "seed must be 32 bytes".to_string())?;

        PrincipalKeypair::from_bytes(&seed).map_err(|e| format!("keypair restore: {e}"))
    }

    /// Derive identity info from the active profile's seed.
    fn active_identity_info(&self) -> Result<IdentityInfo, String> {
        let active = self
            .profiles
            .iter()
            .find(|p| p.active)
            .ok_or_else(|| "No active profile".to_string())?;

        let seed_bytes = URL_SAFE_NO_PAD
            .decode(&active.principal_seed_b64)
            .map_err(|e| format!("seed decode: {e}"))?;

        let seed: [u8; 32] = seed_bytes
            .try_into()
            .map_err(|_| "seed must be 32 bytes".to_string())?;

        let keypair =
            PrincipalKeypair::from_bytes(&seed).map_err(|e| format!("keypair restore: {e}"))?;

        Ok(IdentityInfo {
            did: keypair.did(),
            public_key_b64: URL_SAFE_NO_PAD.encode(keypair.public_key_bytes()),
            created_at: active.created_at.clone(),
        })
    }

    /// Persist the current profile state to IndexedDB.
    async fn persist(&self) -> Result<(), String> {
        let snapshot = ProfilesSnapshot {
            profiles: self.profiles.clone(),
        };
        let json =
            serde_json::to_string(&snapshot).map_err(|e| format!("profiles serialize: {e}"))?;

        idb::save(PROFILES_IDB_KEY, &json)
            .await
            .map_err(|e| format!("IndexedDB save: {:?}", e))?;

        Ok(())
    }
}
