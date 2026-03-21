//! TTL-bounded session store for PAP agents.
//!
//! Sessions that outlive their TTL are reaped on every mutating operation.
//! With `ed25519-dalek/zeroize`, the `SessionKeypair`'s `SigningKey` zeroes
//! its memory when the session is dropped (either via close or reap).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use pap_did::SessionKeypair;
use pap_transport::TransportError;

const SESSION_TTL: Duration = Duration::from_secs(300); // 5 minutes

struct Entry<T> {
    session_key: SessionKeypair,
    created: Instant,
    data: T,
}

/// Thread-safe session store with automatic TTL reaping.
pub struct SessionStore<T> {
    inner: Mutex<HashMap<String, Entry<T>>>,
}

impl<T> SessionStore<T> {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Insert a new session. Returns the session DID (from the ephemeral key).
    pub fn insert(&self, session_id: String, data: T) -> String {
        let session_key = SessionKeypair::generate();
        let did = session_key.did();
        let mut map = self.inner.lock().unwrap();
        Self::reap(&mut map);
        map.insert(
            session_id,
            Entry {
                session_key,
                created: Instant::now(),
                data,
            },
        );
        did
    }

    /// Check that a session exists.
    pub fn exists(&self, session_id: &str) -> bool {
        let map = self.inner.lock().unwrap();
        map.get(session_id)
            .map(|e| e.created.elapsed() < SESSION_TTL)
            .unwrap_or(false)
    }

    /// Mutate session data. Returns error if session is unknown or expired.
    pub fn with_mut<F, R>(&self, session_id: &str, f: F) -> Result<R, TransportError>
    where
        F: FnOnce(&mut T) -> R,
    {
        let mut map = self.inner.lock().unwrap();
        Self::reap(&mut map);
        let entry = map
            .get_mut(session_id)
            .ok_or_else(|| TransportError::ServerError("Unknown or expired session".into()))?;
        Ok(f(&mut entry.data))
    }

    /// Read session data. Returns error if session is unknown or expired.
    pub fn with<F, R>(&self, session_id: &str, f: F) -> Result<R, TransportError>
    where
        F: FnOnce(&T) -> R,
    {
        let map = self.inner.lock().unwrap();
        let entry = map
            .get(session_id)
            .filter(|e| e.created.elapsed() < SESSION_TTL)
            .ok_or_else(|| TransportError::ServerError("Unknown or expired session".into()))?;
        Ok(f(&entry.data))
    }

    /// Get a clone of the session's signing key for co-signing.
    /// Returns None if session doesn't exist or is expired.
    pub fn signing_key(&self, session_id: &str) -> Option<ed25519_dalek::SigningKey> {
        let map = self.inner.lock().unwrap();
        map.get(session_id)
            .filter(|e| e.created.elapsed() < SESSION_TTL)
            .map(|e| e.session_key.signing_key().clone())
    }

    /// Remove a session. The `SessionKeypair` is dropped (and zeroized).
    pub fn remove(&self, session_id: &str) {
        let mut map = self.inner.lock().unwrap();
        map.remove(session_id);
        Self::reap(&mut map);
    }

    /// Drop all sessions whose TTL has expired.
    fn reap(map: &mut HashMap<String, Entry<T>>) {
        map.retain(|_, e| e.created.elapsed() < SESSION_TTL);
    }
}
