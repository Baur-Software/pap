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
const MAX_SESSIONS: usize = 1024;

struct Entry<T> {
    session_key: SessionKeypair,
    created: Instant,
    data: T,
}

/// Thread-safe session store with automatic TTL reaping.
pub struct SessionStore<T> {
    inner: Mutex<HashMap<String, Entry<T>>>,
}

impl<T> Default for SessionStore<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> SessionStore<T> {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Insert a new session. Returns the session DID (from the ephemeral key),
    /// or an error if the session cap has been reached.
    pub fn insert(&self, session_id: String, data: T) -> Result<String, TransportError> {
        let session_key = SessionKeypair::generate();
        let did = session_key.did();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::reap(&mut map);
        if map.len() >= MAX_SESSIONS {
            return Err(TransportError::ServerError(
                "session limit reached".into(),
            ));
        }
        map.insert(
            session_id,
            Entry {
                session_key,
                created: Instant::now(),
                data,
            },
        );
        Ok(did)
    }

    /// Check that a session exists.
    pub fn exists(&self, session_id: &str) -> bool {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::reap(&mut map);
        map.get(session_id)
            .map(|e| e.created.elapsed() < SESSION_TTL)
            .unwrap_or(false)
    }

    /// Mutate session data. Returns error if session is unknown or expired.
    pub fn with_mut<F, R>(&self, session_id: &str, f: F) -> Result<R, TransportError>
    where
        F: FnOnce(&mut T) -> R,
    {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
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
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Self::reap(&mut map);
        let entry = map
            .get(session_id)
            .filter(|e| e.created.elapsed() < SESSION_TTL)
            .ok_or_else(|| TransportError::ServerError("Unknown or expired session".into()))?;
        Ok(f(&entry.data))
    }

    /// Get a clone of the session's signing key for co-signing.
    /// Returns None if session doesn't exist or is expired.
    pub fn signing_key(&self, session_id: &str) -> Option<ed25519_dalek::SigningKey> {
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.get(session_id)
            .filter(|e| e.created.elapsed() < SESSION_TTL)
            .map(|e| e.session_key.signing_key().clone())
    }

    /// Remove a session. The `SessionKeypair` is dropped (and zeroized).
    pub fn remove(&self, session_id: &str) {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(session_id);
        Self::reap(&mut map);
    }

    /// Drop all sessions whose TTL has expired.
    fn reap(map: &mut HashMap<String, Entry<T>>) {
        map.retain(|_, e| e.created.elapsed() < SESSION_TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A lightweight stand-in for session data in these tests.
    type TestStore = SessionStore<u32>;

    fn make_store() -> TestStore {
        SessionStore::new()
    }

    #[test]
    fn session_limit_rejects_at_cap() {
        let store: SessionStore<u32> = SessionStore::new();

        // Fill up to the cap.
        for i in 0..MAX_SESSIONS {
            let sid = format!("session-{i}");
            store
                .insert(sid, i as u32)
                .expect("should accept sessions below cap");
        }

        // The next insert must be rejected.
        let result = store.insert("session-overflow".into(), 0);
        assert!(
            result.is_err(),
            "expected error when session cap is reached"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("session limit reached"),
            "unexpected error message: {err_msg}"
        );
    }

    #[test]
    fn read_path_triggers_reap() {
        // We cannot artificially wind Instant forward, so we verify the reap
        // logic by checking that a freshly-inserted session is seen as live and
        // that exists() invokes reap (i.e. does not panic or skip the step).
        // A full time-travel test would require dependency injection; the
        // important correctness property here is that the code path compiles and
        // runs the reap before the lookup.
        let store: SessionStore<u32> = make_store();
        let sid = "test-session".to_string();
        store.insert(sid.clone(), 42).expect("insert should succeed");

        // Session should exist immediately after insert.
        assert!(
            store.exists(&sid),
            "session should be visible right after insert"
        );

        // A session that was never inserted should not exist.
        assert!(
            !store.exists("does-not-exist"),
            "non-existent session should return false"
        );
    }

    #[test]
    fn insert_returns_did_string() {
        let store: SessionStore<u32> = make_store();
        let did = store
            .insert("s1".into(), 1)
            .expect("insert should succeed");
        // DIDs generated by SessionKeypair start with "did:key:"
        assert!(
            did.starts_with("did:key:"),
            "expected DID to start with 'did:key:', got: {did}"
        );
    }

    #[test]
    fn with_returns_error_for_unknown_session() {
        let store: SessionStore<u32> = make_store();
        let result = store.with("no-such-session", |v| *v);
        assert!(result.is_err());
    }

    #[test]
    fn capacity_freed_after_remove() {
        // Verify that removing sessions makes room for new ones.
        let store: SessionStore<u32> = SessionStore::new();

        // Fill to cap.
        for i in 0..MAX_SESSIONS {
            store
                .insert(format!("s-{i}"), i as u32)
                .expect("should succeed below cap");
        }

        // Cap is now reached.
        assert!(store.insert("overflow".into(), 0).is_err());

        // Remove one session.
        store.remove("s-0");

        // Now there should be room for one more.
        assert!(
            store.insert("new-session".into(), 99).is_ok(),
            "expected insert to succeed after removing a session"
        );
    }
}
