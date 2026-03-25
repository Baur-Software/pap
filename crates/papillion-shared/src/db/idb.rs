//! Low-level async IndexedDB helpers for WASM persistence.
//!
//! Provides async wrappers around the callback-based IndexedDB API
//! using `web-sys` bindings and `js_sys::Promise`. Each profile's
//! database state is stored under a separate key in a single
//! IndexedDB object store, giving per-principal isolation.
//!
//! The IDB connection is cached in a `thread_local` `RefCell` so
//! repeated `load` / `save` calls reuse the same handle instead of
//! opening a new connection on every operation.

/// The fixed IndexedDB database name used by Papillion.
#[cfg(target_arch = "wasm32")]
const IDB_NAME: &str = "papillion";

/// IndexedDB schema version — bump when the object-store layout changes.
#[cfg(target_arch = "wasm32")]
const IDB_VERSION: u32 = 1;

/// The single object store that holds serialised database snapshots.
#[cfg(target_arch = "wasm32")]
const STORE_NAME: &str = "db_snapshots";

// ── wasm32 implementation ────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
mod inner {
    use super::{IDB_NAME, IDB_VERSION, STORE_NAME};
    use js_sys::Promise;
    use std::cell::RefCell;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{
        Event, IdbDatabase, IdbFactory, IdbObjectStore, IdbOpenDbRequest, IdbRequest,
        IdbTransaction, IdbTransactionMode,
    };

    thread_local! {
        /// Cached IDB connection — avoids re-opening on every operation.
        static CACHED_DB: RefCell<Option<IdbDatabase>> = const { RefCell::new(None) };
    }

    /// Wrap an `IdbRequest` in a `JsFuture` that resolves with the request's result.
    ///
    /// Installs one-shot `onsuccess` / `onerror` handlers via `Closure::once`.
    /// The closures must outlive the `Promise::new` callback, so they are
    /// leaked with `forget()`.  Callers should null the request handlers
    /// after awaiting to break the JS→WASM reference cycle. The leaked
    /// slab entries (~200 bytes each) are a known, acceptable trade-off
    /// of the wasm-bindgen IndexedDB binding pattern.
    fn await_request(request: &IdbRequest) -> JsFuture {
        let req = request.clone();
        let promise = Promise::new(&mut |resolve, reject| {
            let req_for_result = req.clone();
            let req_for_error = req.clone();
            let onsuccess = Closure::once(move |_: Event| {
                let result = req_for_result.result().unwrap_or(JsValue::UNDEFINED);
                let _ = resolve.call1(&JsValue::NULL, &result);
            });
            let onerror = Closure::once(move |_: Event| {
                let err_msg = req_for_error
                    .error()
                    .ok()
                    .flatten()
                    .map(|e: web_sys::DomException| e.message())
                    .unwrap_or_else(|| "unknown IndexedDB error".into());
                let _ = reject.call1(&JsValue::NULL, &JsValue::from_str(&err_msg));
            });
            req.set_onsuccess(Some(onsuccess.as_ref().unchecked_ref()));
            req.set_onerror(Some(onerror.as_ref().unchecked_ref()));
            onsuccess.forget();
            onerror.forget();
        });
        JsFuture::from(promise)
    }

    /// Open (or create) the Papillion IndexedDB database.
    ///
    /// On first open the `db_snapshots` object store is created via the
    /// `onupgradeneeded` callback.  An `onblocked` handler is installed
    /// so that if another tab holds a connection during a version
    /// upgrade the caller gets an error instead of hanging forever.
    async fn open_db_fresh() -> Result<IdbDatabase, JsValue> {
        let window = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
        let factory: IdbFactory = window
            .indexed_db()?
            .ok_or_else(|| JsValue::from_str("IndexedDB not available"))?;

        let open_req: IdbOpenDbRequest = factory.open_with_u32(IDB_NAME, IDB_VERSION)?;

        // Create the object store during version upgrade
        let on_upgrade = Closure::once(|event: Event| {
            let target = event.target().expect("event target");
            let req: &IdbOpenDbRequest = target.unchecked_ref();
            let db: IdbDatabase = req.result().expect("open result").unchecked_into();
            if !db.object_store_names().contains(STORE_NAME) {
                db.create_object_store(STORE_NAME)
                    .expect("create object store");
            }
        });
        open_req.set_onupgradeneeded(Some(on_upgrade.as_ref().unchecked_ref()));

        // Prevent hanging if another tab blocks the version upgrade
        let on_blocked = Closure::once(|_: Event| {
            web_sys::console::warn_1(&"papillion: IndexedDB open blocked by another tab".into());
        });
        open_req.set_onblocked(Some(on_blocked.as_ref().unchecked_ref()));

        let db_js = await_request(&open_req).await?;
        // Safe to drop now — upgrade / blocked have already fired (if needed)
        drop(on_upgrade);
        drop(on_blocked);

        // Null out handlers so their leaked closures can be freed
        open_req.set_onsuccess(None);
        open_req.set_onerror(None);
        open_req.set_onupgradeneeded(None);
        open_req.set_onblocked(None);

        Ok(db_js.unchecked_into())
    }

    /// Return a cached IDB connection, opening a fresh one if needed.
    async fn get_db() -> Result<IdbDatabase, JsValue> {
        let cached = CACHED_DB.with(|cell| cell.borrow().clone());
        if let Some(db) = cached {
            return Ok(db);
        }

        let db = open_db_fresh().await?;
        CACHED_DB.with(|cell| {
            *cell.borrow_mut() = Some(db.clone());
        });
        Ok(db)
    }

    /// Load a JSON snapshot from IndexedDB by key.
    ///
    /// Returns `None` when the key does not exist (first launch for this
    /// profile).
    pub async fn load(key: &str) -> Result<Option<String>, JsValue> {
        let db = get_db().await?;

        let tx: IdbTransaction =
            db.transaction_with_str_and_mode(STORE_NAME, IdbTransactionMode::Readonly)?;
        let store: IdbObjectStore = tx.object_store(STORE_NAME)?;
        let request = store.get(&JsValue::from_str(key))?;
        let result = await_request(&request).await?;

        // Null out handlers to release closure refs
        request.set_onsuccess(None);
        request.set_onerror(None);

        if result.is_undefined() || result.is_null() {
            Ok(None)
        } else {
            Ok(result.as_string())
        }
    }

    /// Persist a JSON snapshot to IndexedDB under the given key.
    pub async fn save(key: &str, data: &str) -> Result<(), JsValue> {
        let db = get_db().await?;

        let tx: IdbTransaction =
            db.transaction_with_str_and_mode(STORE_NAME, IdbTransactionMode::Readwrite)?;
        let store: IdbObjectStore = tx.object_store(STORE_NAME)?;
        let request = store.put_with_key(&JsValue::from_str(data), &JsValue::from_str(key))?;
        await_request(&request).await?;

        // Null out handlers to release closure refs
        request.set_onsuccess(None);
        request.set_onerror(None);

        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
pub use inner::{load, save};
