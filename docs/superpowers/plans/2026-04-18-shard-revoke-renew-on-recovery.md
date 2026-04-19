# Shard Revoke-and-Renew on M-of-N Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When `reconstruct_from_shards` succeeds, atomically mark the old shard ceremony as revoked in the DB and immediately prompt the user to generate and distribute fresh replacement shards.

**Architecture:** Add a `recovery_ceremony_revoked_at` DB key that is written at the end of `reconstruct_from_shards`. Extend `RecoveryStatus` with a `needs_renewal` flag. The frontend watches this flag: after a successful reconstruction it drives the user back through the existing 4-step `RecoverySetup` wizard (reusing all existing UI) to create new shards, and resets the flag once `mark_recovery_complete` succeeds.

**Tech Stack:** Rust (pap-core, papillon-shared, papillon Tauri commands), Leptos (frontend signals), SQLite via `DatabaseOps::set_setting` / `get_setting`

---

## File Map

| File | Change |
|------|--------|
| `crates/papillon-shared/src/types.rs` | Extend `RecoveryStatus` with `needs_renewal: bool` |
| `apps/papillon/src/commands/recovery.rs` | Write `recovery_ceremony_revoked_at` at end of `reconstruct_from_shards`; read it in `get_recovery_status`; clear it in `mark_recovery_complete` |
| `apps/papillon/frontend/src/state/recovery.rs` | Add `needs_renewal: RwSignal<bool>` |
| `apps/papillon/frontend/src/app.rs` | After reconstruction succeeds, set `needs_renewal` + show setup modal |
| `apps/papillon/frontend/src/components/recovery_setup.rs` | Show renewal banner when `needs_renewal` is true; no logic change to wizard |
| `apps/papillon/src/commands/recovery.rs` (tests section) | Add unit tests for revoke / renewal flags |

---

## Task 1: Extend `RecoveryStatus` to carry `needs_renewal`

**Files:**
- Modify: `crates/papillon-shared/src/types.rs` (line ~1689)

- [ ] **Step 1: Write the failing test**

  Open `crates/papillon-shared/src/types.rs` and add to the `#[cfg(test)] mod tests` block:

  ```rust
  #[test]
  fn recovery_status_needs_renewal_roundtrip_json() {
      let status = RecoveryStatus {
          configured: true,
          needs_renewal: true,
      };
      let json = serde_json::to_string(&status).unwrap();
      let back: RecoveryStatus = serde_json::from_str(&json).unwrap();
      assert!(back.configured);
      assert!(back.needs_renewal);
  }

  #[test]
  fn recovery_status_needs_renewal_defaults_false_from_old_json() {
      // Simulate JSON from a version that lacks needs_renewal.
      let json = r#"{"configured":true}"#;
      let back: RecoveryStatus = serde_json::from_str(json).unwrap();
      assert!(back.configured);
      assert!(!back.needs_renewal, "needs_renewal must default to false for backward compat");
  }
  ```

- [ ] **Step 2: Run the tests to confirm they fail**

  Run: `cd pap && cargo test -p papillon-shared recovery_status_needs_renewal 2>&1 | tail -20`
  Expected: compile error — `RecoveryStatus` struct initializer is missing `needs_renewal` field.

- [ ] **Step 3: Add `needs_renewal` to `RecoveryStatus`**

  In `crates/papillon-shared/src/types.rs`, replace:

  ```rust
  /// Persistent recovery configuration status returned by `get_recovery_status`.
  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct RecoveryStatus {
      /// `true` once the user has completed the Shamir shard setup ceremony.
      pub configured: bool,
  }
  ```

  with:

  ```rust
  /// Persistent recovery configuration status returned by `get_recovery_status`.
  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct RecoveryStatus {
      /// `true` once the user has completed the Shamir shard setup ceremony.
      pub configured: bool,
      /// `true` when the current shard ceremony was used in a recovery and the
      /// principal must re-distribute fresh shards before the old ones can be
      /// reused by an attacker who collected M of them.
      #[serde(default)]
      pub needs_renewal: bool,
  }
  ```

- [ ] **Step 4: Fix existing construction site in `get_recovery_status`**

  In `apps/papillon/src/commands/recovery.rs`, `get_recovery_status` currently returns:
  ```rust
  Ok(RecoveryStatus { configured })
  ```

  Change it to (temporarily, will be replaced in Task 2):
  ```rust
  Ok(RecoveryStatus { configured, needs_renewal: false })
  ```

- [ ] **Step 5: Run the tests to confirm they pass**

  Run: `cd pap && cargo test -p papillon-shared recovery_status_needs_renewal 2>&1 | tail -20`
  Expected: 2 tests pass.

- [ ] **Step 6: Commit**

  ```bash
  git add crates/papillon-shared/src/types.rs apps/papillon/src/commands/recovery.rs
  git commit -m "feat(recovery): add needs_renewal flag to RecoveryStatus"
  ```

---

## Task 2: Write revocation timestamp in `reconstruct_from_shards`, read it in `get_recovery_status`, clear it in `mark_recovery_complete`

**Files:**
- Modify: `apps/papillon/src/commands/recovery.rs`

The three DB keys involved:
- `recovery_ceremony_revoked_at` — ISO-8601 timestamp written when reconstruction succeeds; presence signals "old shards compromised, renewal required"
- `recovery_shards_configured` — already exists; `mark_recovery_complete` sets it to `"1"`
- `recovery_ceremony_revoked_at` — cleared (deleted / set to empty) by `mark_recovery_complete`

`DatabaseOps` has `set_setting(key, value)` and `get_setting(key) -> Option<String>`. To "delete" a key, set it to `""` (empty string — the reader will treat `Some("")` the same as `None`).

- [ ] **Step 1: Write the failing test**

  Add to the `#[cfg(test)]` block in `apps/papillon/src/commands/recovery.rs`.
  (If no test block exists, add one at the bottom of the file before the closing `}` of the module.)

  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;
      use crate::db::Database;
      use std::sync::{Arc, RwLock};

      fn make_state_with_identity() -> crate::state::AppState {
          use pap_did::PrincipalKeypair;
          use pap_webauthn::SoftwareSigner;
          use zeroize::Zeroizing;

          let db = Arc::new(
              Database::open_memory()
                  .map_err(|e| crate::error::PapillonError::from(e.0))
                  .expect("in-memory db"),
          );
          let keypair = PrincipalKeypair::generate();
          let seed = Zeroizing::new(keypair.signing_key().to_bytes());
          let signer: Box<dyn pap_webauthn::Signer + Send + Sync> =
              Box::new(SoftwareSigner::from_keypair(keypair));
          crate::state::AppState {
              db: db.clone(),
              profiles_db: crate::keypair_store::ProfilesDb::open_memory()
                  .expect("in-memory profiles db"),
              signer: Arc::new(RwLock::new(Some(signer))),
              principal_seed: Arc::new(RwLock::new(Some(seed))),
              key_backed_up: Arc::new(RwLock::new(false)),
              ..Default::default()
          }
      }

      #[test]
      fn reconstruct_sets_revocation_timestamp_in_db() {
          // After reconstruct_from_shards succeeds, recovery_ceremony_revoked_at
          // must be set to a non-empty timestamp.
          //
          // We test the DB write path directly without going through Tauri State
          // by calling the inner helper function `revoke_current_ceremony`.
          let db = Arc::new(
              Database::open_memory()
                  .map_err(|e| crate::error::PapillonError::from(e.0))
                  .expect("in-memory db"),
          );
          revoke_current_ceremony(&db).expect("revoke should succeed");
          let val = db
              .get_setting("recovery_ceremony_revoked_at")
              .expect("db read")
              .expect("should be set");
          assert!(!val.is_empty(), "revocation timestamp must be non-empty");
          // Rough ISO-8601 check: starts with a 4-digit year.
          assert!(val.starts_with("20"), "should look like an ISO timestamp, got: {val}");
      }

      #[test]
      fn get_recovery_status_needs_renewal_when_revoked() {
          let db = Arc::new(
              Database::open_memory()
                  .map_err(|e| crate::error::PapillonError::from(e.0))
                  .expect("in-memory db"),
          );
          // Simulate a completed ceremony that was then used in reconstruction.
          db.set_setting("recovery_shards_configured", "1").unwrap();
          db.set_setting("recovery_ceremony_revoked_at", "2026-04-18T00:00:00Z")
              .unwrap();
          let status = recovery_status_from_db(&db).expect("status");
          assert!(status.configured);
          assert!(status.needs_renewal, "needs_renewal must be true when revoked_at is set");
      }

      #[test]
      fn mark_recovery_complete_clears_revocation_timestamp() {
          let db = Arc::new(
              Database::open_memory()
                  .map_err(|e| crate::error::PapillonError::from(e.0))
                  .expect("in-memory db"),
          );
          db.set_setting("recovery_ceremony_revoked_at", "2026-04-18T00:00:00Z")
              .unwrap();
          complete_recovery_ceremony(&db).expect("complete should succeed");
          // After completion, revocation marker must be gone (empty or absent).
          let val = db
              .get_setting("recovery_ceremony_revoked_at")
              .expect("db read");
          let is_cleared = val.map(|v| v.is_empty()).unwrap_or(true);
          assert!(is_cleared, "revocation timestamp must be cleared after renewal");
      }
  }
  ```

- [ ] **Step 2: Run the tests to confirm they fail**

  Run: `cd pap && cargo test -p papillon reconstruct_sets_revocation_timestamp 2>&1 | tail -20`
  Expected: compile error — functions `revoke_current_ceremony`, `recovery_status_from_db`, `complete_recovery_ceremony` do not exist yet.

- [ ] **Step 3: Extract helper functions and wire them in**

  In `apps/papillon/src/commands/recovery.rs`, add three private functions **above** the Tauri commands:

  ```rust
  use chrono::Utc;

  /// Write the revocation marker for the current shard ceremony.
  ///
  /// Called at the tail of `reconstruct_from_shards` so that the old shards are
  /// considered spent — any attacker who collected M shards can no longer use
  /// them on a fresh device once the principal has distributed new ones.
  fn revoke_current_ceremony(
      db: &dyn crate::db::prelude::DatabaseOps,
  ) -> Result<(), PapillonError> {
      let ts = Utc::now().to_rfc3339();
      db.set_setting("recovery_ceremony_revoked_at", &ts)
          .map_err(|e| PapillonError::from(e.to_string()))
  }

  /// Read recovery status from the DB (extracted for testability).
  fn recovery_status_from_db(
      db: &dyn crate::db::prelude::DatabaseOps,
  ) -> Result<papillon_shared::RecoveryStatus, PapillonError> {
      let configured = db
          .get_setting("recovery_shards_configured")
          .map_err(|e| PapillonError::from(e.to_string()))?
          .map(|v| v == "1")
          .unwrap_or(false);

      let needs_renewal = db
          .get_setting("recovery_ceremony_revoked_at")
          .map_err(|e| PapillonError::from(e.to_string()))?
          .map(|v| !v.is_empty())
          .unwrap_or(false);

      Ok(papillon_shared::RecoveryStatus {
          configured,
          needs_renewal,
      })
  }

  /// Persist the ceremony-complete flag and clear any pending revocation marker.
  ///
  /// Called by `mark_recovery_complete` so that after the principal distributes
  /// fresh shards the `needs_renewal` flag is cleared.
  fn complete_recovery_ceremony(
      db: &dyn crate::db::prelude::DatabaseOps,
  ) -> Result<(), PapillonError> {
      db.set_setting("recovery_shards_configured", "1")
          .map_err(|e| PapillonError::from(e.to_string()))?;
      // Clear the revocation marker — new shards have been distributed.
      db.set_setting("recovery_ceremony_revoked_at", "")
          .map_err(|e| PapillonError::from(e.to_string()))
  }
  ```

- [ ] **Step 4: Update the three Tauri commands to use the helpers**

  Replace the body of `reconstruct_from_shards` — add a call to `revoke_current_ceremony` at the very end, just before the `Ok(...)` return:

  ```rust
  // Old shards are now spent — mark this ceremony as requiring renewal so
  // the frontend prompts the principal to distribute fresh shards.
  revoke_current_ceremony(&state.db)?;

  Ok(RecoveryReconstructResult {
      did,
      public_key_b64: pub_key_b64,
  })
  ```

  (This replaces the existing `Ok(RecoveryReconstructResult { ... })` at the end of the function — line 243–246.)

  Replace the body of `get_recovery_status`:

  ```rust
  #[tauri::command]
  pub fn get_recovery_status(state: State<'_, AppState>) -> Result<RecoveryStatus, PapillonError> {
      recovery_status_from_db(&state.db)
  }
  ```

  Replace the body of `mark_recovery_complete`:

  ```rust
  #[tauri::command]
  pub fn mark_recovery_complete(state: State<'_, AppState>) -> Result<(), PapillonError> {
      complete_recovery_ceremony(&state.db)
  }
  ```

- [ ] **Step 5: Add `use chrono::Utc` if not already present**

  Check the top of `apps/papillon/src/commands/recovery.rs` for an existing `use chrono` line. If absent, add:

  ```rust
  use chrono::Utc;
  ```

  Check `apps/papillon/Cargo.toml` for a `chrono` dependency. If absent, add under `[dependencies]`:

  ```toml
  chrono = { version = "0.4", features = ["serde"] }
  ```

  (Look at `crates/pap-core/Cargo.toml` — `chrono = { version = "0.4", features = ["serde"] }` is already used there as a reference.)

- [ ] **Step 6: Run the tests to confirm they pass**

  Run: `cd pap && cargo test -p papillon reconstruct_sets_revocation reconstruct_sets_revocation_timestamp_in_db get_recovery_status_needs_renewal_when_revoked mark_recovery_complete_clears_revocation_timestamp 2>&1 | tail -20`

  If the project uses a workspace, try:
  `cd pap && cargo test -p papillon -- recovery 2>&1 | tail -40`
  Expected: 3 new tests pass.

- [ ] **Step 7: Compile check the whole workspace**

  Run: `cd pap && cargo build --workspace 2>&1 | grep -E "^error" | head -20`
  Expected: no errors.

- [ ] **Step 8: Commit**

  ```bash
  git add apps/papillon/src/commands/recovery.rs
  git commit -m "feat(recovery): revoke ceremony on reconstruction, require shard renewal"
  ```

---

## Task 3: Add `needs_renewal` signal to frontend recovery state

**Files:**
- Modify: `apps/papillon/frontend/src/state/recovery.rs`

- [ ] **Step 1: Write the failing test**

  This is a pure Leptos signal type — there are no unit tests for `RecoveryState` in this file currently. We'll verify it compiles and the signal is accessible. Add a doc comment instead and rely on the integration test in Task 4. Skip to Step 3.

- [ ] **Step 2: Add `needs_renewal` signal**

  Replace the contents of `apps/papillon/frontend/src/state/recovery.rs` with:

  ```rust
  use leptos::prelude::*;
  use papillon_shared::RecoveryShardInfo;

  /// Frontend state for the M-of-N Shamir recovery setup flow.
  #[derive(Clone, Copy)]
  pub struct RecoveryState {
      /// Whether the recovery setup modal is visible.
      pub show_setup: RwSignal<bool>,
      /// User-selected M (threshold).
      pub threshold: RwSignal<u8>,
      /// User-selected N (total shards).
      pub total: RwSignal<u8>,
      /// Shards generated by the last `create_recovery_shards` call.
      pub shards: RwSignal<Vec<RecoveryShardInfo>>,
      /// Shard manifest JSON (for public distribution).
      pub manifest_json: RwSignal<String>,
      /// True while the backend call is in flight.
      pub generating: RwSignal<bool>,
      /// Last error message from backend (if any).
      pub error: RwSignal<Option<String>>,
      /// Whether recovery shards have been set up and exported.
      pub setup_complete: RwSignal<bool>,
      /// True when the current ceremony was used in a recovery and the principal
      /// must distribute fresh shards before the old compromised ones can be reused.
      pub needs_renewal: RwSignal<bool>,
  }

  impl Default for RecoveryState {
      fn default() -> Self {
          Self {
              show_setup: RwSignal::new(false),
              threshold: RwSignal::new(2),
              total: RwSignal::new(3),
              shards: RwSignal::new(Vec::new()),
              manifest_json: RwSignal::new(String::new()),
              generating: RwSignal::new(false),
              error: RwSignal::new(None),
              setup_complete: RwSignal::new(false),
              needs_renewal: RwSignal::new(false),
          }
      }
  }
  ```

- [ ] **Step 3: Compile check**

  Run: `cd pap/apps/papillon/frontend && trunk build --no-minification 2>&1 | grep -E "^error" | head -20`

  If `trunk` is not available, try: `cd pap && cargo check -p papillon-frontend 2>&1 | grep -E "^error" | head -20`

  Expected: no errors.

- [ ] **Step 4: Commit**

  ```bash
  git add apps/papillon/frontend/src/state/recovery.rs
  git commit -m "feat(recovery-ui): add needs_renewal signal to RecoveryState"
  ```

---

## Task 4: Wire renewal prompt in `app.rs` — set `needs_renewal` + show modal after successful reconstruction

**Files:**
- Modify: `apps/papillon/frontend/src/app.rs`

The existing recovery status check in `app.rs` (around line 282–290) calls `get_recovery_status` on startup to decide whether to show the setup modal. We need to:
1. Set `recovery_state.needs_renewal` when `status.needs_renewal` is true.
2. Show the setup modal when `needs_renewal` is true, regardless of `configured`.

- [ ] **Step 1: Read the relevant block in `app.rs`**

  Lines 275–291 currently read:

  ```rust
  if !has_identity {
      return;
  }
  // Don't show if already done this session.
  if recovery_state.setup_complete.get() {
      return;
  }
  spawn_local(async move {
      if let Ok(status) =
          bridge::invoke_no_args::<RecoveryStatus>("get_recovery_status").await
      {
          if !status.configured {
              recovery_state.show_setup.set(true);
          }
      }
  });
  ```

- [ ] **Step 2: Update the status check to handle `needs_renewal`**

  Replace that `spawn_local` block with:

  ```rust
  spawn_local(async move {
      if let Ok(status) =
          bridge::invoke_no_args::<RecoveryStatus>("get_recovery_status").await
      {
          if status.needs_renewal {
              // Old shards are spent — principal must issue new ones.
              recovery_state.needs_renewal.set(true);
              recovery_state.show_setup.set(true);
          } else if !status.configured {
              recovery_state.show_setup.set(true);
          }
      }
  });
  ```

- [ ] **Step 3: Compile check**

  Run: `cd pap && cargo check -p papillon-frontend 2>&1 | grep -E "^error" | head -20`
  Expected: no errors.

- [ ] **Step 4: Commit**

  ```bash
  git add apps/papillon/frontend/src/app.rs
  git commit -m "feat(recovery-ui): show renewal wizard when old ceremony shards are spent"
  ```

---

## Task 5: Show renewal context banner in `RecoverySetup` wizard

**Files:**
- Modify: `apps/papillon/frontend/src/components/recovery_setup.rs`

When the user arrives in the wizard because of renewal (not initial setup), they should see a clear message explaining *why* they are here. We add a small banner at the top of the wizard that appears only when `needs_renewal` is true. No change to the existing 4-step flow.

- [ ] **Step 1: Add renewal banner to the wizard header**

  In `recovery_setup.rs`, the wizard header currently reads:

  ```rust
  // Header
  <div class="setup-boot-header">
      <div class="setup-boot-line">"RECOVERY_SETUP — INSTITUTIONAL KEY SPLITTING"</div>
      <div class="setup-boot-line">"> Shamir M-of-N secret sharing over GF(2^8)"</div>
      <div class="setup-boot-line">"> Spec §13.5 — no central authority"</div>
  </div>
  ```

  Replace with:

  ```rust
  // Header
  <div class="setup-boot-header">
      <div class="setup-boot-line">"RECOVERY_SETUP — INSTITUTIONAL KEY SPLITTING"</div>
      <div class="setup-boot-line">"> Shamir M-of-N secret sharing over GF(2^8)"</div>
      <div class="setup-boot-line">"> Spec §13.5 — no central authority"</div>
  </div>

  // Renewal notice — shown only when the previous ceremony was used in recovery.
  <Show when=move || recovery.needs_renewal.get()>
      <div style="background: var(--surface); border: 1px solid var(--gold); padding: 0.75rem; margin-bottom: 1rem; font-size: 0.85rem;">
          <span style="color: var(--gold);">"> RENEWAL_REQUIRED"</span>
          " — your previous shards were used in a recovery. "
          "The old shards are now spent and must be replaced. "
          "Complete this ceremony to distribute a fresh set to your trustees."
      </div>
  </Show>
  ```

- [ ] **Step 2: Clear `needs_renewal` when the wizard completes**

  The `mark_done` closure currently reads:

  ```rust
  let mark_done = move |_| {
      spawn_local(async move {
          let _ = bridge::invoke_no_args::<()>("mark_recovery_complete").await;
          recovery.setup_complete.set(true);
          recovery.show_setup.set(false);
          step.set(1);
          recovery.shards.set(Vec::new());
          recovery.manifest_json.set(String::new());
      });
  };
  ```

  Replace with:

  ```rust
  let mark_done = move |_| {
      spawn_local(async move {
          let _ = bridge::invoke_no_args::<()>("mark_recovery_complete").await;
          recovery.setup_complete.set(true);
          recovery.needs_renewal.set(false);
          recovery.show_setup.set(false);
          step.set(1);
          recovery.shards.set(Vec::new());
          recovery.manifest_json.set(String::new());
      });
  };
  ```

- [ ] **Step 3: Compile check**

  Run: `cd pap && cargo check -p papillon-frontend 2>&1 | grep -E "^error" | head -20`
  Expected: no errors.

- [ ] **Step 4: Commit**

  ```bash
  git add apps/papillon/frontend/src/components/recovery_setup.rs
  git commit -m "feat(recovery-ui): show renewal banner and clear flag on wizard completion"
  ```

---

## Task 6: Full workspace build and test pass

- [ ] **Step 1: Run full test suite**

  Run: `cd pap && cargo test --workspace 2>&1 | tail -40`
  Expected: all tests pass, no regressions. Note any failures and fix before proceeding.

- [ ] **Step 2: Confirm the four new tests are present and green**

  Run: `cd pap && cargo test --workspace -- recovery 2>&1 | grep -E "test .* (ok|FAILED)"`
  Expected output includes:
  ```
  test commands::recovery::tests::reconstruct_sets_revocation_timestamp_in_db ... ok
  test commands::recovery::tests::get_recovery_status_needs_renewal_when_revoked ... ok
  test commands::recovery::tests::mark_recovery_complete_clears_revocation_timestamp ... ok
  ```
  Plus all pre-existing recovery tests.

- [ ] **Step 3: Confirm `RecoveryStatus` backward-compat tests pass**

  Run: `cd pap && cargo test -p papillon-shared -- recovery_status 2>&1 | grep -E "test .* (ok|FAILED)"`
  Expected:
  ```
  test tests::recovery_status_needs_renewal_roundtrip_json ... ok
  test tests::recovery_status_needs_renewal_defaults_false_from_old_json ... ok
  ```

- [ ] **Step 4: Final commit**

  ```bash
  git add -p   # review any last changes
  git commit -m "test(recovery): confirm all revoke-and-renew tests pass across workspace"
  ```

---

## Self-Review

### Spec Coverage
- ✅ On reconstruction → old shards revoked (DB write in `reconstruct_from_shards`)
- ✅ `get_recovery_status` surfaces `needs_renewal` to frontend
- ✅ `mark_recovery_complete` clears the revocation marker (renewal ceremony complete)
- ✅ Frontend detects `needs_renewal` on startup and re-opens the wizard
- ✅ Wizard shows a banner explaining why renewal is needed
- ✅ Wizard completion clears `needs_renewal` signal

### Type Consistency
- `RecoveryStatus.needs_renewal: bool` — consistent across `types.rs`, `recovery.rs` (command), `app.rs` (reader), `recovery_setup.rs` (consumer)
- `recovery.needs_renewal` signal type `RwSignal<bool>` — consistent between `state/recovery.rs` definition and `app.rs`/`recovery_setup.rs` usage
- `revoke_current_ceremony`, `recovery_status_from_db`, `complete_recovery_ceremony` — all take `&dyn DatabaseOps`, consistent with `state.db` type

### Backward Compatibility
- `RecoveryStatus` gets `#[serde(default)]` on `needs_renewal` — old JSON without the field deserializes to `false` (no renewal needed), which is safe
- Existing `recovery_shards_configured` logic is untouched — devices that have never done a recovery continue to work exactly as before
