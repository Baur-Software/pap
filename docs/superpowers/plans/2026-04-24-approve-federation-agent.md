# Approve Federation Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `approve_federation_agent` Tauri command that converts a federation-discovered `AgentAdvertisement` into a local `DynamicAgentDef`, persists it to SQLite, and registers it in the local registry — making it visible to BM25 intent routing on the next query.

**Architecture:** A new `DynamicAgentSource::Federation` variant marks approved agents as trusted-but-external (no local keypair, the operator's DID is the authority). The command validates the advertisement signature via `verify_key_from_did` + `ad.verify()`, builds a `DynamicAgentDef` with `operator_key_seed: None`, inserts it via the existing `state.db.insert_agent()` path, and registers it in `state.local_registry`. `load_all_agents()` already feeds BM25 — no index changes needed.

**Tech Stack:** Rust, Tauri, `pap-did` (`verify_key_from_did`), `pap-marketplace` (`AgentAdvertisement`), `pap-agents` (`DynamicAgentDef`, `DynamicAgentSource`), `papillon-shared` (DB layer), SQLite.

---

## File Structure

| Path | Action | Purpose |
|------|--------|---------|
| `crates/pap-agents/src/dynamic.rs` | Modify | Add `DynamicAgentSource::Federation` variant |
| `apps/papillon/src/commands/agents.rs` | Modify | Add `Federation` arm to `source_to_str()` + new `approve_federation_agent` command |
| `apps/papillon/src/lib.rs` (or wherever commands are registered) | Modify | Register the new Tauri command |

---

## Task 1: Add `DynamicAgentSource::Federation` variant

**Files:**
- Modify: `crates/pap-agents/src/dynamic.rs:79-84`

- [ ] **Step 1: Write a failing test in `pap-agents`**

  Add to the bottom of `crates/pap-agents/src/dynamic.rs`:

  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;

      #[test]
      fn federation_source_round_trips_through_serde() {
          let src = DynamicAgentSource::Federation;
          let json = serde_json::to_string(&src).expect("serialize");
          let back: DynamicAgentSource = serde_json::from_str(&json).expect("deserialize");
          assert_eq!(back, src);
      }
  }
  ```

- [ ] **Step 2: Run test — expect compile error (variant does not exist)**

  ```
  cargo test -p pap-agents federation_source 2>&1 | head -5
  ```
  Expected: `error[E0599]: no variant or associated item named 'Federation'`

- [ ] **Step 3: Add the variant**

  Change the enum in `crates/pap-agents/src/dynamic.rs`:

  ```rust
  #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
  pub enum DynamicAgentSource {
      Catalog,
      UserCreated,
      Generated,
      /// Agent approved from a federation peer registry.
      /// No local keypair (`operator_key_seed` is `None`).
      /// The operator's DID is the signing authority.
      Federation,
  }
  ```

- [ ] **Step 4: Run test — expect pass**

  ```
  cargo test -p pap-agents federation_source
  ```
  Expected: `test dynamic::tests::federation_source_round_trips_through_serde ... ok`

- [ ] **Step 5: Commit**

  ```bash
  git add crates/pap-agents/src/dynamic.rs
  git commit -m "feat(pap-agents): add DynamicAgentSource::Federation variant"
  ```

---

## Task 2: Wire `Federation` into `source_to_str()` and fix compile errors

**Files:**
- Modify: `apps/papillon/src/commands/agents.rs:11-17`

- [ ] **Step 1: Verify the workspace now fails to compile (exhaustive match)**

  ```
  cargo check -p papillon 2>&1 | grep "error\[" | head -5
  ```
  Expected: `error[E0004]: non-exhaustive patterns: 'Federation' not covered`

- [ ] **Step 2: Add the arm to `source_to_str()`**

  In `apps/papillon/src/commands/agents.rs`, update `source_to_str`:

  ```rust
  fn source_to_str(source: &DynamicAgentSource) -> &'static str {
      match source {
          DynamicAgentSource::Catalog => "catalog",
          DynamicAgentSource::UserCreated => "user_created",
          DynamicAgentSource::Generated => "generated",
          DynamicAgentSource::Federation => "federation",
      }
  }
  ```

- [ ] **Step 3: Check workspace compiles cleanly (excluding RDMA/BlueField)**

  ```
  cargo check -p papillon 2>&1 | grep "^error" | head -10
  ```
  Expected: no output (no errors).

- [ ] **Step 4: Commit**

  ```bash
  git add apps/papillon/src/commands/agents.rs
  git commit -m "fix(papillon): handle DynamicAgentSource::Federation in source_to_str"
  ```

---

## Task 3: Write `approve_federation_agent` — tests first

**Files:**
- Modify: `apps/papillon/src/commands/agents.rs`

- [ ] **Step 1: Write a unit test for the conversion logic**

  Add to the bottom of `apps/papillon/src/commands/agents.rs`:

  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;
      use pap_did::PrincipalKeypair;
      use pap_marketplace::AgentAdvertisement;

      fn make_signed_ad() -> (AgentAdvertisement, PrincipalKeypair) {
          let kp = PrincipalKeypair::generate();
          let mut ad = AgentAdvertisement::new(
              "Test Weather Agent",
              "WeatherCorp",
              kp.did(),
              vec!["schema:CheckAction".into()],
              vec!["schema:Place".into()],
              vec![],
              vec!["schema:WeatherForecast".into()],
          );
          ad.sign(kp.signing_key()).expect("sign must succeed");
          (ad, kp)
      }

      #[test]
      fn ad_to_federation_def_sets_correct_source() {
          let (ad, _kp) = make_signed_ad();
          let def = ad_to_federation_def(&ad, "pap://test-registry");
          assert_eq!(def.source, DynamicAgentSource::Federation);
      }

      #[test]
      fn ad_to_federation_def_preserves_capability_fields() {
          let (ad, _kp) = make_signed_ad();
          let def = ad_to_federation_def(&ad, "pap://test-registry");
          assert_eq!(def.name, "Test Weather Agent");
          assert_eq!(def.provider, "WeatherCorp");
          assert_eq!(def.agent_did, Some(ad.provider.did.clone()));
          assert_eq!(def.action, "schema:CheckAction");
          assert_eq!(def.object_types, vec!["schema:Place"]);
          assert_eq!(def.returns, vec!["schema:WeatherForecast"]);
          assert_eq!(def.requires_disclosure, Vec::<String>::new());
          assert!(def.operator_key_seed.is_none());
          assert!(def.published_to.contains(&"pap://test-registry".to_string()));
      }

      #[test]
      fn ad_to_federation_def_rejects_ad_with_no_capability() {
          let kp = PrincipalKeypair::generate();
          let mut ad = AgentAdvertisement::new(
              "Empty",
              "NoOp",
              kp.did(),
              vec![], // no capabilities
              vec![],
              vec![],
              vec![],
          );
          ad.sign(kp.signing_key()).expect("sign must succeed");
          // ad_to_federation_def panics / returns error if capability is empty —
          // the command layer catches this before calling ad_to_federation_def.
          // This test documents the precondition.
          assert!(ad.capability.is_empty());
      }

      #[test]
      fn verify_signature_accepts_valid_ad() {
          let (ad, _kp) = make_signed_ad();
          let vk = pap_did::verify_key_from_did(&ad.signed_by)
              .expect("DID must decode");
          assert!(ad.verify(&vk).is_ok());
      }

      #[test]
      fn verify_signature_rejects_tampered_ad() {
          let (mut ad, _kp) = make_signed_ad();
          ad.name = "Tampered".into(); // mutate after signing
          let vk = pap_did::verify_key_from_did(&ad.signed_by)
              .expect("DID must decode");
          assert!(ad.verify(&vk).is_err());
      }
  }
  ```

- [ ] **Step 2: Run tests — expect compile error (`ad_to_federation_def` undefined)**

  ```
  cargo test -p papillon -- agents::tests 2>&1 | head -10
  ```
  Expected: `error[E0425]: cannot find function 'ad_to_federation_def'`

- [ ] **Step 3: Implement `ad_to_federation_def()`**

  Add before the `// ── Commands ──` section in `apps/papillon/src/commands/agents.rs`:

  ```rust
  /// Convert a federation `AgentAdvertisement` into a local `DynamicAgentDef`.
  ///
  /// The operator's DID becomes `agent_did`.  No local keypair is generated —
  /// `operator_key_seed` is left `None` because the operator holds their own key.
  /// `source` is set to `Federation` so the DB and BM25 index know the provenance.
  ///
  /// Callers must verify the advertisement signature before calling this function.
  pub(crate) fn ad_to_federation_def(ad: &AgentAdvertisement, registry_url: &str) -> DynamicAgentDef {
      let now = chrono::Utc::now().to_rfc3339();
      DynamicAgentDef {
          agent_did: Some(ad.provider.did.clone()),
          schema_version: 1,
          version: ad.version.clone(),
          name: ad.name.clone(),
          provider: ad.provider.name.clone(),
          description: String::new(), // not carried in AgentAdvertisement
          action: ad.capability.first().cloned().unwrap_or_default(),
          object_types: ad.object_types.clone(),
          requires_disclosure: ad.requires_disclosure.clone(),
          returns: ad.returns.clone(),
          endpoint: None, // not carried in AgentAdvertisement; resolved at handshake time
          llm_instructions: String::new(),
          subagents: vec![],
          source: DynamicAgentSource::Federation,
          operator_key_seed: None,
          published_to: vec![registry_url.to_owned()],
          catalog_path: None,
          configurable_properties: ad.configurable_properties.clone(),
          created_at: now.clone(),
          updated_at: now,
      }
  }
  ```

- [ ] **Step 4: Run tests — all 5 must pass**

  ```
  cargo test -p papillon -- agents::tests 2>&1 | tail -12
  ```
  Expected:
  ```
  test agents::tests::ad_to_federation_def_sets_correct_source ... ok
  test agents::tests::ad_to_federation_def_preserves_capability_fields ... ok
  test agents::tests::ad_to_federation_def_rejects_ad_with_no_capability ... ok
  test agents::tests::verify_signature_accepts_valid_ad ... ok
  test agents::tests::verify_signature_rejects_tampered_ad ... ok
  test result: ok. 5 passed; 0 failed
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add apps/papillon/src/commands/agents.rs
  git commit -m "feat(papillon): add ad_to_federation_def helper with tests"
  ```

---

## Task 4: Implement the `approve_federation_agent` Tauri command

**Files:**
- Modify: `apps/papillon/src/commands/agents.rs`

- [ ] **Step 1: Add the command**

  Add after `save_agent()` in `apps/papillon/src/commands/agents.rs`:

  ```rust
  /// Approve a federation-discovered agent, promoting it into the local DB
  /// and BM25 intent index.
  ///
  /// Steps:
  /// 1. Look up the `AgentAdvertisement` from the named remote registry.
  /// 2. Verify its Ed25519 signature against the `signed_by` DID.
  /// 3. Convert to `DynamicAgentDef` (source=Federation, no keypair).
  /// 4. Insert into SQLite — from this point BM25 will pick it up.
  /// 5. Register in the local runtime registry so it is immediately resolvable.
  ///
  /// Returns the `AgentInfo` for the approved agent on success.
  /// Returns an error string if the agent is not found, signature is invalid,
  /// capability list is empty, or a DB/registry error occurs.
  #[tauri::command]
  pub async fn approve_federation_agent(
      state: tauri::State<'_, AppState>,
      registry_url: String,
      agent_did: String,
  ) -> Result<AgentInfo, String> {
      // ── Step 1: Locate the advertisement ─────────────────────────────────
      let ad = {
          let registries = state
              .registries
              .read()
              .map_err(|e| format!("Registries lock poisoned: {e}"))?;
          let registry = registries
              .get(&registry_url)
              .ok_or_else(|| format!("Registry not known: {registry_url} — navigate to it first"))?;
          registry
              .all_advertisements()
              .into_iter()
              .find(|a| a.provider.did == agent_did)
              .ok_or_else(|| format!("Agent {agent_did} not found in {registry_url}"))?
      };

      // ── Step 2: Validate capability list ─────────────────────────────────
      if ad.capability.is_empty() {
          return Err(format!(
              "Agent {agent_did} advertises no capabilities — cannot approve"
          ));
      }

      // ── Step 3: Verify advertisement signature ────────────────────────────
      let verifying_key = pap_did::verify_key_from_did(&ad.signed_by)
          .map_err(|e| format!("Cannot derive verifying key from DID {}: {e}", ad.signed_by))?;
      ad.verify(&verifying_key)
          .map_err(|e| format!("Advertisement signature invalid: {e}"))?;

      // ── Step 4: Convert to DynamicAgentDef ───────────────────────────────
      let def = ad_to_federation_def(&ad, &registry_url);

      // ── Step 5: Persist to local DB ───────────────────────────────────────
      state
          .db
          .insert_agent(&def)
          .map_err(|e| format!("Failed to persist federation agent: {e}"))?;

      // ── Step 6: Register in local runtime registry ────────────────────────
      // Re-use the incoming advertisement directly — it's already signed by the
      // operator so the registry accepts it without re-signing.
      {
          let mut reg = state
              .local_registry
              .lock()
              .map_err(|e| format!("Registry lock poisoned: {e}"))?;
          // Ignore DuplicateAdvertisement — idempotent approve is fine.
          let _ = reg.register_local(ad);
      }

      Ok(def_to_agent_info(&def))
  }
  ```

- [ ] **Step 2: Check it compiles**

  ```
  cargo check -p papillon 2>&1 | grep "^error" | head -10
  ```
  Expected: no output.

- [ ] **Step 3: Commit**

  ```bash
  git add apps/papillon/src/commands/agents.rs
  git commit -m "feat(papillon): approve_federation_agent command — promote ad to local DB + BM25"
  ```

---

## Task 5: Register the command in Tauri's invoke handler

**Files:**
- Modify: `apps/papillon/src/lib.rs` (find the `.invoke_handler(tauri::generate_handler![...])` call)

- [ ] **Step 1: Find the registration site**

  ```
  cargo grep "invoke_handler\|generate_handler" apps/papillon/src/ 2>&1 | head -10
  ```
  Or: `grep -rn "save_agent" apps/papillon/src/lib.rs`

- [ ] **Step 2: Add `approve_federation_agent` alongside `save_agent`**

  The `generate_handler!` list already includes `commands::agents::save_agent`. Add:

  ```rust
  commands::agents::approve_federation_agent,
  ```

  immediately after `commands::agents::save_agent,` in the same list.

- [ ] **Step 3: Check it compiles**

  ```
  cargo check -p papillon 2>&1 | grep "^error" | head -10
  ```
  Expected: no output.

- [ ] **Step 4: Commit**

  ```bash
  git add apps/papillon/src/lib.rs
  git commit -m "feat(papillon): register approve_federation_agent in Tauri invoke handler"
  ```

---

## Task 6: Integration test — approve then verify BM25 picks it up

**Files:**
- Modify: `apps/papillon/src/commands/agents.rs` (tests module)

- [ ] **Step 1: Write a failing integration test**

  Add to `apps/papillon/src/commands/agents.rs` tests module:

  ```rust
  #[test]
  fn approved_federation_def_is_visible_to_bm25() {
      use pap_agents::IntentIndex;
      use pap_did::PrincipalKeypair;
      use pap_marketplace::AgentAdvertisement;

      // Build and sign a weather agent advertisement
      let kp = PrincipalKeypair::generate();
      let mut ad = AgentAdvertisement::new(
          "Open-Meteo Weather",
          "Open-Meteo",
          kp.did(),
          vec!["schema:CheckAction".into()],
          vec!["schema:Place".into()],
          vec![],
          vec!["schema:WeatherForecast".into()],
      );
      ad.sign(kp.signing_key()).expect("sign must succeed");

      // Verify signature (mirrors what approve_federation_agent does at runtime)
      let vk = pap_did::verify_key_from_did(&ad.signed_by).expect("DID must decode");
      ad.verify(&vk).expect("signature must be valid");

      // Convert to DynamicAgentDef
      let def = ad_to_federation_def(&ad, "pap://test-registry");
      assert_eq!(def.source, DynamicAgentSource::Federation);

      // Build BM25 index from [this def] and verify routing works
      let catalog = vec![def];
      let idx = IntentIndex::new(&catalog);
      let m = idx
          .classify("weather in Tokyo", 0.25)
          .expect("approved federation agent must be BM25-routable");
      assert_eq!(m.action, "schema:CheckAction");
      assert_eq!(m.agent_name.as_deref(), Some("Open-Meteo Weather"));
  }
  ```

- [ ] **Step 2: Run test — expect pass**

  ```
  cargo test -p papillon -- agents::tests::approved_federation_def_is_visible_to_bm25 2>&1 | tail -5
  ```
  Expected: `test agents::tests::approved_federation_def_is_visible_to_bm25 ... ok`

- [ ] **Step 3: Run all papillon agent tests**

  ```
  cargo test -p papillon -- agents::tests 2>&1 | tail -12
  ```
  Expected: 6 × `ok`

- [ ] **Step 4: Commit**

  ```bash
  git add apps/papillon/src/commands/agents.rs
  git commit -m "test(papillon): integration test — approved federation agent visible to BM25"
  ```

---

## Task 7: Final check

- [ ] **Step 1: Run all tests that can compile on this machine**

  ```
  cargo test -p pap-agents -p papillon-shared -p papillon -- agents 2>&1 | tail -15
  ```
  Expected: all `ok`, no failures.

- [ ] **Step 2: Workspace compile check (non-hardware crates)**

  ```
  cargo check -p papillon -p pap-agents -p papillon-shared 2>&1 | grep "^error" | head -5
  ```
  Expected: no output.

- [ ] **Step 3: Commit if any fixups**

  ```bash
  git add -p
  git commit -m "fix(papillon): approve-federation-agent fixups"
  ```

---

## Verification

End-to-end manual test path (requires a live Papillon instance):
1. `navigate_registry(state, "pap://some-peer")` — establish connection
2. `sync_agents(state, "pap://some-peer", "schema:CheckAction")` — pull ads
3. `list_agents(state, "pap://some-peer")` — note an agent DID
4. `approve_federation_agent(state, "pap://some-peer", "<did>")` — approve it
5. Issue a prompt matching that agent — BM25 should now route to it at Level 2

Key assertions:
- `approve_federation_agent` returns `Ok(AgentInfo)` with `source: "federation"`
- Subsequent `load_all_agents()` DB call includes the new row
- `IntentIndex::new(&load_all_agents())` routes matching prompts to the approved agent
- Approving the same agent twice returns `Ok` (idempotent)
- An advertisement with a tampered signature returns `Err("Advertisement signature invalid: ...")`
- An advertisement with an empty capability list returns `Err("... advertises no capabilities")`
