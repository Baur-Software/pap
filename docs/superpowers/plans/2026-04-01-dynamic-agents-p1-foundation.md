# Dynamic Agents — Part 1: Foundation (deps, data model, DB)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the `toml` dependency, delete 13 compiled agents, define DynamicAgentDef data model, and add the agents DB migration.

**Architecture:** DynamicAgentDef is the runtime config struct replacing compile-time AgentMeta for dynamic agents. It lives in crates/pap-agents/src/dynamic.rs. The DB migration adds the agents table to papillon-shared's NativeDatabase.

**Tech Stack:** Rust, toml 0.8, serde/serde_json, rusqlite (papillon-shared), ed25519-dalek

---

## Task 1: Add toml crate + delete 13 compiled agents

Files:
- Modify: `Cargo.toml` (root workspace)
- Modify: `crates/pap-agents/Cargo.toml`
- Delete: `crates/pap-agents/src/agents/arxiv.rs`
- Delete: `crates/pap-agents/src/agents/credential_store.rs`
- Delete: `crates/pap-agents/src/agents/dictionary.rs`
- Delete: `crates/pap-agents/src/agents/duckduckgo.rs`
- Delete: `crates/pap-agents/src/agents/frankfurter.rs`
- Delete: `crates/pap-agents/src/agents/github_repos.rs`
- Delete: `crates/pap-agents/src/agents/hacker_news.rs`
- Delete: `crates/pap-agents/src/agents/ip_geolocation.rs`
- Delete: `crates/pap-agents/src/agents/nominatim.rs`
- Delete: `crates/pap-agents/src/agents/open_library.rs`
- Delete: `crates/pap-agents/src/agents/open_meteo.rs`
- Delete: `crates/pap-agents/src/agents/rest_countries.rs`
- Delete: `crates/pap-agents/src/agents/wikipedia.rs`
- Modify: `crates/pap-agents/src/agents/mod.rs`
- Modify: `crates/pap-agents/src/registry.rs`

- [ ] **Step 1.1** — Add `toml = "0.8"` to `[workspace.dependencies]` in root `Cargo.toml`.

  In `/Users/toadkicker/Documents/GitHub/pap/Cargo.toml`, insert after the `serde_json` line:

  ```toml
  toml = "0.8"
  ```

- [ ] **Step 1.2** — Add `toml = { workspace = true }` to `crates/pap-agents/Cargo.toml` dependencies.

  In `/Users/toadkicker/Documents/GitHub/pap/crates/pap-agents/Cargo.toml`, append to `[dependencies]`:

  ```toml
  toml = { workspace = true }
  ```

- [ ] **Step 1.3** — Delete all 13 compiled agent source files:

  ```bash
  rm crates/pap-agents/src/agents/arxiv.rs
  rm crates/pap-agents/src/agents/credential_store.rs
  rm crates/pap-agents/src/agents/dictionary.rs
  rm crates/pap-agents/src/agents/duckduckgo.rs
  rm crates/pap-agents/src/agents/frankfurter.rs
  rm crates/pap-agents/src/agents/github_repos.rs
  rm crates/pap-agents/src/agents/hacker_news.rs
  rm crates/pap-agents/src/agents/ip_geolocation.rs
  rm crates/pap-agents/src/agents/nominatim.rs
  rm crates/pap-agents/src/agents/open_library.rs
  rm crates/pap-agents/src/agents/open_meteo.rs
  rm crates/pap-agents/src/agents/rest_countries.rs
  rm crates/pap-agents/src/agents/wikipedia.rs
  ```

- [ ] **Step 1.4** — Replace `crates/pap-agents/src/agents/mod.rs` — only `WebReaderExecutor` remains:

  ```rust
  pub mod web_reader;

  pub use web_reader::WebReaderExecutor;
  ```

- [ ] **Step 1.5** — Replace the body of `build_agents()` in `crates/pap-agents/src/registry.rs` — only registers `WebReaderExecutor`. Remove all 12 now-deleted executor registrations and their tier comments. The `register_executor` and `register_handler` helpers are unchanged. The new body:

  ```rust
  pub fn build_agents(extra: Vec<(&'static str, Arc<dyn AgentHandler>, AgentMeta)>) -> AgentSet {
      let mut registry = FederatedRegistry::new();
      let mut keypairs = HashMap::new();
      let mut handlers: HashMap<String, Arc<dyn AgentHandler>> = HashMap::new();

      // Only compiled agent: HTML parsing requires custom Rust (not expressible as TOML).
      register_executor(
          WebReaderExecutor,
          &mut registry,
          &mut keypairs,
          &mut handlers,
      );

      // Register extra agents (e.g., on-device AI, app-specific agents)
      for (name, handler, meta) in extra {
          register_handler(
              name,
              handler,
              meta,
              &mut registry,
              &mut keypairs,
              &mut handlers,
          );
      }

      AgentSet {
          registry,
          keypairs,
          handlers,
      }
  }
  ```

- [ ] **Step 1.6** — Update the test `build_agents_registers_all_standard` in `registry.rs` to assert `handlers.len() == 1` and check only `"Web Page Reader"`. Replace the existing test body:

  ```rust
  #[test]
  fn build_agents_registers_all_standard() {
      let set = build_agents(vec![]);
      assert_eq!(set.handlers.len(), 1);
      assert_eq!(set.keypairs.len(), 1);
      assert!(set.handlers.contains_key("Web Page Reader"));
  }
  ```

  Also remove the now-stale tests that reference deleted agents by name:
  - `advertisements_queryable_by_action_type` — remove the `DuckDuckGo Search` assertion (or delete the test if it only covers deleted agents)
  - `disclosure_required_agents_declare_properties` — delete (references `IP Geolocation` which is removed)

  The remaining tests (`names_match_between_handlers_and_keypairs`, `all_advertisements_are_signed`, `all_advertisements_have_valid_schema_org_actions`, `advertisements_match_handler_count`, `advertisements_are_re_registrable_in_fresh_registry`) are generic and still pass with 1 agent.

- [ ] **Step 1.7** — Run the targeted test:

  ```bash
  cargo test -p pap-agents -- build_agents_registers_all_standard
  ```

  Expected output:

  ```
  test registry::tests::build_agents_registers_all_standard ... ok

  test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured
  ```

- [ ] **Step 1.8** — Commit:

  ```bash
  git add Cargo.toml crates/pap-agents/Cargo.toml \
      crates/pap-agents/src/agents/mod.rs \
      crates/pap-agents/src/registry.rs
  git rm crates/pap-agents/src/agents/arxiv.rs \
      crates/pap-agents/src/agents/credential_store.rs \
      crates/pap-agents/src/agents/dictionary.rs \
      crates/pap-agents/src/agents/duckduckgo.rs \
      crates/pap-agents/src/agents/frankfurter.rs \
      crates/pap-agents/src/agents/github_repos.rs \
      crates/pap-agents/src/agents/hacker_news.rs \
      crates/pap-agents/src/agents/ip_geolocation.rs \
      crates/pap-agents/src/agents/nominatim.rs \
      crates/pap-agents/src/agents/open_library.rs \
      crates/pap-agents/src/agents/open_meteo.rs \
      crates/pap-agents/src/agents/rest_countries.rs \
      crates/pap-agents/src/agents/wikipedia.rs
  git commit -m "chore(pap-agents): delete 13 compiled agents, add toml dep"
  ```

---

## Task 2: DynamicAgentDef data model

Files:
- Create: `crates/pap-agents/src/dynamic.rs`
- Modify: `crates/pap-agents/src/lib.rs`

- [ ] **Step 2.1** — Create `crates/pap-agents/src/dynamic.rs` with the complete file contents:

  ```rust
  use std::collections::HashMap;
  use serde::{Deserialize, Serialize};

  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct DynamicAgentDef {
      pub agent_did: Option<String>,
      pub schema_version: u32,
      pub name: String,
      pub provider: String,
      pub description: String,
      pub action: String,
      pub object_types: Vec<String>,
      pub requires_disclosure: Vec<String>,
      pub returns: Vec<String>,
      pub endpoint: Option<HttpEndpointConfig>,
      pub llm_instructions: String,
      pub subagents: Vec<String>,
      pub source: DynamicAgentSource,
      #[serde(skip_serializing_if = "Option::is_none")]
      pub operator_key_seed: Option<[u8; 32]>,
      pub published_to: Vec<String>,
      #[serde(skip_serializing_if = "Option::is_none")]
      pub catalog_path: Option<String>,
      pub created_at: String,
      pub updated_at: String,
  }

  #[derive(Debug, Clone, Serialize, Deserialize)]
  pub struct HttpEndpointConfig {
      pub url_template: String,
      pub method: HttpMethod,
      #[serde(default)]
      pub headers: HashMap<String, String>,
      pub body_template: Option<String>,
      pub response_jsonpath: String,
      pub response_schema_type: String,
  }

  #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
  pub enum HttpMethod { Get, Post }

  #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
  pub enum DynamicAgentSource {
      Catalog,
      UserCreated,
      Generated,
  }

  /// Validate that a URL is safe to use as an HTTP endpoint.
  ///
  /// Returns `false` for any of:
  /// - Non-https scheme
  /// - `localhost` host
  /// - IPv4 RFC 1918 ranges: 127.x, 10.x, 172.16–31.x, 192.168.x
  /// - Link-local: 169.254.x
  /// - Bare IPv4 or IPv6 address literals (any address, not just private ones)
  ///
  /// Defense-in-depth: this check is enforced both at save time and at execution time
  /// (see spec §4.1).
  pub fn is_safe_url(url: &str) -> bool {
      // Must be https://
      let rest = match url.strip_prefix("https://") {
          Some(r) => r,
          None => return false,
      };

      // Extract host (everything before the first '/', '?', '#', or end of string)
      let host = rest
          .split(|c| c == '/' || c == '?' || c == '#')
          .next()
          .unwrap_or(rest)
          .to_ascii_lowercase();

      // Remove port if present
      let host = match host.rfind(':') {
          Some(i) => &host[..i],
          None => &host,
      };

      // Reject localhost
      if host == "localhost" {
          return false;
      }

      // Reject bare IPv6 literals (wrapped in brackets: [::1], [fe80::1], etc.)
      if host.starts_with('[') {
          return false;
      }

      // Parse as IPv4 to reject RFC 1918, loopback, and link-local ranges,
      // and to reject any bare IPv4 literal (all-numeric octets).
      if let Ok(addr) = host.parse::<std::net::Ipv4Addr>() {
          let octets = addr.octets();
          // Reject ALL IPv4 literals — agents must use hostnames.
          // This also covers: 127.x (loopback), 10.x, 172.16-31.x,
          // 192.168.x, 169.254.x (link-local), and 0.x.
          let _ = octets; // All literals rejected regardless of range.
          return false;
      }

      // Reject RFC 1918 and special-purpose hostnames by octet prefix
      // (catches dotted-decimal variants not parsed as Ipv4Addr, e.g. "010.0.0.1").
      // This is belt-and-suspenders; the parse above handles the canonical form.
      let segments: Vec<&str> = host.split('.').collect();
      if segments.len() == 4 {
          if let (Ok(a), Ok(b), Ok(c)) = (
              segments[0].parse::<u16>(),
              segments[1].parse::<u16>(),
              segments[2].parse::<u16>(),
          ) {
              // 127.x.x.x
              if a == 127 { return false; }
              // 10.x.x.x
              if a == 10 { return false; }
              // 172.16.x.x – 172.31.x.x
              if a == 172 && (16..=31).contains(&b) { return false; }
              // 192.168.x.x
              if a == 192 && b == 168 { return false; }
              // 169.254.x.x (link-local)
              if a == 169 && b == 254 { return false; }
              // Suppress unused warning for c
              let _ = c;
          }
      }

      true
  }

  #[cfg(test)]
  mod tests {
      use super::*;

      // ── is_safe_url ──────────────────────────────────────────────────────

      #[test]
      fn https_public_host_is_safe() {
          assert!(is_safe_url("https://api.example.com/v1?q=rust"));
          assert!(is_safe_url("https://world.openfoodfacts.org/cgi/search.pl"));
          assert!(is_safe_url("https://api.duckduckgo.com/?q=foo&format=json"));
      }

      #[test]
      fn http_scheme_rejected() {
          assert!(!is_safe_url("http://api.example.com/v1"));
      }

      #[test]
      fn ftp_scheme_rejected() {
          assert!(!is_safe_url("ftp://files.example.com/data"));
      }

      #[test]
      fn no_scheme_rejected() {
          assert!(!is_safe_url("api.example.com/v1"));
      }

      #[test]
      fn localhost_rejected() {
          assert!(!is_safe_url("https://localhost/api"));
          assert!(!is_safe_url("https://localhost:8080/api"));
      }

      #[test]
      fn loopback_ipv4_rejected() {
          assert!(!is_safe_url("https://127.0.0.1/api"));
          assert!(!is_safe_url("https://127.0.0.1:8080/api"));
          assert!(!is_safe_url("https://127.1.2.3/api"));
      }

      #[test]
      fn rfc1918_10_block_rejected() {
          assert!(!is_safe_url("https://10.0.0.1/api"));
          assert!(!is_safe_url("https://10.255.255.255/api"));
      }

      #[test]
      fn rfc1918_172_block_rejected() {
          assert!(!is_safe_url("https://172.16.0.1/api"));
          assert!(!is_safe_url("https://172.20.0.1/api"));
          assert!(!is_safe_url("https://172.31.255.255/api"));
      }

      #[test]
      fn rfc1918_172_outside_block_allowed() {
          // 172.15.x and 172.32.x are public
          assert!(is_safe_url("https://172.15.0.1/api"));
          assert!(is_safe_url("https://172.32.0.1/api"));
      }

      #[test]
      fn rfc1918_192_168_rejected() {
          assert!(!is_safe_url("https://192.168.1.1/api"));
          assert!(!is_safe_url("https://192.168.0.1:443/api"));
      }

      #[test]
      fn link_local_169_254_rejected() {
          assert!(!is_safe_url("https://169.254.0.1/api"));
          assert!(!is_safe_url("https://169.254.169.254/latest/meta-data/"));
      }

      #[test]
      fn ipv6_literal_rejected() {
          assert!(!is_safe_url("https://[::1]/api"));
          assert!(!is_safe_url("https://[fe80::1]/api"));
          assert!(!is_safe_url("https://[2001:db8::1]/api"));
      }

      #[test]
      fn bare_ipv4_public_rejected() {
          // Even a public IPv4 literal must be rejected — agents use hostnames.
          assert!(!is_safe_url("https://1.1.1.1/dns-query"));
          assert!(!is_safe_url("https://8.8.8.8/"));
      }

      // ── DynamicAgentDef round-trip ───────────────────────────────────────

      #[test]
      fn dynamic_agent_def_serializes_and_deserializes() {
          let def = DynamicAgentDef {
              agent_did: Some("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string()),
              schema_version: 1,
              name: "Open Food Facts".to_string(),
              provider: "Open Food Facts".to_string(),
              description: "Look up nutritional data for food products".to_string(),
              action: "schema:SearchAction".to_string(),
              object_types: vec!["schema:FoodEstablishment".to_string()],
              requires_disclosure: vec![],
              returns: vec!["schema:NutritionInformation".to_string()],
              endpoint: Some(HttpEndpointConfig {
                  url_template: "https://world.openfoodfacts.org/cgi/search.pl?search_terms={query}&json=1".to_string(),
                  method: HttpMethod::Get,
                  headers: HashMap::new(),
                  body_template: None,
                  response_jsonpath: "$.products[0]".to_string(),
                  response_schema_type: "schema:NutritionInformation".to_string(),
              }),
              llm_instructions: "You are a nutrition lookup assistant.".to_string(),
              subagents: vec![],
              source: DynamicAgentSource::Catalog,
              operator_key_seed: None,
              published_to: vec![],
              catalog_path: Some("food/open_food_facts.toml".to_string()),
              created_at: "2026-04-01T00:00:00Z".to_string(),
              updated_at: "2026-04-01T00:00:00Z".to_string(),
          };

          let json = serde_json::to_string(&def).unwrap();
          let back: DynamicAgentDef = serde_json::from_str(&json).unwrap();

          assert_eq!(back.name, def.name);
          assert_eq!(back.schema_version, 1);
          assert_eq!(back.source, DynamicAgentSource::Catalog);
          assert_eq!(back.action, "schema:SearchAction");
          assert!(back.operator_key_seed.is_none());
          assert_eq!(back.catalog_path, Some("food/open_food_facts.toml".to_string()));
      }

      #[test]
      fn operator_key_seed_absent_from_json_when_none() {
          let def = DynamicAgentDef {
              agent_did: None,
              schema_version: 1,
              name: "Test".to_string(),
              provider: "Test".to_string(),
              description: "test".to_string(),
              action: "schema:SearchAction".to_string(),
              object_types: vec![],
              requires_disclosure: vec![],
              returns: vec![],
              endpoint: None,
              llm_instructions: String::new(),
              subagents: vec![],
              source: DynamicAgentSource::UserCreated,
              operator_key_seed: None,
              published_to: vec![],
              catalog_path: None,
              created_at: "2026-04-01T00:00:00Z".to_string(),
              updated_at: "2026-04-01T00:00:00Z".to_string(),
          };
          let json = serde_json::to_string(&def).unwrap();
          assert!(!json.contains("operator_key_seed"));
          assert!(!json.contains("catalog_path"));
      }

      #[test]
      fn http_method_serializes_as_variant_name() {
          let get = serde_json::to_string(&HttpMethod::Get).unwrap();
          let post = serde_json::to_string(&HttpMethod::Post).unwrap();
          assert_eq!(get, "\"Get\"");
          assert_eq!(post, "\"Post\"");
      }

      #[test]
      fn dynamic_agent_source_variants_round_trip() {
          for src in [
              DynamicAgentSource::Catalog,
              DynamicAgentSource::UserCreated,
              DynamicAgentSource::Generated,
          ] {
              let json = serde_json::to_string(&src).unwrap();
              let back: DynamicAgentSource = serde_json::from_str(&json).unwrap();
              assert_eq!(src, back);
          }
      }
  }
  ```

- [ ] **Step 2.2** — Export from `crates/pap-agents/src/lib.rs`. Add the module declaration and pub use:

  ```rust
  pub mod dynamic;
  pub use dynamic::{DynamicAgentDef, DynamicAgentSource, HttpEndpointConfig, HttpMethod, is_safe_url};
  ```

- [ ] **Step 2.3** — Run all tests in the `dynamic` module:

  ```bash
  cargo test -p pap-agents -- dynamic::
  ```

  Expected output:

  ```
  test dynamic::tests::https_public_host_is_safe ... ok
  test dynamic::tests::http_scheme_rejected ... ok
  test dynamic::tests::ftp_scheme_rejected ... ok
  test dynamic::tests::no_scheme_rejected ... ok
  test dynamic::tests::localhost_rejected ... ok
  test dynamic::tests::loopback_ipv4_rejected ... ok
  test dynamic::tests::rfc1918_10_block_rejected ... ok
  test dynamic::tests::rfc1918_172_block_rejected ... ok
  test dynamic::tests::rfc1918_172_outside_block_allowed ... ok
  test dynamic::tests::rfc1918_192_168_rejected ... ok
  test dynamic::tests::link_local_169_254_rejected ... ok
  test dynamic::tests::ipv6_literal_rejected ... ok
  test dynamic::tests::bare_ipv4_public_rejected ... ok
  test dynamic::tests::dynamic_agent_def_serializes_and_deserializes ... ok
  test dynamic::tests::operator_key_seed_absent_from_json_when_none ... ok
  test dynamic::tests::http_method_serializes_as_variant_name ... ok
  test dynamic::tests::dynamic_agent_source_variants_round_trip ... ok

  test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured
  ```

- [ ] **Step 2.4** — Commit:

  ```bash
  git add crates/pap-agents/src/dynamic.rs crates/pap-agents/src/lib.rs
  git commit -m "feat(pap-agents): add DynamicAgentDef data model and URL safety validation"
  ```

---

## Task 3: DB migration — agents table

Files:
- Modify: `crates/papillon-shared/src/db/native.rs`
- Modify: `crates/papillon-shared/src/db/mod.rs` (DatabaseOps trait)

- [ ] **Step 3.1** — Append the agents table DDL to the existing `execute_batch` call in `NativeDatabase::migrate()` in `crates/papillon-shared/src/db/native.rs`. Add the following SQL block directly before the closing `"` of the `execute_batch` string (after the `idx_templates_enabled` index):

  ```sql
  CREATE TABLE IF NOT EXISTS agents (
      agent_did TEXT PRIMARY KEY,
      schema_version INTEGER NOT NULL DEFAULT 1,
      name TEXT NOT NULL,
      provider TEXT NOT NULL,
      description TEXT NOT NULL,
      action TEXT NOT NULL,
      object_types_json TEXT NOT NULL DEFAULT '[]',
      requires_disclosure_json TEXT NOT NULL DEFAULT '[]',
      returns_json TEXT NOT NULL DEFAULT '[]',
      endpoint_json TEXT,
      llm_instructions TEXT NOT NULL DEFAULT '',
      subagents_json TEXT NOT NULL DEFAULT '[]',
      source TEXT NOT NULL CHECK(source IN ('catalog','user_created','generated')),
      operator_key_seed BLOB NOT NULL,
      published_to_json TEXT NOT NULL DEFAULT '[]',
      catalog_path TEXT,
      removed_from_catalog INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
  );
  CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_catalog_path
      ON agents(catalog_path) WHERE catalog_path IS NOT NULL;
  CREATE INDEX IF NOT EXISTS idx_agents_action ON agents(action);
  CREATE INDEX IF NOT EXISTS idx_agents_source ON agents(source);
  ```

- [ ] **Step 3.2** — Add the four agent CRUD methods to the `DatabaseOps` trait in `crates/papillon-shared/src/db/mod.rs`.

  First, add the import at the top of the file (after `use crate::types::Template;`):

  ```rust
  use pap_agents::DynamicAgentDef;
  ```

  Then append to the trait body:

  ```rust
  // ── Agent Management ─────────────────────────────────────────────────

  /// Insert a new dynamic agent definition.
  fn insert_agent(&self, def: &DynamicAgentDef) -> Result<(), DbError>;

  /// Load all non-removed agent definitions.
  fn load_all_agents(&self) -> Result<Vec<DynamicAgentDef>, DbError>;

  /// Update an existing agent definition in-place (same agent_did).
  fn update_agent(&self, def: &DynamicAgentDef) -> Result<(), DbError>;

  /// Delete an agent by DID. Catalog agents should use removed_from_catalog instead.
  fn delete_agent(&self, agent_did: &str) -> Result<(), DbError>;
  ```

  Note: `papillon-shared/Cargo.toml` must gain `pap-agents = { workspace = true }` in `[dependencies]` for the import to resolve. Add that dependency before implementing the trait methods.

- [ ] **Step 3.3** — Implement all four methods on `NativeDatabase` in `crates/papillon-shared/src/db/native.rs`.

  Add at the top of the file:

  ```rust
  use pap_agents::{DynamicAgentDef, DynamicAgentSource, HttpEndpointConfig, HttpMethod};
  ```

  **`insert_agent` — full implementation:**

  ```rust
  fn insert_agent(&self, def: &DynamicAgentDef) -> Result<(), DbError> {
      let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

      let agent_did = def.agent_did.as_deref().ok_or_else(|| {
          DbError("insert_agent: agent_did must be set before insert".to_string())
      })?;
      let seed = def.operator_key_seed.ok_or_else(|| {
          DbError("insert_agent: operator_key_seed must be set before insert".to_string())
      })?;

      let object_types_json = serde_json::to_string(&def.object_types)
          .map_err(|e| DbError(format!("serialize object_types: {e}")))?;
      let requires_disclosure_json = serde_json::to_string(&def.requires_disclosure)
          .map_err(|e| DbError(format!("serialize requires_disclosure: {e}")))?;
      let returns_json = serde_json::to_string(&def.returns)
          .map_err(|e| DbError(format!("serialize returns: {e}")))?;
      let endpoint_json = def
          .endpoint
          .as_ref()
          .map(|e| serde_json::to_string(e))
          .transpose()
          .map_err(|e| DbError(format!("serialize endpoint: {e}")))?;
      let subagents_json = serde_json::to_string(&def.subagents)
          .map_err(|e| DbError(format!("serialize subagents: {e}")))?;
      let published_to_json = serde_json::to_string(&def.published_to)
          .map_err(|e| DbError(format!("serialize published_to: {e}")))?;
      let source_str = match def.source {
          DynamicAgentSource::Catalog => "catalog",
          DynamicAgentSource::UserCreated => "user_created",
          DynamicAgentSource::Generated => "generated",
      };

      conn.execute(
          "INSERT INTO agents (
              agent_did, schema_version, name, provider, description, action,
              object_types_json, requires_disclosure_json, returns_json,
              endpoint_json, llm_instructions, subagents_json, source,
              operator_key_seed, published_to_json, catalog_path,
              created_at, updated_at
          ) VALUES (
              ?1, ?2, ?3, ?4, ?5, ?6,
              ?7, ?8, ?9,
              ?10, ?11, ?12, ?13,
              ?14, ?15, ?16,
              ?17, ?18
          )",
          params![
              agent_did,
              def.schema_version,
              def.name,
              def.provider,
              def.description,
              def.action,
              object_types_json,
              requires_disclosure_json,
              returns_json,
              endpoint_json,
              def.llm_instructions,
              subagents_json,
              source_str,
              seed.as_slice(),
              published_to_json,
              def.catalog_path,
              def.created_at,
              def.updated_at,
          ],
      )
      .map_err(|e| DbError(format!("db insert agent: {e}")))?;

      Ok(())
  }
  ```

  **`load_all_agents` — full implementation (returns all non-removed agents):**

  ```rust
  fn load_all_agents(&self) -> Result<Vec<DynamicAgentDef>, DbError> {
      let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

      let mut stmt = conn
          .prepare(
              "SELECT agent_did, schema_version, name, provider, description, action,
                      object_types_json, requires_disclosure_json, returns_json,
                      endpoint_json, llm_instructions, subagents_json, source,
                      operator_key_seed, published_to_json, catalog_path,
                      created_at, updated_at
               FROM agents
               WHERE removed_from_catalog = 0
               ORDER BY name",
          )
          .map_err(|e| DbError(format!("db prepare: {e}")))?;

      let rows = stmt
          .query_map([], |row| {
              let source_str: String = row.get(12)?;
              let source = match source_str.as_str() {
                  "catalog" => DynamicAgentSource::Catalog,
                  "user_created" => DynamicAgentSource::UserCreated,
                  "generated" => DynamicAgentSource::Generated,
                  other => {
                      return Err(rusqlite::Error::FromSqlConversionFailure(
                          12,
                          rusqlite::types::Type::Text,
                          format!("unknown source: {other}").into(),
                      ))
                  }
              };

              let seed_blob: Vec<u8> = row.get(13)?;
              let seed_arr: [u8; 32] = seed_blob.try_into().map_err(|_| {
                  rusqlite::Error::FromSqlConversionFailure(
                      13,
                      rusqlite::types::Type::Blob,
                      "operator_key_seed must be 32 bytes".into(),
                  )
              })?;

              let endpoint_json: Option<String> = row.get(9)?;
              let endpoint = endpoint_json
                  .map(|j| {
                      serde_json::from_str::<HttpEndpointConfig>(&j).map_err(|e| {
                          rusqlite::Error::FromSqlConversionFailure(
                              9,
                              rusqlite::types::Type::Text,
                              Box::new(e),
                          )
                      })
                  })
                  .transpose()?;

              let parse_json_array = |idx: usize, raw: String| -> Result<Vec<String>, rusqlite::Error> {
                  serde_json::from_str::<Vec<String>>(&raw).map_err(|e| {
                      rusqlite::Error::FromSqlConversionFailure(idx, rusqlite::types::Type::Text, Box::new(e))
                  })
              };

              Ok(DynamicAgentDef {
                  agent_did: Some(row.get(0)?),
                  schema_version: row.get::<_, i64>(1)? as u32,
                  name: row.get(2)?,
                  provider: row.get(3)?,
                  description: row.get(4)?,
                  action: row.get(5)?,
                  object_types: parse_json_array(6, row.get(6)?)?,
                  requires_disclosure: parse_json_array(7, row.get(7)?)?,
                  returns: parse_json_array(8, row.get(8)?)?,
                  endpoint,
                  llm_instructions: row.get(10)?,
                  subagents: parse_json_array(11, row.get(11)?)?,
                  source,
                  operator_key_seed: Some(seed_arr),
                  published_to: parse_json_array(14, row.get(14)?)?,
                  catalog_path: row.get(15)?,
                  created_at: row.get(16)?,
                  updated_at: row.get(17)?,
              })
          })
          .map_err(|e| DbError(format!("db query: {e}")))?;

      let mut agents = Vec::new();
      for row in rows {
          agents.push(row.map_err(|e| DbError(format!("db row: {e}")))?);
      }
      Ok(agents)
  }
  ```

  **`update_agent` — implementation:**

  ```rust
  fn update_agent(&self, def: &DynamicAgentDef) -> Result<(), DbError> {
      let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

      let agent_did = def.agent_did.as_deref().ok_or_else(|| {
          DbError("update_agent: agent_did must be set".to_string())
      })?;

      let object_types_json = serde_json::to_string(&def.object_types)
          .map_err(|e| DbError(format!("serialize object_types: {e}")))?;
      let requires_disclosure_json = serde_json::to_string(&def.requires_disclosure)
          .map_err(|e| DbError(format!("serialize requires_disclosure: {e}")))?;
      let returns_json = serde_json::to_string(&def.returns)
          .map_err(|e| DbError(format!("serialize returns: {e}")))?;
      let endpoint_json = def
          .endpoint
          .as_ref()
          .map(|e| serde_json::to_string(e))
          .transpose()
          .map_err(|e| DbError(format!("serialize endpoint: {e}")))?;
      let subagents_json = serde_json::to_string(&def.subagents)
          .map_err(|e| DbError(format!("serialize subagents: {e}")))?;
      let published_to_json = serde_json::to_string(&def.published_to)
          .map_err(|e| DbError(format!("serialize published_to: {e}")))?;

      let rows_changed = conn
          .execute(
              "UPDATE agents SET
                  schema_version = ?1, name = ?2, provider = ?3,
                  description = ?4, action = ?5,
                  object_types_json = ?6, requires_disclosure_json = ?7,
                  returns_json = ?8, endpoint_json = ?9,
                  llm_instructions = ?10, subagents_json = ?11,
                  published_to_json = ?12, updated_at = ?13
               WHERE agent_did = ?14",
              params![
                  def.schema_version,
                  def.name,
                  def.provider,
                  def.description,
                  def.action,
                  object_types_json,
                  requires_disclosure_json,
                  returns_json,
                  endpoint_json,
                  def.llm_instructions,
                  subagents_json,
                  published_to_json,
                  def.updated_at,
                  agent_did,
              ],
          )
          .map_err(|e| DbError(format!("db update agent: {e}")))?;

      if rows_changed == 0 {
          return Err(DbError(format!("Agent not found: {agent_did}")));
      }
      Ok(())
  }
  ```

  **`delete_agent` — implementation:**

  ```rust
  fn delete_agent(&self, agent_did: &str) -> Result<(), DbError> {
      let conn = self.conn.lock().map_err(|e| DbError(e.to_string()))?;

      let rows_changed = conn
          .execute(
              "DELETE FROM agents WHERE agent_did = ?1",
              params![agent_did],
          )
          .map_err(|e| DbError(format!("db delete agent: {e}")))?;

      if rows_changed == 0 {
          return Err(DbError(format!("Agent not found: {agent_did}")));
      }
      Ok(())
  }
  ```

- [ ] **Step 3.4** — Write tests in the `#[cfg(test)] mod tests` block of `native.rs`. Add a helper and three test functions:

  ```rust
  fn sample_agent_def(agent_did: &str, catalog_path: Option<&str>) -> DynamicAgentDef {
      DynamicAgentDef {
          agent_did: Some(agent_did.to_string()),
          schema_version: 1,
          name: format!("Test Agent {agent_did}"),
          provider: "Test Provider".to_string(),
          description: "A test agent".to_string(),
          action: "schema:SearchAction".to_string(),
          object_types: vec!["schema:WebPage".to_string()],
          requires_disclosure: vec![],
          returns: vec!["schema:SearchResult".to_string()],
          endpoint: Some(HttpEndpointConfig {
              url_template: "https://api.example.com/search?q={query}".to_string(),
              method: HttpMethod::Get,
              headers: std::collections::HashMap::new(),
              body_template: None,
              response_jsonpath: "$.results[*]".to_string(),
              response_schema_type: "schema:SearchResult".to_string(),
          }),
          llm_instructions: "You are a search assistant.".to_string(),
          subagents: vec![],
          source: DynamicAgentSource::Catalog,
          operator_key_seed: Some([42u8; 32]),
          published_to: vec![],
          catalog_path: catalog_path.map(|s| s.to_string()),
          created_at: "2026-04-01T00:00:00Z".to_string(),
          updated_at: "2026-04-01T00:00:00Z".to_string(),
      }
  }

  #[test]
  fn insert_and_load_agent_round_trip() {
      let db = test_db();
      let def = sample_agent_def("did:key:zTestAgent1", Some("search/test.toml"));

      db.insert_agent(&def).unwrap();

      let agents = db.load_all_agents().unwrap();
      assert_eq!(agents.len(), 1);

      let loaded = &agents[0];
      assert_eq!(loaded.agent_did, def.agent_did);
      assert_eq!(loaded.name, def.name);
      assert_eq!(loaded.provider, def.provider);
      assert_eq!(loaded.action, def.action);
      assert_eq!(loaded.object_types, def.object_types);
      assert_eq!(loaded.returns, def.returns);
      assert_eq!(loaded.source, DynamicAgentSource::Catalog);
      assert_eq!(loaded.operator_key_seed, Some([42u8; 32]));
      assert_eq!(loaded.catalog_path, Some("search/test.toml".to_string()));
      assert!(loaded.endpoint.is_some());
      let ep = loaded.endpoint.as_ref().unwrap();
      assert_eq!(ep.url_template, "https://api.example.com/search?q={query}");
      assert_eq!(ep.method, HttpMethod::Get);
  }

  #[test]
  fn catalog_path_unique_constraint() {
      let db = test_db();
      let def1 = sample_agent_def("did:key:zAgent1", Some("search/test.toml"));
      let def2 = sample_agent_def("did:key:zAgent2", Some("search/test.toml")); // same path

      db.insert_agent(&def1).unwrap();
      // Second insert with same catalog_path must fail (UNIQUE INDEX)
      let result = db.insert_agent(&def2);
      assert!(result.is_err(), "duplicate catalog_path should be rejected");
  }

  #[test]
  fn load_agents_excludes_removed() {
      let db = test_db();
      let active = sample_agent_def("did:key:zActive", Some("search/active.toml"));
      db.insert_agent(&active).unwrap();

      // Mark as removed via raw SQL (simulates catalog removal detection)
      {
          let conn = db.conn.lock().unwrap();
          conn.execute(
              "UPDATE agents SET removed_from_catalog = 1 WHERE agent_did = ?1",
              params!["did:key:zActive"],
          )
          .unwrap();
      }

      let agents = db.load_all_agents().unwrap();
      assert_eq!(agents.len(), 0, "removed agents must be excluded from load_all_agents");
  }
  ```

- [ ] **Step 3.5** — Run the targeted tests:

  ```bash
  cargo test -p papillon-shared -- agents
  ```

  Expected output:

  ```
  test db::native::tests::insert_and_load_agent_round_trip ... ok
  test db::native::tests::catalog_path_unique_constraint ... ok
  test db::native::tests::load_agents_excludes_removed ... ok

  test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured
  ```

- [ ] **Step 3.6** — Commit:

  ```bash
  git add crates/papillon-shared/src/db/native.rs \
      crates/papillon-shared/src/db/mod.rs \
      crates/papillon-shared/Cargo.toml
  git commit -m "feat(papillon-shared): add agents table migration and CRUD ops"
  ```

---

## Completion Checklist

- [ ] `toml = "0.8"` in workspace deps and in `pap-agents/Cargo.toml`
- [ ] 13 `.rs` files deleted; only `web_reader.rs` + `mod.rs` remain under `crates/pap-agents/src/agents/`
- [ ] `build_agents()` registers exactly 1 handler (`Web Page Reader`)
- [ ] `build_agents_registers_all_standard` test asserts `len() == 1`
- [ ] `crates/pap-agents/src/dynamic.rs` created with full `DynamicAgentDef`, `HttpEndpointConfig`, `HttpMethod`, `DynamicAgentSource`, and `is_safe_url`
- [ ] All URL safety rejection cases covered by unit tests
- [ ] `agents` table DDL added to `NativeDatabase::migrate()` with `IF NOT EXISTS` guards
- [ ] `catalog_path` unique partial index created
- [ ] `DatabaseOps` trait extended with `insert_agent`, `load_all_agents`, `update_agent`, `delete_agent`
- [ ] All 4 methods implemented in `NativeDatabase` using `params![]`
- [ ] Round-trip, unique-constraint, and removed-exclusion tests pass
- [ ] Three commits made as specified above
