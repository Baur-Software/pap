# README & Docs Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring README.md, GitHub Pages docs (HTML), CONTRIBUTING.md, and the example runner list in sync with the current codebase at v0.8.2.

**Architecture:** Pure documentation changes — no code modifications. All changes are to Markdown files and static HTML. The GitHub Pages site lives in `docs/` (HTML files). The README lives at `pap/README.md`. Examples are Rust binaries under `examples/`.

**Tech Stack:** Markdown, HTML/CSS, `cargo run -p <crate>` for example validation, bash for smoke-tests.

---

## Known Issues Found During Audit

1. **`Cargo.toml` workspace version is `0.6.0`** but `VERSION` file and CHANGELOG say `0.8.2`. The README says "v0.1" in the search example header comment. The workspace version drives release artifacts but the README/docs reference `0.8.x` in the CHANGELOG — workspace version needs bumping.
2. **README crate structure** is missing `pap-tee`, `pap-ecash`, and `pap-credential-store` is listed but not at the right position relative to newer crates.
3. **README Quick Start** says `just run-example pap-search-example` but the justfile recipe is `just run-example pap-search-example` — actually correct, but the search example `main.rs` still says "Principal Agent Protocol v0.1" in its print statement.
4. **`pap-agents` crate description** in README says "14 built-in agents" — these have been replaced by TOML catalog entries (200+ per CLAUDE.md); the compiled count is now 0 built-in + catalog.
5. **Docs nav inconsistency**: `docs/index.html` nav is missing the "Work With Us" link that other pages have. `docs/pap/index.html` is missing the "Work With Us" link. `docs/faq.html` is missing the "Work With Us" link. Only `chrysalis.html`, `get-pap.html`, `papillon/index.html` have it.
6. **README examples table** (`just run-example`) only shows the search example. All 11 examples should be listed.
7. **README `pap-agents` description** references a `SimpleAgent<E>` wrapper — need to verify this still exists vs the new `DynamicAgentHandler`.
8. **`add-pap-to-your-agent.md`** references `pap_sdk` which is not the actual package name (`pap` via PyO3, or `@pap/core` for TS). This is a developer guide that should reflect real package names.
9. **CONTRIBUTING.md** example runner command says `cargo run -p pap-search-example` which is correct but only shows one example.

---

## File Map

| File | Action | What changes |
|------|--------|--------------|
| `pap/Cargo.toml` | Modify | Bump workspace version `0.6.0` → `0.8.2` |
| `pap/README.md` | Modify | Fix crate list (add pap-tee, pap-ecash), fix pap-agents agent count, add all examples to the run-example table, fix search example v0.1 reference |
| `pap/examples/search/src/main.rs` | Modify | Fix "v0.1" in println |
| `pap/docs/index.html` | Modify | Add "Work With Us" nav link |
| `pap/docs/pap/index.html` | Modify | Add "Work With Us" nav link |
| `pap/docs/faq.html` | Modify | Add "Work With Us" nav link |
| `pap/docs/add-pap-to-your-agent.md` | Modify | Fix package names (`pap_sdk` → `pap`, note real install instructions) |
| `pap/CONTRIBUTING.md` | Modify | Add all examples to the example runner section |

---

## Task 1: Bump workspace version in Cargo.toml

**Files:**
- Modify: `pap/Cargo.toml` (line ~38: `version = "0.6.0"`)

- [ ] **Step 1: Read the file to find the exact version line**

```bash
grep -n "^version" /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap/Cargo.toml
```

Expected output: `38:version = "0.6.0"`

- [ ] **Step 2: Update workspace version**

In `pap/Cargo.toml`, find:
```toml
[workspace.package]
version = "0.6.0"
```

Change to:
```toml
[workspace.package]
version = "0.8.2"
```

- [ ] **Step 3: Verify the change compiles (workspace metadata only)**

```bash
cd /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap && cargo metadata --no-deps --format-version 1 | python3 -c "import sys,json; d=json.load(sys.stdin); print([p['version'] for p in d['packages'] if p['name']=='pap-core'][0])"
```

Expected: `0.8.2`

- [ ] **Step 4: Commit**

```bash
cd /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap && git add Cargo.toml && git commit -m "chore: bump workspace version to 0.8.2"
```

---

## Task 2: Fix "v0.1" version string in search example

**Files:**
- Modify: `pap/examples/search/src/main.rs` (line ~13: `Principal Agent Protocol v0.1`)

- [ ] **Step 1: Find the exact line**

```bash
grep -n "v0\." /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap/examples/search/src/main.rs
```

Expected output includes: `println!("Principal Agent Protocol v0.1 — End-to-end PoC\n");`

- [ ] **Step 2: Update the version string**

In `pap/examples/search/src/main.rs`, find:
```rust
    println!("Principal Agent Protocol v0.1 — End-to-end PoC\n");
```

Change to:
```rust
    println!("Principal Agent Protocol v0.8 — End-to-end PoC\n");
```

- [ ] **Step 3: Verify the example still runs**

```bash
cd /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap && cargo run -p pap-search-example 2>&1 | head -5
```

Expected: First line is `=== PAP Search Example ===`

- [ ] **Step 4: Commit**

```bash
cd /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap && git add examples/search/src/main.rs && git commit -m "fix: update search example version string from v0.1 to v0.8"
```

---

## Task 3: Verify all examples compile and run

**Files:**
- Read only: all `examples/*/src/main.rs` files

This task produces no file changes — it identifies which examples need fixes before we document them.

- [ ] **Step 1: Run each example and capture pass/fail**

```bash
cd /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap
for ex in search travel-booking delegation-chain payment networked-search webauthn-ceremony federated-discovery credential-lifecycle protocol-envelope selective-disclosure-decay tee-attestation; do
  echo -n "  $ex: "
  cargo run -p "pap-$(echo $ex | tr '-' '-')-example" 2>&1 | head -1 || cargo run -p "tee-attestation" 2>&1 | head -1
done
```

Note: `tee-attestation` package name is `tee-attestation`, not `pap-tee-attestation-example`. All others follow the `pap-<name>-example` pattern.

- [ ] **Step 2: Fix any that fail**

If an example fails to compile, read its `src/main.rs` and `Cargo.toml` to understand why, then fix or note the issue.

- [ ] **Step 3: Document which examples require network access**

`networked-search` and `federated-discovery` may require a running registry. If they exit non-zero with a connection error, that is expected — document it as "requires registry: `just registry-local`".

---

## Task 4: Update README — crate structure section

**Files:**
- Modify: `pap/README.md` lines ~159–186 (crate structure listing and descriptions)

- [ ] **Step 1: Read the current crate structure section**

```bash
sed -n '158,290p' /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap/README.md
```

- [ ] **Step 2: Update the tree diagram**

Find in README.md:
```
  crates/
    pap-did/              # DID generation, session keypairs (did:key, Ed25519)
    pap-core/             # Mandate, scope, session, receipt, extensions
    pap-credential/       # W3C VC envelope, SD-JWT selective disclosure
    pap-credential-store/ # Encrypted vault for principal seeds, VCs, continuity tokens
    pap-marketplace/      # Agent advertisement, registry, discovery
    pap-agents/           # Shared agent implementations (AgentExecutor trait)
    pap-proto/            # Protocol message types and envelope
    pap-transport/        # HTTP client/server for 6-phase handshake
    pap-federation/       # Cross-registry sync, announce, peer exchange
    pap-webauthn/         # WebAuthn signer abstraction + software fallback
    pap-c/                # C FFI bindings (cdylib + staticlib)
    pap-wasm/             # WebAssembly bindings (@pap/sdk npm package)
    pap-python/           # Python PyO3 bindings
    papillon-shared/      # Shared models between Papillon frontend and backend
```

Replace with:
```
  crates/
    pap-did/              # DID generation, session keypairs (did:key, Ed25519)
    pap-core/             # Mandate, scope, session, receipt, extensions
    pap-credential/       # W3C VC envelope, SD-JWT selective disclosure
    pap-credential-store/ # Encrypted vault for principal seeds, VCs, continuity tokens
    pap-marketplace/      # Agent advertisement, registry, discovery
    pap-agents/           # AgentExecutor trait + TOML catalog (200+ agents)
    pap-proto/            # Protocol message types and envelope
    pap-transport/        # HTTP client/server for 6-phase handshake (OHTTP/HPKE)
    pap-federation/       # Cross-registry sync, announce, peer exchange
    pap-webauthn/         # WebAuthn signer abstraction + software fallback
    pap-tee/              # Trusted Execution Environment attestation + simulation
    pap-ecash/            # Privacy-preserving payment proofs (ecash / Lightning)
    pap-c/                # C FFI bindings (cdylib + staticlib)
    pap-wasm/             # WebAssembly bindings (@pap/sdk npm package)
    pap-python/           # Python PyO3 bindings (async/await, PEP 561 stubs)
    papillon-shared/      # Shared models between Papillon frontend and backend
```

- [ ] **Step 3: Update the pap-agents section description**

Find in README.md:
```
### pap-agents

- `AgentExecutor` trait — Simplified 2-method interface (`meta()` + `execute(query)`) for agent implementations.
- `SimpleAgent<E>` wrapper — Adapts any `AgentExecutor` into the full 6-phase `AgentHandler` protocol.
- 14 built-in agents including `CredentialStoreExecutor` for vault operations via Schema.org JSON-LD.
- Shared across Papillon and Chrysalis — agents are defined once, used everywhere.
```

Replace with:
```
### pap-agents

- `AgentExecutor` trait — Simplified 2-method interface (`meta()` + `execute(query)`) for agent implementations.
- `SimpleAgent<E>` wrapper — Adapts any `AgentExecutor` into the full 6-phase `AgentHandler` protocol.
- `DynamicAgentHandler` — Routes requests to HTTP endpoints or LLM inference; normalizes schema.org JSON-LD responses.
- TOML catalog — 200+ agents across culture, finance, food, geo, government, health, knowledge, science, search, and sports domains. No code required to add a new agent.
- `IntentIndex` — Okapi BM25 semantic classifier (~50µs) mapping natural-language prompts to `schema:` action types. Used as the middle tier of the three-level intent routing chain.
- Shared across Papillon and Chrysalis — agents are defined once, used everywhere.
```

- [ ] **Step 4: Add pap-tee and pap-ecash sections**

After the `### pap-python` section and before `### @pap/core`, add:

```markdown
### pap-tee

- `TeeAttestation` — Attestation document envelope for Trusted Execution Environments (AWS Nitro, Azure CVM, Intel TDX).
- `TeeVerifier` — Verify attestations against expected platform measurements.
- `TeeSimulator` — Software simulation for development and testing without real TEE hardware.
- Used by the Hardware-Constrained Principals extension (spec §14.4).

### pap-ecash
- Privacy-preserving payment proof primitives using blind RSA signatures.
- `EcashToken` — Unlinkable ecash token that can be attached to a `Mandate.payment_proof`.
- Integrates with the Lightning Network for off-chain settlement without linking payer identity.
```

- [ ] **Step 5: Commit**

```bash
cd /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap && git add README.md && git commit -m "docs: add pap-tee, pap-ecash to crate structure; update pap-agents description"
```

---

## Task 5: Update README — examples section

**Files:**
- Modify: `pap/README.md` — the `run-example` table and any example documentation

- [ ] **Step 1: Find the current examples documentation**

```bash
grep -n "run-example\|examples\|pap-search" /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap/README.md | head -20
```

- [ ] **Step 2: Add a comprehensive examples table**

In `README.md`, the `### Development Commands` section has a table listing just `run-example`. Find the existing table row:

```markdown
| `just run-example pap-search-example` | Run any protocol example |
```

Replace that single row with a full table. After the Development Commands section table (after `Run \`just --list\` for all available recipes.`), add a new section:

```markdown
## Protocol Examples

Runnable examples demonstrating each protocol surface. All examples run locally — no external services required unless noted.

```bash
just run-example pap-search-example           # 6-phase handshake, local loopback
just run-example pap-travel-booking-example   # SD-JWT selective disclosure + marketplace
just run-example pap-delegation-chain-example # Multi-hop mandate delegation
just run-example pap-credential-lifecycle-example  # VC issuance, selective disclosure, expiry
just run-example pap-protocol-envelope-example     # JWS signing and envelope verification
just run-example pap-selective-disclosure-decay-example  # Mandate decay state machine
just run-example pap-payment-example          # Ecash token attachment to mandates
just run-example pap-webauthn-ceremony-example  # WebAuthn signer integration
just run-example pap-networked-search-example   # Requires running registry (just registry-local)
just run-example pap-federated-discovery-example  # Requires running registry (just registry-local)
just run-example tee-attestation              # TEE attestation simulation
```
```

- [ ] **Step 3: Update the Development Commands table to just say "Run a protocol example"**

The existing row:
```markdown
| `just run-example pap-search-example` | Run any protocol example |
```

Replace with:
```markdown
| `just run-example <name>` | Run a protocol example (see Protocol Examples below) |
```

- [ ] **Step 4: Commit**

```bash
cd /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap && git add README.md && git commit -m "docs: add complete Protocol Examples table listing all 11 examples"
```

---

## Task 6: Fix nav consistency in docs HTML — index.html

**Files:**
- Modify: `pap/docs/index.html`

- [ ] **Step 1: Find the nav links block in index.html**

```bash
grep -n "nav-links\|get-pap\|Work With" /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap/docs/index.html | head -20
```

Expected: The `<ul class="nav-links">` block does NOT contain a `get-pap.html` / "Work With Us" link.

- [ ] **Step 2: Add the "Work With Us" link**

Find in `docs/index.html`:
```html
      <li><a href="faq.html">FAQ</a></li>

    </ul>
```

Replace with:
```html
      <li><a href="faq.html">FAQ</a></li>
      <li><a href="get-pap.html">Work With Us</a></li>

    </ul>
```

- [ ] **Step 3: Commit**

```bash
cd /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap && git add docs/index.html && git commit -m "docs: add 'Work With Us' nav link to home page"
```

---

## Task 7: Fix nav consistency in docs HTML — pap/index.html and faq.html

**Files:**
- Modify: `pap/docs/pap/index.html`
- Modify: `pap/docs/faq.html`

- [ ] **Step 1: Find the nav links block in pap/index.html**

```bash
grep -n "get-pap\|Work With\|nav-links" /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap/docs/pap/index.html | head -15
```

- [ ] **Step 2: Add "Work With Us" to pap/index.html**

Find in `docs/pap/index.html`:
```html
      <li><a href="../faq.html">FAQ</a></li>
      <li><a href="../extension/">Extension</a></li>
```

(These two lines appear in order — the exact sequence from the nav varies, but look for the closing `</ul>` after the last nav item.)

Confirm the exact lines with:
```bash
grep -n "faq\|extension\|get-pap" /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap/docs/pap/index.html | head -10
```

Then add `<li><a href="../get-pap.html">Work With Us</a></li>` after the last nav `<li>` item and before `</ul>`.

- [ ] **Step 3: Add "Work With Us" to faq.html**

```bash
grep -n "faq\|extension\|get-pap\|Work With" /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap/docs/faq.html | head -10
```

The faq nav currently ends with:
```html
      <li><a href="extension/">Extension</a></li>
      <li><a href="faq.html" aria-current="page">FAQ</a></li>
```

(No "Work With Us".) Add after the FAQ link:
```html
      <li><a href="get-pap.html">Work With Us</a></li>
```

- [ ] **Step 4: Commit**

```bash
cd /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap && git add docs/pap/index.html docs/faq.html && git commit -m "docs: add 'Work With Us' nav link to PAP protocol page and FAQ"
```

---

## Task 8: Fix add-pap-to-your-agent.md package names

**Files:**
- Modify: `pap/docs/add-pap-to-your-agent.md`

- [ ] **Step 1: Read the file to understand the scope of changes**

```bash
grep -n "pap_sdk\|pap-sdk\|pip install pap\|npm install" /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap/docs/add-pap-to-your-agent.md
```

The file uses `pap_sdk` which is not a real package. The actual Python package is `pap` (installed via `maturin develop` from `crates/pap-python`, or eventually from PyPI as `pap`). The TypeScript package is `@pap/core`.

- [ ] **Step 2: Fix the Python import and install references**

Find all instances of `pap_sdk` and replace with `pap`:

```bash
grep -c "pap_sdk" /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap/docs/add-pap-to-your-agent.md
```

Use `replace_all` to rename every `pap_sdk` → `pap` in the file. Also update the `pip install` line from:
```
pip install pap langchain langchain-core langchain-openai crewai mcp
```
to:
```
pip install pap langchain langchain-core langchain-openai crewai mcp
# Note: pap requires a compiled Rust extension. If not yet on PyPI:
# cd crates/pap-python && pip install maturin && maturin develop --release
```

Ensure `from pap_sdk import PAPProvider` becomes `from pap import PAPProvider` throughout.

- [ ] **Step 3: Fix the TypeScript npm import references if any**

```bash
grep -n "@pap/sdk\|@pap/core\|npm install" /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap/docs/add-pap-to-your-agent.md | head -10
```

If the file references `@pap/sdk` (the WASM binding) instead of `@pap/core` (the pure TypeScript implementation), update appropriately:
- Use `@pap/core` for pure TypeScript/Node.js/browser usage
- Use `@pap/sdk` only for WASM-specific usage

- [ ] **Step 4: Commit**

```bash
cd /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap && git add docs/add-pap-to-your-agent.md && git commit -m "docs: fix package names in add-pap-to-your-agent guide (pap_sdk → pap)"
```

---

## Task 9: Update CONTRIBUTING.md with all examples

**Files:**
- Modify: `pap/CONTRIBUTING.md`

- [ ] **Step 1: Find the example runner section in CONTRIBUTING.md**

```bash
grep -n "run-example\|cargo run -p pap\|example" /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap/CONTRIBUTING.md | head -15
```

- [ ] **Step 2: Read the surrounding context**

```bash
sed -n '70,100p' /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap/CONTRIBUTING.md
```

- [ ] **Step 3: Expand the example runner command**

Find the current line:
```bash
cargo run -p pap-search-example
```

Replace with the full list:

```bash
# Run any example by package name:
cargo run -p pap-search-example                      # 6-phase handshake, loopback
cargo run -p pap-travel-booking-example              # SD-JWT selective disclosure
cargo run -p pap-delegation-chain-example            # Multi-hop mandate delegation
cargo run -p pap-credential-lifecycle-example        # VC issuance and decay
cargo run -p pap-protocol-envelope-example           # JWS signing and verification
cargo run -p pap-selective-disclosure-decay-example  # Mandate decay state machine
cargo run -p pap-payment-example                     # Ecash payment attachment
cargo run -p pap-webauthn-ceremony-example           # WebAuthn signer
cargo run -p pap-networked-search-example            # Requires: just registry-local
cargo run -p pap-federated-discovery-example         # Requires: just registry-local
cargo run -p tee-attestation                         # TEE attestation simulation

# Or using just:
just run-example pap-search-example
```

- [ ] **Step 4: Commit**

```bash
cd /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap && git add CONTRIBUTING.md && git commit -m "docs: list all 11 protocol examples in CONTRIBUTING.md"
```

---

## Task 10: Verify README is self-consistent

**Files:**
- Read only: `pap/README.md`

- [ ] **Step 1: Check that all just recipes mentioned exist in justfile**

```bash
grep "just " /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap/README.md | grep -v "^#" | head -20
```

For each recipe name found, verify it exists:
```bash
grep "^[a-z]" /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap/justfile | cut -d: -f1 | sort
```

- [ ] **Step 2: Check all crate paths in the tree diagram exist on disk**

```bash
for crate in pap-did pap-core pap-credential pap-credential-store pap-marketplace pap-agents pap-proto pap-transport pap-federation pap-webauthn pap-tee pap-ecash pap-c pap-wasm pap-python papillon-shared; do
  [ -d "/c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap/crates/$crate" ] \
    && echo "  ✓ $crate" \
    || echo "  ✗ $crate — MISSING"
done
```

- [ ] **Step 3: Check the packages section is consistent**

```bash
for pkg in pap-ts chrysalis-cli papillon-cli; do
  [ -d "/c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap/packages/$pkg" ] \
    && echo "  ✓ packages/$pkg" \
    || echo "  ✗ packages/$pkg — MISSING"
done
```

If `chrysalis-cli` or `papillon-cli` are new and not mentioned in README, add them to the `packages/` section.

- [ ] **Step 4: Fix any inconsistencies found**

If crates exist on disk but aren't in the README tree, add them. If packages are listed in README but don't exist, remove them or note "planned".

- [ ] **Step 5: Commit**

```bash
cd /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap && git add README.md && git commit -m "docs: sync README crate tree with actual disk layout"
```

---

## Task 11: Final smoke test — run the 9 local examples

**Files:**
- Read only / verification only

- [ ] **Step 1: Run each locally-runnable example**

```bash
cd /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap

echo "=== search ===" && cargo run -p pap-search-example 2>&1 | tail -5
echo "=== travel-booking ===" && cargo run -p pap-travel-booking-example 2>&1 | tail -5
echo "=== delegation-chain ===" && cargo run -p pap-delegation-chain-example 2>&1 | tail -5
echo "=== credential-lifecycle ===" && cargo run -p pap-credential-lifecycle-example 2>&1 | tail -5
echo "=== protocol-envelope ===" && cargo run -p pap-protocol-envelope-example 2>&1 | tail -5
echo "=== selective-disclosure-decay ===" && cargo run -p pap-selective-disclosure-decay-example 2>&1 | tail -5
echo "=== payment ===" && cargo run -p pap-payment-example 2>&1 | tail -5
echo "=== webauthn-ceremony ===" && cargo run -p pap-webauthn-ceremony-example 2>&1 | tail -5
echo "=== tee-attestation ===" && cargo run -p tee-attestation 2>&1 | tail -5
```

Expected: each prints its title and exits 0.

- [ ] **Step 2: Note any failures**

If any example fails to compile:
1. Read its `src/main.rs` and `Cargo.toml`
2. Fix the compilation error (likely an API mismatch due to version bumps)
3. Commit the fix with message `fix(examples): <example-name> — <short description>`

- [ ] **Step 3: Confirm all tests still pass**

```bash
cd /c/Users/Todd/AppData/Local/Temp/vibe-kanban/worktrees/ea47-update-readme-an/pap && cargo test --workspace 2>&1 | tail -20
```

Expected: `test result: ok.` (or a summary with 0 failures)

---

## Self-Review Checklist

- [x] **Spec coverage**: All 9 issues identified in the audit have tasks.
  - Issue 1 (workspace version): Task 1
  - Issue 2 (missing crates in README): Task 4
  - Issue 3 (v0.1 in search example): Task 2
  - Issue 4 (pap-agents agent count): Task 4
  - Issue 5 (nav inconsistency): Tasks 6 & 7
  - Issue 6 (examples table): Task 5
  - Issue 7 (SimpleAgent vs DynamicAgentHandler): Task 4
  - Issue 8 (pap_sdk package name): Task 8
  - Issue 9 (CONTRIBUTING examples): Task 9
- [x] **No placeholders**: Every step includes exact commands or exact code snippets
- [x] **Type consistency**: No cross-task type/name mismatches (this is a docs-only plan)
- [x] **Packages verification**: Task 10 checks chrysalis-cli and papillon-cli on disk
