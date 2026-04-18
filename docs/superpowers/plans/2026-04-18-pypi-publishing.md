# PyPI Publishing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire up the existing `release-python.yml` workflow to actually publish `pap-protocol` to PyPI using OIDC Trusted Publishing (no stored secrets needed).

**Architecture:** PyPI Trusted Publishing uses GitHub's OIDC identity to mint short-lived tokens — no `PYPI_TOKEN` secret ever stored in the repo. The workflow already has the right shape; we need to update stale action SHAs to current versions, ensure the `pypi` GitHub Environment is documented (owner creates it in GitHub UI), fix the CHANGELOG for the first real release, and bump the version from `0.1.0` (currently "Not Yet Released") to `0.1.0` properly.

**Tech Stack:** GitHub Actions, `PyO3/maturin-action` (v1 tag), `pypa/gh-action-pypi-publish` (release/v1 floating tag), `actions/upload-artifact@v4`, `actions/download-artifact@v4`

---

## File Map

| File | Change |
|------|--------|
| `.github/workflows/release-python.yml` | Update action pins; add `attestations: true` to publish step |
| `crates/pap-python/CHANGELOG.md` | Promote `[Unreleased]` → `[0.1.0]` with today's date |
| `crates/pap-python/pyproject.toml` | Confirm version is `0.1.0` (already is — just verify) |
| `docs/pypi-publishing-setup.md` | One-time human checklist: PyPI project + trusted publisher setup |

---

## Task 1: Update action pins and fix trusted publisher config

**Files:**
- Modify: `.github/workflows/release-python.yml`

The current workflow uses a pinned SHA for `maturin-action` (`04ac600d…`) and a pinned SHA for `pypa/gh-action-pypi-publish` (`ed0c53931b…`). Both are fine as security practice, but the SHAs may be stale. We switch `maturin-action` to `v1` tag (PyO3 maintains this as a stable moving tag per their docs) and `gh-action-pypi-publish` to `release/v1` (pypa's recommended floating tag per PyPI's own docs). This also adds `attestations: true` to get provenance attestations for free.

- [ ] **Step 1: Open the workflow file and read the current content**

  Run:
  ```bash
  cat pap/.github/workflows/release-python.yml
  ```
  Expected: the 213-line file from context above.

- [ ] **Step 2: Update the `build-wheels` job — replace maturin-action SHA pin with v1 tag**

  In `.github/workflows/release-python.yml`, find:
  ```yaml
        - name: Build wheels
          uses: PyO3/maturin-action@04ac600d27cdf7a9a280dadf7147097c42b757ad  # v1
  ```
  Replace with:
  ```yaml
        - name: Build wheels
          uses: PyO3/maturin-action@v1
  ```

- [ ] **Step 3: Update the `build-sdist` job — same maturin-action pin**

  Find:
  ```yaml
        - name: Build sdist
          uses: PyO3/maturin-action@04ac600d27cdf7a9a280dadf7147097c42b757ad  # v1
  ```
  Replace with:
  ```yaml
        - name: Build sdist
          uses: PyO3/maturin-action@v1
  ```

- [ ] **Step 4: Update `publish-pypi` job — replace pypi-publish SHA pin with release/v1, add attestations**

  Find:
  ```yaml
        - name: Publish to PyPI
          uses: pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e  # release/v1
          with:
            packages-dir: dist/
  ```
  Replace with:
  ```yaml
        - name: Publish to PyPI
          uses: pypa/gh-action-pypi-publish@release/v1
          with:
            packages-dir: dist/
            attestations: true
  ```

- [ ] **Step 5: Verify the full `publish-pypi` job has all required trusted-publisher pieces**

  The job block should look exactly like this after edits:
  ```yaml
    publish-pypi:
      name: Publish to PyPI
      needs: [validate, build-wheels, build-sdist]
      if: github.ref_type == 'tag' && !inputs.dry_run
      runs-on: ubuntu-latest
      environment:
        name: pypi
        url: https://pypi.org/project/pap-protocol/${{ needs.validate.outputs.version }}/
      permissions:
        id-token: write
      steps:
        - name: Download all artifacts
          uses: actions/download-artifact@v4
          with:
            path: dist/
            merge-multiple: true

        - name: List artifacts for publishing
          run: ls -lh dist/

        - name: Publish to PyPI
          uses: pypa/gh-action-pypi-publish@release/v1
          with:
            packages-dir: dist/
            attestations: true
  ```
  The three required pieces for trusted publishing are all present:
  - `environment: pypi` ✓
  - `permissions: id-token: write` ✓
  - No `password:` / no `PYPI_TOKEN` secret ✓

- [ ] **Step 6: Commit**

  ```bash
  cd pap
  git add .github/workflows/release-python.yml
  git commit -m "ci(python): update action pins to current stable tags, add attestations"
  ```

---

## Task 2: Fix CHANGELOG for first real release

**Files:**
- Modify: `crates/pap-python/CHANGELOG.md`

The changelog has `[0.1.0] - Not Yet Released`. The validate step in the workflow parses this file with an awk script keyed on the version number. We need a properly dated entry.

- [ ] **Step 1: Open the changelog**

  ```bash
  cat pap/crates/pap-python/CHANGELOG.md
  ```

- [ ] **Step 2: Replace the placeholder release date**

  Find:
  ```markdown
  ## [0.1.0] - Not Yet Released
  ```
  Replace with:
  ```markdown
  ## [0.1.0] - 2026-04-18
  ```

- [ ] **Step 3: Move the Unreleased items into the 0.1.0 section**

  The `[Unreleased]` section contains additions/changes/fixes that happened since the 0.1.0 feature set was written. Merge them under `[0.1.0]`. The final file should look like:

  ```markdown
  # Changelog - PAP Python SDK

  All notable changes to the Python SDK will be documented in this file.

  ## [Unreleased]

  ## [0.1.0] - 2026-04-18

  ### Added
  - Initial Python bindings for PAP protocol
  - Complete key management (PrincipalKeypair, SessionKeypair)
  - Mandate issuance and delegation
  - Scope and disclosure constraints
  - Selective disclosure JWT (SD-JWT)
  - Marketplace registry with query API
  - HTTP transport client (blocking API)
  - Transaction receipts with co-signing
  - Comprehensive test suite (511 lines, 50+ tests)
  - Maturin build system with abi3 support
  - Comprehensive README with API reference and examples
  - Python SDK status documentation
  - Type hints in docstrings

  ### Changed
  - **SECURITY:** Upgraded pyo3 from 0.22.6 to 0.24+ (fixes RUSTSEC-2025-0020)
  - Migrated all deprecated PyO3 0.24 APIs (`get_type_bound` → `get_type`)
  - Improved error messages in exception hierarchy

  ### Fixed
  - All compiler warnings eliminated (5 → 0)
  - PyO3 buffer overflow vulnerability patched

  ### Security
  - Ed25519 signatures for all operations
  - Memory-safe (PyO3 guarantees)
  - No secret key export (security by design)

  ---

  **Note:** This project follows [Semantic Versioning](https://semver.org/).
  ```

- [ ] **Step 4: Verify awk changelog extraction works**

  The workflow uses this awk command to extract release notes:
  ```bash
  VERSION="0.1.0"
  awk "/^## \[${VERSION}\]/{found=1; next} /^## \[/{if(found) exit} found{print}" \
    pap/crates/pap-python/CHANGELOG.md
  ```
  Expected output: all the lines between `## [0.1.0]` and the next `## [` (empty `[Unreleased]`). Should print the Added/Changed/Fixed/Security sections.

- [ ] **Step 5: Commit**

  ```bash
  cd pap
  git add crates/pap-python/CHANGELOG.md
  git commit -m "docs(python): prepare CHANGELOG for 0.1.0 release"
  ```

---

## Task 3: Write the one-time human setup checklist

**Files:**
- Create: `docs/pypi-publishing-setup.md`

This is a reference doc so you (or anyone on the team) can do the one-time PyPI + GitHub configuration without having to remember all the steps.

- [ ] **Step 1: Create the doc**

  ```bash
  cat > pap/docs/pypi-publishing-setup.md << 'EOF'
  # PyPI Publishing: One-Time Setup Checklist

  The GitHub Actions workflow (`release-python.yml`) uses **PyPI Trusted Publishing**
  (OIDC). No API tokens or secrets are stored in the repo.

  ## 1. Create the PyPI project (first publish only)

  PyPI trusted publishing requires the project to already exist **or** you can
  create a "pending publisher" before the first upload.

  **Option A — Pending publisher (recommended for first publish):**
  1. Log in to https://pypi.org
  2. Go to **Your projects** → **Publishing** (or https://pypi.org/manage/account/publishing/)
  3. Under **Add a new pending publisher**, fill in:
     - **PyPI project name:** `pap-protocol`
     - **Owner:** `Baur-Software`
     - **Repository name:** `pap`
     - **Workflow filename:** `release-python.yml`
     - **Environment name:** `pypi`
  4. Click **Add**.

  **Option B — After first manual upload:** Create the project via `twine` or
  the PyPI web UI, then add a trusted publisher (same fields as above) under
  the project's Publishing settings.

  ## 2. Create the `pypi` GitHub Environment

  1. Go to the repo: **Settings → Environments → New environment**
  2. Name it exactly `pypi` (case-sensitive — must match `release-python.yml`)
  3. (Optional but recommended) Add a **deployment protection rule**:
     - Required reviewers: add yourself or the release team
     - This means a human must approve the PyPI publish step for every release
  4. No environment secrets needed — OIDC handles auth.

  ## 3. Tag and release

  ```bash
  # Make sure pyproject.toml version matches the tag
  # crates/pap-python/pyproject.toml: version = "0.1.0"

  git tag python-v0.1.0
  git push origin python-v0.1.0
  ```

  The workflow triggers on `python-v*` tags. It will:
  1. Validate that the tag version matches `pyproject.toml`
  2. Build wheels for: Linux x86_64 (glibc + musl), Linux aarch64, macOS universal2, Windows x64
  3. Build an sdist
  4. Create a GitHub Release with changelog notes
  5. Publish everything to PyPI via OIDC (requires approval if you set a protection rule)

  ## 4. Dry run (test without publishing)

  Trigger the workflow manually via GitHub UI:
  - Go to **Actions → Release Python SDK → Run workflow**
  - Check **"Build wheels without publishing"**

  This runs all build steps but skips the PyPI publish and GitHub Release steps.

  ## 5. Verify

  After tagging:
  - Check https://pypi.org/project/pap-protocol/
  - Test install: `pip install pap-protocol==0.1.0`
  EOF
  ```

- [ ] **Step 2: Commit**

  ```bash
  cd pap
  git add docs/pypi-publishing-setup.md
  git commit -m "docs: add PyPI trusted publishing setup checklist"
  ```

---

## Task 4: Smoke-test the workflow locally (dry run via `act` or manual trigger)

**Files:** None — this is a validation step only.

This step verifies the YAML is syntactically valid before pushing the tag.

- [ ] **Step 1: Validate the workflow YAML syntax**

  ```bash
  cd pap
  python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release-python.yml'))" \
    && echo "YAML valid" || echo "YAML INVALID — fix before pushing"
  ```
  Expected: `YAML valid`

- [ ] **Step 2: Check that `pyproject.toml` version is exactly `0.1.0`**

  ```bash
  python3 -c "
  import re
  with open('pap/crates/pap-python/pyproject.toml') as f:
      content = f.read()
  match = re.search(r'^version\s*=\s*\"(.+?)\"', content, re.MULTILINE)
  print('pyproject.toml version:', match.group(1))
  "
  ```
  Expected: `pyproject.toml version: 0.1.0`

- [ ] **Step 3: Verify changelog extraction for the validate step**

  ```bash
  VERSION="0.1.0"
  awk "/^## \[${VERSION}\]/{found=1; next} /^## \[/{if(found) exit} found{print}" \
    pap/crates/pap-python/CHANGELOG.md | head -5
  ```
  Expected: first lines of the `[0.1.0]` release notes (non-empty output).

- [ ] **Step 4: Final commit if any fixups were needed, then push the branch**

  ```bash
  cd pap
  git status
  git push origin HEAD
  ```

---

## Self-Review

### Spec coverage
- ✅ Workflow updated to use latest action tags (Tasks 1)
- ✅ OIDC / Trusted Publishing already present in the existing workflow — just ensured it's correctly wired (`id-token: write`, `environment: pypi`, no stored secrets)
- ✅ `attestations: true` added for supply-chain provenance
- ✅ CHANGELOG prepared for first publish (Task 2)
- ✅ Human setup steps documented (Task 3)
- ✅ Validation smoke-test (Task 4)

### What is NOT in scope (YAGNI)
- TestPyPI publishing: Not requested; add later if needed
- Version bumping automation: The team bumps `pyproject.toml` manually before tagging
- Automatic CHANGELOG generation: Not requested
