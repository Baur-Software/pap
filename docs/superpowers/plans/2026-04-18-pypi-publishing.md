# PyPI Publishing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Wire up the existing `release-python.yml` workflow to publish `pap-protocol` to PyPI using OIDC Trusted Publishing (no stored secrets needed).

**Architecture:** PyPI Trusted Publishing uses GitHub's OIDC identity to mint short-lived tokens — no `PYPI_TOKEN` ever stored. Version is read from a single source: `Cargo.toml` `[workspace.package]`. The workflow already has the right shape; we update stale action SHAs, enforce single-source versioning, fix the CHANGELOG, update the workflow's validate step, add the setup doc, and update the action pins.

**Tech Stack:** GitHub Actions, `PyO3/maturin-action@v1`, `pypa/gh-action-pypi-publish@release/v1`, `actions/upload-artifact@v4`, `actions/download-artifact@v4`

---

## File Map

| File | Change |
|------|--------|
| `crates/pap-python/pyproject.toml` | ✅ `version = "0.6.0"` → `dynamic = ["version"]` (reads from Cargo.toml) |
| `crates/pap-python/CHANGELOG.md` | ✅ Promoted to `[0.6.0] - 2026-04-18`, merged Unreleased content |
| `.github/workflows/release-python.yml` | ✅ validate reads `Cargo.toml`; action pins updated; `attestations: true` added |
| `docs/pypi-publishing-setup.md` | Remaining: one-time human checklist |

---

## Task 1: Version consistency + workflow validate step ✅ DONE

- [x] `pyproject.toml`: replace `version = "0.6.0"` with `dynamic = ["version"]`
- [x] `CHANGELOG.md`: promote `[0.1.0] - Not Yet Released` → `[0.6.0] - 2026-04-18`
- [x] `release-python.yml` validate step: read version from `Cargo.toml [workspace.package]` instead of `pyproject.toml`
- [x] Verify regex: `python3 -c "import re; ..."` → `0.6.0` ✓
- [x] Commit: `feat(python): single source of truth for SDK version`

---

## Task 2: Update action pins and add attestations ✅ DONE

- [x] `build-wheels` job: `PyO3/maturin-action@04ac600d…` → `PyO3/maturin-action@v1`
- [x] `build-sdist` job: same pin update
- [x] `publish-pypi` job: `pypa/gh-action-pypi-publish@ed0c5393…` → `pypa/gh-action-pypi-publish@release/v1` + `attestations: true`
- [x] Commit: `ci(python): update action pins to current stable tags, add attestations`

---

## Task 3: Write the one-time human setup doc

**Files:**
- Create: `docs/pypi-publishing-setup.md`

- [ ] **Step 1: Create the file**

```markdown
# PyPI Publishing: One-Time Setup Checklist

The workflow (`release-python.yml`) uses **PyPI Trusted Publishing** (OIDC).
No API tokens or secrets are stored in the repo or GitHub.

## 1. Add a Pending Publisher on PyPI (do before first tag)

1. Log in to https://pypi.org
2. Go to https://pypi.org/manage/account/publishing/
3. Under **Add a new pending publisher**, fill in:
   - **PyPI project name:** `pap-protocol`
   - **Owner:** `Baur-Software`
   - **Repository name:** `pap`
   - **Workflow filename:** `release-python.yml`
   - **Environment name:** `pypi`
4. Click **Add**.

## 2. Create the `pypi` GitHub Environment

1. Repo → **Settings → Environments → New environment**
2. Name: `pypi` (exact match, case-sensitive)
3. Recommended: add a **Required reviewers** deployment protection rule
   so a human approves each PyPI publish
4. No secrets needed — OIDC handles auth.

## 3. Tag and release

The Python SDK version tracks the Rust workspace (`Cargo.toml` `[workspace.package]`).
To release, bump the workspace version and push a matching tag:

```bash
# 1. Bump version in Cargo.toml [workspace.package] (e.g. 0.6.0 → 0.7.0)
# 2. Update CHANGELOG.md with the new version and date
# 3. Commit and tag:
git tag python-v0.7.0
git push origin python-v0.7.0
```

The workflow will:
1. Validate tag matches `Cargo.toml` workspace version
2. Build wheels: Linux x86_64 (glibc + musl), aarch64, macOS universal2, Windows x64
3. Build sdist
4. Create GitHub Release with changelog notes
5. Publish to PyPI via OIDC (requires environment approval if configured)

## 4. Dry run (build without publishing)

Actions → **Release Python SDK** → **Run workflow** → check "Build wheels without publishing"

## 5. Verify after tagging

- https://pypi.org/project/pap-protocol/
- `pip install pap-protocol==0.6.0`
```

- [ ] **Step 2: Commit**

```bash
git add docs/pypi-publishing-setup.md
git commit -m "docs: add PyPI trusted publishing setup checklist"
```

---

## Task 4: Smoke-test validation

- [ ] **Step 1: YAML syntax check**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release-python.yml'))" && echo "YAML valid"
```
Expected: `YAML valid`

- [ ] **Step 2: Version reads correctly from Cargo.toml**

```bash
python3 -c "
import re
with open('Cargo.toml') as f:
    content = f.read()
match = re.search(r'\[workspace\.package\].*?^version\s*=\s*\"(.+?)\"', content, re.MULTILINE | re.DOTALL)
print('version:', match.group(1))
"
```
Expected: `version: 0.6.0`

- [ ] **Step 3: Changelog awk extraction**

```bash
VERSION="0.6.0"
awk "/^## \[${VERSION}\]/{found=1; next} /^## \[/{if(found) exit} found{print}" \
  crates/pap-python/CHANGELOG.md | head -5
```
Expected: non-empty output starting with `### Added`

- [ ] **Step 4: Push branch**

```bash
git push origin HEAD
```

---

## What's NOT in scope (YAGNI)
- TestPyPI: add later if needed
- Automated version bumping
- Automatic CHANGELOG generation
