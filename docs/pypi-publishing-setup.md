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
# 1. Bump version in VERSION file (e.g. 0.8.2 → 0.9.0)
# 2. Update Cargo.toml [workspace.package] version to match
# 3. Update crates/pap-python/CHANGELOG.md with the new version and date
# 4. Commit, then tag:
git tag python-v0.8.2
git push origin python-v0.8.2
```

The workflow will:
1. Validate tag matches `Cargo.toml` workspace version
2. Build wheels: Linux x86_64 (glibc + musl), aarch64, macOS universal2, Windows x64
3. Build sdist
4. Create GitHub Release with changelog notes extracted from `CHANGELOG.md`
5. Publish to PyPI via OIDC (requires environment approval if configured)

## 4. Dry run (build without publishing)

Actions → **Release Python SDK** → **Run workflow** → check "Build wheels without publishing"

Builds all wheels and sdist, skips GitHub Release and PyPI publish. Good for validating
the build matrix works before a real release.

## 5. Verify after tagging

- https://pypi.org/project/pap-protocol/
- `pip install pap-protocol==0.8.2`
