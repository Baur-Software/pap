#!/usr/bin/env bash
# Validate that every workspace member in Cargo.toml is accounted for in each
# Dockerfile that does selective COPY + sed-based member removal.
#
# For each Dockerfile, every workspace member must either:
#   1. Be COPYed into the build context (or a sub-path of it), OR
#   2. Be removed by a sed -e deletion line
#
# This prevents the exact class of bug where a new crate is added to the
# workspace but the Dockerfiles are not updated, causing cargo-leptos / cargo
# metadata to fail at build time.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CARGO_TOML="$REPO_ROOT/Cargo.toml"

# Extract workspace members from Cargo.toml (lines like:    "crates/pap-did",)
mapfile -t MEMBERS < <(
    sed -n '/^members = \[/,/^\]/p' "$CARGO_TOML" \
    | sed -n 's/.*"\([^"]*\)".*/\1/p' \
    | sort
)

DOCKERFILES=(
    "apps/registry/Dockerfile"
    "apps/papillon/Dockerfile"
    "e2e/Dockerfile.ci-chrysalis"
)

errors=0

for df_rel in "${DOCKERFILES[@]}"; do
    df="$REPO_ROOT/$df_rel"
    if [[ ! -f "$df" ]]; then
        echo "SKIP: $df_rel (file not found)"
        continue
    fi

    echo "Checking $df_rel ..."

    # Collect paths that are COPYed (COPY crates/pap-did ./crates/pap-did)
    mapfile -t COPIED < <(
        grep '^COPY ' "$df" \
        | awk '{print $2}' \
        | sed 's|/\?$||; s|^\./||' \
        | sort -u
    )

    # Collect members removed by sed -e lines. Two formats:
    #   -e '/..."crates\/pap-foo"/d'     (exact: closing " before /d)
    #   -e '/..."examples\//d'           (prefix: no closing ", matches all examples/*)
    # We extract the path between the opening " and either "/d or /d, then unescape.
    mapfile -t SEDDED < <(
        grep -E '^\s+-e\s' "$df" \
        | sed 's|.*\*"||' \
        | sed 's|"/d.*||; s|/d.*||' \
        | sed 's|\\\/|/|g' \
        | sort -u
    )

    for member in "${MEMBERS[@]}"; do
        found=0

        # Check if COPYed: a COPY source is the member itself, or starts with
        # "member/" (e.g. COPY apps/registry/Cargo.toml covers member apps/registry)
        for copied in "${COPIED[@]}"; do
            if [[ "$copied" == "$member" || "$copied" == "$member/"* ]]; then
                found=1
                break
            fi
        done

        # Check if sed-deleted: the sed pattern is an exact match or a prefix
        # (e.g. "examples/" matches "examples/search", "examples/payment", etc.)
        if [[ $found -eq 0 ]]; then
            for sedded in "${SEDDED[@]}"; do
                if [[ "$member" == "$sedded" || "$member" == "$sedded"* ]]; then
                    found=1
                    break
                fi
            done
        fi

        if [[ $found -eq 0 ]]; then
            echo "  ERROR: workspace member '$member' is neither COPYed nor sed-deleted in $df_rel"
            errors=$((errors + 1))
        fi
    done
done

if [[ $errors -gt 0 ]]; then
    echo ""
    echo "FAILED: $errors workspace member(s) not accounted for in Dockerfiles."
    echo "Either COPY the crate into the Docker build context, or add a sed deletion line."
    exit 1
fi

echo ""
echo "OK: all workspace members accounted for in all Dockerfiles."
