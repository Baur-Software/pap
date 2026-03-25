#!/usr/bin/env bash
# check_regression.sh — Compare Criterion benchmark results against baseline.
# Exits non-zero if any p50 (median) regresses >20% vs baseline.json.
#
# Usage:
#   cargo bench -p pap-bench
#   bash benches/check_regression.sh [--update-baseline]
#
# With --update-baseline, writes current results back to baseline.json.
# Requires only bash + awk + sed (no Python, no grep -P).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASELINE="$SCRIPT_DIR/baseline.json"
CRITERION_DIR="target/criterion"
THRESHOLD=20  # percent

if [ ! -f "$BASELINE" ]; then
    echo "ERROR: baseline.json not found at $BASELINE"
    exit 1
fi

if [ ! -d "$CRITERION_DIR" ]; then
    echo "ERROR: Criterion output not found at $CRITERION_DIR"
    echo "Run 'cargo bench -p pap-bench' first."
    exit 1
fi

UPDATE_BASELINE=0
if [ "${1:-}" = "--update-baseline" ]; then
    UPDATE_BASELINE=1
fi

FAILED=0

# Parse benchmark names from baseline.json
BENCH_NAMES=$(awk -F'"' '/"p50_ns"/{found=1} found==0 && /^  "/{name=$2} /"p50_ns"/{print name; found=0}' "$BASELINE")

if [ -z "$BENCH_NAMES" ]; then
    echo "ERROR: Could not parse benchmark names from baseline.json"
    exit 1
fi

# Extract median point_estimate (nanoseconds) from a Criterion estimates.json.
# Criterion writes single-line JSON; we split on "median": to isolate
# the median block, then extract its point_estimate.
extract_median() {
    awk -F'"median":' '{print $2}' "$1" \
        | awk -F'"point_estimate":' '{print $2}' \
        | awk -F',' '{printf "%d\n", $1}'
}

echo "PAP Protocol Benchmark Regression Check"
echo "========================================"
echo ""

for NAME in $BENCH_NAMES; do
    ESTIMATES="$CRITERION_DIR/$NAME/new/estimates.json"
    if [ ! -f "$ESTIMATES" ]; then
        echo "  WARNING: No results for '$NAME' — skipping"
        continue
    fi

    CURRENT_NS=$(extract_median "$ESTIMATES")

    # Extract baseline p50_ns (value after the colon only)
    BASELINE_NS=$(awk -F': ' -v name="$NAME" '
        $0 ~ "\"" name "\"" { found=1 }
        found && /p50_ns/ {
            val=$2
            gsub(/[^0-9]/, "", val)
            print val
            exit
        }
    ' "$BASELINE")

    if [ -z "$CURRENT_NS" ] || [ -z "$BASELINE_NS" ]; then
        echo "  WARNING: Could not parse values for '$NAME' — skipping"
        continue
    fi

    # Regression percentage (x10 for one decimal place)
    if [ "$BASELINE_NS" -eq 0 ]; then
        REGRESSION_DISPLAY="+0.0"
    else
        REGRESSION_X10=$(( (CURRENT_NS - BASELINE_NS) * 1000 / BASELINE_NS ))
        ABS_X10=$REGRESSION_X10
        if [ $REGRESSION_X10 -ge 0 ]; then
            SIGN="+"
        else
            SIGN="-"
            ABS_X10=$(( -REGRESSION_X10 ))
        fi
        REG_INT=$(( ABS_X10 / 10 ))
        REG_FRAC=$(( ABS_X10 % 10 ))
        REGRESSION_DISPLAY="${SIGN}${REG_INT}.${REG_FRAC}"
    fi

    CUR_US=$(awk "BEGIN { printf \"%.1f\", $CURRENT_NS / 1000 }")
    BASE_US=$(awk "BEGIN { printf \"%.1f\", $BASELINE_NS / 1000 }")

    # Regression gate: fail if current > baseline * 1.20
    LIMIT=$(( BASELINE_NS + BASELINE_NS * THRESHOLD / 100 ))
    if [ "$CURRENT_NS" -gt "$LIMIT" ]; then
        STATUS="FAIL"
        FAILED=1
    else
        STATUS="ok"
    fi

    printf "  %-35s %10s µs  (baseline: %s µs, %s%%)  [%s]\n" \
        "$NAME" "$CUR_US" "$BASE_US" "$REGRESSION_DISPLAY" "$STATUS"
done

echo ""

if [ "$UPDATE_BASELINE" -eq 1 ]; then
    echo "Updating baseline.json with current results..."
    for NAME in $BENCH_NAMES; do
        ESTIMATES="$CRITERION_DIR/$NAME/new/estimates.json"
        [ ! -f "$ESTIMATES" ] && continue

        NS=$(extract_median "$ESTIMATES")
        [ -z "$NS" ] && continue

        # Replace p50_ns value in baseline.json (only the value after the colon)
        awk -v name="$NAME" -v ns="$NS" '
            $0 ~ "\"" name "\"" { found=1 }
            found && /p50_ns/ {
                sub(/"p50_ns": [0-9]+/, "\"p50_ns\": " ns)
                found=0
            }
            { print }
        ' "$BASELINE" > "${BASELINE}.tmp" && mv "${BASELINE}.tmp" "$BASELINE"
    done
    echo "Baseline updated."
fi

if [ "$FAILED" -ne 0 ]; then
    echo "REGRESSION DETECTED: One or more benchmarks regressed >${THRESHOLD}% vs baseline."
    exit 1
else
    echo "All benchmarks within ${THRESHOLD}% of baseline."
    exit 0
fi
