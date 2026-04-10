#!/usr/bin/env bash
# check_regression.sh — Compare Criterion benchmark results against baseline.
# Exits non-zero if any p50 (median) regresses >20% vs baseline.
#
# Usage:
#   cargo bench -p pap-bench
#   bash benches/check_regression.sh [--baseline <path>] [--update-baseline] [--output <path>]
#
# --baseline <path>     Use an alternative baseline.json (default: benches/baseline.json)
# --update-baseline     Write current results back to baseline.json
# --output <path>       Write human-readable results table to a file (for CI PR comments)
#
# Requires only bash + awk + sed (no Python, no grep -P).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASELINE="$SCRIPT_DIR/baseline.json"
CRITERION_DIR="target/criterion"
THRESHOLD=30  # percent — bumped 20→30 because GitHub-hosted runners show 20-27% variance
              # across the runner pool for crypto-heavy benchmarks (Ed25519, SD-JWT, mandates).
              # A 30% gate still catches meaningful regressions while absorbing inter-runner drift.

# ── Argument parsing ──────────────────────────────────────────────────
UPDATE_BASELINE=0
OUTPUT_FILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --update-baseline)
            UPDATE_BASELINE=1
            shift
            ;;
        --baseline)
            if [ -z "${2:-}" ]; then
                echo "ERROR: --baseline requires a path argument"
                exit 1
            fi
            BASELINE="$2"
            shift 2
            ;;
        --output)
            if [ -z "${2:-}" ]; then
                echo "ERROR: --output requires a path argument"
                exit 1
            fi
            OUTPUT_FILE="$2"
            shift 2
            ;;
        *)
            echo "ERROR: Unknown argument: $1"
            echo "Usage: $0 [--baseline <path>] [--update-baseline] [--output <path>]"
            exit 1
            ;;
    esac
done

# ── Validate inputs ──────────────────────────────────────────────────
if [ ! -f "$BASELINE" ]; then
    echo "ERROR: baseline.json not found at $BASELINE"
    exit 1
fi

if [ ! -d "$CRITERION_DIR" ]; then
    echo "ERROR: Criterion output not found at $CRITERION_DIR"
    echo "Run 'cargo bench -p pap-bench' first."
    exit 1
fi

# ── Output helpers ────────────────────────────────────────────────────
# Truncate output file if specified
if [ -n "$OUTPUT_FILE" ]; then
    : > "$OUTPUT_FILE"
fi

# Print to stdout and optionally to the output file
emit() {
    if [ -n "$OUTPUT_FILE" ]; then
        printf '%s\n' "$1" | tee -a "$OUTPUT_FILE"
    else
        printf '%s\n' "$1"
    fi
}

emitf() {
    local formatted
    formatted=$(printf "$@")
    if [ -n "$OUTPUT_FILE" ]; then
        printf '%s\n' "$formatted" | tee -a "$OUTPUT_FILE"
    else
        printf '%s\n' "$formatted"
    fi
}

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

# ── Main comparison loop ─────────────────────────────────────────────
emit "PAP Protocol Benchmark Regression Check"
emit "========================================"
emit "Baseline: $BASELINE"
emit "Threshold: ${THRESHOLD}%"
emit ""

for NAME in $BENCH_NAMES; do
    ESTIMATES="$CRITERION_DIR/$NAME/new/estimates.json"
    if [ ! -f "$ESTIMATES" ]; then
        emit "  WARNING: No results for '$NAME' — skipping"
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
        emit "  WARNING: Could not parse values for '$NAME' — skipping"
        continue
    fi

    # Guard against parse failures that produce 0 (would silently pass the gate)
    if [ "$CURRENT_NS" -le 0 ] || [ "$BASELINE_NS" -le 0 ]; then
        emit "  ERROR: Invalid values for '$NAME' (current=${CURRENT_NS}, baseline=${BASELINE_NS}) — failing"
        FAILED=1
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

    CUR_US=$(awk -v ns="$CURRENT_NS" 'BEGIN { printf "%.1f", ns / 1000 }')
    BASE_US=$(awk -v ns="$BASELINE_NS" 'BEGIN { printf "%.1f", ns / 1000 }')

    # Regression gate: fail if current > baseline * (1 + threshold/100)
    LIMIT=$(( BASELINE_NS + BASELINE_NS * THRESHOLD / 100 ))
    if [ "$CURRENT_NS" -gt "$LIMIT" ]; then
        STATUS="FAIL"
        FAILED=1
    else
        STATUS="ok"
    fi

    emitf "  %-35s %10s µs  (baseline: %s µs, %s%%)  [%s]" \
        "$NAME" "$CUR_US" "$BASE_US" "$REGRESSION_DISPLAY" "$STATUS"
done

emit ""

# ── Update baseline if requested ─────────────────────────────────────
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

# ── Exit status ───────────────────────────────────────────────────────
if [ "$FAILED" -ne 0 ]; then
    emit "REGRESSION DETECTED: One or more benchmarks regressed >${THRESHOLD}% vs baseline."
    exit 1
else
    emit "All benchmarks within ${THRESHOLD}% of baseline."
    exit 0
fi
