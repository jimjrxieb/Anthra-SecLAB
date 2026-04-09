#!/usr/bin/env bash
# Evidence Collection Pipeline
# Runs all scenario detections, collects output to evidence/YYYY-MM-DD/,
# generates SHA256 manifest, and appends findings to POA&M.
#
# Usage:
#   bash tools/collect-evidence.sh              # Run all scenarios
#   bash tools/collect-evidence.sh SC-7         # Run one scenario
#   bash tools/collect-evidence.sh --fix-first  # Run fix, then detect (baseline)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
DATE="$(date -u +%Y-%m-%d)"
EVIDENCE_DIR="${PROJECT_DIR}/evidence/${DATE}"
SCENARIO_DIR="${PROJECT_DIR}/scenarios"
POAM_FILE="${PROJECT_DIR}/docs/poam-template.md"

FIX_FIRST="${1:-}"
TARGET_SCENARIO="${1:-all}"

# Handle --fix-first flag
if [ "${FIX_FIRST}" = "--fix-first" ]; then
    FIX_FIRST="yes"
    TARGET_SCENARIO="${2:-all}"
else
    FIX_FIRST="no"
fi

mkdir -p "${EVIDENCE_DIR}"

echo "============================================"
echo "Evidence Collection Pipeline"
echo "Date: ${DATE}"
echo "Output: ${EVIDENCE_DIR}/"
echo "Target: ${TARGET_SCENARIO}"
echo "Fix first: ${FIX_FIRST}"
echo "============================================"
echo ""

# Collect scenarios to run
SCENARIOS=()
if [ "${TARGET_SCENARIO}" = "all" ]; then
    for dir in "${SCENARIO_DIR}"/*/; do
        [ -d "${dir}" ] && SCENARIOS+=("$(basename "${dir}")")
    done
else
    # Match by control ID prefix (e.g., "SC-7" matches "SC-7-boundary-protection")
    for dir in "${SCENARIO_DIR}"/${TARGET_SCENARIO}*/; do
        [ -d "${dir}" ] && SCENARIOS+=("$(basename "${dir}")")
    done
fi

if [ ${#SCENARIOS[@]} -eq 0 ]; then
    echo "ERROR: No scenarios found matching '${TARGET_SCENARIO}'"
    exit 1
fi

PASS_COUNT=0
FAIL_COUNT=0

for SCENARIO in "${SCENARIOS[@]}"; do
    SCENARIO_PATH="${SCENARIO_DIR}/${SCENARIO}"
    CONTROL_ID="${SCENARIO%%-*}-${SCENARIO#*-}"
    CONTROL_ID="${SCENARIO%%[-_]*}-$(echo "${SCENARIO}" | cut -d'-' -f2)"

    echo ""
    echo "============================================"
    echo "Scenario: ${SCENARIO}"
    echo "============================================"

    # Run fix first if requested (establishes secure baseline)
    if [ "${FIX_FIRST}" = "yes" ] && [ -x "${SCENARIO_PATH}/fix.sh" ]; then
        echo ""
        echo "--- Running fix (baseline) ---"
        bash "${SCENARIO_PATH}/fix.sh" || true
    fi

    # Run detection
    if [ -x "${SCENARIO_PATH}/detect.sh" ]; then
        echo ""
        echo "--- Running detection ---"
        EVIDENCE_DIR="${EVIDENCE_DIR}" bash "${SCENARIO_PATH}/detect.sh" || true
    else
        echo "WARNING: No detect.sh found for ${SCENARIO}"
    fi
done

# Generate SHA256 manifest
echo ""
echo "============================================"
echo "Generating SHA256 manifest"
echo "============================================"
MANIFEST="${EVIDENCE_DIR}/SHA256SUMS"
if compgen -G "${EVIDENCE_DIR}/*.json" > /dev/null 2>&1; then
    (cd "${EVIDENCE_DIR}" && sha256sum *.json > SHA256SUMS)
    echo "Manifest written to ${MANIFEST}"
    cat "${MANIFEST}"
else
    echo "No evidence files found — check tool output above for errors"
fi

echo ""
echo "============================================"
echo "Evidence collection complete: ${EVIDENCE_DIR}/"
echo "============================================"
ls -la "${EVIDENCE_DIR}/"
