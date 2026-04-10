#!/usr/bin/env bash
# run-dast.sh — DAST scan wrapper for Anthra-SecLAB staging
#
# Calls the real tool from GP-CONSULTING/03-RUNTIME-SECURITY/tools/run-dast.sh
# That script handles: curl spot-checks, K8s metadata/SA probes, ZAP baseline, Nuclei
#
# See playbook: GP-CONSULTING/03-RUNTIME-SECURITY/playbooks/11-dast-scan-and-fix.md
#
# Usage:
#   ./scripts/security/run-dast.sh
#   ./scripts/security/run-dast.sh --target http://custom-url --namespace custom-ns
#   ./scripts/security/run-dast.sh --json
#   ./scripts/security/run-dast.sh --report reports/dast/scan-$(date +%Y%m%d).md

set -euo pipefail

CONSULTING="${GP_CONSULTING:-$HOME/linkops-industries/GP-copilot/GP-CONSULTING}"
DAST_TOOL="$CONSULTING/03-RUNTIME-SECURITY/tools/run-dast.sh"

if [[ ! -f "$DAST_TOOL" ]]; then
    echo "ERROR: Cannot find $DAST_TOOL"
    echo "Set GP_CONSULTING env var or ensure GP-CONSULTING is at the expected path."
    exit 1
fi

# Defaults for staging
TARGET="${TARGET:-http://localhost:8080}"
NAMESPACE="${NAMESPACE:-portfolio}"

# Pass through all args, inject defaults if not provided
ARGS=("$@")
HAS_TARGET=false
HAS_NS=false

for arg in "${ARGS[@]}"; do
    [[ "$arg" == "--target" ]] && HAS_TARGET=true
    [[ "$arg" == "--namespace" ]] && HAS_NS=true
done

[[ "$HAS_TARGET" == "false" ]] && ARGS+=(--target "$TARGET")
[[ "$HAS_NS" == "false" ]] && ARGS+=(--namespace "$NAMESPACE")

echo "=== Anthra-SecLAB Staging DAST ==="
echo "  Tool:      $DAST_TOOL"
echo "  Playbook:  03-RUNTIME-SECURITY/playbooks/11-dast-scan-and-fix.md"
echo ""

bash "$DAST_TOOL" "${ARGS[@]}"
