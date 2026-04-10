#!/usr/bin/env bash
# Test K8s manifests against conftest policies.
# Run this locally before pushing — same check as CI.
#
# Usage:
#   bash scripts/test-policies.sh
#   bash scripts/test-policies.sh k8s/deployments/

set -euo pipefail
MANIFESTS="${1:-infrastructure}"
POLICIES="policies/conftest"

if ! command -v conftest &>/dev/null; then
  echo "conftest not installed: https://www.conftest.dev/install/"
  exit 1
fi

echo "Testing $MANIFESTS/ against $POLICIES/"
conftest test "$MANIFESTS" --policy "$POLICIES" --all-namespaces --output stdout
