#!/usr/bin/env bash
# CM-7 Least Functionality — Fix
# NIST 800-53: CM-7 | Layer: L3 Network | Package: 02-CLUSTER-HARDEN
# Type: Preventive
#
# Removes wildcard ingress and scopes ingress rules to named services.
# Depends on SC-7 fix having run first (default-deny must exist).
# Idempotent.

set -euo pipefail

NAMESPACE="anthra"

echo "=== CM-7 Fix: Removing overpermissive ingress ==="

# Delete the wildcard ingress rule if it exists
kubectl delete networkpolicy -n "${NAMESPACE}" allow-all-ingress --ignore-not-found

# Ensure the per-service rules from SC-7 are in place
# (CM-7 fix depends on SC-7 fix — run SC-7 fix first if netpols are missing)
NETPOL_COUNT=$(kubectl get networkpolicy -n "${NAMESPACE}" --no-headers 2>/dev/null | wc -l)
if [ "${NETPOL_COUNT}" -lt 2 ]; then
    echo "WARNING: Few NetworkPolicies found. Run SC-7 fix first:"
    echo "  bash scenarios/SC-7-boundary-protection/fix.sh"
    exit 1
fi

echo "=== CM-7 Fix complete ==="
kubectl get networkpolicy -n "${NAMESPACE}" -o wide
