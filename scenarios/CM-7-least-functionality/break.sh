#!/usr/bin/env bash
# CM-7 Least Functionality — Break
# NIST 800-53: CM-7 | Layer: L3 Network | Package: 02-CLUSTER-HARDEN
#
# Adds a wildcard ingress rule that allows all pod-to-pod traffic,
# bypassing any per-service restrictions. Idempotent.
#
# Prerequisite: SC-7 fix must have run so default-deny + per-service
# rules exist. This scenario adds a rule that overrides them.

set -euo pipefail

NAMESPACE="anthra"

echo "=== CM-7 Break: Adding wildcard ingress ==="

# Ensure SC-7 policies exist first (otherwise there's nothing to break)
NETPOL_COUNT=$(kubectl get networkpolicy -n "${NAMESPACE}" --no-headers 2>/dev/null | wc -l)
if [ "${NETPOL_COUNT}" -eq 0 ]; then
    echo "ERROR: No NetworkPolicies exist. Run SC-7 fix first:"
    echo "  bash scenarios/SC-7-boundary-protection/fix.sh"
    exit 1
fi

# Add wildcard ingress — allows all pods to talk to all pods
cat <<'POLICY' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-ingress
  namespace: anthra
  labels:
    seclab-scenario: CM-7
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - {}
POLICY

echo "=== CM-7 Break complete — all pod-to-pod ingress allowed ==="
kubectl get networkpolicy -n "${NAMESPACE}" -o wide
