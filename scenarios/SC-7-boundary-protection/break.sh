#!/usr/bin/env bash
# SC-7 Boundary Protection — Break
# NIST 800-53: SC-7 | Layer: L3 Network | Package: 02-CLUSTER-HARDEN
#
# Deliberately removes all NetworkPolicies from the anthra namespace,
# leaving pods with unrestricted ingress. Idempotent.

set -euo pipefail

NAMESPACE="anthra"

echo "=== SC-7 Break: Removing all boundary protection ==="

# Delete all NetworkPolicies labeled as SC-7 scenario
kubectl delete networkpolicy -n "${NAMESPACE}" -l seclab-scenario=SC-7 --ignore-not-found

# Also delete any other netpols in the namespace (clean slate for detection)
kubectl delete networkpolicy -n "${NAMESPACE}" --all --ignore-not-found

echo "=== SC-7 Break complete — namespace has no ingress restrictions ==="
kubectl get networkpolicy -n "${NAMESPACE}" 2>/dev/null || echo "No NetworkPolicies found"
