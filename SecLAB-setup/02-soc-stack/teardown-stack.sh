#!/usr/bin/env bash
# SecLAB SOC Stack Teardown
# Removes all security tools. Preserves the cluster and application.
# Splunk (gp-splunk on host) is NOT affected.

set -euo pipefail

echo "============================================"
echo "SecLAB SOC Stack Teardown"
echo "============================================"

echo "Removing Falco..."
helm uninstall falco -n falco 2>/dev/null || echo "  (not installed)"

echo "Removing Fluent Bit..."
helm uninstall fluent-bit -n logging 2>/dev/null || echo "  (not installed)"

echo "Removing Prometheus + Grafana..."
helm uninstall prometheus -n monitoring 2>/dev/null || echo "  (not installed)"

echo "Removing Kyverno policies..."
kubectl delete clusterpolicy --all 2>/dev/null || echo "  (none found)"

echo "Removing Kyverno..."
helm uninstall kyverno -n kyverno 2>/dev/null || echo "  (not installed)"

echo "Cleaning up namespaces..."
for ns in falco logging monitoring kyverno; do
    kubectl delete namespace "${ns}" --ignore-not-found 2>/dev/null
done

echo ""
echo "SOC stack removed. Cluster and application still running."
echo "gp-splunk container NOT affected."
echo "============================================"
