#!/usr/bin/env bash
# SecLAB SOC Stack Deployment
# Installs security tools in correct dependency order.
# Idempotent — safe to run multiple times (helm upgrade --install).
#
# Order matters:
#   1. Kyverno — admission control first (catches issues in subsequent deploys)
#   2. Kyverno policies — applied after controller is ready
#   3. Prometheus + Grafana — monitoring up before Falco (track Falco health)
#   4. Fluent Bit — log pipeline ready before Falco (ship Falco container logs)
#   5. Falco + Falcosidekick — runtime detection last (alerts go to ready pipeline)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================"
echo "SecLAB SOC Stack Deployment"
echo "============================================"
echo ""

# --- Prerequisites ---
echo "--- Checking prerequisites ---"
if ! kubectl cluster-info &>/dev/null; then
    echo "ERROR: No cluster connection. Run setup-cluster.sh first."
    exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -q gp-splunk; then
    echo "WARNING: gp-splunk is not running. Falco alerts and log shipping will fail."
    echo "  Start with: docker start gp-splunk"
fi
echo ""

# --- 1. Kyverno ---
echo "--- [1/5] Installing Kyverno (admission control) ---"
helm upgrade --install kyverno kyverno/kyverno \
    --namespace kyverno \
    --create-namespace \
    --values "${SCRIPT_DIR}/kyverno/values.yaml" \
    --wait --timeout 5m
echo "  Kyverno installed"
echo ""

# --- 2. Kyverno Policies ---
echo "--- [2/5] Applying baseline policies (audit mode) ---"
kubectl apply -f "${SCRIPT_DIR}/kyverno/baseline-policies/"
echo "  Policies applied (audit mode — violations logged, not blocked)"
echo ""

# --- 3. Prometheus + Grafana ---
echo "--- [3/5] Installing Prometheus + Grafana (monitoring) ---"
helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
    --namespace monitoring \
    --create-namespace \
    --values "${SCRIPT_DIR}/prometheus-grafana/values.yaml" \
    --wait --timeout 5m
echo "  Prometheus + Grafana installed"

# Import SOC dashboard as ConfigMap
if [ -f "${SCRIPT_DIR}/prometheus-grafana/dashboards/soc-overview.json" ]; then
    kubectl create configmap soc-overview-dashboard \
        --from-file=soc-overview.json="${SCRIPT_DIR}/prometheus-grafana/dashboards/soc-overview.json" \
        --namespace monitoring \
        --dry-run=client -o yaml | \
        kubectl label --local -f - grafana_dashboard="1" -o yaml | \
        kubectl apply -f -
    echo "  SOC dashboard imported"
fi
echo ""

# --- 4. Fluent Bit ---
echo "--- [4/5] Installing Fluent Bit (log shipping → Splunk) ---"
helm upgrade --install fluent-bit fluent/fluent-bit \
    --namespace logging \
    --create-namespace \
    --values "${SCRIPT_DIR}/splunk-forwarder/fluentbit-values.yaml" \
    --wait --timeout 3m
echo "  Fluent Bit installed — shipping logs to gp-splunk HEC"
echo ""

# --- 5. Falco ---
echo "--- [5/5] Installing Falco (runtime detection) ---"
helm upgrade --install falco falcosecurity/falco \
    --namespace falco \
    --create-namespace \
    --values "${SCRIPT_DIR}/falco/values.yaml" \
    --wait --timeout 5m
echo "  Falco installed — alerts forwarding to Splunk via Falcosidekick"
echo ""

# --- Verification ---
echo "============================================"
echo "Verification"
echo "============================================"
echo ""

echo "--- Namespaces ---"
kubectl get ns | grep -E 'kyverno|monitoring|logging|falco|anthra'
echo ""

echo "--- Pod Status ---"
for ns in kyverno monitoring logging falco; do
    echo "  ${ns}:"
    kubectl get pods -n "${ns}" --no-headers 2>/dev/null | while read line; do
        echo "    ${line}"
    done
done
echo ""

echo "--- Kyverno Policy Reports ---"
kubectl get clusterpolicyreport --no-headers 2>/dev/null | head -5
echo ""

echo "--- Access URLs ---"
echo "  Splunk:  http://localhost:8000  (admin / GPcopilot2026!)"
echo "  Grafana: http://localhost:30300 (admin / SecLAB2026!)"
echo ""

echo "============================================"
echo "SOC stack deployed. Daily workflow:"
echo "  1. Grafana  → cluster health + metrics"
echo "  2. Splunk   → Falco alerts + container logs"
echo "  3. Kyverno  → policy violation reports"
echo "============================================"
