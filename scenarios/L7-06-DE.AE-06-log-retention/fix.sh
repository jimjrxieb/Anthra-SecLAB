#!/usr/bin/env bash
# =============================================================================
# L7-06 — DE.AE-06: Log Retention Too Short
# Phase: FIX — Set log retention to 90 days minimum
#
# CSF:       DETECT / DE.AE-06 (Info on adverse events provided to authorized staff)
# CIS v8:    8.10 — Retain Audit Logs
# NIST:      AU-11 — Audit Record Retention
# Cluster:   k3d-seclab
# Namespace: logging (Fluent Bit), anthra (target)
#
# WHAT THIS DOES:
#   Path A — Loki deployed: patches Loki ConfigMap to set retention_period: 720h
#             (30 days) with a note that production must be 2160h (90 days).
#             Lab storage limits may prevent the full 90-day setting.
#
#   Path B — No Loki: deploys a Fluent Bit output ConfigMap patch that redirects
#             logs to a file-based output with documented retention requirements,
#             and provides the Loki Helm values needed to deploy durable storage.
#
# RANK: C — Retention policy changes require GRC review and documented approval.
#       This script implements the technical fix. The GRC documentation must
#       accompany this change (see remediate.md).
# =============================================================================
set -euo pipefail

LOGGING_NS="logging"
ANTHRA_NS="anthra"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Lab retention: 720h (30 days) — saves disk space in the lab
# Production retention: 2160h (90 days) for FedRAMP Moderate
LAB_RETENTION="720h"
PROD_RETENTION="2160h"

echo "============================================================"
echo "L7-06 FIX — Set Log Retention to 90-Day Minimum"
echo "Timestamp: ${TIMESTAMP}"
echo ""
echo "  Lab setting:        ${LAB_RETENTION} (30 days — disk-safe for lab)"
echo "  Production setting: ${PROD_RETENTION} (90 days — FedRAMP floor)"
echo "============================================================"
echo ""

# --- Detect Loki ---
LOKI_NS=$(kubectl get pods --all-namespaces \
  --no-headers 2>/dev/null | grep -i loki | awk '{print $1}' | head -1 || true)

if [[ -n "${LOKI_NS}" ]]; then
  echo "PATH A: Loki detected in namespace '${LOKI_NS}'"
  echo "        Updating retention_period to ${LAB_RETENTION}."
  echo ""

  LOKI_CM=$(kubectl get configmap -n "${LOKI_NS}" \
    --no-headers 2>/dev/null | grep -i loki | awk '{print $1}' | head -1 || true)

  if [[ -z "${LOKI_CM}" ]]; then
    echo "ERROR: Loki ConfigMap not found in ${LOKI_NS}."
    exit 1
  fi

  echo "  Target ConfigMap: ${LOKI_CM}"
  echo ""

  # --- Restore from saved original, then apply correct setting ---
  if [[ -f /tmp/loki-config-before-break.yaml ]]; then
    echo "  Restoring from pre-break backup..."
    kubectl apply -f /tmp/loki-config-before-break.yaml
    echo "  Backup restored."
  else
    echo "  No pre-break backup found. Working from current ConfigMap."
  fi

  echo ""
  echo "  Patching retention_period to ${LAB_RETENTION}..."

  # Get current config to patch
  kubectl get configmap -n "${LOKI_NS}" "${LOKI_CM}" \
    -o yaml > /tmp/loki-config-current.yaml

  python3 -c "
import sys, re

with open('/tmp/loki-config-current.yaml', 'r') as f:
    raw = f.read()

retention = '${LAB_RETENTION}'

# Ensure retention_deletes_enabled: true is present
if 'retention_deletes_enabled' not in raw:
    raw = raw.replace(
        'limits_config:',
        'limits_config:\n  retention_deletes_enabled: true'
    )

# Set or replace retention_period
if 'retention_period' in raw:
    raw = re.sub(r'retention_period:\s*\S+', f'retention_period: {retention}', raw)
else:
    raw = raw.replace(
        'limits_config:',
        f'limits_config:\n  retention_period: {retention}'
    )

with open('/tmp/loki-config-fixed.yaml', 'w') as f:
    f.write(raw)
print('Config patched successfully.')
"

  kubectl apply -f /tmp/loki-config-fixed.yaml
  echo ""
  echo "  ConfigMap updated. Restarting Loki..."
  kubectl rollout restart deployment -n "${LOKI_NS}" 2>/dev/null \
    || kubectl rollout restart statefulset -n "${LOKI_NS}" 2>/dev/null \
    || echo "  (restart manually if needed)"

  echo ""
  echo "  Waiting 15 seconds for Loki to restart..."
  sleep 15

  echo ""
  echo "  FIX APPLIED:"
  echo "  - Retention set to: ${LAB_RETENTION} (30 days for lab)"
  echo "  - Production must use: ${PROD_RETENTION} (90 days)"
  echo "  - retention_deletes_enabled: true"
  echo ""
  echo "  To verify: run verify.sh"
  echo ""
  echo "  NOTE FOR PRODUCTION:"
  echo "  In a real FedRAMP environment, also configure:"
  echo "  - compactor.retention_enabled: true"
  echo "  - compactor.working_directory: /data/loki/compactor"
  echo "  - storage_config.boltdb_shipper.active_index_directory: /data/loki/index"
  echo "  - Persistent volume with sufficient capacity for 90 days of log volume"

else
  echo "PATH B: Loki not deployed. Providing durable storage deployment guidance."
  echo ""
  echo "  In a buffer-only environment, logs cannot be retained for 90 days."
  echo "  The fix requires deploying a durable log backend."
  echo ""
  echo "  ============================================================"
  echo "  OPTION 1: Deploy Loki with 90-day retention (recommended)"
  echo "  ============================================================"
  echo ""
  echo "  Add the Grafana Helm repo:"
  echo "    helm repo add grafana https://grafana.github.io/helm-charts"
  echo "    helm repo update"
  echo ""
  echo "  Deploy Loki with 90-day retention (lab values — local storage):"

  cat << 'LOKI_VALUES'
  ---
  # loki-values-lab.yaml
  # Deploy: helm install loki grafana/loki -n logging -f loki-values-lab.yaml
  loki:
    auth_enabled: false
    limits_config:
      retention_period: 720h          # 30 days for lab (set 2160h for production)
      retention_deletes_enabled: true
      ingestion_rate_mb: 10
      ingestion_burst_size_mb: 20
    compactor:
      retention_enabled: true
      working_directory: /data/loki/compactor
    storage:
      type: filesystem
    storage_config:
      filesystem:
        directory: /data/loki/chunks
  persistence:
    enabled: true
    size: 20Gi                        # increase for production

  # Update Fluent Bit output to forward to Loki after deployment:
  # [OUTPUT]
  #     Name        loki
  #     Match       kube.*
  #     Host        loki.logging.svc.cluster.local
  #     Port        3100
  #     Labels      job=fluent-bit, namespace=$kubernetes['namespace_name']
LOKI_VALUES

  echo ""
  echo "  ============================================================"
  echo "  OPTION 2: Configure Fluent Bit file output (temporary bridge)"
  echo "  ============================================================"
  echo ""
  echo "  Add to Fluent Bit ConfigMap output section:"

  cat << 'FB_VALUES'
  [OUTPUT]
      Name        file
      Match       kube.anthra.*
      Path        /var/log/anthra-audit
      File        audit.log
      # NOTE: file output retains logs on the node only.
      # This is NOT 90-day retention — it is a bridge until Loki is deployed.
      # Node log files are bounded by node disk space.
      # Implement log rotation with logrotate on the node for durability.
FB_VALUES

  echo ""
  echo "  IMPORTANT: File output alone does not satisfy AU-11."
  echo "  It bridges the collection gap but does not provide durable, queryable"
  echo "  storage with a verified 90-day retention window."
  echo ""
  echo "  Deploy Loki as the definitive fix. File output is temporary only."
fi

echo ""
echo "============================================================"
echo "FIX COMPLETE — ${TIMESTAMP}"
echo ""
echo "  Run verify.sh to confirm the retention setting is applied."
echo "  Complete remediate.md for the GRC documentation."
echo "============================================================"
