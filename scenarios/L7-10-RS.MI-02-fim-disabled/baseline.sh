#!/usr/bin/env bash
#
# CSF: RESPOND / RS.MI-02 — Incidents are eradicated
# CIS v8: 3.14 — Log Sensitive Data Access
# NIST 800-53: SI-7 — Software, Firmware, and Information Integrity
#
# L7-10 RS.MI-02 — Baseline: Check FIM coverage for /tmp in Portfolio API
# Records current Falco rule coverage for file writes and /tmp state.
# Run this BEFORE break.sh to establish the ground truth.
#
# Usage: bash baseline.sh
# Expected: Falco has no targeted rules for /tmp in anthra namespace (the gap)

set -euo pipefail

NAMESPACE="anthra"
FALCO_NAMESPACE="falco"
LABEL_SELECTOR="app.kubernetes.io/component=api"
OUTFILE="/tmp/L7-10-baseline-$(date +%Y%m%d-%H%M%S).txt"

echo "=== L7-10 RS.MI-02 Baseline ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Namespace: ${NAMESPACE}"
echo "Falco namespace: ${FALCO_NAMESPACE}"
echo ""

{
  echo "=== L7-10 Baseline: $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
  echo "Scenario: FIM Not Covering Critical Writable Paths"
} >> "${OUTFILE}"

# ── Step 1: Locate the API pod ──────────────────────────────────────────────

API_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l "${LABEL_SELECTOR}" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${API_POD}" ]]; then
  echo "ERROR: No running API pod found in namespace '${NAMESPACE}' with label '${LABEL_SELECTOR}'"
  echo "       Check pod status: kubectl get pods -n ${NAMESPACE}"
  exit 1
fi

echo "API pod: ${API_POD}"
echo "" | tee -a "${OUTFILE}"

# ── Step 2: Check /tmp state in the API pod (pre-break) ────────────────────

echo "--- Current /tmp contents in API pod ---" | tee -a "${OUTFILE}"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
  ls -la /tmp/ 2>/dev/null | tee -a "${OUTFILE}" \
  || echo "WARNING: Could not inspect /tmp (may be empty or exec denied)" | tee -a "${OUTFILE}"
echo "" | tee -a "${OUTFILE}"

# ── Step 3: Check security context — confirm readOnlyRootFilesystem ─────────

echo "--- Security context: readOnlyRootFilesystem ---" | tee -a "${OUTFILE}"
kubectl get pod "${API_POD}" -n "${NAMESPACE}" \
  -o jsonpath='{range .spec.containers[*]}Container: {.name}{"\n"}  readOnlyRootFilesystem: {.securityContext.readOnlyRootFilesystem}{"\n"}{end}' \
  2>/dev/null | tee -a "${OUTFILE}" \
  || echo "WARNING: Could not retrieve security context" | tee -a "${OUTFILE}"
echo "" | tee -a "${OUTFILE}"

# ── Step 4: Check volume mounts — find writable emptyDir paths ──────────────

echo "--- Volume mounts (identifying writable paths) ---" | tee -a "${OUTFILE}"
kubectl get pod "${API_POD}" -n "${NAMESPACE}" \
  -o jsonpath='{range .spec.containers[*]}Container: {.name}{"\n"}{range .volumeMounts[*]}  mount: {.mountPath}  readOnly: {.readOnly}{"\n"}{end}{end}' \
  2>/dev/null | tee -a "${OUTFILE}" \
  || echo "WARNING: Could not retrieve volume mounts" | tee -a "${OUTFILE}"
echo "" | tee -a "${OUTFILE}"

# ── Step 5: Check Falco rules for /tmp coverage ──────────────────────────────

echo "--- Falco rules: searching for /tmp coverage ---" | tee -a "${OUTFILE}"

# Search Falco ConfigMaps for any rules referencing /tmp
FALCO_CM_COUNT=$(kubectl get configmap -n "${FALCO_NAMESPACE}" \
  -o name 2>/dev/null | wc -l || echo "0")
echo "Falco ConfigMaps found: ${FALCO_CM_COUNT}" | tee -a "${OUTFILE}"
echo "" | tee -a "${OUTFILE}"

echo "Searching ConfigMaps for '/tmp' references:" | tee -a "${OUTFILE}"
kubectl get configmap -n "${FALCO_NAMESPACE}" -o yaml 2>/dev/null \
  | grep -i "tmp" | grep -v "^--" | head -20 \
  | tee -a "${OUTFILE}" \
  || echo "  No /tmp references found in Falco ConfigMaps" | tee -a "${OUTFILE}"
echo "" | tee -a "${OUTFILE}"

echo "Searching ConfigMaps for 'anthra' namespace references:" | tee -a "${OUTFILE}"
kubectl get configmap -n "${FALCO_NAMESPACE}" -o yaml 2>/dev/null \
  | grep -i "anthra" | head -20 \
  | tee -a "${OUTFILE}" \
  || echo "  No 'anthra' references found in Falco ConfigMaps" | tee -a "${OUTFILE}"
echo "" | tee -a "${OUTFILE}"

# ── Step 6: Check Falco rules for file-write coverage generally ─────────────

echo "--- Falco rules: file write rules (open/openat) ---" | tee -a "${OUTFILE}"
kubectl get configmap -n "${FALCO_NAMESPACE}" -o yaml 2>/dev/null \
  | grep -A 3 "is_open_write" | head -40 \
  | tee -a "${OUTFILE}" \
  || echo "  No is_open_write rules found in ConfigMaps" | tee -a "${OUTFILE}"
echo "" | tee -a "${OUTFILE}"

# ── Step 7: Check Falco pod health ──────────────────────────────────────────

echo "--- Falco pod status ---" | tee -a "${OUTFILE}"
kubectl get pods -n "${FALCO_NAMESPACE}" \
  -l "app.kubernetes.io/name=falco" \
  -o wide 2>/dev/null | tee -a "${OUTFILE}" \
  || echo "WARNING: Could not list Falco pods" | tee -a "${OUTFILE}"
echo "" | tee -a "${OUTFILE}"

# ── Step 8: Check recent Falco output for any /tmp alerts ───────────────────

echo "--- Recent Falco logs: any /tmp alerts? ---" | tee -a "${OUTFILE}"
FALCO_POD=$(kubectl get pods -n "${FALCO_NAMESPACE}" \
  -l "app.kubernetes.io/name=falco" \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -n "${FALCO_POD}" ]]; then
  kubectl logs -n "${FALCO_NAMESPACE}" "${FALCO_POD}" --tail=100 2>/dev/null \
    | grep -i "tmp\|anthra\|portfolio" \
    | tee -a "${OUTFILE}" \
    || echo "  No /tmp, anthra, or portfolio alerts in recent Falco logs" | tee -a "${OUTFILE}"
else
  echo "  WARNING: Could not locate Falco pod" | tee -a "${OUTFILE}"
fi
echo "" | tee -a "${OUTFILE}"

# ── Summary ──────────────────────────────────────────────────────────────────

echo "=== Baseline Summary ===" | tee -a "${OUTFILE}"
echo "" | tee -a "${OUTFILE}"
echo "What to note before proceeding to break.sh:" | tee -a "${OUTFILE}"
echo "  1. Is /tmp empty before the break? (Step 2 output)" | tee -a "${OUTFILE}"
echo "  2. Is readOnlyRootFilesystem=true? (Step 3 output)" | tee -a "${OUTFILE}"
echo "  3. Is /tmp mounted as emptyDir? (Step 4 output)" | tee -a "${OUTFILE}"
echo "  4. Do any Falco rules cover /tmp in anthra? (Steps 5-6 output)" | tee -a "${OUTFILE}"
echo "  5. Is Falco running and healthy? (Step 7 output)" | tee -a "${OUTFILE}"
echo "" | tee -a "${OUTFILE}"
echo "Baseline saved to: ${OUTFILE}"
echo "=== Baseline complete ==="
echo ""
echo "NEXT STEP: Run break.sh to plant attacker artifacts in /tmp, then proceed to detect.md"
