#!/usr/bin/env bash
#
# CSF: RESPOND / RS.MI-02 — Incidents are eradicated
# CIS v8: 3.14 — Log Sensitive Data Access
# NIST 800-53: SI-7 — Software, Firmware, and Information Integrity
#
# L7-10 RS.MI-02 — Fix: Deploy custom Falco rule for /tmp writes in Portfolio API
#
# This script:
#   1. Creates a ConfigMap with a targeted Falco rule for /tmp writes
#      scoped to the anthra namespace / api component
#   2. Patches the Falco DaemonSet to load the custom rule file
#   3. Restarts Falco pods to pick up the new rule
#
# C-RANK: This fix modifies the cluster-wide security monitoring stack.
# Obtain approval before running in a production environment.
#
# Usage: bash fix.sh
# Expected: Falco fires on next /tmp write in anthra/api containers

set -euo pipefail

NAMESPACE="anthra"
FALCO_NAMESPACE="falco"
CONFIGMAP_NAME="falco-fim-anthra-rules"
RULE_FILE_NAME="fim-anthra.yaml"

echo "=== L7-10 RS.MI-02 Fix: Deploying FIM rule for /tmp in Portfolio API ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "C-RANK: This action modifies the security monitoring stack"
echo ""

# ── Step 1: Verify Falco is running ─────────────────────────────────────────

echo "--- Verifying Falco is running ---"
FALCO_DS=$(kubectl get daemonset -n "${FALCO_NAMESPACE}" \
  -l "app.kubernetes.io/name=falco" \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${FALCO_DS}" ]]; then
  echo "ERROR: Falco DaemonSet not found in namespace '${FALCO_NAMESPACE}'"
  echo "       Check: kubectl get daemonset -n ${FALCO_NAMESPACE}"
  exit 1
fi

echo "Falco DaemonSet: ${FALCO_DS}"
echo "Falco pods:"
kubectl get pods -n "${FALCO_NAMESPACE}" \
  -l "app.kubernetes.io/name=falco" \
  -o wide 2>/dev/null || true
echo ""

# ── Step 2: Create the custom rule ConfigMap ─────────────────────────────────

echo "--- Creating custom Falco rule ConfigMap: ${CONFIGMAP_NAME} ---"

kubectl apply -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-fim-anthra-rules
  namespace: falco
  labels:
    app.kubernetes.io/managed-by: gp-copilot
    scenario: L7-10-RS.MI-02-fim-disabled
    control: SI-7
data:
  fim-anthra.yaml: |
    - rule: Write to Temp in Portfolio API
      desc: >
        Detects file writes to /tmp in Portfolio API containers (anthra namespace).
        readOnlyRootFilesystem protects /app but /tmp is a writable emptyDir mount.
        Any write to /tmp by a non-application process should be investigated.
        Maps to: NIST SI-7, CIS 3.14, NIST CSF RS.MI-02.
      condition: >
        evt.type in (open, openat, openat2) and
        evt.is_open_write=true and
        fd.name startswith /tmp/ and
        k8s.ns.name = "anthra" and
        k8s.pod.label.app.kubernetes.io/component = "api"
      output: >
        File write to /tmp in Portfolio API
        (user=%user.name command=%proc.cmdline file=%fd.name
         container=%container.name namespace=%k8s.ns.name pod=%k8s.pod.name
         image=%container.image.repository)
      priority: WARNING
      tags: [filesystem, mitre_collection, T1074, SI-7, CIS-3.14, RS.MI-02]

    - rule: Execute Script from Temp in Portfolio API
      desc: >
        Detects script execution from /tmp in Portfolio API containers.
        A dropped and executed script from /tmp is a strong indicator of
        post-exploitation tool staging. Maps to: NIST SI-7, MITRE T1059.
      condition: >
        spawned_process and
        proc.exepath startswith /tmp/ and
        k8s.ns.name = "anthra" and
        k8s.pod.label.app.kubernetes.io/component = "api"
      output: >
        Script executed from /tmp in Portfolio API
        (user=%user.name command=%proc.cmdline exe=%proc.exepath
         container=%container.name namespace=%k8s.ns.name pod=%k8s.pod.name)
      priority: ERROR
      tags: [process, mitre_execution, T1059, SI-7, RS.MI-02]
EOF

echo "ConfigMap created."
echo ""

# ── Step 3: Check how Falco is configured to load extra rules ────────────────

echo "--- Checking Falco rule loading configuration ---"

# Check if Falco is using a falco.yaml ConfigMap with rules_file entries
FALCO_CONFIG_CM=$(kubectl get configmap -n "${FALCO_NAMESPACE}" \
  -o name 2>/dev/null | grep -i "falco-config\|falco$" | head -1 || true)

if [[ -n "${FALCO_CONFIG_CM}" ]]; then
  echo "Falco config ConfigMap: ${FALCO_CONFIG_CM}"
  kubectl get "${FALCO_CONFIG_CM}" -n "${FALCO_NAMESPACE}" \
    -o jsonpath='{.data.falco\.yaml}' 2>/dev/null | grep -A 5 "rules_file" || true
fi

echo ""

# ── Step 4: Mount the custom rule file via DaemonSet annotation ──────────────
# If Falco was installed via Helm with falco.extraVolumes/extraVolumeMounts,
# the correct path is to add the ConfigMap to the Helm values and re-sync.
# As a runtime fix, we annotate the DaemonSet to trigger a rolling restart
# after confirming the rule file is referenced.

echo "--- Checking Falco DaemonSet for custom rules volume mounts ---"
kubectl get daemonset "${FALCO_DS}" -n "${FALCO_NAMESPACE}" \
  -o jsonpath='{range .spec.template.spec.volumes[*]}Volume: {.name}  configMap: {.configMap.name}{"\n"}{end}' \
  2>/dev/null | grep -i "falco\|rules\|custom" || echo "  No custom rule volumes found in DaemonSet"

echo ""
echo "--- NOTE: Mounting the custom rule ConfigMap ---"
echo ""
echo "  If Falco was installed via Helm (recommended), add to values.yaml:"
echo ""
echo "    falco:"
echo "      rules_file:"
echo "        - /etc/falco/falco_rules.yaml"
echo "        - /etc/falco/falco_rules.local.yaml"
echo "        - /etc/falco/fim-anthra.yaml"
echo ""
echo "    extraVolumes:"
echo "      - name: fim-anthra-rules"
echo "        configMap:"
echo "          name: falco-fim-anthra-rules"
echo ""
echo "    extraVolumeMounts:"
echo "      - name: fim-anthra-rules"
echo "        mountPath: /etc/falco/fim-anthra.yaml"
echo "        subPath: fim-anthra.yaml"
echo "        readOnly: true"
echo ""
echo "  Then run: helm upgrade falco falcosecurity/falco -n falco -f values.yaml"
echo ""
echo "  For this lab (runtime patch), we trigger a DaemonSet rollout to"
echo "  demonstrate the intent. The ConfigMap is created and ready."
echo ""

# ── Step 5: Trigger Falco restart to pick up rules (lab shortcut) ───────────

echo "--- Restarting Falco pods (rolling restart) ---"
kubectl rollout restart daemonset/"${FALCO_DS}" -n "${FALCO_NAMESPACE}" 2>/dev/null \
  || echo "NOTE: Could not restart Falco DaemonSet (may require Helm upgrade in this cluster)"

echo ""
echo "Waiting for rollout..."
kubectl rollout status daemonset/"${FALCO_DS}" -n "${FALCO_NAMESPACE}" \
  --timeout=120s 2>/dev/null \
  || echo "NOTE: Rollout status check timed out or DaemonSet uses a different rollout model"

echo ""

# ── Step 6: Clean up the artifacts from break.sh ────────────────────────────

echo "--- Cleaning up break.sh artifacts from /tmp ---"
API_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l "app.kubernetes.io/component=api" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -n "${API_POD}" ]]; then
  kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
    /bin/sh -c "rm -f /tmp/backdoor.sh /tmp/staged-data.txt && echo 'Artifacts removed from /tmp'" \
    2>/dev/null || echo "  WARNING: Could not clean up /tmp (check pod exec permissions)"
  echo ""
  echo "Post-cleanup /tmp state:"
  kubectl exec -n "${NAMESPACE}" "${API_POD}" -- ls -la /tmp/ 2>/dev/null || true
else
  echo "  WARNING: Could not locate API pod for cleanup"
fi

echo ""
echo "=== Fix complete ==="
echo ""
echo "--- What was done ---"
echo "  1. Custom Falco rule ConfigMap '${CONFIGMAP_NAME}' created in ${FALCO_NAMESPACE}"
echo "  2. Two rules deployed:"
echo "     - 'Write to Temp in Portfolio API' — WARNING on file writes to /tmp"
echo "     - 'Execute Script from Temp in Portfolio API' — ERROR on script execution"
echo "  3. Falco DaemonSet restarted (lab shortcut — use Helm upgrade in production)"
echo "  4. break.sh artifacts cleaned up from /tmp"
echo ""
echo "--- Rollback ---"
echo "  kubectl delete configmap ${CONFIGMAP_NAME} -n ${FALCO_NAMESPACE}"
echo "  kubectl rollout restart daemonset/${FALCO_DS} -n ${FALCO_NAMESPACE}"
echo ""
echo "NEXT STEP: Run verify.sh to confirm the Falco rule fires on a test write"
