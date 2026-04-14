#!/usr/bin/env bash
#
# CSF: PROTECT / PR.PS-01 — Configuration management practices established and applied
# CIS v8: 16.12 — Implement Code-Level Security Checks
# NIST 800-53: SI-10 — Information Input Validation, SC-8 — Transmission Confidentiality
#
# L7-02 PR.PS-01 — Break: Strip all security headers from the UI nginx config
#
# The UI container has readOnlyRootFilesystem: true set in the Helm chart.
# /etc/nginx/conf.d/ is backed by the container image layer — not writable.
# To inject a stripped config, this script:
#   1. Patches the UI deployment to add an emptyDir volume for /etc/nginx/conf.d/
#      and sets readOnlyRootFilesystem: false (training environment only)
#   2. After rollout, execs into the new pod and writes the stripped config
#   3. Reloads nginx
#
# IMPORTANT: This is a destructive training break. Run fix.sh to restore.
# The Helm chart is NOT modified — patches are applied directly to the deployment
# (ArgoCD will drift-detect this; that is intentional for the training scenario).
#
# Usage: bash break.sh
# Expected: curl to UI returns no security headers in response

set -euo pipefail

NAMESPACE="anthra"
DEPLOYMENT="portfolio-anthra-portfolio-app-ui"
LABEL_SELECTOR="app.kubernetes.io/component=ui"

echo "=== L7-02 PR.PS-01 Break: Stripping security headers from UI nginx ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "WARNING: This modifies the live deployment. Run fix.sh to restore."
echo ""

# Confirm the deployment exists
if ! kubectl get deployment "${DEPLOYMENT}" -n "${NAMESPACE}" &>/dev/null; then
  echo "ERROR: Deployment '${DEPLOYMENT}' not found in namespace '${NAMESPACE}'"
  echo "       Check: kubectl get deployment -n ${NAMESPACE}"
  exit 1
fi

echo "--- Step 1: Capture pre-break header state ---"
UI_POD_BEFORE=$(kubectl get pods -n "${NAMESPACE}" \
  -l "${LABEL_SELECTOR}" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -n "${UI_POD_BEFORE}" ]]; then
  HEADERS_BEFORE=$(kubectl exec -n "${NAMESPACE}" "${UI_POD_BEFORE}" -- \
    curl -sI http://localhost:8080/ 2>/dev/null \
    | grep -iE "(content-security|x-frame|x-content-type|x-xss|strict-transport|referrer-policy|permissions-policy)" \
    || echo "(none found)")
  echo "Security headers BEFORE break:"
  echo "${HEADERS_BEFORE}"
else
  echo "WARNING: No running pod found before break — continuing anyway"
fi

echo ""
echo "--- Step 2: Patch deployment to mount writable /etc/nginx/conf.d/ ---"
echo "Adding emptyDir volume for /etc/nginx/conf.d/ and disabling readOnlyRootFilesystem..."

# Apply a strategic merge patch to add the emptyDir volume and disable readOnly filesystem
# This allows writing the stripped config without rebuilding the image
kubectl patch deployment "${DEPLOYMENT}" -n "${NAMESPACE}" \
  --type='json' \
  -p='[
    {
      "op": "add",
      "path": "/spec/template/spec/volumes/-",
      "value": {
        "name": "nginx-conf-d",
        "emptyDir": {}
      }
    },
    {
      "op": "add",
      "path": "/spec/template/spec/containers/0/volumeMounts/-",
      "value": {
        "name": "nginx-conf-d",
        "mountPath": "/etc/nginx/conf.d"
      }
    },
    {
      "op": "replace",
      "path": "/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem",
      "value": false
    }
  ]'

echo "Patch applied. Waiting for rollout..."
kubectl rollout status deployment/"${DEPLOYMENT}" \
  -n "${NAMESPACE}" \
  --timeout=120s

echo ""
echo "--- Step 3: Write stripped nginx config (no security headers) ---"

# Locate the new pod
UI_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l "${LABEL_SELECTOR}" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${UI_POD}" ]]; then
  echo "ERROR: No running UI pod found after rollout."
  echo "       Check: kubectl get pods -n ${NAMESPACE}"
  exit 1
fi

echo "New pod: ${UI_POD}"
echo ""

# Write the stripped config — minimal nginx, no security headers
# This simulates an operator who overwrote the config without the security block
kubectl exec -n "${NAMESPACE}" "${UI_POD}" -- \
  sh -c 'cat > /etc/nginx/conf.d/default.conf << '"'"'NGINXEOF'"'"'
server {
    listen 8080;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }
}
NGINXEOF'

echo "Stripped config written to /etc/nginx/conf.d/default.conf"

# Validate the config before reloading
echo ""
echo "--- Validating nginx config syntax ---"
kubectl exec -n "${NAMESPACE}" "${UI_POD}" -- nginx -t 2>&1 || {
  echo "ERROR: nginx config test failed. The stripped config has a syntax error."
  echo "       Check the config above and retry."
  exit 1
}

# Reload nginx with the stripped config
echo ""
echo "--- Reloading nginx ---"
kubectl exec -n "${NAMESPACE}" "${UI_POD}" -- nginx -s reload
echo "nginx reloaded successfully"

echo ""
echo "--- Step 4: Verify headers are gone ---"
HEADERS_AFTER=$(kubectl exec -n "${NAMESPACE}" "${UI_POD}" -- \
  curl -sI http://localhost:8080/ 2>/dev/null \
  | grep -iE "(content-security|x-frame|x-content-type|x-xss|strict-transport|referrer-policy|permissions-policy)" \
  || echo "(none — headers successfully stripped)")

echo "Security headers AFTER break:"
echo "${HEADERS_AFTER}"

echo ""
echo "--- Step 5: Confirm page still loads (HTTP 200) ---"
HTTP_STATUS=$(kubectl exec -n "${NAMESPACE}" "${UI_POD}" -- \
  curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ 2>/dev/null || echo "ERR")
echo "HTTP status: ${HTTP_STATUS}"

if [[ "${HTTP_STATUS}" == "200" ]]; then
  echo "UI is serving pages — vulnerability is silent (no functional impact, security only)"
else
  echo "WARNING: UI returned ${HTTP_STATUS} — the page may not be loading correctly"
fi

echo ""
echo "=== Break complete ==="
echo ""
echo "The security headers have been stripped. The UI looks identical to users"
echo "but sends no security directives to the browser."
echo ""
echo "To verify the break from your machine:"
echo "  kubectl port-forward -n ${NAMESPACE} svc/portfolio-anthra-portfolio-app-ui 8080:80 &"
echo "  curl -sI http://localhost:8080/ | grep -iE '(content-security|x-frame|x-content-type|x-xss|strict-transport|referrer|permissions)'"
echo "  # Expected: no output (no security headers)"
echo ""
echo "NEXT STEP: Follow detect.md to practice discovery, then run fix.sh to restore"
