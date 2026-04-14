#!/usr/bin/env bash
#
# CSF: PROTECT / PR.PS-01 — Configuration management practices established and applied
# CIS v8: 16.12 — Implement Code-Level Security Checks
# NIST 800-53: SI-10 — Information Input Validation, SC-8 — Transmission Confidentiality
#
# L7-02 PR.PS-01 — Fix: Restore hardened nginx config with all security headers
#
# This script:
#   1. Writes the hardened nginx config (matching the Dockerfile source) to the pod
#   2. Validates the config syntax
#   3. Reloads nginx
#   4. Reverts the deployment patch from break.sh (re-enables readOnlyRootFilesystem,
#      removes the emptyDir volume for /etc/nginx/conf.d/)
#   5. Confirms headers are present in the response after rollout
#
# NOTE: The deployment patch revert causes a rollout. The new pod will use the
# original image config (baked in at build time), which already has all headers.
# This restores the source-of-truth configuration.
#
# Usage: bash fix.sh
# Expected: All 7 security headers present in response from new pod

set -euo pipefail

NAMESPACE="anthra"
DEPLOYMENT="portfolio-anthra-portfolio-app-ui"
LABEL_SELECTOR="app.kubernetes.io/component=ui"

echo "=== L7-02 PR.PS-01 Fix: Restoring hardened nginx security headers ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Namespace: ${NAMESPACE}"
echo ""

# Confirm the deployment exists
if ! kubectl get deployment "${DEPLOYMENT}" -n "${NAMESPACE}" &>/dev/null; then
  echo "ERROR: Deployment '${DEPLOYMENT}' not found in namespace '${NAMESPACE}'"
  echo "       Check: kubectl get deployment -n ${NAMESPACE}"
  exit 1
fi

# Locate current running pod
UI_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l "${LABEL_SELECTOR}" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${UI_POD}" ]]; then
  echo "ERROR: No running UI pod found. Check: kubectl get pods -n ${NAMESPACE}"
  exit 1
fi

echo "Current pod: ${UI_POD}"
echo ""

echo "--- Step 1: Write hardened nginx config to running pod ---"
echo "Writing config with all 7 security headers..."
echo ""

# Write the full hardened config matching the Dockerfile source exactly
# CSP allows self + unsafe-inline/eval for the React SPA + Google Fonts
kubectl exec -n "${NAMESPACE}" "${UI_POD}" -- \
  sh -c 'cat > /etc/nginx/conf.d/default.conf << '"'"'NGINXEOF'"'"'
server {
    listen 8080;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    # Security Headers
    add_header Content-Security-Policy "default-src '"'"'self'"'"'; script-src '"'"'self'"'"' '"'"'unsafe-inline'"'"' '"'"'unsafe-eval'"'"'; style-src '"'"'self'"'"' '"'"'unsafe-inline'"'"' https://fonts.googleapis.com; font-src '"'"'self'"'"' https://fonts.gstatic.com; img-src '"'"'self'"'"' data: https:; connect-src '"'"'self'"'"' https://linksmlm.com wss://linksmlm.com; frame-ancestors '"'"'self'"'"';" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Cache static assets (JS/CSS/images) with versioned filenames
    location ~* \.(?:css|js|jpg|jpeg|gif|png|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        try_files $uri =404;
    }

    # Never cache index.html (entry point)
    location = /index.html {
        add_header Cache-Control "no-cache, no-store, must-revalidate";
        expires 0;
    }

    # SPA fallback for routes
    location / {
        try_files $uri $uri/ /index.html;
    }
}
NGINXEOF'

echo "Config written."

echo ""
echo "--- Step 2: Validate nginx config syntax ---"
kubectl exec -n "${NAMESPACE}" "${UI_POD}" -- nginx -t 2>&1 || {
  echo "ERROR: nginx config test failed."
  echo "       The config above may have a quoting issue."
  echo "       Check the config manually:"
  echo "       kubectl exec -n ${NAMESPACE} ${UI_POD} -- cat /etc/nginx/conf.d/default.conf"
  exit 1
}
echo "Config syntax OK."

echo ""
echo "--- Step 3: Reload nginx ---"
kubectl exec -n "${NAMESPACE}" "${UI_POD}" -- nginx -s reload
echo "nginx reloaded."

echo ""
echo "--- Step 4: Quick header verification before rollout ---"
QUICK_CHECK=$(kubectl exec -n "${NAMESPACE}" "${UI_POD}" -- \
  curl -sI http://localhost:8080/ 2>/dev/null \
  | grep -iE "(content-security|x-frame|x-content-type|x-xss|strict-transport|referrer-policy|permissions-policy)" \
  || echo "(none — check failed)")
echo "Headers in current pod (immediate check):"
echo "${QUICK_CHECK}"

echo ""
echo "--- Step 5: Revert deployment patch (re-enable readOnlyRootFilesystem) ---"
echo "Removing the emptyDir volume for /etc/nginx/conf.d/ and restoring security context..."
echo ""
echo "NOTE: This causes a pod rollout. The new pod will load the config from"
echo "      the container image (Dockerfile), which already has all 7 headers baked in."
echo "      This is the permanent fix — the runtime exec above was a temporary step."
echo ""

# Remove the nginx-conf-d volumeMount from the container
# and the nginx-conf-d volume from the pod spec,
# and restore readOnlyRootFilesystem: true
#
# Strategy: check whether the break patch was applied first
CONFD_VOLUME=$(kubectl get deployment "${DEPLOYMENT}" -n "${NAMESPACE}" \
  -o jsonpath='{range .spec.template.spec.volumes[*]}{.name}{"\n"}{end}' \
  | grep "nginx-conf-d" || true)

if [[ -n "${CONFD_VOLUME}" ]]; then
  echo "Break patch detected — reverting..."

  # Find the index of the nginx-conf-d volume to remove it
  VOLUME_INDEX=$(kubectl get deployment "${DEPLOYMENT}" -n "${NAMESPACE}" \
    -o json \
    | python3 -c "
import json, sys
d = json.load(sys.stdin)
volumes = d['spec']['template']['spec']['volumes']
for i, v in enumerate(volumes):
    if v['name'] == 'nginx-conf-d':
        print(i)
        break
" 2>/dev/null || echo "")

  MOUNT_INDEX=$(kubectl get deployment "${DEPLOYMENT}" -n "${NAMESPACE}" \
    -o json \
    | python3 -c "
import json, sys
d = json.load(sys.stdin)
mounts = d['spec']['template']['spec']['containers'][0]['volumeMounts']
for i, m in enumerate(mounts):
    if m['name'] == 'nginx-conf-d':
        print(i)
        break
" 2>/dev/null || echo "")

  PATCHES="[]"
  if [[ -n "${VOLUME_INDEX}" ]]; then
    PATCHES=$(echo "${PATCHES}" | python3 -c "
import json, sys
patches = json.load(sys.stdin)
patches.append({'op': 'remove', 'path': '/spec/template/spec/volumes/${VOLUME_INDEX}'})
print(json.dumps(patches))
")
  fi

  if [[ -n "${MOUNT_INDEX}" ]]; then
    PATCHES=$(echo "${PATCHES}" | python3 -c "
import json, sys
patches = json.load(sys.stdin)
patches.append({'op': 'remove', 'path': '/spec/template/spec/containers/0/volumeMounts/${MOUNT_INDEX}'})
print(json.dumps(patches))
")
  fi

  # Re-enable readOnlyRootFilesystem
  PATCHES=$(echo "${PATCHES}" | python3 -c "
import json, sys
patches = json.load(sys.stdin)
patches.append({'op': 'replace', 'path': '/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem', 'value': True})
print(json.dumps(patches))
")

  if [[ "${PATCHES}" != "[]" ]]; then
    kubectl patch deployment "${DEPLOYMENT}" -n "${NAMESPACE}" \
      --type='json' \
      -p="${PATCHES}"

    echo "Patch applied. Waiting for rollout..."
    kubectl rollout status deployment/"${DEPLOYMENT}" \
      -n "${NAMESPACE}" \
      --timeout=120s
    echo "Rollout complete."
  else
    echo "No patches needed — deployment already in original state."
  fi
else
  echo "Break patch not detected — deployment already in original state."
  echo "The config reload above is the active fix. A new pod deployment"
  echo "would restore the image-baked config automatically."
fi

echo ""
echo "=== Fix applied ==="
echo ""
echo "--- Permanent fix reminder ---"
echo ""
echo "The headers are now restored in the running pod. The permanent fix is"
echo "keeping the Dockerfile config intact — which it already is. This scenario"
echo "simulates what happens when the config is overwritten at runtime."
echo ""
echo "To prevent this in production:"
echo "  - Keep readOnlyRootFilesystem: true (already set in Helm values)"
echo "  - Mount /etc/nginx/conf.d/ as readOnly if needed from a ConfigMap"
echo "  - Use a Kyverno policy to detect unexpected pod exec sessions"
echo ""
echo "NEXT STEP: Run verify.sh to confirm all headers are present"
