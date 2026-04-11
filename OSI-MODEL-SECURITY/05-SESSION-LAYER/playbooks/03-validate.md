# 03-validate.md — L5 Session Layer Validation

| Field | Value |
|---|---|
| **NIST Controls** | AC-2, AC-6, AC-12, IA-2, SC-23 |
| **Tools** | All auditors, kubectl auth can-i, az CLI, Keycloak admin |
| **Time** | 1 hour |
| **Rank** | D (re-run auditors, compare before/after) |

---

## Purpose

Re-run all auditors after remediation and verify that findings are resolved. Compare before/after states from the evidence directories. Archive for compliance record-keeping.

---

## Step 1: Re-run All Auditors

```bash
# Run all auditors and save output
VALIDATE_DIR="/tmp/jsa-evidence/l5-validation-$(date +%Y%m%d)"
mkdir -p "${VALIDATE_DIR}"

./01-auditors/audit-rbac-privileges.sh default 2>&1 | tee "${VALIDATE_DIR}/rbac-after.txt"
./01-auditors/audit-service-accounts.sh default 2>&1 | tee "${VALIDATE_DIR}/sa-after.txt"
./01-auditors/audit-session-policy.sh 2>&1 | tee "${VALIDATE_DIR}/session-policy-after.txt"
./01-auditors/audit-mfa-status.sh 2>&1 | tee "${VALIDATE_DIR}/mfa-after.txt"
```

---

## Step 2: Verify MFA Coverage Improved

```bash
# Check Entra ID MFA coverage
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/reports/credentialUserRegistrationDetails" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
users = data.get('value', [])
total = len(users)
registered = sum(1 for u in users if u.get('isMfaRegistered'))
pct = registered / total * 100 if total > 0 else 0
print(f'MFA coverage: {registered}/{total} = {pct:.1f}%')
if pct >= 95:
    print('PASS: MFA coverage ≥95%')
elif pct >= 80:
    print('WARN: MFA coverage between 80-95% — continue pushing to remaining users')
else:
    print('FAIL: MFA coverage <80% — significant exposure remains')
" 2>/dev/null || echo "Check portal for MFA registration report"

# Check Keycloak TOTP coverage
KC_URL="${KEYCLOAK_URL:-http://localhost:8080}"
KC_REALM="${KEYCLOAK_REALM:-master}"
KC_TOKEN="${KEYCLOAK_ADMIN_TOKEN:-}"

if [[ -n "$KC_TOKEN" ]]; then
    curl -s "${KC_URL}/admin/realms/${KC_REALM}/authentication/required-actions/CONFIGURE_TOTP" \
      -H "Authorization: Bearer ${KC_TOKEN}" \
      | python3 -c "
import json, sys
d = json.load(sys.stdin)
default = d.get('defaultAction', False)
enabled = d.get('enabled', False)
print(f'CONFIGURE_TOTP — enabled: {enabled}, defaultAction: {default}')
if default and enabled:
    print('PASS: TOTP is a default required action')
else:
    print('FAIL: TOTP is not enforced as default action')
"
fi
```

---

## Step 3: Test Session Timeout

### Keycloak idle timeout test

```bash
KC_URL="${KEYCLOAK_URL:-http://localhost:8080}"
KC_REALM="${KEYCLOAK_REALM:-master}"

# Get a session token
TOKENS=$(curl -s -X POST \
  "${KC_URL}/realms/${KC_REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=testpass&grant_type=password&client_id=account-console")

ACCESS_TOKEN=$(echo "$TOKENS" | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token','ERROR'))")

if [[ "$ACCESS_TOKEN" == "ERROR" ]]; then
    echo "WARN: Could not obtain test token — check credentials"
else
    # Decode and check expiry
    echo "$ACCESS_TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -c "
import json, sys, datetime
d = json.load(sys.stdin)
exp = d.get('exp')
iat = d.get('iat')
if exp and iat:
    lifetime = exp - iat
    print(f'Access token lifetime: {lifetime}s ({lifetime/60:.1f}min)')
    if lifetime <= 300:
        print('PASS: Access token ≤5 minutes')
    else:
        print(f'WARN: Access token {lifetime}s — target ≤300s')
"
fi

# Note: Full idle timeout test requires waiting the configured idle period (900s = 15min)
# Manual test: log in, wait 16 minutes without activity, attempt to use the session — should prompt for re-auth
```

---

## Step 4: Verify RBAC Changes

```bash
NAMESPACE="default"

echo "=== K8s RBAC Verification ==="
echo ""
echo "1. Cluster-admin bindings:"
kubectl get clusterrolebindings -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
found = False
for item in data.get('items', []):
    if item.get('roleRef', {}).get('name') == 'cluster-admin':
        for s in item.get('subjects', []):
            if s.get('kind') == 'ServiceAccount':
                print(f'  WARN: SA {s.get(\"namespace\",\"?\")} / {s.get(\"name\",\"?\")} still has cluster-admin')
                found = True
if not found:
    print('  PASS: No service accounts with cluster-admin CRBs')
"

echo ""
echo "2. Default SA automount:"
kubectl get serviceaccount default -n "${NAMESPACE}" \
  -o jsonpath='{.automountServiceAccountToken}' 2>/dev/null
echo " (should be false)"

echo ""
echo "3. kubectl auth can-i tests (default SA):"
for OP in "create deployments" "delete pods" "get secrets" "create clusterrolebindings"; do
    VERB="${OP%% *}"
    RESOURCE="${OP##* }"
    RESULT=$(kubectl auth can-i "${VERB}" "${RESOURCE}" \
        --namespace "${NAMESPACE}" \
        --as "system:serviceaccount:${NAMESPACE}:default" \
        2>/dev/null || echo "no")
    STATUS="[PASS]"
    [[ "$RESULT" == "yes" ]] && STATUS="[FAIL]"
    echo "  ${STATUS} can-i ${OP}: ${RESULT}"
done
```

---

## Step 5: Evidence Archive

```bash
ARCHIVE_DATE=$(date +%Y%m%d)
ARCHIVE_DIR="${HOME}/evidence/l5-session-layer"
mkdir -p "${ARCHIVE_DIR}"

# Collect all evidence from /tmp/jsa-evidence/
tar -czf "${ARCHIVE_DIR}/l5-evidence-${ARCHIVE_DATE}.tar.gz" \
  /tmp/jsa-evidence/rbac-audit-* \
  /tmp/jsa-evidence/sa-audit-* \
  /tmp/jsa-evidence/session-policy-audit-* \
  /tmp/jsa-evidence/mfa-audit-* \
  /tmp/jsa-evidence/fix-rbac-* \
  /tmp/jsa-evidence/fix-session-timeout-* \
  /tmp/jsa-evidence/mfa-fix-* \
  /tmp/jsa-evidence/l5-validation-* \
  2>/dev/null || true

ls -lh "${ARCHIVE_DIR}/"
echo ""
echo "Evidence archived: ${ARCHIVE_DIR}/l5-evidence-${ARCHIVE_DATE}.tar.gz"
echo ""
echo "Next: 04-triage-alerts.md — configure daily alert monitoring"
```
