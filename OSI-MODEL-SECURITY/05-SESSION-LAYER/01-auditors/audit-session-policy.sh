#!/usr/bin/env bash
# audit-session-policy.sh — L5 Session Layer dual-stack session policy audit
# NIST: AC-12 (session termination), SC-23 (session authenticity), IA-8 (non-org users)
# Usage: ./audit-session-policy.sh [--entra-only | --keycloak-only]
#        KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_ADMIN_TOKEN env vars for Keycloak
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }

MODE="${1:-both}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/session-policy-audit-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

# Keycloak connection (override via env)
KC_URL="${KEYCLOAK_URL:-http://localhost:8080}"
KC_REALM="${KEYCLOAK_REALM:-master}"
KC_TOKEN="${KEYCLOAK_ADMIN_TOKEN:-}"

echo "======================================================"
echo " L5 Session Policy Audit — AC-12 / SC-23 / IA-8"
echo " Mode: ${MODE}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

FINDINGS=0

# ─── ENTRA ID (Azure AD) ──────────────────────────────────────────────────
if [[ "$MODE" != "--keycloak-only" ]]; then
    echo "═══════════════════════════════════════════════════════"
    echo " Entra ID / Azure AD Session Policy"
    echo "═══════════════════════════════════════════════════════"

    # Check az CLI available and logged in
    if ! command -v az &>/dev/null; then
        WARN "az CLI not found — skipping Entra ID checks"
        INFO "Install: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    elif ! az account show &>/dev/null 2>&1; then
        WARN "Not logged into Azure — run: az login"
        INFO "Skipping Entra ID checks"
    else
        INFO "Azure CLI authenticated"
        TENANT=$(az account show --query tenantId -o tsv 2>/dev/null || echo "unknown")
        INFO "Tenant: ${TENANT}"
        echo ""

        # ── 1. Conditional Access policies ──────────────────────────────
        echo "── Entra ID: Conditional Access Policies ────────────────────"
        CA_POLICIES=$(az rest \
            --method GET \
            --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
            --headers "Content-Type=application/json" \
            2>/dev/null || echo '{"error": "CA policies not accessible"}')
        echo "$CA_POLICIES" > "${EVIDENCE_DIR}/entra-ca-policies.json"

        CA_COUNT=$(echo "$CA_POLICIES" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('value',[])))" 2>/dev/null || echo "0")
        INFO "Conditional Access policies found: ${CA_COUNT}"

        if [[ "$CA_COUNT" == "0" ]]; then
            FAIL "No Conditional Access policies found — AC-12/IA-2 controls missing"
            FINDINGS=$((FINDINGS + 1))
        else
            # Parse and report policy states
            echo "$CA_POLICIES" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for p in data.get('value', []):
    state = p.get('state', 'unknown')
    name = p.get('displayName', 'unnamed')
    icon = '[ENABLED]' if state == 'enabled' else '[REPORT]' if state == 'enabledForReportingButNotEnforced' else '[DISABLED]'
    print(f'{icon} {name} (state: {state})')
" 2>/dev/null || INFO "Could not parse CA policies"
        fi
        echo ""

        # ── 2. Sign-in frequency (session control) ───────────────────────
        echo "── Entra ID: Sign-in Frequency Policies ─────────────────────"
        SIGN_IN_FREQ=$(echo "$CA_POLICIES" | python3 -c "
import json, sys
data = json.load(sys.stdin)
found = []
for p in data.get('value', []):
    sc = p.get('sessionControls', {})
    sif = sc.get('signInFrequency', {})
    if sif.get('isEnabled'):
        value = sif.get('value', '?')
        unit = sif.get('type', '?')
        name = p.get('displayName', 'unnamed')
        found.append(f'{name}: every {value} {unit}')
if found:
    for f in found: print(f'FOUND: {f}')
else:
    print('MISSING')
" 2>/dev/null || echo "PARSE_ERROR")

        echo "$SIGN_IN_FREQ" > "${EVIDENCE_DIR}/entra-signin-frequency.txt"

        if echo "$SIGN_IN_FREQ" | grep -q "MISSING"; then
            FAIL "No sign-in frequency policy found — sessions may persist indefinitely"
            INFO "WHY: NIST AC-12 requires session termination after defined conditions"
            FINDINGS=$((FINDINGS + 1))
        elif echo "$SIGN_IN_FREQ" | grep -q "PARSE_ERROR"; then
            WARN "Could not parse sign-in frequency policies"
        else
            while IFS= read -r line; do
                PASS "$line"
            done <<< "$SIGN_IN_FREQ"
        fi
        echo ""

        # ── 3. Persistent browser session setting ────────────────────────
        echo "── Entra ID: Persistent Browser Session ─────────────────────"
        PBS=$(echo "$CA_POLICIES" | python3 -c "
import json, sys
data = json.load(sys.stdin)
found = []
for p in data.get('value', []):
    sc = p.get('sessionControls', {})
    pbs = sc.get('persistentBrowser', {})
    if pbs.get('isEnabled'):
        mode = pbs.get('mode', '?')
        name = p.get('displayName', 'unnamed')
        found.append(f'{name}: mode={mode}')
if found:
    for f in found: print(f'FOUND: {f}')
else:
    print('MISSING')
" 2>/dev/null || echo "PARSE_ERROR")

        echo "$PBS" > "${EVIDENCE_DIR}/entra-persistent-browser.txt"

        if echo "$PBS" | grep -q "MISSING"; then
            WARN "No persistent browser session policy found — sessions may persist in shared devices"
            FINDINGS=$((FINDINGS + 1))
        else
            while IFS= read -r line; do
                PASS "$line"
            done <<< "$PBS"
        fi
        echo ""
    fi
fi

# ─── KEYCLOAK ─────────────────────────────────────────────────────────────
if [[ "$MODE" != "--entra-only" ]]; then
    echo "═══════════════════════════════════════════════════════"
    echo " Keycloak Session Policy"
    echo "═══════════════════════════════════════════════════════"
    INFO "Keycloak URL: ${KC_URL}"
    INFO "Realm: ${KC_REALM}"
    echo ""

    if [[ -z "$KC_TOKEN" ]]; then
        WARN "KEYCLOAK_ADMIN_TOKEN not set — attempting token request with defaults"
        KC_TOKEN=$(curl -s -X POST \
            "${KC_URL}/realms/master/protocol/openid-connect/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "username=${KEYCLOAK_ADMIN:-admin}" \
            -d "password=${KEYCLOAK_PASSWORD:-admin}" \
            -d "grant_type=password" \
            -d "client_id=admin-cli" \
            2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")
        if [[ -z "$KC_TOKEN" ]]; then
            WARN "Could not obtain Keycloak admin token — skipping Keycloak checks"
            INFO "Set: export KEYCLOAK_ADMIN_TOKEN=<token>"
        fi
    fi

    if [[ -n "$KC_TOKEN" ]]; then
        # ── 1. Realm SSO session settings ──────────────────────────────
        echo "── Keycloak: Realm SSO Session Settings ─────────────────────"
        REALM_DATA=$(curl -s \
            "${KC_URL}/admin/realms/${KC_REALM}" \
            -H "Authorization: Bearer ${KC_TOKEN}" \
            -H "Content-Type: application/json" \
            2>/dev/null || echo '{}')
        echo "$REALM_DATA" > "${EVIDENCE_DIR}/keycloak-realm.json"

        SSO_IDLE=$(echo "$REALM_DATA" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('ssoSessionIdleTimeout', 'NOT_SET'))" 2>/dev/null || echo "PARSE_ERROR")
        SSO_MAX=$(echo "$REALM_DATA" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('ssoSessionMaxLifespan', 'NOT_SET'))" 2>/dev/null || echo "PARSE_ERROR")
        REMEMBER_ME=$(echo "$REALM_DATA" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('rememberMe', 'PARSE_ERROR'))" 2>/dev/null || echo "PARSE_ERROR")

        # SSO idle timeout check (target: ≤1800 seconds / 30 minutes)
        if [[ "$SSO_IDLE" == "NOT_SET" || "$SSO_IDLE" == "PARSE_ERROR" ]]; then
            WARN "ssoSessionIdleTimeout: ${SSO_IDLE}"
            FINDINGS=$((FINDINGS + 1))
        elif [[ "$SSO_IDLE" -gt 1800 ]]; then
            FAIL "ssoSessionIdleTimeout: ${SSO_IDLE}s (${SSO_IDLE}/60=$(( SSO_IDLE / 60 ))min) — exceeds 30min target"
            INFO "WHY: NIST AC-12 — idle sessions should terminate after inactivity"
            FINDINGS=$((FINDINGS + 1))
        else
            PASS "ssoSessionIdleTimeout: ${SSO_IDLE}s ($(( SSO_IDLE / 60 ))min) — compliant"
        fi

        # SSO max lifespan check (target: ≤36000 seconds / 10 hours)
        if [[ "$SSO_MAX" == "NOT_SET" || "$SSO_MAX" == "PARSE_ERROR" ]]; then
            WARN "ssoSessionMaxLifespan: ${SSO_MAX}"
            FINDINGS=$((FINDINGS + 1))
        elif [[ "$SSO_MAX" -gt 36000 ]]; then
            FAIL "ssoSessionMaxLifespan: ${SSO_MAX}s ($(( SSO_MAX / 3600 ))hr) — exceeds 10hr target"
            FINDINGS=$((FINDINGS + 1))
        else
            PASS "ssoSessionMaxLifespan: ${SSO_MAX}s ($(( SSO_MAX / 3600 ))hr) — compliant"
        fi

        # Remember-me check
        if [[ "$REMEMBER_ME" == "True" || "$REMEMBER_ME" == "true" ]]; then
            WARN "rememberMe: enabled — users can create persistent sessions"
            INFO "WHY: Remember-me creates long-lived sessions that bypass AC-12 controls"
            FINDINGS=$((FINDINGS + 1))
        else
            PASS "rememberMe: disabled"
        fi
        echo ""

        # ── 2. Brute force detection ────────────────────────────────────
        echo "── Keycloak: Brute Force Detection ──────────────────────────"
        BF_ENABLED=$(echo "$REALM_DATA" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('bruteForceProtected', False))" 2>/dev/null || echo "false")
        BF_FAILURES=$(echo "$REALM_DATA" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('failureFactor', 'NOT_SET'))" 2>/dev/null || echo "NOT_SET")
        BF_WAIT=$(echo "$REALM_DATA" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('waitIncrementSeconds', 'NOT_SET'))" 2>/dev/null || echo "NOT_SET")

        if [[ "$BF_ENABLED" == "True" || "$BF_ENABLED" == "true" ]]; then
            PASS "Brute force protection: enabled (failures: ${BF_FAILURES}, wait: ${BF_WAIT}s)"
        else
            FAIL "Brute force protection: DISABLED"
            INFO "WHY: Without brute force protection, password spray attacks are uninhibited"
            FINDINGS=$((FINDINGS + 1))
        fi
        echo ""
    fi
fi

# ─── Gap Summary ──────────────────────────────────────────────────────────
echo "======================================================"
echo " Session Policy Audit Summary"
echo " Total findings: ${FINDINGS}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"

cat > "${EVIDENCE_DIR}/summary.txt" <<EOF
L5 Session Policy Audit Summary
Date: $(date)
Mode: ${MODE}
Total Findings: ${FINDINGS}

Files:
- entra-ca-policies.json: Conditional Access policy dump
- entra-signin-frequency.txt: Sign-in frequency policy check
- entra-persistent-browser.txt: Persistent browser session check
- keycloak-realm.json: Realm configuration dump
EOF

if [[ $FINDINGS -gt 0 ]]; then
    echo ""
    WARN "Remediation: see 02-fixers/fix-session-timeout.sh"
fi
