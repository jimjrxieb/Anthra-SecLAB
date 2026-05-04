#!/usr/bin/env bash
# fix-session-timeout.sh — L5 Session Layer session timeout enforcement
# NIST: AC-12 (session termination), SC-23 (session authenticity)
# Dual-stack: Entra ID (Conditional Access) + Keycloak (realm settings)
# Usage: ./fix-session-timeout.sh [--entra-only | --keycloak-only | --dry-run]
#
# CSF 2.0: PR.AA-06 (Physical access managed)
# CIS v8: 6.2 (Establish Access Revoking Process)
# NIST: AC-12 (Session Termination)
#
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }

MODE="${1:-both}"
DRY_RUN=false
if [[ "$MODE" == "--dry-run" ]]; then
    DRY_RUN=true
    MODE="both"
fi

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/fix-session-timeout-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

KC_URL="${KEYCLOAK_URL:-http://localhost:8080}"
KC_REALM="${KEYCLOAK_REALM:-master}"
KC_TOKEN="${KEYCLOAK_ADMIN_TOKEN:-}"

# Target values
ENTRA_SIGNIN_FREQ_HOURS=8
KC_SSO_IDLE=900      # 15 minutes
KC_SSO_MAX=36000     # 10 hours

echo "======================================================"
echo " L5 Session Timeout Fix — AC-12 / SC-23"
echo " Mode: ${MODE} | Dry-run: ${DRY_RUN}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

# ─── ENTRA ID ─────────────────────────────────────────────────────────────
if [[ "$MODE" != "--keycloak-only" ]]; then
    echo "═══════════════════════════════════════════════════════"
    echo " Entra ID: Sign-in Frequency Conditional Access Policy"
    echo "═══════════════════════════════════════════════════════"

    if ! command -v az &>/dev/null; then
        WARN "az CLI not found — skipping Entra ID"
    elif ! az account show &>/dev/null 2>&1; then
        WARN "Not logged into Azure — run: az login"
    else
        # ── Before state ─────────────────────────────────────────────
        echo "── BEFORE state ─────────────────────────────────────────────"
        BEFORE_POLICIES=$(az rest \
            --method GET \
            --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
            2>/dev/null || echo '{"value": []}')
        echo "$BEFORE_POLICIES" > "${EVIDENCE_DIR}/entra-before-ca-policies.json"

        EXISTING_FREQ_POLICY=$(echo "$BEFORE_POLICIES" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for p in data.get('value', []):
    sc = p.get('sessionControls', {})
    if sc.get('signInFrequency', {}).get('isEnabled'):
        print(p['id'] + '|' + p.get('displayName', 'unnamed'))
        break
print('NONE')
" 2>/dev/null | head -1 || echo "NONE")

        if [[ "$EXISTING_FREQ_POLICY" != "NONE" ]]; then
            POLICY_ID="${EXISTING_FREQ_POLICY%%|*}"
            POLICY_NAME="${EXISTING_FREQ_POLICY##*|}"
            WARN "Existing sign-in frequency policy found: ${POLICY_NAME} (${POLICY_ID})"
            INFO "Will update existing policy rather than creating new one"
        else
            INFO "No existing sign-in frequency policy — will create new one"
        fi
        echo ""

        # ── CA policy JSON payload ────────────────────────────────────
        CA_POLICY_JSON=$(cat <<EOF
{
  "displayName": "Require Sign-in Every ${ENTRA_SIGNIN_FREQ_HOURS} Hours",
  "state": "enabled",
  "conditions": {
    "users": {
      "includeUsers": ["All"],
      "excludeUsers": []
    },
    "applications": {
      "includeApplications": ["All"]
    },
    "clientAppTypes": ["browser", "mobileAppsAndDesktopClients"]
  },
  "sessionControls": {
    "signInFrequency": {
      "value": ${ENTRA_SIGNIN_FREQ_HOURS},
      "type": "hours",
      "isEnabled": true
    },
    "persistentBrowser": {
      "mode": "never",
      "isEnabled": true
    }
  }
}
EOF
)
        echo "$CA_POLICY_JSON" > "${EVIDENCE_DIR}/entra-ca-policy-payload.json"
        INFO "Policy payload saved: ${EVIDENCE_DIR}/entra-ca-policy-payload.json"

        if [[ "$DRY_RUN" == "true" ]]; then
            WARN "[DRY-RUN] Would create/update sign-in frequency CA policy (${ENTRA_SIGNIN_FREQ_HOURS}hr)"
        else
            if [[ "$EXISTING_FREQ_POLICY" != "NONE" ]]; then
                RESULT=$(az rest \
                    --method PATCH \
                    --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/${POLICY_ID}" \
                    --headers "Content-Type=application/json" \
                    --body "$CA_POLICY_JSON" \
                    2>&1 || echo "ERROR")
            else
                RESULT=$(az rest \
                    --method POST \
                    --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
                    --headers "Content-Type=application/json" \
                    --body "$CA_POLICY_JSON" \
                    2>&1 || echo "ERROR")
            fi
            echo "$RESULT" > "${EVIDENCE_DIR}/entra-ca-policy-result.json"

            if echo "$RESULT" | grep -qi "error"; then
                FAIL "Entra ID CA policy create/update failed — check ${EVIDENCE_DIR}/entra-ca-policy-result.json"
            else
                PASS "Entra ID sign-in frequency policy applied (${ENTRA_SIGNIN_FREQ_HOURS}hr)"
            fi
        fi

        # ── After state ──────────────────────────────────────────────
        echo ""
        echo "── AFTER state ──────────────────────────────────────────────"
        if [[ "$DRY_RUN" != "true" ]]; then
            AFTER_POLICIES=$(az rest \
                --method GET \
                --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
                2>/dev/null || echo '{"value": []}')
            echo "$AFTER_POLICIES" > "${EVIDENCE_DIR}/entra-after-ca-policies.json"
            INFO "After state saved: ${EVIDENCE_DIR}/entra-after-ca-policies.json"
        fi
    fi
    echo ""
fi

# ─── KEYCLOAK ─────────────────────────────────────────────────────────────
if [[ "$MODE" != "--entra-only" ]]; then
    echo "═══════════════════════════════════════════════════════"
    echo " Keycloak: Realm SSO Session Timeout"
    echo "═══════════════════════════════════════════════════════"
    INFO "Keycloak URL: ${KC_URL} | Realm: ${KC_REALM}"
    INFO "Target: idle=${KC_SSO_IDLE}s ($(( KC_SSO_IDLE / 60 ))min), max=${KC_SSO_MAX}s ($(( KC_SSO_MAX / 3600 ))hr)"
    echo ""

    if [[ -z "$KC_TOKEN" ]]; then
        KC_TOKEN=$(curl -s -X POST \
            "${KC_URL}/realms/master/protocol/openid-connect/token" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "username=${KEYCLOAK_ADMIN:-admin}" \
            -d "password=${KEYCLOAK_PASSWORD:-admin}" \
            -d "grant_type=password" \
            -d "client_id=admin-cli" \
            2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")
    fi

    if [[ -z "$KC_TOKEN" ]]; then
        WARN "Could not obtain Keycloak admin token — skipping Keycloak fix"
    else
        # ── Before state ─────────────────────────────────────────────
        echo "── BEFORE state ─────────────────────────────────────────────"
        BEFORE_REALM=$(curl -s \
            "${KC_URL}/admin/realms/${KC_REALM}" \
            -H "Authorization: Bearer ${KC_TOKEN}" \
            2>/dev/null || echo '{}')
        echo "$BEFORE_REALM" > "${EVIDENCE_DIR}/keycloak-realm-before.json"

        BEFORE_IDLE=$(echo "$BEFORE_REALM" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('ssoSessionIdleTimeout','NOT_SET'))" 2>/dev/null)
        BEFORE_MAX=$(echo "$BEFORE_REALM" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('ssoSessionMaxLifespan','NOT_SET'))" 2>/dev/null)
        INFO "Before: ssoSessionIdleTimeout=${BEFORE_IDLE}s, ssoSessionMaxLifespan=${BEFORE_MAX}s"
        echo ""

        if [[ "$DRY_RUN" == "true" ]]; then
            WARN "[DRY-RUN] Would set: ssoSessionIdleTimeout=${KC_SSO_IDLE}s, ssoSessionMaxLifespan=${KC_SSO_MAX}s"
        else
            # ── Apply realm settings ──────────────────────────────────
            REALM_UPDATE=$(cat <<EOF
{
  "ssoSessionIdleTimeout": ${KC_SSO_IDLE},
  "ssoSessionMaxLifespan": ${KC_SSO_MAX},
  "accessTokenLifespan": 300,
  "accessCodeLifespan": 60,
  "rememberMe": false
}
EOF
)
            echo "$REALM_UPDATE" > "${EVIDENCE_DIR}/keycloak-realm-update-payload.json"

            HTTP_STATUS=$(curl -s -o "${EVIDENCE_DIR}/keycloak-realm-update-result.txt" -w "%{http_code}" \
                -X PUT \
                "${KC_URL}/admin/realms/${KC_REALM}" \
                -H "Authorization: Bearer ${KC_TOKEN}" \
                -H "Content-Type: application/json" \
                -d "$REALM_UPDATE" \
                2>/dev/null || echo "000")

            if [[ "$HTTP_STATUS" == "204" ]]; then
                PASS "Keycloak realm session timeouts applied (HTTP 204)"
            else
                FAIL "Keycloak realm update failed — HTTP ${HTTP_STATUS}"
                INFO "Check: ${EVIDENCE_DIR}/keycloak-realm-update-result.txt"
            fi

            # ── After state ──────────────────────────────────────────
            echo ""
            echo "── AFTER state ──────────────────────────────────────────────"
            AFTER_REALM=$(curl -s \
                "${KC_URL}/admin/realms/${KC_REALM}" \
                -H "Authorization: Bearer ${KC_TOKEN}" \
                2>/dev/null || echo '{}')
            echo "$AFTER_REALM" > "${EVIDENCE_DIR}/keycloak-realm-after.json"

            AFTER_IDLE=$(echo "$AFTER_REALM" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('ssoSessionIdleTimeout','NOT_SET'))" 2>/dev/null)
            AFTER_MAX=$(echo "$AFTER_REALM" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('ssoSessionMaxLifespan','NOT_SET'))" 2>/dev/null)
            INFO "After: ssoSessionIdleTimeout=${AFTER_IDLE}s, ssoSessionMaxLifespan=${AFTER_MAX}s"

            if [[ "$AFTER_IDLE" == "$KC_SSO_IDLE" && "$AFTER_MAX" == "$KC_SSO_MAX" ]]; then
                PASS "Keycloak session timeouts verified correct"
            else
                WARN "Keycloak values may not have applied as expected — check after state"
            fi
        fi
    fi
fi

# ─── Summary ──────────────────────────────────────────────────────────────
echo ""
echo "======================================================"
echo " Session Timeout Fix Summary"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""
INFO "Entra ID — before: ${EVIDENCE_DIR}/entra-before-ca-policies.json"
INFO "Entra ID — after:  ${EVIDENCE_DIR}/entra-after-ca-policies.json"
INFO "Keycloak  — before: ${EVIDENCE_DIR}/keycloak-realm-before.json"
INFO "Keycloak  — after:  ${EVIDENCE_DIR}/keycloak-realm-after.json"
