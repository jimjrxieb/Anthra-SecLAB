#!/usr/bin/env bash
# audit-mfa-status.sh — L5 Session Layer dual-stack MFA coverage audit
# NIST: IA-2 (identification/authentication), IA-8 (non-org users), AC-7 (unsuccessful login attempts)
# Usage: ./audit-mfa-status.sh [--entra-only | --keycloak-only]
#        KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_ADMIN_TOKEN env vars for Keycloak
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }

MODE="${1:-both}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/mfa-audit-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

KC_URL="${KEYCLOAK_URL:-http://localhost:8080}"
KC_REALM="${KEYCLOAK_REALM:-master}"
KC_TOKEN="${KEYCLOAK_ADMIN_TOKEN:-}"

echo "======================================================"
echo " L5 MFA Status Audit — IA-2 / IA-8 / AC-7"
echo " Mode: ${MODE}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

FINDINGS=0

# ─── ENTRA ID ─────────────────────────────────────────────────────────────
if [[ "$MODE" != "--keycloak-only" ]]; then
    echo "═══════════════════════════════════════════════════════"
    echo " Entra ID / Azure AD MFA Status"
    echo "═══════════════════════════════════════════════════════"

    if ! command -v az &>/dev/null; then
        WARN "az CLI not found — skipping Entra ID MFA check"
    elif ! az account show &>/dev/null 2>&1; then
        WARN "Not logged into Azure — run: az login"
    else
        INFO "Azure CLI authenticated"
        echo ""

        # ── 1. User list ──────────────────────────────────────────────
        echo "── Entra ID: User Inventory ──────────────────────────────────"
        USER_LIST=$(az ad user list \
            --query "[].{id:id, upn:userPrincipalName, displayName:displayName, accountEnabled:accountEnabled}" \
            -o json 2>/dev/null || echo '[]')
        echo "$USER_LIST" > "${EVIDENCE_DIR}/entra-users.json"

        TOTAL_USERS=$(echo "$USER_LIST" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
        ENABLED_USERS=$(echo "$USER_LIST" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len([u for u in d if u.get('accountEnabled')]))" 2>/dev/null || echo "0")
        INFO "Total users: ${TOTAL_USERS} | Enabled: ${ENABLED_USERS}"
        echo ""

        # ── 2. Authentication methods per user ────────────────────────
        echo "── Entra ID: MFA Registration Check ─────────────────────────"
        INFO "Checking authentication methods (requires Microsoft.Graph/User.Read.All)"
        INFO "Note: This requires Azure AD Premium P1 or higher for full reporting"

        MFA_REPORT=$(az rest \
            --method GET \
            --url "https://graph.microsoft.com/v1.0/reports/credentialUserRegistrationDetails" \
            --headers "Content-Type=application/json" \
            2>/dev/null || echo '{"error": "Report not accessible — requires Reports.Read.All permission"}')
        echo "$MFA_REPORT" > "${EVIDENCE_DIR}/entra-mfa-registration.json"

        if echo "$MFA_REPORT" | grep -q '"error"'; then
            WARN "MFA registration report not accessible"
            INFO "Alternative: az rest --url 'https://graph.microsoft.com/v1.0/users/{id}/authentication/methods'"
            INFO "Check Azure AD > Users > Authentication methods activity report in portal"
        else
            WITHOUT_MFA=$(echo "$MFA_REPORT" | python3 -c "
import json, sys
data = json.load(sys.stdin)
no_mfa = []
total = 0
for u in data.get('value', []):
    total += 1
    if not u.get('isMfaRegistered', False):
        no_mfa.append(u.get('userPrincipalName', 'unknown'))
pct = round((total - len(no_mfa)) / total * 100, 1) if total > 0 else 0
print(f'TOTAL:{total}')
print(f'WITHOUT_MFA:{len(no_mfa)}')
print(f'PERCENT_WITH_MFA:{pct}')
for u in no_mfa[:20]:  # cap at 20 for output
    print(f'NO_MFA:{u}')
" 2>/dev/null || echo "PARSE_ERROR")

            echo "$WITHOUT_MFA" > "${EVIDENCE_DIR}/entra-users-without-mfa.txt"

            TOTAL=$(echo "$WITHOUT_MFA" | grep "^TOTAL:" | cut -d: -f2 || echo "?")
            NO_MFA_COUNT=$(echo "$WITHOUT_MFA" | grep "^WITHOUT_MFA:" | cut -d: -f2 || echo "?")
            PCT=$(echo "$WITHOUT_MFA" | grep "^PERCENT_WITH_MFA:" | cut -d: -f2 || echo "?")

            INFO "Total users in report: ${TOTAL}"
            INFO "Users without MFA: ${NO_MFA_COUNT}"
            INFO "MFA coverage: ${PCT}%"

            if [[ "$NO_MFA_COUNT" == "0" ]]; then
                PASS "All users have MFA registered (${PCT}% coverage)"
            else
                FAIL "MFA coverage: ${PCT}% — ${NO_MFA_COUNT} user(s) missing MFA"
                INFO "WHY: Microsoft reports 99.9% of compromised accounts lacked MFA (IA-2)"
                FINDINGS=$((FINDINGS + 1))
                echo "Users without MFA (first 20):"
                echo "$WITHOUT_MFA" | grep "^NO_MFA:" | sed 's/^NO_MFA:/  - /'
            fi
        fi
        echo ""

        # ── 3. Check for MFA enforcement CA policy ────────────────────
        echo "── Entra ID: MFA Enforcement Policy Check ───────────────────"
        CA_POLICIES=$(az rest \
            --method GET \
            --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
            2>/dev/null || echo '{"value": []}')

        MFA_POLICY=$(echo "$CA_POLICIES" | python3 -c "
import json, sys
data = json.load(sys.stdin)
mfa_policies = []
for p in data.get('value', []):
    grant = p.get('grantControls', {})
    if grant and 'mfa' in grant.get('builtInControls', []):
        state = p.get('state', 'unknown')
        name = p.get('displayName', 'unnamed')
        mfa_policies.append(f'{name} (state: {state})')
if mfa_policies:
    for pol in mfa_policies: print(f'FOUND:{pol}')
else:
    print('MISSING')
" 2>/dev/null || echo "PARSE_ERROR")

        echo "$MFA_POLICY" > "${EVIDENCE_DIR}/entra-mfa-ca-policy.txt"

        if echo "$MFA_POLICY" | grep -q "^MISSING"; then
            FAIL "No Conditional Access policy enforcing MFA found"
            INFO "WHY: MFA registration without enforcement = optional MFA"
            FINDINGS=$((FINDINGS + 1))
        elif echo "$MFA_POLICY" | grep -q "^PARSE_ERROR"; then
            WARN "Could not parse CA policies for MFA check"
        else
            while IFS= read -r line; do
                POLICY_NAME="${line#FOUND:}"
                if echo "$POLICY_NAME" | grep -q "state: enabled"; then
                    PASS "MFA CA policy (enabled): ${POLICY_NAME}"
                else
                    WARN "MFA CA policy (not enforced): ${POLICY_NAME}"
                    FINDINGS=$((FINDINGS + 1))
                fi
            done <<< "$(echo "$MFA_POLICY" | grep "^FOUND:")"
        fi
        echo ""
    fi
fi

# ─── KEYCLOAK ─────────────────────────────────────────────────────────────
if [[ "$MODE" != "--entra-only" ]]; then
    echo "═══════════════════════════════════════════════════════"
    echo " Keycloak MFA / TOTP Status"
    echo "═══════════════════════════════════════════════════════"
    INFO "Keycloak URL: ${KC_URL} | Realm: ${KC_REALM}"
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
        WARN "Could not obtain Keycloak admin token — skipping Keycloak MFA check"
    else
        # ── 1. Required actions (realm-level TOTP enforcement) ────────
        echo "── Keycloak: Required Actions (TOTP) ────────────────────────"
        REALM_DATA=$(curl -s \
            "${KC_URL}/admin/realms/${KC_REALM}" \
            -H "Authorization: Bearer ${KC_TOKEN}" \
            2>/dev/null || echo '{}')
        echo "$REALM_DATA" > "${EVIDENCE_DIR}/keycloak-realm.json"

        REQUIRED_ACTIONS=$(echo "$REALM_DATA" | python3 -c "
import json, sys
d = json.load(sys.stdin)
actions = d.get('requiredActions', [])
print(json.dumps(actions, indent=2))
" 2>/dev/null || echo "[]")
        echo "$REQUIRED_ACTIONS" > "${EVIDENCE_DIR}/keycloak-required-actions.json"

        TOTP_REQUIRED=$(echo "$REALM_DATA" | python3 -c "
import json, sys
d = json.load(sys.stdin)
actions = d.get('requiredActions', [])
for a in actions:
    if a.get('alias') == 'CONFIGURE_TOTP' and a.get('defaultAction', False):
        print('ENFORCED')
        import sys; sys.exit()
print('NOT_ENFORCED')
" 2>/dev/null || echo "PARSE_ERROR")

        if [[ "$TOTP_REQUIRED" == "ENFORCED" ]]; then
            PASS "CONFIGURE_TOTP is a default required action (enforced for new users)"
        else
            FAIL "CONFIGURE_TOTP is NOT a default required action"
            INFO "WHY: Without TOTP as required action, users can skip MFA setup"
            FINDINGS=$((FINDINGS + 1))
        fi
        echo ""

        # ── 2. Users without TOTP credentials ─────────────────────────
        echo "── Keycloak: Users Without TOTP Configured ──────────────────"
        KC_USERS=$(curl -s \
            "${KC_URL}/admin/realms/${KC_REALM}/users?max=500" \
            -H "Authorization: Bearer ${KC_TOKEN}" \
            2>/dev/null || echo '[]')
        echo "$KC_USERS" > "${EVIDENCE_DIR}/keycloak-users.json"

        USER_COUNT=$(echo "$KC_USERS" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
        INFO "Total Keycloak users in realm: ${USER_COUNT}"

        # Check each user for TOTP credentials (sample first 50 to avoid rate limiting)
        NO_TOTP=0
        TOTP_USERS=0
        SAMPLE_NO_TOTP=()

        while IFS= read -r USER_ID; do
            CREDS=$(curl -s \
                "${KC_URL}/admin/realms/${KC_REALM}/users/${USER_ID}/credentials" \
                -H "Authorization: Bearer ${KC_TOKEN}" \
                2>/dev/null || echo '[]')
            HAS_TOTP=$(echo "$CREDS" | python3 -c "
import json, sys
creds = json.load(sys.stdin)
print('yes' if any(c.get('type') == 'otp' for c in creds) else 'no')
" 2>/dev/null || echo "unknown")
            if [[ "$HAS_TOTP" == "no" ]]; then
                NO_TOTP=$((NO_TOTP + 1))
                # Get username for first few
                if [[ ${#SAMPLE_NO_TOTP[@]} -lt 10 ]]; then
                    USERNAME=$(echo "$KC_USERS" | python3 -c "
import json, sys
users = json.load(sys.stdin)
for u in users:
    if u.get('id') == '${USER_ID}':
        print(u.get('username', u.get('id', 'unknown')))
        break
" 2>/dev/null || echo "$USER_ID")
                    SAMPLE_NO_TOTP+=("$USERNAME")
                fi
            else
                TOTP_USERS=$((TOTP_USERS + 1))
            fi
        done < <(echo "$KC_USERS" | python3 -c "
import json, sys
users = json.load(sys.stdin)
for u in users[:50]:  # sample first 50
    print(u['id'])
" 2>/dev/null || echo "")

        TOTAL_CHECKED=$((NO_TOTP + TOTP_USERS))
        if [[ $TOTAL_CHECKED -gt 0 ]]; then
            PCT_TOTP=$(( TOTP_USERS * 100 / TOTAL_CHECKED ))
            INFO "Sampled ${TOTAL_CHECKED} users: ${TOTP_USERS} have TOTP, ${NO_TOTP} do not"
            INFO "TOTP coverage (sampled): ${PCT_TOTP}%"

            if [[ $NO_TOTP -eq 0 ]]; then
                PASS "All sampled users have TOTP configured"
            else
                FAIL "Users without TOTP (sampled): ${NO_TOTP}"
                for u in "${SAMPLE_NO_TOTP[@]:-}"; do
                    INFO "  - $u"
                done
                FINDINGS=$((FINDINGS + 1))
            fi
        fi
        echo ""
    fi
fi

# ─── Summary ──────────────────────────────────────────────────────────────
echo "======================================================"
echo " MFA Audit Summary"
echo " Total findings: ${FINDINGS}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"

cat > "${EVIDENCE_DIR}/summary.txt" <<EOF
L5 MFA Status Audit Summary
Date: $(date)
Mode: ${MODE}
Total Findings: ${FINDINGS}

Files:
- entra-users.json: Entra ID user list
- entra-mfa-registration.json: MFA registration report
- entra-users-without-mfa.txt: Users missing MFA
- entra-mfa-ca-policy.txt: CA policy MFA enforcement check
- keycloak-realm.json: Realm config (required actions)
- keycloak-required-actions.json: Required actions list
- keycloak-users.json: Keycloak user list
EOF

if [[ $FINDINGS -gt 0 ]]; then
    echo ""
    WARN "Remediation: see 02-fixers/fix-mfa-enforcement.md"
fi
