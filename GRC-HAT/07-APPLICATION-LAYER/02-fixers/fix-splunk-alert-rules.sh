#!/usr/bin/env bash
# fix-splunk-alert-rules.sh — Deploy Splunk correlation searches from template
# NIST: AU-6 (audit review), SI-4 (information system monitoring)
# Usage: ./fix-splunk-alert-rules.sh [--dry-run]
#
# CSF 2.0: DE.AE-02 (Adverse events analyzed)
# CIS v8: 8.11 (Tune SIEM Alert Thresholds)
# NIST: AU-6 (Audit Review)
#
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }
SECTION() { echo -e "\n${BLUE}═══ $* ═══${NC}"; }

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_FILE="${SCRIPT_DIR}/../03-templates/splunk/savedsearches.conf"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/splunk-rules-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================"
echo " Splunk Alert Rules Deployment — AU-6 / SI-4"
echo " Template: ${TEMPLATE_FILE}"
echo " Dry run: ${DRY_RUN}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

SPLUNK_HOST="${SPLUNK_HOST:-localhost}"
SPLUNK_PORT="${SPLUNK_MGMT_PORT:-8089}"
SPLUNK_USER="${SPLUNK_USER:-admin}"
SPLUNK_PASS="${SPLUNK_PASS:-}"
SPLUNK_APP="${SPLUNK_APP:-search}"

# Local Splunk install path (for direct file deployment)
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
SAVEDSEARCHES_PATH="${SPLUNK_HOME}/etc/apps/${SPLUNK_APP}/local/savedsearches.conf"

if [[ ! -f "$TEMPLATE_FILE" ]]; then
    FAIL "Template not found: $TEMPLATE_FILE"
    INFO "Run from 02-fixers/ directory or ensure 03-templates/splunk/savedsearches.conf exists"
    exit 1
fi

SECTION "Pre-deployment: Backup existing searches"

# Backup via REST API
if [[ -n "$SPLUNK_PASS" ]]; then
    if curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
        "https://${SPLUNK_HOST}:${SPLUNK_PORT}/services/saved/searches?output_mode=json&count=0" \
        > "$EVIDENCE_DIR/before-saved-searches.json" 2>/dev/null; then
        BEFORE_COUNT=$(jq '.entry | length' "$EVIDENCE_DIR/before-saved-searches.json" 2>/dev/null || echo "0")
        PASS "Pre-deployment backup: $BEFORE_COUNT existing saved searches"
    else
        WARN "Could not backup via REST API — continuing"
    fi
elif [[ -f "$SAVEDSEARCHES_PATH" ]]; then
    cp "$SAVEDSEARCHES_PATH" "$EVIDENCE_DIR/savedsearches.conf.before" 2>/dev/null || true
    PASS "Backed up existing savedsearches.conf"
fi

SECTION "Deploying Splunk Correlation Searches"

if $DRY_RUN; then
    WARN "DRY RUN MODE — no changes will be made"
    echo ""
    echo "Would deploy the following searches from template:"
    grep "^\[" "$TEMPLATE_FILE" | grep -v "^\[default\]" | sed 's/\[//;s/\]//' | while read -r NAME; do
        echo "  - $NAME"
    done
    echo ""
    INFO "Re-run without --dry-run to apply"
    exit 0
fi

# Method 1: REST API deployment (preferred — no Splunk restart required)
deploy_via_rest() {
    local SEARCH_NAME="$1"
    local SEARCH_QUERY="$2"
    local CRON="$3"
    local SEVERITY="$4"
    local SUPPRESS="$5"

    echo "Deploying: $SEARCH_NAME"

    RESPONSE=$(curl -sk -o /dev/null -w "%{http_code}" \
        -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
        -X POST \
        "https://${SPLUNK_HOST}:${SPLUNK_PORT}/servicesNS/${SPLUNK_USER}/${SPLUNK_APP}/saved/searches" \
        --data-urlencode "name=${SEARCH_NAME}" \
        --data-urlencode "search=${SEARCH_QUERY}" \
        --data-urlencode "cron_schedule=${CRON}" \
        --data-urlencode "is_scheduled=1" \
        --data-urlencode "disabled=0" \
        --data-urlencode "alert_type=number of events" \
        --data-urlencode "alert_comparator=greater than" \
        --data-urlencode "alert_threshold=0" \
        --data-urlencode "alert.severity=${SEVERITY}" \
        --data-urlencode "suppress=${SUPPRESS}" 2>/dev/null)

    if [[ "$RESPONSE" == "201" || "$RESPONSE" == "200" ]]; then
        PASS "Deployed: $SEARCH_NAME (HTTP $RESPONSE)"
        return 0
    elif [[ "$RESPONSE" == "409" ]]; then
        WARN "Already exists: $SEARCH_NAME (HTTP 409) — updating..."
        # Update existing
        curl -sk -o /dev/null \
            -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
            -X POST \
            "https://${SPLUNK_HOST}:${SPLUNK_PORT}/servicesNS/${SPLUNK_USER}/${SPLUNK_APP}/saved/searches/${SEARCH_NAME}" \
            --data-urlencode "search=${SEARCH_QUERY}" \
            --data-urlencode "cron_schedule=${CRON}" \
            --data-urlencode "disabled=0" 2>/dev/null
        PASS "Updated: $SEARCH_NAME"
        return 0
    else
        FAIL "Failed to deploy $SEARCH_NAME (HTTP $RESPONSE)"
        return 1
    fi
}

if [[ -n "$SPLUNK_PASS" ]]; then
    echo "Deploying via REST API..."
    DEPLOY_COUNT=0
    FAIL_COUNT=0

    # Failed Login Threshold
    if deploy_via_rest \
        "JSA-Failed-Login-Threshold" \
        "index=main sourcetype=WinEventLog EventCode=4625 | stats count by src_ip, user | where count > 5" \
        "*/5 * * * *" \
        "3" \
        "1"; then
        DEPLOY_COUNT=$((DEPLOY_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    # Privilege Escalation
    if deploy_via_rest \
        "JSA-Privilege-Escalation" \
        "index=main sourcetype=WinEventLog EventCode=4672 OR EventCode=4728 OR EventCode=4732 | stats count by user, src_ip, EventCode" \
        "*/5 * * * *" \
        "4" \
        "1"; then
        DEPLOY_COUNT=$((DEPLOY_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    # File Integrity Change
    if deploy_via_rest \
        "JSA-File-Integrity-Change" \
        "index=main sourcetype=wazuh rule.groups{} IN (syscheck) | stats count by agent.name, syscheck.path, syscheck.event" \
        "*/10 * * * *" \
        "3" \
        "1"; then
        DEPLOY_COUNT=$((DEPLOY_COUNT + 1))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    PASS "Deployed: $DEPLOY_COUNT searches | Failed: $FAIL_COUNT"

    # Post-deployment verification
    SECTION "Post-deployment verification"
    if curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
        "https://${SPLUNK_HOST}:${SPLUNK_PORT}/services/saved/searches?output_mode=json&count=0" \
        > "$EVIDENCE_DIR/after-saved-searches.json" 2>/dev/null; then

        AFTER_COUNT=$(jq '.entry | length' "$EVIDENCE_DIR/after-saved-searches.json" 2>/dev/null || echo "0")
        PASS "Post-deployment: $AFTER_COUNT saved searches"
        echo "BEFORE: $BEFORE_COUNT → AFTER: $AFTER_COUNT" | tee -a "$EVIDENCE_DIR/deployment-summary.txt"

        # Verify JSA searches present
        for SEARCH_NAME in "JSA-Failed-Login-Threshold" "JSA-Privilege-Escalation" "JSA-File-Integrity-Change"; do
            if jq -r '.entry[].name' "$EVIDENCE_DIR/after-saved-searches.json" 2>/dev/null | grep -q "$SEARCH_NAME"; then
                PASS "Confirmed present: $SEARCH_NAME"
            else
                FAIL "NOT FOUND after deployment: $SEARCH_NAME"
            fi
        done
    fi

else
    # Method 2: Direct file deployment (requires access to Splunk host)
    WARN "SPLUNK_PASS not set — attempting direct file deployment to $SAVEDSEARCHES_PATH"

    if [[ ! -d "$(dirname "$SAVEDSEARCHES_PATH")" ]]; then
        mkdir -p "$(dirname "$SAVEDSEARCHES_PATH")"
    fi

    # Append template to savedsearches.conf
    if [[ -f "$SAVEDSEARCHES_PATH" ]]; then
        PASS "Existing savedsearches.conf found — appending"
        echo "" >> "$SAVEDSEARCHES_PATH"
        echo "# JSA Security Rules — deployed $(date)" >> "$SAVEDSEARCHES_PATH"
    fi

    cat "$TEMPLATE_FILE" >> "$SAVEDSEARCHES_PATH"
    PASS "Template appended to $SAVEDSEARCHES_PATH"

    # Reload Splunk
    if command -v splunk &>/dev/null; then
        splunk reload saved-searches 2>/dev/null && PASS "Splunk saved searches reloaded" || WARN "Could not reload — restart may be required"
    else
        WARN "splunk command not found — restart Splunk to apply changes"
        INFO "Run: systemctl restart splunk"
    fi
fi

echo ""
echo "======================================================"
echo " Deployment Complete"
echo " Evidence: ${EVIDENCE_DIR}"
echo "======================================================"

{
    echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "action: fix-splunk-alert-rules"
    echo "dry_run: $DRY_RUN"
    echo "evidence_dir: $EVIDENCE_DIR"
} >> "$EVIDENCE_DIR/deployment-summary.txt"
