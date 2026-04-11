#!/usr/bin/env bash
# audit-alert-rules.sh — L7 Application Layer SIEM alert rule audit (Sentinel + Splunk)
# NIST: AU-6 (audit review and analysis), SI-4 (information system monitoring)
# Usage: ./audit-alert-rules.sh [--sentinel-only | --splunk-only]
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }
SECTION() { echo -e "\n${BLUE}═══ $* ═══${NC}"; }

MODE="${1:-all}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/alert-rules-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================"
echo " L7 SIEM Alert Rule Audit — AU-6 / SI-4"
echo " Mode: ${MODE}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

FINDINGS=0

# Critical detections every SIEM should have
REQUIRED_DETECTIONS=(
    "brute force"
    "privilege escalation"
    "impossible travel"
    "new admin"
    "mass download"
)

# ─── Microsoft Sentinel ───────────────────────────────────────────────────────
if [[ "$MODE" == "all" || "$MODE" == "--sentinel-only" ]]; then
    SECTION "Microsoft Sentinel — Analytics Rules"

    WORKSPACE_NAME="${SENTINEL_WORKSPACE:-}"
    RESOURCE_GROUP="${SENTINEL_RG:-}"
    SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:-}"

    if ! command -v az &>/dev/null; then
        WARN "az CLI not found — skipping Sentinel rule audit"
    elif [[ -z "$WORKSPACE_NAME" || -z "$RESOURCE_GROUP" || -z "$SUBSCRIPTION_ID" ]]; then
        WARN "Set SENTINEL_WORKSPACE, SENTINEL_RG, AZURE_SUBSCRIPTION_ID to audit Sentinel rules"
        FINDINGS=$((FINDINGS + 1))
    else
        SENTINEL_BASE="https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/${WORKSPACE_NAME}/providers/Microsoft.SecurityInsights"

        # List all analytics rules
        echo "Listing Sentinel analytics rules..."
        if az rest \
            --method GET \
            --url "${SENTINEL_BASE}/alertRules?api-version=2022-11-01" \
            --output json > "$EVIDENCE_DIR/sentinel-rules-all.json" 2>/dev/null; then

            TOTAL_RULES=$(jq '.value | length' "$EVIDENCE_DIR/sentinel-rules-all.json" 2>/dev/null || echo "0")
            ENABLED_RULES=$(jq '[.value[] | select(.properties.enabled == true)] | length' "$EVIDENCE_DIR/sentinel-rules-all.json" 2>/dev/null || echo "0")

            PASS "Total analytics rules: $TOTAL_RULES"
            PASS "Enabled rules: $ENABLED_RULES"

            if [[ "$TOTAL_RULES" -eq 0 ]]; then
                FAIL "No analytics rules configured — no detection coverage"
                FINDINGS=$((FINDINGS + 3))
            elif [[ "$ENABLED_RULES" -eq 0 ]]; then
                FAIL "Rules exist but none are enabled"
                FINDINGS=$((FINDINGS + 2))
            elif [[ "$ENABLED_RULES" -lt 10 ]]; then
                WARN "Only $ENABLED_RULES enabled rules — coverage may be insufficient"
                FINDINGS=$((FINDINGS + 1))
            fi

            # Check for critical detection categories
            echo ""
            echo "Checking for critical detection categories..."
            RULE_NAMES=$(jq -r '.value[].properties.displayName // empty' "$EVIDENCE_DIR/sentinel-rules-all.json" 2>/dev/null | tr '[:upper:]' '[:lower:]')

            for DETECTION in "${REQUIRED_DETECTIONS[@]}"; do
                if echo "$RULE_NAMES" | grep -qi "$DETECTION"; then
                    PASS "Detection present: $DETECTION"
                else
                    WARN "No rule matching: '$DETECTION' — coverage gap"
                    FINDINGS=$((FINDINGS + 1))
                fi
            done

            # High severity rules
            HIGH_RULES=$(jq '[.value[] | select(.properties.severity == "High" and .properties.enabled == true)] | length' "$EVIDENCE_DIR/sentinel-rules-all.json" 2>/dev/null || echo "0")
            INFO "High severity enabled rules: $HIGH_RULES"
            [[ "$HIGH_RULES" -lt 3 ]] && { WARN "Fewer than 3 High severity rules enabled"; FINDINGS=$((FINDINGS + 1)); }

            # Save rule list
            jq -r '.value[] | "\(.properties.severity // "N/A") | \(if .properties.enabled then "ENABLED" else "DISABLED" end) | \(.properties.displayName // "unnamed")"' \
                "$EVIDENCE_DIR/sentinel-rules-all.json" 2>/dev/null | sort > "$EVIDENCE_DIR/sentinel-rule-list.txt"
            INFO "Full rule list saved to $EVIDENCE_DIR/sentinel-rule-list.txt"
        else
            FAIL "Cannot list Sentinel analytics rules — check permissions (Sentinel Reader)"
            FINDINGS=$((FINDINGS + 1))
        fi

        # Active incidents
        echo ""
        echo "Checking open incidents..."
        if az rest \
            --method GET \
            --url "${SENTINEL_BASE}/incidents?api-version=2022-11-01&\$filter=properties/status ne 'Closed'&\$top=50" \
            --output json > "$EVIDENCE_DIR/sentinel-open-incidents.json" 2>/dev/null; then

            OPEN_COUNT=$(jq '.value | length' "$EVIDENCE_DIR/sentinel-open-incidents.json" 2>/dev/null || echo "0")
            HIGH_INCIDENTS=$(jq '[.value[] | select(.properties.severity == "High")] | length' "$EVIDENCE_DIR/sentinel-open-incidents.json" 2>/dev/null || echo "0")
            PASS "Open incidents: $OPEN_COUNT (High severity: $HIGH_INCIDENTS)"
            [[ "$HIGH_INCIDENTS" -gt 5 ]] && { WARN "$HIGH_INCIDENTS unresolved High severity incidents"; FINDINGS=$((FINDINGS + 1)); }
        else
            WARN "Could not query open incidents"
        fi
    fi
fi

# ─── Splunk ───────────────────────────────────────────────────────────────────
if [[ "$MODE" == "all" || "$MODE" == "--splunk-only" ]]; then
    SECTION "Splunk — Saved Searches (Correlation Rules)"

    SPLUNK_HOST="${SPLUNK_HOST:-localhost}"
    SPLUNK_PORT="${SPLUNK_MGMT_PORT:-8089}"
    SPLUNK_USER="${SPLUNK_USER:-admin}"
    SPLUNK_PASS="${SPLUNK_PASS:-}"

    if [[ -z "$SPLUNK_PASS" ]]; then
        WARN "Set SPLUNK_PASS to audit Splunk saved searches"
        INFO "Example: export SPLUNK_PASS=changeme"
        FINDINGS=$((FINDINGS + 1))
    else
        echo "Querying Splunk saved searches..."
        if curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
            "https://${SPLUNK_HOST}:${SPLUNK_PORT}/services/saved/searches?output_mode=json&count=0&search=alert_type%3Dalways+OR+is_scheduled%3D1" \
            > "$EVIDENCE_DIR/splunk-searches.json" 2>/dev/null; then

            TOTAL_SEARCHES=$(jq '.entry | length' "$EVIDENCE_DIR/splunk-searches.json" 2>/dev/null || echo "0")
            ENABLED_SEARCHES=$(jq '[.entry[] | select(.content.disabled == "0" or .content.disabled == false)] | length' "$EVIDENCE_DIR/splunk-searches.json" 2>/dev/null || echo "0")

            PASS "Total saved searches: $TOTAL_SEARCHES"
            PASS "Enabled/scheduled searches: $ENABLED_SEARCHES"

            [[ "$TOTAL_SEARCHES" -eq 0 ]] && { FAIL "No saved searches — no detection coverage"; FINDINGS=$((FINDINGS + 3)); }
            [[ "$ENABLED_SEARCHES" -eq 0 ]] && { FAIL "No enabled scheduled searches"; FINDINGS=$((FINDINGS + 2)); }

            # Check for critical detection categories
            echo ""
            echo "Checking for critical detection categories..."
            SEARCH_NAMES=$(jq -r '.entry[].name // empty' "$EVIDENCE_DIR/splunk-searches.json" 2>/dev/null | tr '[:upper:]' '[:lower:]')

            for DETECTION in "${REQUIRED_DETECTIONS[@]}"; do
                if echo "$SEARCH_NAMES" | grep -qi "${DETECTION// /-}\|${DETECTION// /_}\|$DETECTION"; then
                    PASS "Detection present: $DETECTION"
                else
                    WARN "No search matching: '$DETECTION' — coverage gap"
                    FINDINGS=$((FINDINGS + 1))
                fi
            done

            # Save search list
            jq -r '.entry[] | "\(if (.content.disabled == "0" or .content.disabled == false) then "ENABLED" else "DISABLED" end) | \(.content.alert_severity // "N/A") | \(.name)"' \
                "$EVIDENCE_DIR/splunk-searches.json" 2>/dev/null | sort > "$EVIDENCE_DIR/splunk-search-list.txt"
            INFO "Full search list saved to $EVIDENCE_DIR/splunk-search-list.txt"
        else
            FAIL "Cannot query Splunk REST API — check credentials and host"
            FINDINGS=$((FINDINGS + 1))
        fi
    fi
fi

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "======================================================"
echo " Alert Rule Audit Complete"
echo " Evidence: ${EVIDENCE_DIR}"
echo " Total findings: ${FINDINGS}"
echo "======================================================"

{
    echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "audit: alert-rules"
    echo "mode: $MODE"
    echo "findings: $FINDINGS"
    echo "evidence_dir: $EVIDENCE_DIR"
} > "$EVIDENCE_DIR/audit-summary.txt"

[[ $FINDINGS -gt 0 ]] && exit 1 || exit 0
