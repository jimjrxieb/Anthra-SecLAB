#!/usr/bin/env bash
# audit-log-retention.sh — L7 Application Layer log retention compliance check
# NIST: AU-11 (audit record retention)
# Usage: ./audit-log-retention.sh [--sentinel-only | --splunk-only]
#
# CSF 2.0: DE.AE-06 (Adverse event info provided)
# CIS v8: 8.10 (Retain Audit Logs)
# NIST: AU-11 (Audit Record Retention)
#
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }
SECTION() { echo -e "\n${BLUE}═══ $* ═══${NC}"; }

MODE="${1:-all}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/log-retention-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================"
echo " L7 Log Retention Compliance Audit — AU-11"
echo " Mode: ${MODE}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

# Compliance framework retention requirements (in days)
declare -A RETENTION_REQUIREMENTS=(
    ["HIPAA"]="2190"        # 6 years
    ["FedRAMP"]="1095"      # 3 years
    ["PCI-DSS"]="365"       # 1 year (90 days online)
    ["SOC2"]="365"          # 1 year typical
    ["NIST-800-53"]="365"   # 1 year minimum (AU-11)
)

FINDINGS=0
RETENTION_DAYS=0

check_retention_compliance() {
    local ACTUAL_DAYS="$1"
    local SOURCE="$2"
    RETENTION_DAYS=$ACTUAL_DAYS

    echo ""
    echo "Retention compliance check for: $SOURCE ($ACTUAL_DAYS days)"
    echo "─────────────────────────────────────────────"

    for FRAMEWORK in "${!RETENTION_REQUIREMENTS[@]}"; do
        REQ="${RETENTION_REQUIREMENTS[$FRAMEWORK]}"
        if [[ "$ACTUAL_DAYS" -ge "$REQ" ]]; then
            PASS "$FRAMEWORK: ${ACTUAL_DAYS}d >= ${REQ}d required"
        else
            DEFICIT=$(( REQ - ACTUAL_DAYS ))
            FAIL "$FRAMEWORK: ${ACTUAL_DAYS}d < ${REQ}d required (${DEFICIT}d short)"
            FINDINGS=$((FINDINGS + 1))
        fi
    done
}

# ─── Microsoft Sentinel / Log Analytics ───────────────────────────────────────
if [[ "$MODE" == "all" || "$MODE" == "--sentinel-only" ]]; then
    SECTION "Microsoft Sentinel — Log Analytics Retention"

    WORKSPACE_NAME="${SENTINEL_WORKSPACE:-}"
    RESOURCE_GROUP="${SENTINEL_RG:-}"

    if ! command -v az &>/dev/null; then
        WARN "az CLI not found — skipping Sentinel retention check"
    elif [[ -z "$WORKSPACE_NAME" || -z "$RESOURCE_GROUP" ]]; then
        WARN "Set SENTINEL_WORKSPACE and SENTINEL_RG to check Sentinel retention"
        FINDINGS=$((FINDINGS + 1))
    else
        echo "Querying Sentinel workspace retention settings..."
        if az monitor log-analytics workspace show \
            --workspace-name "$WORKSPACE_NAME" \
            --resource-group "$RESOURCE_GROUP" \
            --query '{retentionInDays:retentionInDays, dailyQuotaGb:workspaceCapping.dailyQuotaGb, sku:sku.name}' \
            --output json > "$EVIDENCE_DIR/sentinel-retention.json" 2>/dev/null; then

            SENTINEL_RETENTION=$(jq -r '.retentionInDays // 90' "$EVIDENCE_DIR/sentinel-retention.json")
            SKU=$(jq -r '.sku // "unknown"' "$EVIDENCE_DIR/sentinel-retention.json")
            QUOTA=$(jq -r '.dailyQuotaGb // "unlimited"' "$EVIDENCE_DIR/sentinel-retention.json")

            INFO "Workspace SKU: $SKU"
            INFO "Daily ingestion cap: ${QUOTA} GB"
            PASS "Sentinel retention: $SENTINEL_RETENTION days"

            check_retention_compliance "$SENTINEL_RETENTION" "Microsoft Sentinel"

            # Note: Sentinel free tier = 90 days, paid = up to 730 days
            if [[ "$SENTINEL_RETENTION" -lt 90 ]]; then
                FAIL "Retention below Sentinel free tier default (90 days)"
                FINDINGS=$((FINDINGS + 1))
            elif [[ "$SENTINEL_RETENTION" -eq 90 ]]; then
                WARN "Retention at default 90 days — likely not meeting compliance requirements"
                INFO "Set: az monitor log-analytics workspace update --workspace-name $WORKSPACE_NAME --resource-group $RESOURCE_GROUP --retention-time 365"
            fi

            # Check archive tier (Sentinel supports 7 years via archive)
            ARCHIVE_QUERY='Usage | where TimeGenerated > ago(30d) | summarize TotalGB=sum(Quantity)/1024 by DataType | top 10 by TotalGB desc'
            if az monitor log-analytics query \
                --workspace "$WORKSPACE_NAME" \
                --resource-group "$RESOURCE_GROUP" \
                --analytics-query "$ARCHIVE_QUERY" \
                --output json > "$EVIDENCE_DIR/sentinel-usage.json" 2>/dev/null; then
                INFO "Top data types by volume (30d) saved to evidence"
            fi
        else
            FAIL "Cannot query Sentinel workspace — check az login"
            FINDINGS=$((FINDINGS + 1))
        fi
    fi
fi

# ─── Splunk ───────────────────────────────────────────────────────────────────
if [[ "$MODE" == "all" || "$MODE" == "--splunk-only" ]]; then
    SECTION "Splunk — Index Retention Settings"

    SPLUNK_HOST="${SPLUNK_HOST:-localhost}"
    SPLUNK_PORT="${SPLUNK_MGMT_PORT:-8089}"
    SPLUNK_USER="${SPLUNK_USER:-admin}"
    SPLUNK_PASS="${SPLUNK_PASS:-}"

    if [[ -z "$SPLUNK_PASS" ]]; then
        WARN "Set SPLUNK_PASS to check Splunk retention"

        # Try btool (local Splunk install)
        if command -v splunk &>/dev/null; then
            echo "Trying local Splunk btool..."
            if splunk btool indexes list --debug 2>/dev/null | grep -E "frozenTimePeriodInSecs|maxTotalDataSizeMB" > "$EVIDENCE_DIR/splunk-btool-retention.txt" 2>/dev/null; then
                PASS "Splunk btool output captured"

                # Default index check
                DEFAULT_FROZEN=$(grep -A1 "^\[main\]" "$EVIDENCE_DIR/splunk-btool-retention.txt" 2>/dev/null | grep frozenTimePeriodInSecs | awk '{print $3}' || echo "0")
                if [[ -n "$DEFAULT_FROZEN" && "$DEFAULT_FROZEN" -gt 0 ]]; then
                    DEFAULT_DAYS=$(( DEFAULT_FROZEN / 86400 ))
                    PASS "Default (main) index retention: $DEFAULT_DAYS days"
                    check_retention_compliance "$DEFAULT_DAYS" "Splunk main index"
                fi
            else
                WARN "btool could not read index config"
            fi
        else
            WARN "Splunk not installed locally and SPLUNK_PASS not set — skipping"
            FINDINGS=$((FINDINGS + 1))
        fi
    else
        echo "Querying Splunk index retention via REST API..."
        if curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
            "https://${SPLUNK_HOST}:${SPLUNK_PORT}/services/data/indexes?output_mode=json&count=0" \
            > "$EVIDENCE_DIR/splunk-indexes-full.json" 2>/dev/null; then

            INDEX_COUNT=$(jq '.entry | length' "$EVIDENCE_DIR/splunk-indexes-full.json" 2>/dev/null || echo "0")
            PASS "Found $INDEX_COUNT Splunk indexes"

            # Check each critical index
            echo ""
            for IDX in main security wineventlog linux_secure; do
                FROZEN_SECS=$(jq -r --arg idx "$IDX" '.entry[] | select(.name == $idx) | .content.frozenTimePeriodInSecs // "0"' "$EVIDENCE_DIR/splunk-indexes-full.json" 2>/dev/null | head -1)

                if [[ -z "$FROZEN_SECS" || "$FROZEN_SECS" == "0" ]]; then
                    WARN "Index '$IDX' not found or retention not set (0 = unlimited/default)"
                else
                    FROZEN_DAYS=$(( FROZEN_SECS / 86400 ))
                    check_retention_compliance "$FROZEN_DAYS" "Splunk index: $IDX"
                fi
            done

            # Save full retention table
            jq -r '.entry[] | "\(.name): \((.content.frozenTimePeriodInSecs // 0 | tonumber) / 86400 | floor) days (\(.content.frozenTimePeriodInSecs // 0) secs)"' \
                "$EVIDENCE_DIR/splunk-indexes-full.json" 2>/dev/null | sort > "$EVIDENCE_DIR/splunk-retention-table.txt"
            INFO "Full retention table saved to $EVIDENCE_DIR/splunk-retention-table.txt"
        else
            FAIL "Cannot query Splunk REST API"
            FINDINGS=$((FINDINGS + 1))
        fi
    fi
fi

# ─── Compliance Summary Table ─────────────────────────────────────────────────
echo ""
SECTION "Compliance Framework Retention Reference"
echo ""
printf "%-15s %-15s %-40s\n" "Framework" "Min Days" "Notes"
printf "%-15s %-15s %-40s\n" "---------" "--------" "-----"
printf "%-15s %-15s %-40s\n" "HIPAA" "2190 (6yr)" "Audit logs, medical records"
printf "%-15s %-15s %-40s\n" "FedRAMP" "1095 (3yr)" "AU-11 control requirement"
printf "%-15s %-15s %-40s\n" "PCI-DSS v4" "365 (1yr)" "90 days immediately available"
printf "%-15s %-15s %-40s\n" "SOC 2" "365 (1yr)" "Typical auditor expectation"
printf "%-15s %-15s %-40s\n" "NIST 800-53" "365 (1yr)" "AU-11 baseline"
echo ""

# ─── Summary ──────────────────────────────────────────────────────────────────
echo "======================================================"
echo " Log Retention Audit Complete"
echo " Evidence: ${EVIDENCE_DIR}"
echo " Total findings: ${FINDINGS}"
echo "======================================================"

{
    echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "audit: log-retention"
    echo "mode: $MODE"
    echo "findings: $FINDINGS"
    echo "evidence_dir: $EVIDENCE_DIR"
} > "$EVIDENCE_DIR/audit-summary.txt"

[[ $FINDINGS -gt 0 ]] && exit 1 || exit 0
