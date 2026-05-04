#!/usr/bin/env bash
# audit-siem-ingest.sh — L7 Application Layer SIEM health check (Sentinel + Splunk)
# NIST: AU-2 (event logging), AU-6 (audit review), SI-4 (information system monitoring)
# Usage: ./audit-siem-ingest.sh [--sentinel-only | --splunk-only]
#
# CSF 2.0: DE.AE-07 (Threat intel integrated)
# CIS v8: 8.2 (Collect Audit Logs)
# NIST: AU-2 (Audit Events)
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
EVIDENCE_DIR="/tmp/jsa-evidence/siem-ingest-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================"
echo " L7 SIEM Ingest Health Audit — AU-2/AU-6/SI-4"
echo " Mode: ${MODE}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

FINDINGS=0

# ─── Sentinel Audit ───────────────────────────────────────────────────────────
if [[ "$MODE" == "all" || "$MODE" == "--sentinel-only" ]]; then
    SECTION "Microsoft Sentinel — Workspace Health"

    # Prerequisite: az CLI logged in
    if ! command -v az &>/dev/null; then
        WARN "az CLI not found — skipping Sentinel checks"
        INFO "Install: https://docs.microsoft.com/cli/azure/install-azure-cli"
    else
        # Get workspace details from env or prompt
        WORKSPACE_NAME="${SENTINEL_WORKSPACE:-}"
        RESOURCE_GROUP="${SENTINEL_RG:-}"

        if [[ -z "$WORKSPACE_NAME" || -z "$RESOURCE_GROUP" ]]; then
            WARN "Set SENTINEL_WORKSPACE and SENTINEL_RG environment variables to enable Sentinel checks"
            INFO "Example: export SENTINEL_WORKSPACE=my-sentinel-ws SENTINEL_RG=my-rg"
            FINDINGS=$((FINDINGS + 1))
        else
            echo "Checking Sentinel workspace: $WORKSPACE_NAME (RG: $RESOURCE_GROUP)"

            # Workspace health
            if az monitor log-analytics workspace show \
                --workspace-name "$WORKSPACE_NAME" \
                --resource-group "$RESOURCE_GROUP" \
                --output json > "$EVIDENCE_DIR/sentinel-workspace.json" 2>/dev/null; then

                WS_STATUS=$(jq -r '.provisioningState // "unknown"' "$EVIDENCE_DIR/sentinel-workspace.json")
                RETENTION=$(jq -r '.retentionInDays // "unknown"' "$EVIDENCE_DIR/sentinel-workspace.json")

                if [[ "$WS_STATUS" == "Succeeded" ]]; then
                    PASS "Sentinel workspace provisioning state: $WS_STATUS"
                else
                    FAIL "Sentinel workspace state: $WS_STATUS"
                    FINDINGS=$((FINDINGS + 1))
                fi
                INFO "Log retention: ${RETENTION} days"
                [[ "$RETENTION" -lt 90 ]] 2>/dev/null && { WARN "Retention < 90 days — check compliance requirements"; FINDINGS=$((FINDINGS + 1)); }
            else
                FAIL "Cannot query Sentinel workspace — check az login and permissions"
                FINDINGS=$((FINDINGS + 1))
            fi

            # Recent data ingestion (last 1 hour)
            echo ""
            echo "Checking recent data ingestion (last 1 hour)..."
            INGEST_QUERY='union withsource=TableName * | where TimeGenerated > ago(1h) | summarize RecordCount=count() by TableName | top 10 by RecordCount desc'

            if az monitor log-analytics query \
                --workspace "$WORKSPACE_NAME" \
                --resource-group "$RESOURCE_GROUP" \
                --analytics-query "$INGEST_QUERY" \
                --output json > "$EVIDENCE_DIR/sentinel-ingest-check.json" 2>/dev/null; then

                TABLE_COUNT=$(jq '. | length' "$EVIDENCE_DIR/sentinel-ingest-check.json" 2>/dev/null || echo "0")
                if [[ "$TABLE_COUNT" -gt 0 ]]; then
                    PASS "Sentinel receiving data — $TABLE_COUNT active tables in last hour"
                    jq -r '.[] | "  \(.TableName): \(.RecordCount) records"' "$EVIDENCE_DIR/sentinel-ingest-check.json" 2>/dev/null | head -10
                else
                    FAIL "No data ingested in last hour — possible connector issue"
                    FINDINGS=$((FINDINGS + 1))
                fi
            else
                WARN "Could not run ingest query — check Sentinel permissions (Log Analytics Reader)"
            fi

            # Data connector status
            echo ""
            echo "Checking data connectors..."
            if az rest \
                --method GET \
                --url "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/${WORKSPACE_NAME}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2022-11-01" \
                --output json > "$EVIDENCE_DIR/sentinel-connectors.json" 2>/dev/null; then

                CONNECTOR_COUNT=$(jq '.value | length' "$EVIDENCE_DIR/sentinel-connectors.json" 2>/dev/null || echo "0")
                PASS "Found $CONNECTOR_COUNT data connectors configured"
                jq -r '.value[] | "  \(.kind): \(.properties.dataTypes.alerts.state // "N/A")"' "$EVIDENCE_DIR/sentinel-connectors.json" 2>/dev/null | head -15
            else
                WARN "Could not list data connectors — check Sentinel Contributor permissions"
            fi
        fi
    fi
fi

# ─── Splunk Audit ─────────────────────────────────────────────────────────────
if [[ "$MODE" == "all" || "$MODE" == "--splunk-only" ]]; then
    SECTION "Splunk — HEC and Index Health"

    SPLUNK_HOST="${SPLUNK_HOST:-localhost}"
    SPLUNK_HEC_PORT="${SPLUNK_HEC_PORT:-8088}"
    SPLUNK_MGMT_PORT="${SPLUNK_MGMT_PORT:-8089}"
    SPLUNK_USER="${SPLUNK_USER:-admin}"
    SPLUNK_PASS="${SPLUNK_PASS:-}"

    # HEC health check
    echo "Checking Splunk HEC endpoint: ${SPLUNK_HOST}:${SPLUNK_HEC_PORT}..."
    HEC_RESPONSE=$(curl -sk "https://${SPLUNK_HOST}:${SPLUNK_HEC_PORT}/services/collector/health" \
        --max-time 5 -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")

    if [[ "$HEC_RESPONSE" == "200" ]]; then
        PASS "Splunk HEC endpoint healthy (HTTP 200)"
        echo "HEC_STATUS=healthy" >> "$EVIDENCE_DIR/splunk-hec.txt"
    elif [[ "$HEC_RESPONSE" == "400" ]]; then
        PASS "Splunk HEC reachable (HTTP 400 = no token provided, endpoint is up)"
        echo "HEC_STATUS=reachable" >> "$EVIDENCE_DIR/splunk-hec.txt"
    elif [[ "$HEC_RESPONSE" == "000" ]]; then
        FAIL "Splunk HEC not reachable on ${SPLUNK_HOST}:${SPLUNK_HEC_PORT}"
        FINDINGS=$((FINDINGS + 1))
        echo "HEC_STATUS=unreachable" >> "$EVIDENCE_DIR/splunk-hec.txt"
    else
        WARN "Splunk HEC returned HTTP $HEC_RESPONSE"
        echo "HEC_STATUS=http_${HEC_RESPONSE}" >> "$EVIDENCE_DIR/splunk-hec.txt"
    fi

    # Index status via REST API
    if [[ -n "$SPLUNK_PASS" ]]; then
        echo ""
        echo "Checking Splunk index status..."
        if curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
            "https://${SPLUNK_HOST}:${SPLUNK_MGMT_PORT}/services/data/indexes?output_mode=json&count=0" \
            > "$EVIDENCE_DIR/splunk-indexes.json" 2>/dev/null; then

            INDEX_COUNT=$(jq '.entry | length' "$EVIDENCE_DIR/splunk-indexes.json" 2>/dev/null || echo "0")
            PASS "Found $INDEX_COUNT Splunk indexes"

            # Check for required security indexes
            for IDX in main security wineventlog linux_secure; do
                if jq -r '.entry[].name' "$EVIDENCE_DIR/splunk-indexes.json" 2>/dev/null | grep -q "^${IDX}$"; then
                    PASS "Required index present: $IDX"
                else
                    WARN "Expected index not found: $IDX"
                    FINDINGS=$((FINDINGS + 1))
                fi
            done

            # Recent event count across all indexes
            jq -r '.entry[] | "  \(.name): \(.content.totalEventCount // 0) events"' \
                "$EVIDENCE_DIR/splunk-indexes.json" 2>/dev/null | head -15
        else
            WARN "Could not query Splunk REST API — check credentials"
        fi
    else
        WARN "Set SPLUNK_PASS to enable Splunk index checks"
        INFO "Example: export SPLUNK_PASS=changeme"
    fi

    # Active SIEM determination
    echo ""
    echo "---"
    if [[ "$HEC_RESPONSE" == "200" || "$HEC_RESPONSE" == "400" ]]; then
        PASS "Active SIEM: Splunk is reachable and accepting data"
        echo "ACTIVE_SIEM=splunk" >> "$EVIDENCE_DIR/siem-status.txt"
    else
        INFO "Splunk not reachable — check if Microsoft Sentinel is primary SIEM"
        echo "ACTIVE_SIEM=unknown" >> "$EVIDENCE_DIR/siem-status.txt"
    fi
fi

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "======================================================"
echo " SIEM Ingest Audit Complete"
echo " Evidence: ${EVIDENCE_DIR}"
echo " Total findings: ${FINDINGS}"
echo "======================================================"

{
    echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "audit: siem-ingest"
    echo "mode: $MODE"
    echo "findings: $FINDINGS"
    echo "evidence_dir: $EVIDENCE_DIR"
} > "$EVIDENCE_DIR/audit-summary.txt"

[[ $FINDINGS -gt 0 ]] && exit 1 || exit 0
