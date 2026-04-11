#!/usr/bin/env bash
# audit-edr-agents.sh — L7 Application Layer EDR health check (Defender + Wazuh)
# NIST: SI-4 (information system monitoring), SI-3 (malicious code protection)
# Usage: ./audit-edr-agents.sh [--defender-only | --wazuh-only]
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }
SECTION() { echo -e "\n${BLUE}═══ $* ═══${NC}"; }

MODE="${1:-all}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/edr-agents-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================"
echo " L7 EDR Agent Audit — SI-4 / SI-3"
echo " Mode: ${MODE}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

FINDINGS=0

# ─── Defender for Endpoint ────────────────────────────────────────────────────
if [[ "$MODE" == "all" || "$MODE" == "--defender-only" ]]; then
    SECTION "Microsoft Defender for Endpoint"

    if command -v mdatp &>/dev/null; then
        echo "mdatp CLI found — running health check..."

        # Full health dump
        if mdatp health > "$EVIDENCE_DIR/defender-health.txt" 2>/dev/null; then
            PASS "mdatp health command succeeded"

            # Real-time protection
            RTP=$(grep -i "real_time_protection_enabled" "$EVIDENCE_DIR/defender-health.txt" | awk '{print $NF}' || echo "unknown")
            if [[ "$RTP" == "true" ]]; then
                PASS "Real-time protection: enabled"
            else
                FAIL "Real-time protection: DISABLED (value: $RTP)"
                FINDINGS=$((FINDINGS + 1))
            fi

            # Definition freshness
            DEF_UPDATED=$(grep -i "definitions_updated" "$EVIDENCE_DIR/defender-health.txt" | awk '{print $NF}' || echo "unknown")
            DEF_VERSION=$(grep -i "definitions_version" "$EVIDENCE_DIR/defender-health.txt" | awk '{print $NF}' || echo "unknown")
            INFO "Definitions last updated: $DEF_UPDATED"
            INFO "Definitions version: $DEF_VERSION"

            # Check if definitions are stale (older than 7 days)
            if [[ "$DEF_UPDATED" != "unknown" ]]; then
                DEF_AGE=$(( ( $(date +%s) - $(date -d "$DEF_UPDATED" +%s 2>/dev/null || echo "0") ) / 86400 ))
                if [[ $DEF_AGE -gt 7 ]]; then
                    FAIL "Definitions are ${DEF_AGE} days old — update required"
                    FINDINGS=$((FINDINGS + 1))
                else
                    PASS "Definitions are current (${DEF_AGE} days old)"
                fi
            fi

            # Health score
            HEALTH_ISSUES=$(grep -i "healthy.*false" "$EVIDENCE_DIR/defender-health.txt" | wc -l || echo "0")
            if [[ "$HEALTH_ISSUES" -gt 0 ]]; then
                WARN "$HEALTH_ISSUES health issues detected — review defender-health.txt"
                FINDINGS=$((FINDINGS + HEALTH_ISSUES))
            else
                PASS "No health issues detected in mdatp status"
            fi

            # Device ID (confirms enrollment)
            DEVICE_ID=$(grep -i "device_id" "$EVIDENCE_DIR/defender-health.txt" | awk '{print $NF}' || echo "")
            if [[ -n "$DEVICE_ID" ]]; then
                PASS "Device enrolled in MDE: $DEVICE_ID"
            else
                WARN "Device ID not found — may not be enrolled in MDE tenant"
                FINDINGS=$((FINDINGS + 1))
            fi
        else
            FAIL "mdatp health command failed — agent may not be running"
            FINDINGS=$((FINDINGS + 1))
        fi

        # Service status
        if systemctl is-active mdatp.service &>/dev/null 2>&1; then
            PASS "mdatp service is active (systemd)"
        elif pgrep -x "wdavdaemon" &>/dev/null; then
            PASS "wdavdaemon process running"
        else
            FAIL "Defender daemon not found running"
            FINDINGS=$((FINDINGS + 1))
        fi

    else
        # Windows PowerShell check
        if command -v powershell.exe &>/dev/null || command -v pwsh &>/dev/null; then
            PS_CMD="Get-MpComputerStatus | Select-Object AMRunningMode, AMProductVersion, AntivirusSignatureLastUpdated, RealTimeProtectionEnabled | ConvertTo-Json"
            PSBIN="powershell.exe"
            command -v pwsh &>/dev/null && PSBIN="pwsh"

            if $PSBIN -NonInteractive -Command "$PS_CMD" > "$EVIDENCE_DIR/defender-ps-status.json" 2>/dev/null; then
                PASS "Windows Defender status retrieved"
                RTP=$(jq -r '.RealTimeProtectionEnabled // false' "$EVIDENCE_DIR/defender-ps-status.json" 2>/dev/null)
                SIG_DATE=$(jq -r '.AntivirusSignatureLastUpdated // "unknown"' "$EVIDENCE_DIR/defender-ps-status.json" 2>/dev/null)
                [[ "$RTP" == "true" ]] && PASS "Real-time protection enabled" || { FAIL "Real-time protection disabled"; FINDINGS=$((FINDINGS + 1)); }
                INFO "Signature last updated: $SIG_DATE"
            else
                WARN "Could not run PowerShell Defender check"
            fi
        else
            WARN "mdatp and PowerShell not found — Defender check skipped"
            INFO "Defender for Endpoint requires Linux MDE agent or Windows Defender"
        fi
    fi
fi

# ─── Wazuh ────────────────────────────────────────────────────────────────────
if [[ "$MODE" == "all" || "$MODE" == "--wazuh-only" ]]; then
    SECTION "Wazuh Agent / Manager"

    # Check for Wazuh manager vs agent
    WAZUH_TYPE="none"
    command -v wazuh-control &>/dev/null && WAZUH_TYPE="manager"
    [[ -f /var/ossec/bin/wazuh-control ]] && WAZUH_TYPE="manager"
    [[ -f /var/ossec/bin/ossec-control ]] && WAZUH_TYPE="agent"
    systemctl is-active wazuh-agent &>/dev/null 2>&1 && WAZUH_TYPE="agent"
    systemctl is-active wazuh-manager &>/dev/null 2>&1 && WAZUH_TYPE="manager"

    if [[ "$WAZUH_TYPE" == "none" ]]; then
        FAIL "Wazuh not found on this host (no wazuh-control, no systemd service)"
        FINDINGS=$((FINDINGS + 1))
        INFO "Install Wazuh: https://documentation.wazuh.com/current/installation-guide/"
    else
        INFO "Wazuh type detected: $WAZUH_TYPE"

        # Service status
        WAZUH_SVC="wazuh-${WAZUH_TYPE}"
        if systemctl is-active "$WAZUH_SVC" &>/dev/null 2>&1; then
            PASS "Wazuh $WAZUH_TYPE service is active"
            systemctl status "$WAZUH_SVC" --no-pager -l > "$EVIDENCE_DIR/wazuh-service-status.txt" 2>/dev/null || true
        else
            FAIL "Wazuh $WAZUH_TYPE service is NOT active"
            FINDINGS=$((FINDINGS + 1))
        fi

        # wazuh-control status
        if [[ -x /var/ossec/bin/wazuh-control ]]; then
            /var/ossec/bin/wazuh-control status > "$EVIDENCE_DIR/wazuh-control-status.txt" 2>/dev/null || true
            PASS "wazuh-control status captured"
            grep -E "running|stopped" "$EVIDENCE_DIR/wazuh-control-status.txt" | head -10
        fi

        # Agent enrollment check (manager side)
        if [[ "$WAZUH_TYPE" == "manager" ]]; then
            if [[ -f /var/ossec/etc/client.keys ]]; then
                AGENT_COUNT=$(grep -c "." /var/ossec/etc/client.keys 2>/dev/null || echo "0")
                PASS "$AGENT_COUNT agents enrolled (client.keys)"
                cp /var/ossec/etc/client.keys "$EVIDENCE_DIR/wazuh-agents.txt" 2>/dev/null || true
            else
                WARN "client.keys not found — no agents enrolled or non-standard path"
                FINDINGS=$((FINDINGS + 1))
            fi

            # Active response check
            if grep -q "<active-response>" /var/ossec/etc/ossec.conf 2>/dev/null; then
                PASS "Active response configured in ossec.conf"
            else
                WARN "Active response not configured — automated blocking disabled"
                FINDINGS=$((FINDINGS + 1))
            fi

            # Rule count
            RULE_FILES=$(find /var/ossec/ruleset/rules/ -name "*.xml" 2>/dev/null | wc -l)
            INFO "Active rule files: $RULE_FILES"
            [[ $RULE_FILES -lt 10 ]] && { WARN "Low rule count — check ruleset installation"; FINDINGS=$((FINDINGS + 1)); }

            # Recent alerts
            if [[ -f /var/ossec/logs/alerts/alerts.log ]]; then
                TODAY_ALERTS=$(grep -c "$(date '+%Y %b %e')" /var/ossec/logs/alerts/alerts.log 2>/dev/null || echo "0")
                PASS "Wazuh alerts today: $TODAY_ALERTS"
                tail -20 /var/ossec/logs/alerts/alerts.log > "$EVIDENCE_DIR/wazuh-recent-alerts.txt" 2>/dev/null || true
            elif [[ -f /var/ossec/logs/alerts/alerts.json ]]; then
                TODAY_ALERTS=$(grep -c "$(date '+%Y-%m-%d')" /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo "0")
                PASS "Wazuh JSON alerts today: $TODAY_ALERTS"
                tail -5 /var/ossec/logs/alerts/alerts.json > "$EVIDENCE_DIR/wazuh-recent-alerts.json" 2>/dev/null || true
            else
                WARN "Alert log not found at expected path"
            fi
        fi

        # FIM check
        if grep -q "<syscheck>" /var/ossec/etc/ossec.conf 2>/dev/null; then
            PASS "Wazuh syscheck (FIM) configured"
            FIM_DIRS=$(grep -A1 "<directories" /var/ossec/etc/ossec.conf 2>/dev/null | grep -v "directories" | grep -v "^--$" | head -5)
            INFO "FIM directories: $FIM_DIRS"
        else
            FAIL "Wazuh syscheck not configured — file integrity monitoring disabled"
            FINDINGS=$((FINDINGS + 1))
        fi
    fi
fi

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "======================================================"
echo " EDR Agent Audit Complete"
echo " Evidence: ${EVIDENCE_DIR}"
echo " Total findings: ${FINDINGS}"
echo "======================================================"

{
    echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "audit: edr-agents"
    echo "mode: $MODE"
    echo "findings: $FINDINGS"
    echo "evidence_dir: $EVIDENCE_DIR"
} > "$EVIDENCE_DIR/audit-summary.txt"

[[ $FINDINGS -gt 0 ]] && exit 1 || exit 0
