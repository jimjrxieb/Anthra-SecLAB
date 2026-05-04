#!/usr/bin/env bash
set -euo pipefail

# PURPOSE:      Orchestrator — run all Layer 2 Data Link auditors in sequence.
#               Collects results and produces a combined summary.
# NIST CONTROLS: SI-4 (monitoring), SC-7 (boundary), AC-3 (access), IA-2 (authentication)
# WHERE TO RUN: Linux host; run as root or sudo for full results
# USAGE:        sudo ./run-all-audits.sh [interface]
#               Default interface: eth0
#
# CSF 2.0: ID.RA-01 (Vulnerabilities identified)
# CIS v8: 7.1 (Establish Vulnerability Management Process)
# NIST: CA-2 (Security Assessment)
#

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

info()   { echo -e "${CYAN}[INFO]${NC} $1"; }
header() { echo ""; echo -e "${CYAN}========================================${NC}"; echo -e "${CYAN} $1${NC}"; echo -e "${CYAN}========================================${NC}"; }

INTERFACE="${1:-eth0}"
LAYER="02-DATA-LINK-LAYER"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RUN_EVIDENCE="/tmp/jsa-evidence/${LAYER}-run-all-${TIMESTAMP}"
mkdir -p "$RUN_EVIDENCE"

# Resolve script directory for absolute paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDITORS_DIR="$(dirname "$SCRIPT_DIR")/01-auditors"

TOTAL_PASS=0
TOTAL_WARN=0
TOTAL_FAIL=0
AUDITORS_RUN=0
AUDITORS_FAILED=0

echo ""
echo "============================================================"
echo " Layer 2 Data Link — All Auditors"
echo " NIST: SI-4 | SC-7 | AC-3 | IA-2"
echo " Interface: $INTERFACE"
echo " Run ID: $TIMESTAMP"
echo " Evidence Root: $RUN_EVIDENCE"
echo "============================================================"

# --- ARP Integrity Audit ---
header "Audit 1/3: ARP Integrity"
AUDIT_SCRIPT="$AUDITORS_DIR/audit-arp-integrity.sh"
if [[ -x "$AUDIT_SCRIPT" ]]; then
    set +e
    OUTPUT=$("$AUDIT_SCRIPT" "$INTERFACE" 2>&1)
    EXIT_CODE=$?
    set -e

    echo "$OUTPUT"
    echo "$OUTPUT" > "$RUN_EVIDENCE/audit-1-arp-integrity.log"
    ((AUDITORS_RUN++))

    # Parse pass/warn/fail counts from output
    PASS_COUNT=$(echo "$OUTPUT" | grep -c '^\[PASS\]\|\[32m\[PASS\]' 2>/dev/null || echo 0)
    WARN_COUNT=$(echo "$OUTPUT" | grep -c '^\[WARN\]\|\[33m\[WARN\]' 2>/dev/null || echo 0)
    FAIL_COUNT=$(echo "$OUTPUT" | grep -c '^\[FAIL\]\|\[31m\[FAIL\]' 2>/dev/null || echo 0)

    if [[ $EXIT_CODE -ne 0 ]]; then
        echo -e "${RED}[AUDIT FAIL]${NC} ARP Integrity audit exited with code $EXIT_CODE"
        ((AUDITORS_FAILED++))
    fi
else
    echo -e "${RED}[ERROR]${NC} Auditor not found or not executable: $AUDIT_SCRIPT"
    ((AUDITORS_FAILED++))
fi

# --- VLAN Configuration Audit ---
header "Audit 2/3: VLAN Configuration"
AUDIT_SCRIPT="$AUDITORS_DIR/audit-vlan-config.sh"
if [[ -x "$AUDIT_SCRIPT" ]]; then
    set +e
    OUTPUT=$("$AUDIT_SCRIPT" 2>&1)
    EXIT_CODE=$?
    set -e

    echo "$OUTPUT"
    echo "$OUTPUT" > "$RUN_EVIDENCE/audit-2-vlan-config.log"
    ((AUDITORS_RUN++))

    if [[ $EXIT_CODE -ne 0 ]]; then
        echo -e "${RED}[AUDIT FAIL]${NC} VLAN Configuration audit exited with code $EXIT_CODE"
        ((AUDITORS_FAILED++))
    fi
else
    echo -e "${RED}[ERROR]${NC} Auditor not found or not executable: $AUDIT_SCRIPT"
    ((AUDITORS_FAILED++))
fi

# --- 802.1X NAC Status Audit ---
header "Audit 3/3: 802.1X NAC Status"
AUDIT_SCRIPT="$AUDITORS_DIR/audit-802.1x-status.sh"
if [[ -x "$AUDIT_SCRIPT" ]]; then
    set +e
    OUTPUT=$("$AUDIT_SCRIPT" "$INTERFACE" 2>&1)
    EXIT_CODE=$?
    set -e

    echo "$OUTPUT"
    echo "$OUTPUT" > "$RUN_EVIDENCE/audit-3-802.1x-status.log"
    ((AUDITORS_RUN++))

    if [[ $EXIT_CODE -ne 0 ]]; then
        echo -e "${RED}[AUDIT FAIL]${NC} 802.1X NAC audit exited with code $EXIT_CODE"
        ((AUDITORS_FAILED++))
    fi
else
    echo -e "${RED}[ERROR]${NC} Auditor not found or not executable: $AUDIT_SCRIPT"
    ((AUDITORS_FAILED++))
fi

# --- Combined Summary ---
echo ""
echo "============================================================"
echo " LAYER 2 RUN-ALL SUMMARY"
echo "============================================================"
echo " Auditors run:    $AUDITORS_RUN / 3"
echo " Auditors failed: $AUDITORS_FAILED"
echo ""
echo " Evidence root:   $RUN_EVIDENCE"
echo ""
info "Review individual audit logs in: $RUN_EVIDENCE"
info "For remediation steps, see: playbooks/02-fix-SC7-arp-protection.md"
info "For VLAN hardening, see:     playbooks/02a-fix-AC3-vlan-segmentation.md"
echo ""

# Write run summary
cat > "$RUN_EVIDENCE/run-summary.txt" <<EOF
Layer 2 Data Link — All Auditors Run
Date: $(date)
Hostname: $(hostname)
Interface: $INTERFACE
Auditors Run: $AUDITORS_RUN / 3
Auditors with Failures: $AUDITORS_FAILED
NIST Controls: SI-4, SC-7, AC-3, IA-2
Evidence Dir: $RUN_EVIDENCE
EOF

if [[ $AUDITORS_FAILED -gt 0 ]]; then
    echo -e "${RED}[RESULT]${NC} $AUDITORS_FAILED audit(s) reported failures — remediation required"
    exit 1
else
    echo -e "${GREEN}[RESULT]${NC} All auditors completed — review WARN findings above"
fi
