#!/usr/bin/env bash
# fix-wazuh-fim-paths.sh — Configure Wazuh File Integrity Monitoring for critical paths
# NIST: SI-7 (software, firmware, information integrity)
# Usage: ./fix-wazuh-fim-paths.sh [--dry-run]
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }
SECTION() { echo -e "\n${BLUE}═══ $* ═══${NC}"; }

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

OSSEC_CONF="/var/ossec/etc/ossec.conf"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/wazuh-fim-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================"
echo " Wazuh FIM Configuration — SI-7"
echo " Config: ${OSSEC_CONF}"
echo " Dry run: ${DRY_RUN}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

# Critical paths that must be monitored for integrity
# Each path maps to a NIST control and MITRE technique
declare -A FIM_PATHS=(
    ["/etc/passwd"]="SI-7 T1098 — User account manipulation"
    ["/etc/shadow"]="SI-7 T1003 — Credential dumping target"
    ["/etc/sudoers"]="AC-6 T1548 — Privilege escalation path"
    ["/etc/sudoers.d"]="AC-6 T1548 — Privilege escalation path"
    ["/etc/ssh/sshd_config"]="SI-7 T1098 — SSH backdoor via config change"
    ["/etc/crontab"]="SI-7 T1053 — Scheduled task persistence"
    ["/etc/cron.d"]="SI-7 T1053 — Scheduled task persistence"
    ["/etc/hosts"]="SI-7 T1565 — DNS hijack via hosts file"
    ["/etc/resolv.conf"]="SI-7 T1565 — DNS manipulation"
    ["/etc/kubernetes"]="SI-7 T1610 — K8s control plane config"
    ["/var/ossec/etc"]="SI-7 — Wazuh config self-protection"
    ["/usr/bin"]="SI-7 T1574 — Binary hijacking detection"
    ["/usr/sbin"]="SI-7 T1574 — Binary hijacking detection"
)

# Realtime monitoring paths (high-priority, low latency)
REALTIME_PATHS=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/sudoers"
    "/etc/ssh/sshd_config"
)

if [[ ! -f "$OSSEC_CONF" ]]; then
    FAIL "Wazuh config not found at $OSSEC_CONF"
    INFO "Is Wazuh installed? Check: systemctl status wazuh-manager wazuh-agent"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    FAIL "This script must be run as root (sudo)"
    exit 1
fi

SECTION "Current FIM Configuration"

# Backup current config
cp "$OSSEC_CONF" "$EVIDENCE_DIR/ossec.conf.before"
PASS "Backed up current config to $EVIDENCE_DIR/ossec.conf.before"

# Check what's currently configured
echo ""
echo "Currently monitored paths:"
grep -n "<directories" "$OSSEC_CONF" 2>/dev/null | head -20 || echo "  (none found)"

# Count existing syscheck entries
EXISTING_PATHS=$(grep -c "<directories" "$OSSEC_CONF" 2>/dev/null || echo "0")
INFO "Existing monitored path entries: $EXISTING_PATHS"

SECTION "Configuring FIM Paths"

if $DRY_RUN; then
    WARN "DRY RUN — showing what would be added:"
    echo ""
    echo "Paths to add to <syscheck> block:"
    for PATH_ENTRY in "${!FIM_PATHS[@]}"; do
        REASON="${FIM_PATHS[$PATH_ENTRY]}"
        IS_REALTIME=false
        for RT in "${REALTIME_PATHS[@]}"; do
            [[ "$RT" == "$PATH_ENTRY" ]] && IS_REALTIME=true
        done

        if $IS_REALTIME; then
            echo "  <directories realtime=\"yes\" report_changes=\"yes\">$PATH_ENTRY</directories>"
        else
            echo "  <directories check_all=\"yes\">$PATH_ENTRY</directories>"
        fi
        echo "  <!-- $REASON -->"
    done
    exit 0
fi

# Build syscheck XML block
SYSCHECK_BLOCK="<syscheck>
    <!-- JSA FIM Policy — SI-7 Integrity Monitoring — $(date) -->
    <!-- Realtime monitoring for highest-risk paths -->
"

for RT_PATH in "${REALTIME_PATHS[@]}"; do
    if [[ -e "$RT_PATH" ]]; then
        REASON="${FIM_PATHS[$RT_PATH]:-SI-7 integrity monitoring}"
        SYSCHECK_BLOCK+="    <!-- $REASON -->
    <directories realtime=\"yes\" report_changes=\"yes\" check_all=\"yes\">$RT_PATH</directories>
"
    else
        WARN "Path does not exist (skipping): $RT_PATH"
    fi
done

SYSCHECK_BLOCK+="
    <!-- Scheduled monitoring for additional critical paths -->
"

for PATH_ENTRY in "${!FIM_PATHS[@]}"; do
    # Skip realtime paths — already added
    IS_RT=false
    for RT in "${REALTIME_PATHS[@]}"; do
        [[ "$RT" == "$PATH_ENTRY" ]] && IS_RT=true
    done
    $IS_RT && continue

    if [[ -e "$PATH_ENTRY" ]]; then
        REASON="${FIM_PATHS[$PATH_ENTRY]}"
        SYSCHECK_BLOCK+="    <!-- $REASON -->
    <directories check_all=\"yes\">$PATH_ENTRY</directories>
"
    else
        WARN "Path does not exist (skipping): $PATH_ENTRY"
    fi
done

SYSCHECK_BLOCK+="
    <!-- Ignore noisy paths -->
    <ignore>/proc</ignore>
    <ignore>/sys</ignore>
    <ignore>/dev</ignore>
    <ignore type=\"sregex\">.log$|.tmp$|.swp$</ignore>

    <!-- Scan frequency: every 12 hours for scheduled paths -->
    <frequency>43200</frequency>

    <!-- Alert on new files -->
    <alert_new_files>yes</alert_new_files>

    <!-- Auto-ignore files that change too frequently -->
    <auto_ignore frequency=\"10\" timeframe=\"3600\">no</auto_ignore>
</syscheck>"

# Check if syscheck block already exists
if grep -q "<syscheck>" "$OSSEC_CONF"; then
    WARN "Existing <syscheck> block found — backing up and replacing"

    # Extract content before syscheck
    PRE_SYSCHECK=$(sed '/<syscheck>/,/<\/syscheck>/d' "$OSSEC_CONF")

    # Write new config: pre-syscheck content + new syscheck block
    echo "$PRE_SYSCHECK" > /tmp/ossec-presyscheck.tmp
    # Insert syscheck before </ossec_config>
    sed -i "s|</ossec_config>|${SYSCHECK_BLOCK}\n</ossec_config>|" /tmp/ossec-presyscheck.tmp
    cp /tmp/ossec-presyscheck.tmp "$OSSEC_CONF"
    rm -f /tmp/ossec-presyscheck.tmp
else
    # Add syscheck block before closing tag
    sed -i "s|</ossec_config>|${SYSCHECK_BLOCK}\n</ossec_config>|" "$OSSEC_CONF"
fi

PASS "FIM paths configured in $OSSEC_CONF"

SECTION "Verification"

# Show what was added
echo "Configured FIM paths:"
grep "<directories" "$OSSEC_CONF" | sed 's/^/  /'

# Validate XML syntax
if command -v xmllint &>/dev/null; then
    if xmllint --noout "$OSSEC_CONF" 2>/dev/null; then
        PASS "ossec.conf XML syntax valid"
    else
        FAIL "ossec.conf XML syntax error — restoring backup"
        cp "$EVIDENCE_DIR/ossec.conf.before" "$OSSEC_CONF"
        exit 1
    fi
fi

SECTION "Restart Wazuh"

# Restart agent or manager
WAZUH_SVC="wazuh-manager"
systemctl is-active wazuh-agent &>/dev/null 2>&1 && WAZUH_SVC="wazuh-agent"

if $DRY_RUN; then
    INFO "Would restart: $WAZUH_SVC"
else
    systemctl restart "$WAZUH_SVC" && PASS "Wazuh $WAZUH_SVC restarted" || FAIL "Failed to restart $WAZUH_SVC"
    sleep 3
    systemctl is-active "$WAZUH_SVC" && PASS "$WAZUH_SVC is active" || FAIL "$WAZUH_SVC failed to start"
fi

SECTION "Trigger Initial Scan"

if ! $DRY_RUN && [[ -x /var/ossec/bin/agent_control ]]; then
    /var/ossec/bin/agent_control -r -a 2>/dev/null && PASS "Triggered FIM scan on all agents" || WARN "Could not trigger scan — will run on next scheduled cycle"
fi

echo ""
echo "======================================================"
echo " Wazuh FIM Configuration Complete"
echo " Evidence: ${EVIDENCE_DIR}"
echo "======================================================"

cp "$OSSEC_CONF" "$EVIDENCE_DIR/ossec.conf.after"
diff "$EVIDENCE_DIR/ossec.conf.before" "$EVIDENCE_DIR/ossec.conf.after" > "$EVIDENCE_DIR/ossec.conf.diff" 2>/dev/null || true
INFO "Diff saved: $EVIDENCE_DIR/ossec.conf.diff"

{
    echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "action: fix-wazuh-fim-paths"
    echo "dry_run: $DRY_RUN"
    echo "config: $OSSEC_CONF"
    echo "evidence_dir: $EVIDENCE_DIR"
} > "$EVIDENCE_DIR/fix-summary.txt"
