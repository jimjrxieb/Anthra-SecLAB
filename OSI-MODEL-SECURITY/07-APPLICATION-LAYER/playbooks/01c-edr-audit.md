# 01c-edr-audit.md — EDR Deep-Dive Audit (Defender + Wazuh)

| Field | Value |
|---|---|
| **NIST Controls** | SI-4 (monitoring), SI-3 (malicious code protection), SI-7 (integrity), IR-4 (incident handling) |
| **Tools** | mdatp CLI / Wazuh / wazuh-control / ossec-logtest |
| **Enterprise Equiv** | CrowdStrike Falcon ($300K+) / SentinelOne ($200K+) |
| **Time** | 30 minutes |
| **Rank** | D (read-only audit — no changes) |

---

## Purpose

Verify EDR coverage. CySA+ core competency: you must know how to verify that endpoint detection is working, definitions are current, and that FIM is monitoring the right paths. An EDR that's installed but misconfigured is worse than no EDR — it creates false confidence.

---

## 1. Microsoft Defender for Endpoint

### Linux MDE

```bash
# Full health check
mdatp health 2>/dev/null

# Key checks
mdatp health --field real_time_protection_enabled
mdatp health --field definitions_updated
mdatp health --field definitions_version
mdatp health --field device_id
mdatp health --field org_id

# Service status
systemctl is-active mdatp && echo "[PASS] MDE service active" || echo "[FAIL] MDE service not active"
pgrep -x wdavdaemon && echo "[PASS] wdavdaemon running" || echo "[WARN] wdavdaemon process not found"

# Definition freshness check
DEF_DATE=$(mdatp health --field definitions_updated 2>/dev/null | tr -d '"')
if [[ -n "$DEF_DATE" ]]; then
  DEF_EPOCH=$(date -d "$DEF_DATE" +%s 2>/dev/null || echo "0")
  NOW_EPOCH=$(date +%s)
  DEF_AGE_DAYS=$(( ( NOW_EPOCH - DEF_EPOCH ) / 86400 ))
  [[ $DEF_AGE_DAYS -le 7 ]] && echo "[PASS] Definitions current (${DEF_AGE_DAYS}d old)" || \
    echo "[FAIL] Definitions stale (${DEF_AGE_DAYS}d old) — update required"
fi

# Force definition update
# mdatp definitions update

# Run on-demand scan
# mdatp scan quick
```

### Windows MDE (PowerShell)

```powershell
# Get full Defender status
Get-MpComputerStatus | Select-Object @(
    'AMRunningMode',
    'AntivirusSignatureLastUpdated',
    'AntivirusSignatureAge',
    'AntivirusSignatureVersion',
    'RealTimeProtectionEnabled',
    'AMProductVersion',
    'NISSignatureLastUpdated',
    'NISSignatureVersion'
) | Format-List

# ASR rules status
Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions

# Recent threats
Get-MpThreatDetection | Select-Object -First 10 | Format-Table ActionSuccess, DetectionID, InitialDetectionTime, ProcessName

# Verify tamper protection
Get-MpComputerStatus | Select-Object IsTamperProtected

# Check if managed by MDE portal (confirmed enrollment)
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" -ErrorAction SilentlyContinue).OrgId
```

### Evidence Capture

```bash
# Linux
mdatp health > /tmp/jsa-evidence/mde-health-$(date +%Y%m%d).txt 2>/dev/null

# Windows
Get-MpComputerStatus | ConvertTo-Json | Out-File "C:\Temp\mde-status-$(Get-Date -Format 'yyyyMMdd').json"
```

---

## 2. Wazuh Agent / Manager

### Service Health

```bash
# Check Wazuh type (manager vs agent)
WAZUH_SVC="wazuh-manager"
systemctl is-active wazuh-manager &>/dev/null 2>&1 || WAZUH_SVC="wazuh-agent"

# Service status
systemctl status "$WAZUH_SVC" --no-pager -l | head -20

# wazuh-control status (shows all internal daemons)
/var/ossec/bin/wazuh-control status 2>/dev/null

# Check for running processes
pgrep -la "wazuh\|ossec" | head -10
```

### Agent Enrollment

```bash
# Manager: check enrolled agents
[[ -f /var/ossec/etc/client.keys ]] && {
  echo "Enrolled agents: $(wc -l < /var/ossec/etc/client.keys)"
  cat /var/ossec/etc/client.keys | awk '{print $2, $3}'
} || echo "[WARN] No client.keys found"

# Check agent connectivity (manager)
/var/ossec/bin/agent_control -l 2>/dev/null | head -20

# Agent: check connection to manager
grep -E "server|notify|key" /var/ossec/etc/ossec.conf 2>/dev/null | head -5
```

### Rule Coverage

```bash
# Count rule files
RULE_FILES=$(find /var/ossec/ruleset/rules/ -name "*.xml" 2>/dev/null | wc -l)
echo "Rule files: $RULE_FILES (expected: 50+)"

# Count total rules
TOTAL_RULES=$(grep -rh "<rule " /var/ossec/ruleset/rules/ 2>/dev/null | wc -l)
echo "Total rules: $TOTAL_RULES (expected: 1000+)"

# Check local rules (custom)
LOCAL_RULES=$(grep -c "<rule " /var/ossec/etc/rules/local_rules.xml 2>/dev/null || echo "0")
echo "Custom local rules: $LOCAL_RULES"

# Test a specific rule with ossec-logtest
echo "Mar  1 12:00:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2" | \
  /var/ossec/bin/ossec-logtest 2>/dev/null | head -20
```

### FIM Verification

```bash
# Verify syscheck is enabled
grep -A5 "<syscheck>" /var/ossec/etc/ossec.conf 2>/dev/null | head -10

# List monitored paths
grep "<directories" /var/ossec/etc/ossec.conf 2>/dev/null

# Count FIM paths
FIM_PATHS=$(grep -c "<directories" /var/ossec/etc/ossec.conf 2>/dev/null || echo "0")
echo "Monitored FIM paths: $FIM_PATHS"
[[ $FIM_PATHS -lt 5 ]] && echo "[WARN] Only $FIM_PATHS FIM paths — increase coverage"

# Critical paths check
for CRITICAL_PATH in "/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/ssh/sshd_config"; do
  grep -q "$CRITICAL_PATH" /var/ossec/etc/ossec.conf 2>/dev/null && \
    echo "[PRESENT] FIM: $CRITICAL_PATH" || \
    echo "[MISSING] FIM not covering: $CRITICAL_PATH"
done

# Check for realtime monitoring
grep -c "realtime=\"yes\"" /var/ossec/etc/ossec.conf 2>/dev/null | \
  xargs -I{} echo "Realtime FIM entries: {}"

# Trigger FIM scan and check results (manager)
/var/ossec/bin/agent_control -r -a 2>/dev/null && sleep 10

# Check recent FIM alerts
tail -50 /var/ossec/logs/alerts/alerts.json 2>/dev/null | \
  python3 -c "
import sys,json
for line in sys.stdin:
    try:
        d=json.loads(line)
        if 'syscheck' in d:
            print(f\"FIM: {d.get('agent',{}).get('name','?')} — {d.get('syscheck',{}).get('path','?')}\")
    except:
        pass
" | head -10
```

### Active Response Test

```bash
# Check active response is configured
grep -A5 "<active-response>" /var/ossec/etc/ossec.conf 2>/dev/null | head -20

# List available active response commands
ls /var/ossec/active-response/bin/ 2>/dev/null

# Verify firewall-drop is available
[[ -x /var/ossec/active-response/bin/firewall-drop ]] && \
  echo "[PRESENT] firewall-drop active response" || \
  echo "[MISSING] firewall-drop not found"
```

---

## 3. EDR Coverage Summary

After completing the audit, document:

```
Defender for Endpoint:
  - Real-time protection: ___
  - Definitions age: ___ days (target: < 7 days)
  - ASR rules: ___ enabled / ___ total
  - Device enrolled: Yes / No
  - License tier: ___

Wazuh:
  - Service status: Active / Inactive
  - Agents enrolled: ___ (manager) / Connected: Yes/No (agent)
  - FIM paths: ___ total / ___ realtime
  - Critical paths covered: ___ / 5 required
  - Custom rules: ___
  - Active response: Enabled / Disabled
  - Alerts today: ___
```

---

## Run Automated Audit

```bash
./01-auditors/audit-edr-agents.sh
```

---

## If You Find Gaps

- MDE not installed → `playbooks/00-install-validate.md` section 4
- Definitions stale → `mdatp definitions update` (Linux) or `Update-MpSignature` (Windows)
- FIM paths missing → `02-fixers/fix-wazuh-fim-paths.sh`
- Active response disabled → `02-fixers/fix-defender-active-response.md`
- ASR rules not configured → `02-fixers/fix-defender-active-response.md`
