# 02b-fix-SI7-fim.md — File Integrity Monitoring

| Field | Value |
|---|---|
| **NIST Controls** | SI-7 (software, firmware, and information integrity) |
| **Tools** | Wazuh syscheck / AIDE / Defender FIM |
| **Fixes** | Missing FIM, uncovered critical paths, no realtime monitoring |
| **Time** | 20 minutes |
| **Rank** | D (config change — no human decisions required) |

---

## Purpose

SI-7 requires detecting unauthorized changes to software and information. File Integrity Monitoring (FIM) is the primary technical control. Without FIM, an attacker can modify `/etc/passwd`, replace system binaries, or add cron jobs without any alert firing.

---

## Option A: Wazuh FIM (Primary — Recommended)

### Quick Deploy

```bash
# Fix FIM paths on current host
sudo ./02-fixers/fix-wazuh-fim-paths.sh

# Dry run first
sudo ./02-fixers/fix-wazuh-fim-paths.sh --dry-run
```

### What Gets Configured

The fixer script adds monitoring for:

| Path | Why | Monitoring |
|---|---|---|
| `/etc/passwd` | User account manipulation (T1098) | Realtime |
| `/etc/shadow` | Credential dump target (T1003) | Realtime |
| `/etc/sudoers` | Privilege escalation path (T1548) | Realtime |
| `/etc/ssh/sshd_config` | SSH backdoor via config (T1098) | Realtime |
| `/etc/crontab` | Scheduled task persistence (T1053) | Scheduled |
| `/etc/kubernetes` | K8s control plane config (T1610) | Scheduled |
| `/usr/bin`, `/usr/sbin` | Binary hijacking (T1574) | Scheduled |

### Verify FIM is Working

```bash
# Trigger a test change and verify alert fires
echo "test" > /tmp/test-fim-$(date +%s).txt

# For a real FIM test — add a temporary file to a monitored path
touch /etc/test-fim-$(date +%s).txt
sleep 10

# Check for FIM alert in logs
tail -50 /var/ossec/logs/alerts/alerts.json 2>/dev/null | \
  python3 -c "
import sys,json
for line in sys.stdin:
    try:
        d=json.loads(line)
        if 'syscheck' in d.get('data',{}):
            print('FIM Alert:', json.dumps(d.get('data',{}).get('syscheck',{}), indent=2)[:200])
    except: pass
" | head -30

# Cleanup test file
rm -f /etc/test-fim-*.txt
```

---

## Option B: AIDE (Alternative Integrity Monitor)

Use AIDE when Wazuh is not available or as a secondary check:

```bash
# Install AIDE
apt-get install -y aide aide-common 2>/dev/null || \
  yum install -y aide 2>/dev/null

# Configure AIDE
cat > /etc/aide/aide.conf.d/99-jsa-security.conf << 'EOF'
# JSA FIM policy — NIST SI-7
# Format: path  check_type
# Check types: p=permissions, i=inode, n=number of links, u=user, g=group
# m=mtime, s=size, b=block count, md5=MD5 hash, sha256=SHA256 hash
# FULL = all checks including hash

# Critical files — full verification including hash
/etc/passwd     FULL
/etc/shadow     FULL
/etc/sudoers    FULL
/etc/ssh/sshd_config FULL
/etc/hosts      FULL
/etc/resolv.conf FULL

# System binaries — verify hash, permissions, owner
/usr/bin    CONTENT_EX
/usr/sbin   CONTENT_EX
/bin        CONTENT_EX
/sbin       CONTENT_EX

# Kubernetes configs
/etc/kubernetes FULL

# Init scripts
/etc/init.d FULL
/etc/crontab FULL
/etc/cron.d FULL

# Ignore high-churn paths
!/var
!/tmp
!/proc
!/sys
!/dev
EOF

# Initialize AIDE database (first run — this is the baseline)
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
echo "AIDE database initialized — baseline captured"

# Schedule daily check
cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
# NIST SI-7: Daily file integrity check
REPORT=/var/log/aide/aide-$(date +%Y%m%d).txt
mkdir -p /var/log/aide
/usr/bin/aide --check > "$REPORT" 2>&1
# Alert if changes found
if grep -q "changed\|removed\|added" "$REPORT"; then
  mail -s "[AIDE] File integrity change detected" root < "$REPORT"
  logger -p security.alert "AIDE: File integrity changes detected — see $REPORT"
fi
EOF
chmod +x /etc/cron.daily/aide-check

# Test AIDE
aide --check 2>/dev/null | tail -20
```

---

## Option C: Defender for Endpoint FIM (Windows)

```powershell
# Enable Defender FIM via PowerShell
# Requires Microsoft Defender for Endpoint license

# Enable Controlled Folder Access (protects folders from unauthorized changes)
Set-MpPreference -EnableControlledFolderAccess Enabled

# Add custom protected folders
Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\Windows\System32"
Add-MpPreference -ControlledFolderAccessProtectedFolders "C:\Program Files"

# Verify
Get-MpPreference | Select-Object EnableControlledFolderAccess, ControlledFolderAccessProtectedFolders

# For MDE portal FIM configuration:
# security.microsoft.com > Settings > Endpoints > Advanced features
# Enable: File integrity monitoring
# Then configure paths in:
# security.microsoft.com > Endpoints > Configuration management > File integrity monitoring
```

---

## Verification

```bash
# Wazuh FIM
grep -c "<directories" /var/ossec/etc/ossec.conf 2>/dev/null | \
  xargs -I{} echo "FIM paths configured: {}"

grep "realtime=\"yes\"" /var/ossec/etc/ossec.conf 2>/dev/null | wc -l | \
  xargs -I{} echo "Realtime paths: {}"

# Run audit to confirm
./01-auditors/audit-edr-agents.sh --wazuh-only

# Generate FIM evidence
mkdir -p ../evidence
cat << 'EOF' > ../evidence/fim-coverage-$(date +%Y%m%d).txt
FIM Coverage Assessment — $(date)
Audit: NIST SI-7 — Software and Information Integrity

Monitored paths:
$(grep "<directories" /var/ossec/etc/ossec.conf 2>/dev/null || echo "See ossec.conf")

Realtime paths:
$(grep 'realtime="yes"' /var/ossec/etc/ossec.conf 2>/dev/null || echo "See ossec.conf")
EOF
echo "Evidence saved"
```

**Next step:** `03-validate.md`
