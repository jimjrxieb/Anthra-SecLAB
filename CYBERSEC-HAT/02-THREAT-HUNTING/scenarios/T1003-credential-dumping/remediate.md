# T1003 Credential Dumping — Remediation

## If Active Dumping Detected (Process Running)

```bash
# Kill the dumping process
sudo kill -9 <PID>

# Preserve evidence first
sudo cp /proc/<PID>/exe /tmp/forensic-sample-$(date +%s)
sudo strings /proc/<PID>/exe > /tmp/forensic-strings-$(date +%s).txt
```

## Credential Rotation (if dumping confirmed)

All credentials on the affected system must be considered compromised:

1. **Linux passwords:** `sudo passwd <username>` for all accounts
2. **SSH keys:** Rotate all authorized_keys on affected and downstream systems
3. **Service account tokens:** Rotate all API keys, service tokens, database passwords

## Audit Rule Hardening

```bash
# Add auditd rules to monitor credential file access
cat >> /etc/audit/rules.d/credential-monitoring.rules << 'EOF'
-w /etc/passwd -p rwa -k credential-access
-w /etc/shadow -p rwa -k credential-access
-w /etc/sudoers -p rwa -k credential-access
-a always,exit -F arch=b64 -S ptrace -k ptrace-activity
EOF

sudo augenrules --load
sudo systemctl restart auditd
```

## Verify No Persistence

After credential dumping, attackers frequently establish persistence:
```bash
# Check for new SSH authorized_keys
find /home /root -name "authorized_keys" -newer /proc/1 -ls

# Check for new cron jobs
for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null && echo "---user: $u---"; done

# Check for new user accounts
grep -v "nologin\|false" /etc/passwd | tail -10
```

## Verification

- [ ] Suspicious process killed or not running
- [ ] Credentials rotated — verify with `passwd -S <username>`
- [ ] auditd rules in place — `auditctl -l | grep credential-access`
- [ ] No new persistence found
