# Recovery

## Purpose

Restore affected systems to normal operation. Verify the threat is gone. Monitor for re-compromise.

## Recovery Checklist

### Before Bringing Systems Back Online

- [ ] All malware and persistence removed (eradication complete)
- [ ] Vulnerability patched or compensating control in place
- [ ] Credentials rotated for all affected accounts
- [ ] Network monitoring increased on affected hosts
- [ ] Backup integrity verified (ransomware may have encrypted backups too)

### Restoration Options (in order of trust)

1. **Clean rebuild from golden image** — most trusted, most effort
2. **Restore from pre-incident backup** — verify backup predates compromise
3. **Manual cleanup and verification** — least trusted, acceptable for low-severity incidents

### Restore from Backup

```bash
# Verify backup integrity before restoring
sha256sum backup-file.tar.gz   # compare against known hash
# Verify backup date predates earliest known indicator in the timeline
```

### Post-Restoration Validation

```bash
# Re-run audit scripts to confirm clean state
# Check for re-appearance of IOCs (set up monitoring)
watch -n 300 "grep -c 'COMPROMISED_IOC' /var/log/syslog 2>/dev/null"
```

## Increased Monitoring Period

After recovery, increase monitoring on affected systems for 30 days:
- Alert on any connection to previously blocked C2 IPs/domains
- Alert on any process execution matching eradicated malware hashes
- Alert on any account activity from previously compromised accounts
- Daily review of auth logs on affected systems
