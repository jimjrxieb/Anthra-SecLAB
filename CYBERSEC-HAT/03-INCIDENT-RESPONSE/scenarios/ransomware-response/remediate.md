# Ransomware Response — Remediation

## Phase Order (do not skip phases)

```
1. CONTAIN → 2. SCOPE → 3. ERADICATE → 4. RECOVER → 5. HARDEN
```

## Phase 1: Contain

```bash
# Isolate affected host immediately
sudo ip link set <interface> down
# Or block all traffic
sudo iptables -I INPUT -j DROP
sudo iptables -I OUTPUT -j DROP
```

For enterprise: work with network team to move host to quarantine VLAN.

## Phase 2: Scope

- Identify all affected systems (check for ransom notes on all hosts)
- Identify the initial access vector
- Determine if backups are clean and pre-incident

## Phase 3: Eradicate

```bash
# After isolation, identify the ransomware process and kill it
ps aux | grep -iE "crypt|ransom|locker"
sudo kill -9 <PID>

# Remove persistence
crontab -l  # check for persistence
find /etc/cron* -newer /proc/1 -ls
find /etc/systemd/system/ -newer /proc/1 -name "*.service" -ls

# Remove malware binaries
find /tmp /var/tmp /home -newer /proc/1 -executable -type f -ls
# Preserve copies before removing: sha256sum <file> && sudo rm <file>
```

## Phase 4: Recover

1. Verify clean backup exists and pre-dates earliest encryption
2. Verify backup integrity: `sha256sum <backup>` against known hash
3. Rebuild from clean backup or golden image
4. Do NOT restore from backups taken during or after encryption

```bash
# Restore from backup (example — adapt to your backup tool)
# rsync -av --delete /backup/clean/ /restore/target/
```

## Phase 5: Harden (Post-Recovery)

- [ ] Patch initial access vulnerability
- [ ] Enforce MFA on all remote access (VPN, RDP, SSH)
- [ ] Implement network segmentation to limit blast radius of future incidents
- [ ] Deploy or update EDR with ransomware behavior detection
- [ ] Test backup restoration procedure (before the next incident)
- [ ] Enable immutable backups (backups that cannot be deleted by ransomware)

## Verification

- [ ] No encrypted file extensions appearing on restored systems
- [ ] No ransom note files present
- [ ] No outbound connections to previous C2 IPs
- [ ] Initial access vector patched and verified
- [ ] Backup integrity verified and backup air-gap confirmed
