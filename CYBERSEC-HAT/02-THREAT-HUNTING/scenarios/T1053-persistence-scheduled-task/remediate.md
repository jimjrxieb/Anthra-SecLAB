# T1053 Scheduled Task Persistence — Remediation

## Remove Malicious Scheduled Tasks

```bash
# Remove user crontab entry
crontab -e -u <username>   # edit and remove the malicious line

# Or remove the entire crontab for a compromised user
crontab -r -u <username>

# Remove system cron file
sudo rm /etc/cron.d/<malicious-file>

# Remove malicious systemd unit
sudo systemctl stop <malicious-unit>
sudo systemctl disable <malicious-unit>
sudo rm /etc/systemd/system/<malicious-unit>.service
sudo systemctl daemon-reload

# Remove at job
atrm <job-number>   # get job numbers from atq
```

## Verify Complete Removal

```bash
# Rerun detect.sh after removal and confirm clean
crontab -l -u <username>   # should be empty or missing malicious entry
systemctl list-timers --all | grep <unit-name>   # should not appear
```

## Block the Callback (if cron was phoning home)

```bash
# Block C2 domain/IP
sudo iptables -A OUTPUT -d <C2_IP> -j DROP
# Block at DNS if DNS firewall available
```

## Audit All Other Hosts

Persistence is almost always deployed broadly. Check every host:
```bash
# From an orchestration tool or manually per host:
for host in $(cat /etc/hosts | awk '{print $2}' | grep -v localhost); do
    ssh $host "crontab -l 2>/dev/null; ls /etc/cron.d/ 2>/dev/null" 2>/dev/null
done
```

## Harden Against Recurrence

```bash
# Add auditd rule to monitor cron modifications
cat >> /etc/audit/rules.d/persistence-monitoring.rules << 'EOF'
-w /etc/cron.d/ -p wa -k persistence
-w /var/spool/cron/ -p wa -k persistence
-w /etc/systemd/system/ -p wa -k persistence
EOF
sudo augenrules --load
```

## Verification

- [ ] Malicious cron entry removed — crontab -l confirms clean
- [ ] Malicious systemd unit removed — systemctl list-timers clean
- [ ] C2 destination blocked — iptables -L shows DROP rule
- [ ] auditd persistence monitoring rules in place — auditctl -l | grep persistence
