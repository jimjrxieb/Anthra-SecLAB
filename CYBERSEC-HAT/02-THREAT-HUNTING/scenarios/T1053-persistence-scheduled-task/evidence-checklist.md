# T1053 Scheduled Task Persistence — Evidence Checklist

## Hunt Evidence
- [ ] Full crontab dump for all users (user-crontabs.txt)
- [ ] System cron directory contents
- [ ] Systemd timer list
- [ ] Recently modified cron files list
- [ ] Suspicious content search results

## Positive Finding Evidence
- [ ] Full text of malicious cron entry
- [ ] Decoded content (if base64 encoded)
- [ ] File modification timestamp (stat output)
- [ ] VirusTotal / AbuseIPDB result for any C2 IPs/domains referenced

## Remediation Proof
- [ ] Crontab after removal (showing entry is gone)
- [ ] Systemd unit removed (systemctl list-timers)
- [ ] C2 destination blocked (iptables -L)
- [ ] auditd persistence monitoring rules in place (auditctl -l)

## CA-7 Evidence (Negative Finding)
- [ ] Hunt date and analyst name
- [ ] All crontabs reviewed — all entries have business justification
- [ ] No recently modified cron files
- [ ] Systemd timers reviewed and documented
