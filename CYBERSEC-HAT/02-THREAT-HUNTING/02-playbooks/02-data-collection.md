# Data Collection for Hunting

## Purpose

Know what data you need before you start. Hunting against incomplete data wastes time and produces false negatives.

## Data Source Inventory

Before starting a hunt, confirm these sources are available and current:

| Data Type | Source | Coverage Gap Risk |
|-----------|--------|------------------|
| Process execution | auditd execve, Sysmon EID 1, EDR | Blind to execution if missing |
| Network connections | Zeek conn.log, firewall logs, Sysmon EID 3 | Blind to lateral movement if missing |
| Authentication | auth.log, Windows Security 4624/4625 | Blind to credential use if missing |
| File system | auditd file watches, Sysmon EID 11 | Blind to file-based persistence if missing |
| Memory access | auditd ptrace rules, EDR | Blind to LSASS dumping if missing |

## Collection Commands

### Pull process execution logs (auditd)
```bash
ausearch -sc execve --start today 2>/dev/null | head -100
```

### Pull authentication events
```bash
grep "Accepted\|Failed\|sudo" /var/log/auth.log | tail -200
```

### Pull network connections
```bash
ss -tnp
netstat -tnp 2>/dev/null
# From Zeek: cat /var/log/zeek/current/conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto | sort | uniq -c | sort -rn
```

### Pull scheduled tasks / cron
```bash
for user in $(cut -d: -f1 /etc/passwd); do
    ct=$(crontab -l -u "$user" 2>/dev/null)
    [ -n "$ct" ] && echo "=== $user ===" && echo "$ct"
done
ls -la /etc/cron* /var/spool/cron/ 2>/dev/null
systemctl list-timers --all 2>/dev/null
```

## Baseline: What Is Normal?

Before calling something suspicious, know what normal looks like:
- Which users normally run cron jobs?
- Which processes normally have network connections?
- Which processes normally run as root?
- What is the normal volume of failed logins per day?

Document your baseline so the next hunt can compare against it.
