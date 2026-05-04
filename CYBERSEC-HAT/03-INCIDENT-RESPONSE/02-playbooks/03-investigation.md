# Investigation

## Purpose

Understand what happened. Reconstruct the attack timeline. Answer: how did they get in, what did they do, what did they take, where did they go?

## Evidence Collection Order (most volatile first)

1. Running processes (`ps aux`)
2. Network connections (`ss -tnp`, `netstat`)
3. Logged-in users (`who -a`, `w`)
4. Memory (if critical — use Volatility or gcore)
5. Log files (auth.log, syslog, audit.log, app logs)
6. File system artifacts (new files, modified files, /tmp contents)
7. Disk image (if needed for full forensic analysis)

## Collection Commands

```bash
EVIDENCE_DIR="/tmp/ir-evidence-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

# Volatile first
ps aux > "$EVIDENCE_DIR/processes.txt"
ss -tnp > "$EVIDENCE_DIR/network-connections.txt"
who -a > "$EVIDENCE_DIR/logged-in-users.txt"
last -n 100 > "$EVIDENCE_DIR/login-history.txt"
netstat -rn > "$EVIDENCE_DIR/routing-table.txt"

# Logs
cp /var/log/auth.log "$EVIDENCE_DIR/auth.log"
cp /var/log/syslog "$EVIDENCE_DIR/syslog"
ausearch -ts today > "$EVIDENCE_DIR/auditd-today.txt" 2>/dev/null || true

# File system
find /tmp /var/tmp /dev/shm -type f -ls > "$EVIDENCE_DIR/tmp-files.txt"
crontab -l > "$EVIDENCE_DIR/root-crontab.txt" 2>/dev/null
find /home /root -name ".bash_history" -exec cat {} \; > "$EVIDENCE_DIR/bash-histories.txt"
```

## Timeline Reconstruction

Build the attack timeline:
- Start from the earliest known indicator
- Work forward in time
- Every event gets: timestamp, source, what happened, significance
- Map events to ATT&CK techniques

## Key Questions to Answer

1. Initial access: how did the attacker get in?
2. Execution: what did they run?
3. Persistence: how will they maintain access?
4. Privilege escalation: did they escalate?
5. Lateral movement: which other systems are involved?
6. Collection/Exfiltration: what data was accessed or taken?
