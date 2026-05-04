# T1055 Process Injection — Remediation

## Immediate: Isolate

If injection is confirmed with active C2:
1. Isolate the host immediately (disable network)
2. Do NOT reboot — preserve volatile memory evidence

## Preserve Evidence

```bash
# Dump memory of injected process (requires gcore or /proc/mem)
sudo gcore -o /tmp/forensic-dump <PID>

# Or via /proc
sudo dd if=/proc/<PID>/mem of=/tmp/mem-dump-$(date +%s).bin bs=4096 2>/dev/null || true

# Capture current process state
sudo ps aux > /tmp/ps-snapshot-$(date +%s).txt
sudo ss -tnp > /tmp/netstat-snapshot-$(date +%s).txt
```

## Kill and Clean

```bash
# After evidence preserved:
sudo kill -9 <PID>

# If a web shell is suspected, check web server directories
find /var/www /srv/www /usr/share/nginx -name "*.php" -newer /proc/1 -ls 2>/dev/null
find /var/www /srv/www /usr/share/nginx -name "*.sh" -newer /proc/1 -ls 2>/dev/null
```

## Harden Against Recurrence

```bash
# Enable ptrace scope restriction (prevents ptrace between unrelated processes)
echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope

# Make permanent
echo 'kernel.yama.ptrace_scope = 1' | sudo tee -a /etc/sysctl.d/99-ptrace.conf
sudo sysctl -p /etc/sysctl.d/99-ptrace.conf
```

## Verification

- [ ] Injected process terminated — `ps aux | grep <PID>` shows nothing
- [ ] ptrace_scope set — `cat /proc/sys/kernel/yama/ptrace_scope` returns 1
- [ ] No outbound connections from previously injected host
- [ ] Web shell removed if found (web server dirs clean)
