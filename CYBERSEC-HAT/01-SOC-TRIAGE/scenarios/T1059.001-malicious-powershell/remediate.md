# T1059.001 Malicious Scripting — Remediation

## Immediate

1. **Kill the process** if still running:
   ```bash
   sudo kill -9 <PID>
   ```
2. **Isolate the host** if the script made outbound connections or established C2
3. **Preserve evidence** before killing: `sudo cp /proc/<PID>/exe /tmp/malware-sample` and `sudo strings /proc/<PID>/mem > /tmp/mem-strings.txt`

## Clean Up Artifacts

```bash
# Remove any dropped files
find /tmp /var/tmp /dev/shm -newer /proc/1 -type f -ls
# Review each before deleting — preserve copies for forensics

# Remove persistence if established
crontab -l -u <affected_user>   # review
crontab -r -u <affected_user>   # remove if malicious

# Remove unauthorized SSH keys
cat /home/<user>/.ssh/authorized_keys
# Edit to remove unauthorized entries
```

## Block C2 Infrastructure

```bash
# If the script connected to an external host:
sudo iptables -A OUTPUT -d <C2_IP> -j DROP
# Block the domain at DNS level if DNS firewall available
```

## Harden Against Recurrence

- [ ] Audit all cron jobs across all users
- [ ] Restrict write access to /tmp with noexec mount option:
  ```
  # /etc/fstab: tmpfs /tmp tmpfs defaults,noexec,nosuid 0 0
  ```
- [ ] Enable auditd rules for execve syscalls to catch future script execution
- [ ] Review how the script was delivered — close the initial access vector

## Verification

- [ ] Malicious process no longer running — `ps aux | grep <script_name>`
- [ ] C2 IP blocked — `iptables -L | grep <IP>`
- [ ] No persistence remains — `crontab -l`, `ls ~/.ssh/authorized_keys`
- [ ] auditd rule for execve in place — `auditctl -l | grep execve`
