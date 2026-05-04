# T1110 Brute Force / Lockout — Remediation

## Immediate: Block the Source

```bash
# Block attacking IP at the firewall
sudo iptables -A INPUT -s <ATTACKING_IP> -j DROP
sudo iptables -A INPUT -s <ATTACKING_IP> -j LOG --log-prefix "BLOCKED-BRUTE: "

# Verify block
iptables -L INPUT -n -v | grep <ATTACKING_IP>
```

If distributed spray (many IPs): implement a fail2ban rule or SIEM-triggered block.

## Account Hardening

- [ ] Reset any accounts that were successfully authenticated from attacking IPs
- [ ] Review and unlock any accounts that were locked — verify they are not compromised
- [ ] Ensure account lockout policy is configured: 5 failures = 15 minute lockout minimum

## SSH Hardening (if SSH is the target)

```bash
# /etc/ssh/sshd_config — add or verify:
MaxAuthTries 3
LoginGraceTime 20
PermitRootLogin no
PasswordAuthentication no   # Prefer key-based auth
```

## Rate Limiting with fail2ban

```bash
# Install and configure fail2ban
sudo apt install fail2ban -y
sudo systemctl enable fail2ban --now

# /etc/fail2ban/jail.local
[sshd]
enabled = true
maxretry = 5
findtime = 300
bantime = 3600
```

## Verification

- [ ] Attacking IP blocked — confirm `iptables -L | grep <IP>` shows DROP rule
- [ ] No new failures from blocked IP in auth.log
- [ ] fail2ban running — `sudo fail2ban-client status sshd`
- [ ] No successful logins from attacking IP after block
