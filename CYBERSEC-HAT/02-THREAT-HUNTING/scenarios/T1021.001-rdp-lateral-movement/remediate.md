# T1021.001 Lateral Movement — Remediation

## Immediate: Scope the Blast Radius

1. Map every host the compromised account touched during the suspected window
2. These are all potentially compromised — treat them as such
3. Check for persistence on each host (cron, SSH keys, new users)

## Terminate Active Sessions

```bash
# Find and kill suspicious SSH sessions
who -a                         # identify the session
pkill -u <username> -KILL      # kill all processes for that user
# Or target a specific pts
pkill -t pts/<N>               # kill specific terminal
```

## Reset Compromised Credentials

```bash
# Lock the account immediately
sudo usermod -L <username>

# Reset password after investigation
sudo passwd <username>

# Rotate SSH keys
sudo -u <username> ssh-keygen -R <target_host>  # remove known_hosts entry
# Edit /home/<username>/.ssh/authorized_keys on all touched hosts
```

## Network Segmentation (Prevent Recurrence)

```bash
# Restrict SSH to specific source IPs using /etc/hosts.allow
echo "sshd: 192.168.1.0/24" | sudo tee -a /etc/hosts.allow
echo "sshd: ALL" | sudo tee -a /etc/hosts.deny

# Or via iptables: only allow SSH from management subnet
sudo iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j DROP
```

## Verification

- [ ] Account locked — `passwd -S <username>` shows L status
- [ ] Active sessions terminated — `who` shows no sessions for that account
- [ ] SSH key rotated on all touched hosts
- [ ] Network restriction in place — test SSH from unauthorized subnet, confirm rejected
