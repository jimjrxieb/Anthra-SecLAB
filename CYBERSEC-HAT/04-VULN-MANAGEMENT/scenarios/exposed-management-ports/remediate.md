# Exposed Management Ports — Remediation

## SSH Hardening

```bash
# /etc/ssh/sshd_config — apply all of these:
sudo tee /etc/ssh/sshd_config.d/hardening.conf << 'EOF'
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
LoginGraceTime 20
AllowUsers <your_username>
EOF

# Restart SSH (do NOT close your current session until verified)
sudo sshd -t   # syntax check first
sudo systemctl restart sshd

# Verify from a new terminal before closing this one
```

## Restrict to Specific Source IPs

```bash
# Method 1: iptables — allow only management subnet
sudo iptables -I INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j DROP

# Make persistent
sudo iptables-save | sudo tee /etc/iptables/rules.v4

# Method 2: /etc/hosts.allow (TCP wrappers)
echo "sshd: 192.168.1.0/24" | sudo tee -a /etc/hosts.allow
echo "sshd: ALL" | sudo tee -a /etc/hosts.deny
```

## Deploy fail2ban

```bash
sudo apt install fail2ban -y
sudo tee /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
maxretry = 5
findtime = 300
bantime = 3600
EOF
sudo systemctl enable fail2ban --now
sudo fail2ban-client status sshd
```

## Disable Telnet Permanently

```bash
sudo systemctl stop telnetd 2>/dev/null || true
sudo systemctl disable telnetd 2>/dev/null || true
sudo systemctl mask telnetd 2>/dev/null || true
sudo apt-get remove telnetd telnet -y 2>/dev/null || true
```

## Verification

```bash
# Confirm SSH no longer allows password auth
ssh -o PasswordAuthentication=yes <user>@localhost   # should fail

# Confirm root login disabled
ssh root@localhost   # should be rejected

# Confirm fail2ban running
sudo fail2ban-client status sshd

# Re-run detect.sh and confirm EXPOSED items are now RESTRICTED
```
