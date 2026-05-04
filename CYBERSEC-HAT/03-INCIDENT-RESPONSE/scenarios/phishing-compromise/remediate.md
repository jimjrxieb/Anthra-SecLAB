# Phishing Compromise — Remediation

## Immediate (First 30 Minutes)

```bash
# 1. Lock the account
sudo usermod -L <compromised_username>

# 2. Kill all active sessions
pkill -u <compromised_username> -KILL

# 3. Isolate affected host if any process spawned from mail client
sudo ip link set <interface> down
```

## Credential Reset

```bash
# Reset password (out-of-band delivery — do NOT email the new password)
sudo passwd <compromised_username>

# Force MFA re-enrollment from clean device
# (platform-specific: Azure AD, Okta, Google Workspace)
```

## Remove Persistence

```bash
# Check and remove unauthorized SSH keys
cat /home/<username>/.ssh/authorized_keys
# Edit to remove unauthorized entries

# Check and remove unauthorized cron jobs
crontab -l -u <username>
crontab -e -u <username>   # remove malicious entries

# Check for new user accounts created
grep "useradd\|new user" /var/log/auth.log | tail -20
```

## Block IOCs

```bash
# Block the phishing domain at DNS level
# (Add to DNS firewall blocklist or /etc/hosts)
echo "0.0.0.0 <phishing-domain>" | sudo tee -a /etc/hosts

# Block C2 IP if identified
sudo iptables -A OUTPUT -d <c2_ip> -j DROP
```

## Verification

- [ ] Account locked — `passwd -S <username>` shows L
- [ ] Sessions terminated — `who` shows no active sessions
- [ ] No unauthorized SSH keys remain
- [ ] No new cron jobs present
- [ ] C2/phishing domain blocked
- [ ] MFA re-enrollment completed from clean device
