# Remediate

## Remediation Types

| Type | When to Use | Example |
|------|-------------|---------|
| Patch | Vendor has released a fix | Apply OS/app update |
| Configuration change | Misconfiguration, not a code bug | Disable unused service, enforce TLS |
| Compensating control | No patch available | WAF rule, network block, disable feature |
| Accept risk | Low risk, high cost to fix | Document decision with CISO sign-off |

## Patch Process

```bash
# Check available updates
apt list --upgradable 2>/dev/null | grep -E "critical|security"

# Apply security patches only
sudo apt-get update
sudo apt-get upgrade --only-upgrade <package_name>

# Or apply all security updates
sudo unattended-upgrade --dry-run   # preview
sudo unattended-upgrade             # apply

# Verify patch applied
dpkg -l <package_name>
```

## Configuration Hardening

```bash
# Disable unnecessary services (example: telnet)
sudo systemctl stop telnet
sudo systemctl disable telnet
sudo systemctl mask telnet   # prevent future re-enable

# Restrict listening services to specific IPs
# /etc/ssh/sshd_config: ListenAddress 192.168.1.10

# Enforce TLS minimum version
# /etc/ssl/openssl.cnf: MinProtocol = TLSv1.2
```

## Compensating Controls (when no patch exists)

```bash
# Block the vulnerable service at the firewall
sudo iptables -A INPUT -p tcp --dport <port> -s 0.0.0.0/0 -j DROP
sudo iptables -A INPUT -p tcp --dport <port> -s 192.168.1.0/24 -j ACCEPT

# Disable vulnerable feature at application level
# (application-specific — document in POA&M)
```

## Document Everything

For each finding, record:
- Finding ID and CVE (if applicable)
- Remediation action taken
- Who took the action
- Date/time
- Verification method
