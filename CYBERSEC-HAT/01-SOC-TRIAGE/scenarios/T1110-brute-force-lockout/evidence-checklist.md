# T1110 Brute Force / Lockout — Evidence Checklist

## Attack Evidence
- [ ] Auth log extract: all failed attempts (grep "Failed password")
- [ ] Failure count per source IP (detect.sh output)
- [ ] Failure count per target username
- [ ] Time window of attack (first and last failure timestamp)
- [ ] Attack rate (failures per minute)

## Impact Evidence
- [ ] List of accounts that were locked out
- [ ] Any successful logins from attacking IPs (critical — include if present)
- [ ] Privileges of targeted accounts

## Remediation Proof
- [ ] Firewall rule blocking attacking IP (iptables -L output or screenshot)
- [ ] fail2ban status showing bans active
- [ ] Account lockout policy configuration screenshot
- [ ] SSH hardening config (MaxAuthTries, PasswordAuthentication)
