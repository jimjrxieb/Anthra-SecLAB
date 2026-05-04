# Credential Theft Response — Investigation

**ATT&CK:** T1003 (OS Credential Dumping), T1550 (Use Alternate Authentication Material)

## Triage Priority Questions

1. How were credentials stolen? (dumping, phishing, keylogging, breach)
2. Which credentials are compromised? (which accounts, which systems)
3. Have stolen credentials already been used? (active abuse)
4. Is lateral movement in progress?

## Investigation Checklist

### Confirm Theft Vector

- [ ] Review auditd events for /etc/shadow access — did a non-system process touch it?
- [ ] Check for credential dumping tools: `find /tmp -name "*dump*" -o -name "*mimikatz*" -o -name "*secretsdump*"`
- [ ] Review bash history for credential extraction commands
- [ ] Check for memory dumping: gcore, dd against process memory, ptrace syscalls

### Identify Compromised Accounts

- [ ] Which accounts were accessible at the time of compromise?
- [ ] Are these local accounts, domain accounts, service accounts, or all three?
- [ ] What systems do these accounts have access to?
- [ ] Have any of these credentials appeared in external threat intel / paste sites?

### Detect Active Credential Use

- [ ] Check `multi-account-same-ip.txt` — is one IP using multiple accounts? (stolen credentials in use)
- [ ] Check auth logs for successful logins from new IPs for ALL potentially compromised accounts
- [ ] Check cloud/SaaS sign-in logs (Azure AD, Okta) for the same accounts
- [ ] Is MFA being bypassed? Check for MFA fatigue push attacks (many push requests)

### Lateral Movement Assessment

- [ ] Map all systems each compromised account has touched since theft
- [ ] Look for the same credentials used on multiple internal hosts
- [ ] Check for SSH or RDP from compromised host to other internal hosts
- [ ] Check for new accounts or SSH keys added on any touched system

## Escalate If

- Confirmed credential use from new location or unknown IP
- Service account credentials compromised (broad blast radius)
- Domain admin / root credentials involved
- Evidence of active lateral movement
