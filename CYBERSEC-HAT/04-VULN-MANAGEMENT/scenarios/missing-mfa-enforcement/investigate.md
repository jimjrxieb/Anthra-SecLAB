# Missing MFA Enforcement — Investigation

**Controls:** IA-2 (Identification and Authentication), AC-7 (Unsuccessful Logon Attempts)
**Risk:** Password-only authentication enables credential stuffing, brute force, and phishing compromise

## Investigation Checklist

### Scope the Gap

- [ ] Which accounts have no MFA? (from detect.sh `users-without-mfa.txt`)
- [ ] Which of those accounts are privileged? (sudo/wheel group members)
- [ ] Which of those accounts have remote access? (SSH, VPN, web console)
- [ ] The highest risk: privileged accounts + remote access + no MFA = critical gap

### Check for Recent Exploitation

- [ ] For each privileged account without MFA: review auth.log for failed login attempts
  ```bash
  grep "Failed password" /var/log/auth.log | grep "<username>"
  ```
- [ ] Were there recent successful logins from new IPs for these accounts?
- [ ] Has any no-MFA account been used in off-hours or from unusual locations?

### MFA Implementation Assessment

- [ ] Is a MFA PAM module installed? (detect.sh shows pam_google_authenticator, pam_duo, etc.)
- [ ] Is MFA enforced for SSH specifically?
- [ ] Is MFA enforced for sudo?
- [ ] Are there NOPASSWD sudo rules that bypass authentication entirely?

### Root Cause

- [ ] Why are these accounts without MFA? (Never configured, removed, exempted)
- [ ] Is there a policy requiring MFA? (If yes, non-compliance; if no, policy gap)
- [ ] What is the remediation path? (Install TOTP, deploy Duo, configure FIDO2)

## Priority

| Account Type | Remote Access | Priority |
|-------------|---------------|----------|
| Privileged (sudo/admin) | Yes (SSH/VPN) | CRITICAL |
| Privileged (sudo/admin) | Local only | HIGH |
| Standard user | Yes (SSH) | HIGH |
| Standard user | Local only | MEDIUM |
