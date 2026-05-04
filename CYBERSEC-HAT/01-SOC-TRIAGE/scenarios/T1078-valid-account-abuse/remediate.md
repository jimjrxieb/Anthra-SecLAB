# T1078 Valid Account Abuse — Remediation

## Immediate Actions

1. **Terminate all active sessions** for the compromised account (force sign-out everywhere)
2. **Disable the account** in IAM/Active Directory until investigation completes
3. **Reset the password** — generate a strong random password, deliver out-of-band
4. **Revoke all API keys, tokens, and SSH keys** associated with the account
5. **Force MFA re-enrollment** from a clean device

## If Service Account:
1. Rotate the service account password/secret
2. Update all dependent services with new credentials
3. Check if credential was stored in plaintext anywhere (env files, config files, CI/CD)
4. Audit what that service account has access to — scope the blast radius

## Investigation Continuation

- Pull all activity logs for the account for the past 30 days — not just the suspicious event
- Check for persistence: new cron jobs, new SSH authorized_keys, new user accounts
- Check for data access: what files/databases/S3 buckets did the account touch?
- Check for lateral movement: did the account authenticate to other systems?

## Hardening After Remediation

- [ ] Enforce MFA on the account
- [ ] Review and reduce account privileges to least-privilege
- [ ] Set login hour restrictions if system supports it
- [ ] Enable impossible travel alerting in SIEM (if not already present)
- [ ] Check password reuse — was this password used on any external service?

## Verification

- [ ] Account disabled or password changed — confirm old password fails
- [ ] All sessions terminated — confirm no active sessions in session manager
- [ ] MFA reset — confirm user re-enrolled from clean device
- [ ] SIEM alert active — confirm detection rule would catch this pattern in future
