# T1078 Valid Account Abuse — Evidence Checklist

## Authentication Evidence
- [ ] Auth log extract: all activity for the account (grep by username)
- [ ] Login timestamp, source IP, and method (password, key, MFA)
- [ ] GeoIP lookup result for the source IP
- [ ] Comparison: user's normal login locations vs. this login
- [ ] MFA log: was MFA challenged and approved?

## Account State Evidence
- [ ] Account group memberships at time of incident
- [ ] Password last changed timestamp
- [ ] List of active sessions at time of detection
- [ ] List of SSH authorized_keys (before and after)

## Post-Login Activity Evidence
- [ ] Command history for session (if available)
- [ ] Files accessed during the session
- [ ] Network connections made during the session
- [ ] Sudo/privilege escalation attempts

## Remediation Proof
- [ ] Screenshot: password reset confirmed
- [ ] Screenshot: all sessions terminated
- [ ] Screenshot: MFA device revoked and re-enrolled
- [ ] Screenshot: account re-enabled (if disabled during investigation)
