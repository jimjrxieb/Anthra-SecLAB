# T1078 Valid Account Abuse — Investigation

**ATT&CK:** T1078 — Valid Accounts
**Triage time target:** 20 minutes to initial verdict

## Triage Checklist

### Account Analysis

- [ ] Identify the account: is it a user account, service account, or shared account?
- [ ] What is this account's normal working hours and normal login location?
- [ ] Is this account a member of privileged groups (sudo, admin, Domain Admins)?
- [ ] When was the password last changed?
- [ ] Has this account been reported as suspicious before?

### Login Pattern Analysis

- [ ] Compare login time against the user's normal pattern (business hours?)
- [ ] Compare source IP against the user's normal location — is this a new country/city?
- [ ] Is the source IP a known VPN exit node, Tor exit, or datacenter IP? (Check ipinfo.io)
- [ ] Was MFA challenged? Did the user approve an unexpected push?
- [ ] Were there failed login attempts before the successful one? (Password spray or brute force leading to success)

### Post-Login Activity

- [ ] What did the account do after logging in? (Commands run, files accessed, network connections)
- [ ] Did the account attempt to access systems it does not normally access?
- [ ] Were any privilege escalation attempts made?
- [ ] Were any new accounts created or SSH keys added?
- [ ] Were any cron jobs or services modified?

### Verification with User

- [ ] Contact the user through a separate channel (phone or in-person — not email if compromised)
- [ ] Ask: were you logged in at [time] from [location]?
- [ ] If no: account compromise confirmed — escalate immediately

## Key Questions to Answer

1. Did the user actually log in, or was it unauthorized?
2. If unauthorized: how were credentials obtained? (Phishing, reuse, brute force)
3. What did the attacker do during the session?
4. Has any persistence been established?

## Escalate If

- User denies the login
- Login from a country the user has never been to
- Any privileged commands executed after login
- Any new accounts, SSH keys, or scheduled tasks created
- Evidence of lateral movement from the compromised account
