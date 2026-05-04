# Phishing Compromise — Investigation

**ATT&CK:** T1566 (Phishing), T1078 (Valid Accounts)

## Triage Priority Questions (First 15 Minutes)

1. What did the user click? (attachment, link, QR code)
2. What time did they click? (exact timestamp from email)
3. Did any process spawn from the mail client?
4. Is the user's account still active? (or already locked)
5. What systems does this user have access to?

## Investigation Checklist

### Confirm the Click

- [ ] Pull email headers to confirm delivery time
- [ ] Check browser history or mail client logs for the click timestamp
- [ ] Pull process tree for the affected host ±5 minutes of click time
- [ ] Did any process spawn from mail client (outlook, thunderbird → powershell, cmd, bash)?

### Account Scope

- [ ] What groups/roles does the affected account have?
- [ ] What systems can this account access? (VPN, cloud consoles, servers, SaaS apps)
- [ ] Were there any successful logins from new IPs after the click timestamp?
- [ ] Were there any MFA push approvals the user did not initiate?

### Credential Exposure Assessment

- [ ] Is this a password-only account or MFA-protected?
- [ ] Was the phishing page a credential harvester? (look at the URL the user visited)
- [ ] Pull HaveIBeenPwned for the user's domain: was this email in a breach?
- [ ] Check if credentials were used in any external service (Google, Okta, Azure AD sign-in logs)

### Blast Radius

- [ ] List all systems the account touched after the click timestamp
- [ ] Check for lateral movement: did the account log into any other internal systems?
- [ ] Check for data access: what files/databases/email was accessed?
- [ ] Check for new accounts or SSH keys added

## Escalate If

- Credentials confirmed used from new location after click
- Account has admin/privileged access
- Lateral movement detected
- Data exfiltration suspected
