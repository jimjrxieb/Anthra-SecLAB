# T1566.001 Phishing Email — Remediation

**Scope this before acting.** Know what was compromised before you start pulling cables.

## Immediate Actions (First 30 Minutes)

### If attachment was opened / link was clicked:
1. Isolate the host from the network (disable NIC or move to quarantine VLAN)
2. Do NOT power off — preserve volatile memory for forensics
3. Reset the user's password immediately from a clean workstation
4. Revoke all active sessions (force sign-out from all devices in IAM/Azure AD)
5. Disable MFA devices temporarily, re-enroll from scratch

### Email Infrastructure:
1. Block the sending domain at the mail gateway
2. Block the sending IP at the perimeter firewall
3. Search for all recipients of this email in the mail system — did others receive it?
4. Retract the email from all inboxes if mail system supports it (Exchange: Search-Mailbox / Purge)
5. Block the attachment hash at the endpoint security tool

### Indicators to Block:
- Sending IP → block at firewall/mail gateway
- Sending domain → block at DNS firewall and mail gateway
- Attachment SHA256 hash → block at EDR/AV
- URLs in the email → block at web proxy

## Follow-Up Actions (Next 4 Hours)

- Verify isolation of affected host
- Pull full forensic image if credentials or sensitive data may be compromised
- Notify affected user — phishing awareness moment
- Check all other users who received the same email
- File incident ticket with full IOC list

## Verification

- [ ] Sending domain/IP blocked — test: attempt to resolve/connect, confirm blocked
- [ ] User password reset — confirm login works with new creds, fails with old
- [ ] Host isolated — confirm no outbound connections from that IP
- [ ] Email retracted — confirm not visible in other mailboxes
