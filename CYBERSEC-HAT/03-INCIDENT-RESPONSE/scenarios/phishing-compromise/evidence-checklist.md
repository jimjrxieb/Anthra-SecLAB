# Phishing Compromise — Evidence Checklist

## Email Evidence
- [ ] Raw email (.eml) with full headers
- [ ] Delivery timestamp
- [ ] Sending IP enrichment (VirusTotal, AbuseIPDB)
- [ ] URL(s) in email — urlscan.io results
- [ ] Attachment hash + VirusTotal result (if applicable)

## User Action Evidence
- [ ] Timestamp of click (from browser history or mail client log)
- [ ] What was visited/opened (URL, attachment)
- [ ] Process tree at click time (±5 minutes)

## Account Activity Evidence
- [ ] Auth log for compromised account (full extract)
- [ ] Logins from new IPs after click timestamp
- [ ] MFA log — any unexpected push approvals
- [ ] List of systems accessed after click

## Remediation Proof
- [ ] Account locked (passwd -S output)
- [ ] Active sessions killed (who output)
- [ ] SSH authorized_keys after cleanup
- [ ] Crontab after cleanup
- [ ] IOCs blocked (iptables / /etc/hosts)
- [ ] MFA re-enrollment confirmed
