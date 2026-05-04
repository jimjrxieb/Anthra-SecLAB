# T1566.001 Phishing Email — Evidence Checklist

Collect these artifacts before and during remediation. Do not modify originals.

## Email Artifacts
- [ ] Raw email file (.eml or .msg) with full headers
- [ ] Screenshot of email as displayed to user
- [ ] SPF/DKIM/DMARC result (from headers or mail gateway logs)
- [ ] Sending IP enrichment (VirusTotal, AbuseIPDB results)
- [ ] Domain WHOIS record

## Attachment / URL Artifacts (if applicable)
- [ ] SHA256 hash of attachment
- [ ] VirusTotal analysis result (link or screenshot)
- [ ] urlscan.io result for any URLs

## Host Artifacts (if user clicked)
- [ ] Process tree at time of click (screenshot or export from EDR)
- [ ] List of new files created ±15 minutes of click
- [ ] List of new network connections ±15 minutes of click
- [ ] Browser history export (if web-delivered)

## Authentication Artifacts
- [ ] Auth log extract: user account activity ±2 hours of email timestamp
- [ ] MFA push log: any unexpected prompts?
- [ ] Login history: new locations or devices?

## Remediation Proof
- [ ] Screenshot: sending domain blocked in mail gateway
- [ ] Screenshot: hash blocked in EDR
- [ ] Screenshot: password reset confirmed
- [ ] Screenshot: sessions revoked
