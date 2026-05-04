# T1566.001 Phishing Email — Investigation

**ATT&CK:** T1566.001 — Spearphishing Attachment
**Triage time target:** 15 minutes to initial verdict

## Triage Checklist

### Email Artifact Analysis

- [ ] Pull the raw email headers (From, Reply-To, Return-Path, Received-SPF, DKIM, DMARC)
- [ ] Check: does From domain match the Return-Path domain? Mismatch = spoofing indicator
- [ ] Check SPF/DKIM/DMARC result in headers — FAIL = likely spoofed
- [ ] Check originating IP against AbuseIPDB and VirusTotal
- [ ] Check sending domain WHOIS — registered in last 30 days = high risk
- [ ] If attachment present: hash the file (sha256sum), check VirusTotal
- [ ] If URL present: check urlscan.io, VirusTotal URL scan, Unfurl the URL structure

### Host Analysis (if user clicked)

- [ ] What time did the user open the email / click the attachment?
- [ ] Pull process tree for that time window (±5 minutes): what spawned what?
- [ ] Check for new processes spawned by mail client (outlook.exe, thunderbird → cmd.exe, powershell.exe)
- [ ] Check for new files created in %TEMP%, %APPDATA%, Downloads in that window
- [ ] Check for new scheduled tasks, registry run keys, or services created
- [ ] Check for outbound network connections from the affected host in that window

### Account Analysis

- [ ] Did the user report anything? Ask them what they clicked and when
- [ ] Check if the user's credentials appear in HaveIBeenPwned (domain-level search)
- [ ] Check for MFA push events — did user get an unexpected prompt?
- [ ] Check for any successful logins from new locations after the email timestamp

## Key Questions to Answer Before Closing/Escalating

1. Was the attachment/link actually opened?
2. Did any process spawn from the mail client?
3. Is there evidence of outbound C2 (DNS lookups to new domains, unusual ports)?
4. Are credentials at risk?

## Escalate If

- Mail client spawned any child process (cmd, powershell, wscript, mshta)
- New outbound connections established post-click
- New files created in suspicious locations post-click
- User credentials observed in subsequent login attempts from new locations
