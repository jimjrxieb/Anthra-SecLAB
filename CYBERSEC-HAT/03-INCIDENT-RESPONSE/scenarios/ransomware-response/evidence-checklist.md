# Ransomware Response — Evidence Checklist

## Initial Detection Evidence
- [ ] detect.sh full output (save immediately — before any remediation)
- [ ] List of ransom note files with paths and timestamps
- [ ] List of encrypted files with timestamps (first and last)
- [ ] Ransom note contents (copy of text)
- [ ] Ransomware family identification (ID Ransomware result)

## Forensic Collection (before isolation if possible)
- [ ] forensic-collection.sh output (run BEFORE isolating)
- [ ] Running process list at time of detection
- [ ] Network connections at time of detection
- [ ] Memory dump if active encryption (gcore on ransomware process)

## Timeline Evidence
- [ ] Earliest encrypted file timestamp
- [ ] Auth log entries around initial access window
- [ ] Any phishing emails delivered in days prior
- [ ] VPN/RDP logs around initial access time

## Impact Evidence
- [ ] Count of encrypted files per directory
- [ ] Business systems affected (list)
- [ ] Data types potentially affected (PII, PHI, financial, IP)
- [ ] Backup status: clean backup available? Date of clean backup?

## Remediation Proof
- [ ] Isolation confirmed (network disconnected)
- [ ] Malware process killed (ps aux showing clean)
- [ ] Persistence removed (crontab -l clean)
- [ ] Clean backup restored (sha256sum verification)
- [ ] Initial access vector patched
