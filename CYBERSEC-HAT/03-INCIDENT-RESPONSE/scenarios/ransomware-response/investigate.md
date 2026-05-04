# Ransomware Response — Investigation

**ATT&CK:** T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery)
**Priority:** Containment before investigation. Do not delay isolation.

## Immediate Decision Tree

```
Ransomware detected
  → Is encryption still in progress? (CPU high, files changing)
    YES → Isolate NOW (disable NIC), then investigate
    NO  → Preserve volatile state, then isolate
```

## Investigation Checklist

### Scope the Infection

- [ ] Which systems are affected? (check for ransom notes fleet-wide)
- [ ] When did encryption start? (earliest encrypted file timestamp)
- [ ] Is encryption still in progress? (`lsof | grep -E "\.encrypted|\.locked"`)
- [ ] Are backup systems affected? (check backup server — were backups encrypted too?)
- [ ] Are network shares affected? (SMB mounts may also be encrypting)

### Identify the Ransomware Family

- [ ] Read the ransom note — which group? Payment instructions? Which cryptocurrency?
- [ ] Check encrypted file extensions — upload sample to ID Ransomware (id-ransomware.malwarehunterteam.com)
- [ ] This determines: decryptor availability, known TTPs, likely initial access vector

### Establish the Timeline

- [ ] What is the earliest encrypted file timestamp?
- [ ] What is the initial access vector? (check auth.log, email logs, VPN logs for that window)
- [ ] How long was the attacker in the environment before detonating? (dwell time)
- [ ] Which systems were accessed before detonation?

### Initial Access Root Cause

- [ ] Check auth.log for successful logins from new IPs around the initial access window
- [ ] Check for phishing emails delivered in the days before encryption
- [ ] Check for unpatched VPN or RDP vulnerabilities exploited externally
- [ ] Check for valid credential use from suspicious source

## Communication

For P1 ransomware incidents, notify immediately:
- CISO / Security Manager
- Legal / General Counsel (regulatory implications)
- IT Director (recovery planning)
- Executive team if business operations affected
