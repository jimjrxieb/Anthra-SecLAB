# Alert Intake

## Purpose

Receive an alert, assign severity, begin documentation. This runs before any investigation.

## Steps

### 1. Receive the Alert

Open the alert in your SIEM or case management tool. Record:
- Alert name and ID
- Timestamp (UTC)
- Source system / log source
- Alert rule that fired
- Raw log snippet

### 2. Initial Triage Questions (30 seconds)

Answer these before touching anything:
1. Is the affected asset known? Production? Dev? PCI scope?
2. Is the affected user/account a privileged account (admin, service account)?
3. Is this alert rule known to have false positive patterns?
4. Has this exact alert fired recently? Is this a repeat?

### 3. Assign Severity

| Severity | Criteria | SLA |
|----------|----------|-----|
| Critical | Confirmed breach, active exfiltration, ransomware | 15 min response |
| High | Probable true positive, privileged account involved | 1 hr response |
| Medium | Possible true positive, standard user, no lateral movement | 4 hr response |
| Low | Likely false positive, no asset risk | 24 hr review |

### 4. Open a Case

In TheHive or your ticketing tool:
- Title: `[ATT&CK TTP] - [Asset] - [Date]`
- Assign severity
- Tag with ATT&CK technique ID
- Link to raw alert

### 5. Document Initial Assessment

Write 2-3 sentences: what fired, why you think it matters or doesn't, what you're doing next.

Do not close without documentation. If it is a false positive, document why.
