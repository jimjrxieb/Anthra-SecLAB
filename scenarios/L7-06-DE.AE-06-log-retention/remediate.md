# L7-06 — DE.AE-06: Remediate Phase

## AU-11 Requirements and GRC Documentation

You have applied the technical fix. This phase covers what needs to happen in the
GRC system to close the finding properly. A technical fix without GRC documentation
is still an open finding at the next assessment.

---

## AU-11 by Framework: What the Auditor Checks

### FedRAMP Moderate — AU-11 (the floor for this lab)

AU-11 states: "The organization retains audit records for [FedRAMP Assignment: at
least ninety (90) days] to provide support for after-the-fact investigations of
security incidents."

The auditor checks:
1. Is there a documented retention period in the system security plan?
2. Is the actual retention configuration set to that period?
3. Can the system return logs from 90 days ago?

All three must be true. The configuration setting alone is not sufficient — the
auditor will query for old logs. If the storage backend does not have 90 days
of history yet (because it was just set up), document that and show the configuration
is correct and accumulation is in progress.

---

### PCI-DSS v4.0 — Requirement 10.7

Requirement 10.7.1: "Retain audit log history for at least 12 months, with at least
the most recent three months available for immediate analysis."

This means:
- 3 months must be online and queryable (Loki or similar)
- 9 months can be in archive (S3, Glacier, tape)
- Total: 12 months minimum

If the anthra cluster processes cardholder data, PCI-DSS applies and the retention
requirement doubles the FedRAMP floor. 90 days is not enough. 365 days is the minimum.

---

### HIPAA — 45 CFR 164.312(b)

The HIPAA Security Rule requires covered entities to implement hardware, software,
and procedural mechanisms that record and examine activity in information systems
that contain or use electronic protected health information.

HIPAA does not specify a log retention period in the security rule directly, but
the general record retention requirement under 45 CFR 164.530(j) requires 6 years
for policies and procedures. Audit logs tied to PHI access decisions should be
retained for 6 years to support breach investigation and HHS enforcement.

---

### CIS Controls v8 — 8.10 Retain Audit Logs

"Retain audit logs across enterprise assets for a minimum of 90 days."

No exceptions. No "it depends on the framework." CIS 8.10 sets 90 days as the
universal floor. Any system this control applies to must have 90+ days of logs.

---

## GRC Documentation Requirements

The following must be documented to close this finding in a GRC system.

---

### 1. Update the System Security Plan (SSP)

AU-11 implementation statement — what to write:

```
AU-11 — Audit Record Retention

Implementation: The organization retains audit records for 90 days to support
after-the-fact investigations of security incidents. Audit logs are collected
by Fluent Bit DaemonSet in the logging namespace, forwarded to Loki for storage,
and retained with retention_period: 2160h (90 days). retention_deletes_enabled
is set to true; Loki compactor manages record expiration.

Responsible role: Security Operations
Review frequency: Quarterly
Last verified: [Date fix.sh was run]
Verification method: Loki API query returning records from 90+ days ago,
                     plus ConfigMap inspection showing retention_period value.
```

---

### 2. Create or Update the Log Retention Policy

If no written retention policy exists, create one. It must state:
- What logs are retained (all audit events from anthra namespace)
- How long they are retained (90 days minimum for FedRAMP; 365 days if PCI-DSS applies)
- Where they are stored (Loki, with persistent volume)
- Who is responsible for verifying retention (Security Operations)
- What happens when retention cannot be met (escalation to ISSO)
- Review frequency (quarterly)

This policy document is separate from the SSP. The SSP references the policy.
The policy is the authoritative statement. Both must exist.

---

### 3. Open or Update the POA&M Entry

If this finding was identified during an assessment, it requires a POA&M entry.
Use the report-template.md to generate the entry. The POA&M must include:

- Finding: AU-11 not satisfied — retention was 24 hours, requirement is 90 days
- Root cause: Loki ConfigMap retention_period misconfigured (or Loki not deployed)
- Impact: Incident investigations starting more than 24 hours after an event would
  have no log evidence available
- Remediation: Set retention_period to 2160h, restart Loki
- Verification: Loki API query confirms 90-day retention window
- Closed date: [Date verify.sh confirmed compliance]

---

### 4. Evidence Package for the Auditor

The auditor will request evidence. Package the following:

| Evidence Item | Source | What It Proves |
|---------------|--------|---------------|
| Loki ConfigMap output | kubectl get configmap | retention_period is set correctly |
| Loki API response (90d query) | curl Loki /query_range | Logs exist for 90+ days |
| verify.sh output | Script output | Automated confirmation of retention |
| Log retention policy document | GRC system | Policy exists and states 90 days |
| SSP AU-11 statement | SSP document | Control is documented |
| POA&M entry (if applicable) | POA&M tracker | Finding is tracked and closed |

---

## What Changed and Why

| Item | Before | After |
|------|--------|-------|
| Loki retention_period | 24h | 720h (lab) / 2160h (production) |
| retention_deletes_enabled | not set | true |
| AU-11 compliance status | NOT SATISFIED | SATISFIED (after 90 days accumulate) |
| Log availability | 24 hours max | 90 days (production) |
| Investigation capability | Impaired beyond 24h | Supported for 90-day window |

---

## Ongoing Monitoring Requirements

AU-11 is not a one-time fix. It requires ongoing verification.

1. Quarterly: Query Loki for logs from 91 days ago. If they return, retention is working.
2. Monthly: Verify Loki storage is not approaching capacity (retention only works if
   there is space to write new logs).
3. On every Loki configuration change: re-verify retention_period is still set correctly.
4. On every cluster upgrade: verify Loki persistence is still attached and healthy.

Add these checks to your security operations calendar. If Loki runs out of disk space
and stops writing, new logs are lost and AU-11 fails again — even though the retention
setting is correct.

---

## Next Step

Proceed to `verify.sh` to confirm the retention configuration is applied and the
oldest available log timestamp has moved back toward the 90-day target.
