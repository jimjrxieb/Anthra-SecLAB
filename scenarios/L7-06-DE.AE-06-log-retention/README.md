# L7-06 — DE.AE-06: Log Retention Too Short

## Scenario Summary

The Portfolio application is logging. Fluent Bit is running. Logs are being collected.
And then they are gone.

An incident is reported Tuesday morning. The suspicious activity happened Saturday night.
The analyst opens Grafana, queries for Saturday logs from the API pod, and finds nothing.
Not "no events" — nothing. The logs rotated. They no longer exist.

This is a log retention failure. Not a failure to log — a failure to keep what was
logged long enough to be useful. The logging pipeline ran correctly. Fluent Bit
collected every line. But the retention window was set to 24 hours, and by Tuesday,
Saturday might as well not have existed.

This scenario simulates that exact condition. It demonstrates how a technically
functional logging stack can fail to satisfy the core requirement: that audit records
be available for investigation when an incident occurs — which is rarely within 24 hours
of the event itself.

---

## Control Mapping

| Field            | Value                                                                              |
|------------------|------------------------------------------------------------------------------------|
| CSF Function     | DETECT                                                                             |
| CSF Category     | DE.AE — Adverse Event Analysis                                                     |
| CSF Subcategory  | DE.AE-06 — Information on adverse events provided to authorized staff and tools    |
| CIS v8 Control   | 8.10 — Retain Audit Logs                                                           |
| NIST 800-53      | AU-11 — Audit Record Retention                                                     |
| OSI Layer        | Layer 7 — Application                                                              |
| Severity         | HIGH                                                                               |
| Rank             | C — Retention policy change requires GRC approval and documented justification     |
| Difficulty       | Level 1                                                                            |

---

## The Retention Requirements by Framework

This is the core GRC content of this scenario. Every analyst needs to know these numbers.

| Framework         | Minimum Retention | Applies To                          |
|-------------------|------------------|--------------------------------------|
| FedRAMP Moderate  | 90 days online   | All federal system audit records     |
| NIST 800-53 AU-11 | Defined by org   | Defined in security plan (90d min)   |
| PCI-DSS v4.0      | 12 months (1yr)  | 3 months online, 9 months archived   |
| HIPAA             | 6 years          | PHI-related audit logs               |
| SOC 2 Type II     | Defined by org   | Typically 90 days for Type II period |
| CIS v8 8.10       | 90 days          | Security event logs                  |

If the cluster hosts a FedRAMP workload — which anthra simulates — 90 days is the
floor. Not a target. The floor.

---

## What Is Already Broken (or Will Be)

Fluent Bit is collecting logs correctly. The break in this scenario is downstream:
the retention setting. Depending on what is deployed in the lab:

- **Loki** (if deployed): retention set to 24h via `limits_config.retention_period`
- **Fluent Bit buffer only** (no central storage): `Mem_Buf_Limit` exhausts in hours;
  logs that leave the buffer and go nowhere are unrecoverable
- **kubectl logs**: backed by container log files on the node; kubelet rotates these
  at 100MB or 5 days, whichever comes first — both are short of 90 days

Any of these conditions means the same outcome: an incident that happened more than
a day ago has no recoverable logs.

---

## Affected Assets

- **Namespace:** logging
- **DaemonSet:** fluent-bit
- **Log Storage:** Loki (if deployed), or Fluent Bit node buffer only
- **Target workload namespace:** anthra
- **Pods logging:** api, ui, chroma

---

## Scenario Lifecycle

| Phase       | File                 | What Happens                                                    |
|-------------|----------------------|-----------------------------------------------------------------|
| Baseline    | `baseline.sh`        | Capture current retention config and oldest available log       |
| Break       | `break.sh`           | Set retention to 24h (Loki) or document buffer-only condition   |
| Detect      | `detect.md`          | L1 guide — query for old logs, find they are gone               |
| Investigate | `investigate.md`     | What is the current policy? What frameworks apply?              |
| Fix         | `fix.sh`             | Set retention to 90 days minimum                                |
| Remediate   | `remediate.md`       | AU-11 requirements, GRC documentation guide                     |
| Verify      | `verify.sh`          | Confirm retention >= 90 days; query oldest available log entry  |
| Report      | `report-template.md` | POA&M fill-in for DE.AE-06 / CIS 8.10 / AU-11                  |

---

## Why This Matters

AU-11 requires that organizations retain audit records for a defined period to support
after-the-fact investigations of security incidents. The key phrase is "after the fact."
Incidents are not investigated in real time. They are investigated hours, days, or weeks
after the event. If the logs are gone by the time the investigation starts, AU-11 is
not satisfied — regardless of what the logging tool documentation says.

CIS 8.10 requires that audit logs be retained for at least 90 days. This is one of
the most commonly cited gaps in FedRAMP Moderate assessments because it requires
configuration, not just deployment. Fluent Bit running does not mean 90-day retention.
Something has to store those logs for 90 days and make them queryable.

DE.AE-06 requires that information on adverse events be provided to authorized staff
and tools. If the logs no longer exist, that information cannot be provided. The
control fails completely — not partially.

---

## CySA+ OBJ 2.4 Teaching Point

CySA+ Objective 2.4: Given a scenario, analyze output from common vulnerability
assessment tools, including log analysis.

This scenario teaches: a log gap is not always a failure to generate logs. It may
be a failure to retain them. When an investigation finds no logs for a time window,
the analyst must distinguish between:

1. Nothing happened (no events generated)
2. Something happened but was not logged (collection failure)
3. Something was logged but is no longer retained (retention failure)

The third case is this scenario. The detective skill is knowing which question to ask.

---

## References

- NIST 800-53 Rev 5: AU-11 Audit Record Retention
- NIST CSF 2.0: DE.AE-06
- CIS Controls v8: 8.10 Retain Audit Logs
- FedRAMP Moderate Baseline: AU-11 (1) — Audit Record Retention
- PCI-DSS v4.0: Requirement 10.7 — Failures of critical security controls detected
- HIPAA 45 CFR 164.312(b) — Audit controls
- Fluent Bit buffering: https://docs.fluentbit.io/manual/administration/buffering-and-storage
