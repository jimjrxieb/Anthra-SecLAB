# L7-06 DE.AE-06 — Incident Report

**Finding:** Log Retention Below Compliance Threshold
**Date:** _______________
**Analyst:** _______________
**Status:** [ ] Open  [ ] Remediated  [ ] Verified  [ ] Closed

---

## Finding Summary

| Field | Value |
|-------|-------|
| Asset | Loki / Fluent Bit log pipeline |
| Namespace | logging |
| CSF Subcategory | DE.AE-06 (Info on adverse events provided) |
| CIS v8 | 8.10 (Retain Audit Logs) |
| NIST 800-53 | AU-11 (Audit Record Retention) |
| Severity | HIGH |
| Rank | C |

## Retention Metrics

| Metric | Before Fix | After Fix |
|--------|-----------|-----------|
| Retention period | | |
| Oldest available log | | |
| Days of logs accessible | | |

## Framework Requirements

| Framework | Minimum Retention | Current Compliance |
|-----------|------------------|--------------------|
| FedRAMP (AU-11) | 90 days | [ ] Compliant  [ ] Non-compliant |
| PCI-DSS 10.7.1 | 365 days | [ ] Compliant  [ ] Non-compliant |
| HIPAA 45 CFR 164.312(b) | 6 years | [ ] Compliant  [ ] Non-compliant |
| CIS Controls v8 8.10 | 90 days | [ ] Compliant  [ ] Non-compliant |

## Investigation Impact Assessment

If an incident occurred 48 hours ago, could you investigate it?

- [ ] Yes — logs cover that period
- [ ] No — logs have already been rotated

What evidence would be unavailable?

1.
2.
3.

## Timeline

| Time | Action |
|------|--------|
| | Baseline captured — current retention documented |
| | Retention gap identified (below framework minimum) |
| | Investigation completed — compliance impact assessed |
| | Fix applied — retention set to ___ days |
| | Verification — oldest log entry confirmed |
| | Report filed |

## Root Cause

_______________

## Remediation Applied

- [ ] Current retention policy identified
- [ ] Framework requirements compared
- [ ] Loki retention_period updated to >= 2160h (90 days)
- [ ] Fluent Bit buffer configuration reviewed
- [ ] Oldest log entry verified post-fix
- [ ] Retention policy documented for auditor

## POA&M Entry

| ID | Control | Status | Priority | Target Date | Owner |
|----|---------|--------|----------|-------------|-------|
| L7-06 | DE.AE-06 / CIS 8.10 / AU-11 | REMEDIATED | HIGH | | |

## Auditor Evidence Checklist

- [ ] Loki ConfigMap showing retention_period
- [ ] Oldest log entry timestamp
- [ ] Framework compliance matrix (table above)
- [ ] Before/after retention metrics
- [ ] Written retention policy (SSP AU-11 section)
- [ ] Log pipeline architecture diagram
- [ ] Fluent Bit DaemonSet pod count vs node count
- [ ] verify.sh output
- [ ] This report (signed)

## Lessons Learned

1.
2.
3.

---

**Signature:** _______________
**Reviewed by:** _______________
