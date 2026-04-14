# L7-07 DE.AE-07 — Incident Report

**Finding:** Partial Log Collection Failure — Node Without Fluent Bit
**Date:** _______________
**Analyst:** _______________
**Status:** [ ] Open  [ ] Remediated  [ ] Verified  [ ] Closed

---

## Finding Summary

| Field | Value |
|-------|-------|
| Asset | Fluent Bit DaemonSet (logging namespace) |
| Affected Node | |
| CSF Subcategory | DE.AE-07 (Threat intel and contextual info integrated) |
| CIS v8 | 8.2 (Collect Audit Logs) |
| NIST 800-53 | AU-2 (Audit Events) |
| Severity | HIGH |
| Rank | C |

## Gap Metrics

| Metric | During Gap | After Fix |
|--------|-----------|-----------|
| Fluent Bit pod count | | |
| Node count | | |
| Pods on affected node | | |
| Log coverage | | |

## AU-2 Gap Event Record

| Field | Value |
|-------|-------|
| Gap start time | |
| Gap end time | |
| Gap duration | |
| Affected node | |
| Affected pods on node | |
| Events unrecoverable | [ ] Yes  [ ] Unknown |
| Node cordoned | [ ] Yes  [ ] No |

### Compensating Evidence During Gap

- [ ] kubectl events for affected pods still available
- [ ] Falco alerts from affected node (Falco has its own DaemonSet)
- [ ] Prometheus metrics from affected node (node-exporter)
- [ ] Application-level logs (if stdout, lost; if file, may persist)

## Timeline

| Time | Action |
|------|--------|
| | Baseline captured — Fluent Bit 3/3 pods |
| | Gap detected — Fluent Bit pod missing on node |
| | Affected node identified |
| | Pods on affected node enumerated |
| | Investigation completed — gap window calculated |
| | Fix applied — node uncordoned / pod restored |
| | Verification — 3/3 pods, log flow confirmed |
| | Report filed |

## Root Cause

_______________

## Remediation Applied

- [ ] Identified affected node
- [ ] Checked if node was cordoned
- [ ] Uncordoned node (if applicable)
- [ ] Verified Fluent Bit pod rescheduled
- [ ] Confirmed pod reached Running state
- [ ] Verified log flow from restored pod
- [ ] Verified log flow from all nodes matches
- [ ] Documented gap window for audit trail

## POA&M Entry

| ID | Control | Status | Priority | Target Date | Owner |
|----|---------|--------|----------|-------------|-------|
| L7-07 | DE.AE-07 / CIS 8.2 / AU-2 | REMEDIATED | HIGH | | |

## PrometheusRule for Prevention

```yaml
- alert: FluentBitPodMissing
  expr: kube_daemonset_status_desired_number_scheduled{daemonset="fluent-bit"}
        - kube_daemonset_status_number_ready{daemonset="fluent-bit"} > 0
  for: 2m
  labels:
    severity: critical
  annotations:
    summary: "Fluent Bit pod missing on at least one node"
```

- [ ] PrometheusRule deployed
- [ ] Alert fires when pod count < node count

## Auditor Evidence Checklist

- [ ] Fluent Bit pod-to-node mapping (before gap)
- [ ] Gap start timestamp
- [ ] Gap end timestamp
- [ ] Affected node name
- [ ] Pods running on affected node during gap
- [ ] Compensating evidence sources documented
- [ ] Fluent Bit pod-to-node mapping (after fix)
- [ ] Log flow verification per node
- [ ] PrometheusRule YAML deployed
- [ ] This report (signed)

## Lessons Learned

1.
2.
3.

---

**Signature:** _______________
**Reviewed by:** _______________
