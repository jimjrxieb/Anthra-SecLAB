# L7-07 — DE.AE-07: Remediate Phase

## AU-2 Implications and GRC Documentation

You have restored Fluent Bit coverage. This phase covers what the GRC documentation
must capture to properly record the gap event, close the finding, and prevent
recurrence. Restoring the pod is operational. Documenting the gap is compliance.

---

## What AU-2 Requires

NIST 800-53 AU-2 (Event Logging) requires that the organization:

a. Identify the types of events the system is capable of logging in support of
   the audit function
b. Coordinate the event logging function with other organizations requiring
   audit-related information
c. Specify the following event types to be logged: [defined in security plan]
d. Provide a rationale for why the event types are deemed adequate to support
   after-the-fact investigations of security incidents

A Fluent Bit gap directly violates AU-2 for the duration of the gap: events
occurred, those events were not collected, and the audit function was not fulfilled.
The control status during the gap window is: NOT SATISFIED.

---

## Documenting the Gap Window

The gap must be documented — even after the technical fix is applied. An undocumented
gap that is discovered later looks worse than a documented gap that was identified and
remediated promptly.

The gap record must contain:

```
AU-2 Gap Event Record

Date of gap:         [Date break.sh was run]
Gap start time:      [From /tmp/l7-07-gap-start.txt or DaemonSet events]
Gap end time:        [When verify.sh confirmed all pods Running]
Gap duration:        [Minutes or hours]

Affected node:       [Node name]
Node status:         [Cordoned / Pod restart / Node failure]
Affected namespace:  anthra (and all other namespaces on affected node)

Pods on affected node during gap:
  - [list from investigate.md Question 2]

Security-relevant pods affected:
  - [list pods that handle auth, sensitive data, or external connections]

Events unrecoverable:
  All events from pods on [AFFECTED_NODE] between [GAP_START] and [GAP_END]
  are not available in the audit trail.

Was an active incident occurring during the gap? [YES / NO]
If YES: escalate immediately. This is a CRITICAL finding.

Compensating evidence reviewed:
  [List any alternative sources checked — kube-apiserver audit, network logs, etc.]
  Result: [Reconstructed / Not reconstructable]
```

---

## GRC Documentation Requirements

### 1. Create the AU-2 Gap Event Record

Using the template above, create the formal gap record. File it in your GRC system
under the AU-2 control for this system. The record shows:
- The gap was detected promptly (not weeks later)
- The scope was investigated (which pods, which events)
- The fix was applied (Fluent Bit restored)
- Whether compensating evidence exists

This record is your evidence of AU-2 due diligence. Without it, the gap looks like
a control failure you did not notice. With it, it looks like a control failure you
identified, investigated, and remediated.

---

### 2. Update the AU-2 Control Implementation Statement (SSP)

The System Security Plan AU-2 section should be updated to reflect:

```
AU-2 — Event Logging

Implementation: Audit events are collected from all namespaces via Fluent Bit
DaemonSet running in the logging namespace. One pod per node ensures complete
coverage. The following event types are logged: [list per security plan].

Gap monitoring: DaemonSet pod count is compared to node count via automated
health check. Alertmanager fires if pod count drops below node count. Gaps
are documented in the AU-2 gap event log (see supporting evidence).

Known gap event: [Date] — one Fluent Bit pod was unavailable for [duration].
Gap documented in gap event record [ID]. No active incident occurred during
the gap window. Compensating evidence: [result].
```

---

### 3. Implement Alerting to Prevent Future Silent Gaps

The root cause of this scenario is not the deleted pod — it is the absence of an
alert when the pod count dropped. If Alertmanager had fired within 5 minutes of
the pod deletion, the gap would have been 5 minutes, not 20+ minutes.

Add this PrometheusRule to detect Fluent Bit gaps:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: fluent-bit-gap-alert
  namespace: logging
spec:
  groups:
    - name: fluent-bit-coverage
      rules:
        - alert: FluentBitPodMissing
          expr: |
            kube_daemonset_status_desired_number_scheduled{daemonset="fluent-bit",namespace="logging"}
            !=
            kube_daemonset_status_number_ready{daemonset="fluent-bit",namespace="logging"}
          for: 2m
          labels:
            severity: critical
            control: AU-2
          annotations:
            summary: "Fluent Bit pod missing — log collection gap active"
            description: >
              Fluent Bit DaemonSet has {{ $value }} fewer pods than expected.
              One or more nodes have no log collection. AU-2 gap is open.
              Check: kubectl get pods -n logging -l app.kubernetes.io/name=fluent-bit -o wide
```

File this as a change record. Alerting for AU-2 gaps is a control enhancement that
must be documented in the SSP as a new implementation detail.

---

### 4. Evidence Package for the Auditor

| Evidence Item | Source | What It Proves |
|---------------|--------|---------------|
| Gap event record | GRC system | Gap was identified and documented |
| verify.sh output | Script output | Coverage restored — all nodes covered |
| DaemonSet events | kubectl get events | Timeline of pod deletion and restart |
| PrometheusRule YAML | Git / configmap | Alerting in place to prevent recurrence |
| Audit control statement update | SSP | AU-2 implementation reflects current state |
| POA&M entry | POA&M tracker | Finding tracked through remediation |

---

## What Changed and Why

| Item | Before | After |
|------|--------|-------|
| Fluent Bit pod on affected node | Missing | Running |
| Node status | Cordoned / SchedulingDisabled | Ready / Schedulable |
| AU-2 coverage | Partial (2 of 3 nodes) | Complete (3 of 3 nodes) |
| Gap alerting | None | PrometheusRule fires within 2 minutes |
| Gap documentation | Not required | Mandatory gap event record |

---

## Preventing Recurrence

1. Deploy the PrometheusRule from step 3. This is the primary control.
2. Weekly: verify Fluent Bit pod count matches node count.
3. On every node addition or removal: verify DaemonSet desired count updated.
4. On every Kubernetes upgrade: verify Fluent Bit pods restart and recover.
5. Quarterly: review the AU-2 gap event log for patterns.

If gaps are occurring regularly, the cause is likely node instability, resource
pressure on the logging namespace, or a bug in the Fluent Bit configuration that
causes the pod to crash loop. Treat repeated gaps as a systemic issue, not
individual incidents.

---

## Next Step

Proceed to `verify.sh` to confirm all nodes have Fluent Bit coverage and log
flow is consistent across nodes.
