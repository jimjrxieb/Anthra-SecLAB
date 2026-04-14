# L7-07 — DE.AE-07: Log Source Stopped (Fluent Bit Node Gap)

## Scenario Summary

Two of three Fluent Bit pods are running. Grafana shows log volume. The dashboard
looks healthy. But one node went silent 20 minutes ago and nobody noticed.

This is a partial logging failure — harder to detect than a total outage because the
monitoring graphs still show activity. The pods that are running keep reporting.
The silent node looks like a quieter node, not a broken one, until you query by node
and see a flat line where there should be a curve.

During the silence window, every pod on that node ran unmonitored. API requests were
not logged. Auth events were not captured. If an attacker exfiltrated data from a
pod on that node during the gap, there is no audit trail. AU-2 requires complete
collection of audit events. One silent node means the collection is not complete.

This scenario creates a realistic gap by deleting a single Fluent Bit pod, letting the
DaemonSet restart it (which takes 10-60 seconds), and optionally extending the gap by
cordoning the node. The L1 analyst's job is to notice the gap, quantify it, and
document what may have been missed during the silent window.

---

## Control Mapping

| Field            | Value                                                                              |
|------------------|------------------------------------------------------------------------------------|
| CSF Function     | DETECT                                                                             |
| CSF Category     | DE.AE — Adverse Event Analysis                                                     |
| CSF Subcategory  | DE.AE-07 — Cyber threat intelligence and other contextual information integrated   |
| CIS v8 Control   | 8.2 — Collect Audit Logs                                                           |
| NIST 800-53      | AU-2 — Event Logging                                                               |
| OSI Layer        | Layer 7 — Application                                                              |
| Severity         | HIGH                                                                               |
| Rank             | C — Gap documentation and compensating control determination requires L2 approval  |
| Difficulty       | Level 1                                                                            |

---

## Why Partial Failure Is Harder Than Total Failure

A total Fluent Bit outage is obvious. Zero logs flowing. Every dashboard goes flat.
Alertmanager fires within minutes. Someone notices.

A partial outage is different. Most nodes report normally. Log volume drops by one
third. If the cluster has three nodes each generating 100 events/minute, a drop from
300 to 200 events/minute looks like a quieter workload — not a broken collector.

Without a per-node log volume check or a DaemonSet pod count alert, partial failures
persist undetected. This is the realistic threat model: not the dramatic outage but
the quiet gap that lasts long enough to matter.

---

## Affected Assets

- **Namespace:** logging
- **DaemonSet:** fluent-bit
- **Affected node:** one node in k3d-seclab (the node hosting the deleted pod)
- **Target workload namespace:** anthra
- **Pods at risk during gap:** all pods scheduled on the affected node

---

## Scenario Lifecycle

| Phase       | File                 | What Happens                                                      |
|-------------|----------------------|-------------------------------------------------------------------|
| Baseline    | `baseline.sh`        | Count Fluent Bit pods, map pod-to-node, confirm log flow per node |
| Break       | `break.sh`           | Delete one Fluent Bit pod; optionally cordon node for longer gap  |
| Detect      | `detect.md`          | L1 guide — check pod count vs node count; spot the silent node    |
| Investigate | `investigate.md`     | Which node? Which pods? How long? What was not logged?            |
| Fix         | `fix.sh`             | Uncordon node, verify Fluent Bit pod returns, confirm log flow    |
| Remediate   | `remediate.md`       | AU-2 implications, gap documentation, compensating controls       |
| Verify      | `verify.sh`          | All nodes have Fluent Bit pods; log volume consistent             |
| Report      | `report-template.md` | POA&M fill-in for DE.AE-07 / CIS 8.2 / AU-2                      |

---

## Why This Matters

AU-2 requires that organizations identify the types of events the system is capable
of logging, coordinate with other organizations, and ensure those events are logged.
A Fluent Bit gap means a category of events — all events from pods on that node —
was not captured during the gap window. If those events included security-relevant
actions, the organization cannot demonstrate compliance with AU-2 for that period.

CIS 8.2 requires that audit logs be collected from all relevant assets. A DaemonSet
with one pod missing is not collecting from all relevant assets. The control is not
satisfied.

DE.AE-07 requires that cyber threat intelligence and other contextual information be
integrated into adverse event analysis. A logging gap breaks this integration: there
is no contextual information from the affected node to integrate. If an adverse event
occurred there, the analyst has no data to analyze.

---

## CySA+ OBJ 2.2 Teaching Point

CySA+ Objective 2.2: Given a scenario, perform log analysis, including reviewing logs
for anomalies and using log correlation tools.

This scenario teaches: log absence is a signal. When expected log sources go quiet,
the analyst must investigate the silence — not assume nothing happened. The skill being
tested is knowing how to verify log source completeness, not just log content.

The question is never only "what do the logs show?" It is also "are all the logs here?"

---

## References

- NIST 800-53 Rev 5: AU-2 Event Logging
- NIST CSF 2.0: DE.AE-07
- CIS Controls v8: 8.2 Collect Audit Logs
- FedRAMP Moderate Baseline: AU-2 (3) — Reviews and Updates
- Kubernetes DaemonSet documentation: https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/
- Fluent Bit Kubernetes filter: https://docs.fluentbit.io/manual/pipeline/filters/kubernetes
