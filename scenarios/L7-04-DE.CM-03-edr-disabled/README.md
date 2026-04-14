# L7-04 — DE.CM-03: EDR/Falco Agent Down

## Scenario Summary

Falco is the runtime threat detection layer for the `anthra` cluster. It runs as a
DaemonSet in the `falco` namespace — one pod per node — monitoring every syscall
made by every container in real time. When Falco goes down, the cluster goes silent.
No alerts fire. No detections occur. Attackers operating during that window are
invisible to every runtime control downstream (Falcosidekick, Alertmanager, Splunk).

This scenario simulates a misconfiguration that evicts all Falco pods by injecting an
impossible nodeSelector into the DaemonSet spec. The break is realistic — a bad Helm
values override, a botched patch, a CI pipeline that wrote the wrong selector. The
result is the same: zero Falco coverage, zero detection, a monitoring gap that starts
the moment the last pod terminates and ends when someone notices.

The L1 task is to detect the gap, measure it, classify the severity, and document it
correctly for the GRC POA&M — because "we had no EDR for two hours" is a finding
that auditors care about even if nothing bad happened during that window.

---

## Control Mapping

| Field            | Value                                                                  |
|------------------|------------------------------------------------------------------------|
| CSF Function     | DETECT                                                                 |
| CSF Category     | DE.CM — Continuous Monitoring                                          |
| CSF Subcategory  | DE.CM-03 — Computing hardware, software, services monitored            |
| CIS v8 Control   | 13.7 — Deploy Host-Based Intrusion Detection Solution                  |
| NIST 800-53      | SI-4 — Information System Monitoring                                   |
| OSI Layer        | Layer 7 — Application                                                  |
| Severity         | HIGH                                                                   |
| Rank             | C — Requires investigation before fix; compensating control documentation required |
| Difficulty       | Level 1                                                                |

---

## What Breaks

The Falco DaemonSet in namespace `falco` has its nodeSelector patched to an
impossible value (`seclab-break: evict`). No node in the cluster carries that label,
so Kubernetes cannot schedule any Falco pod. All existing pods are evicted. The
DaemonSet shows 0 desired, 0 ready.

During this window:

- No syscall-level monitoring occurs on any node
- No container escape detections fire
- No shell spawn alerts reach Falcosidekick
- No events reach Alertmanager or Splunk
- Privilege escalation, credential access, and crypto mining are all invisible

The cluster continues to function normally. The `anthra` app runs. Users see nothing
wrong. Only the monitoring plane is broken — and that is exactly what an attacker
would want.

---

## Affected Assets

- **Namespace:** falco
- **DaemonSet:** falco
- **Pods:** falco-* (3 pods, one per node)
- **Sidekick:** falcosidekick-* (2 pods, alerting pipeline)
- **Downstream:** Alertmanager, Prometheus, Splunk (all starved of Falco events)

---

## Scenario Lifecycle

| Phase       | File                 | What Happens                                              |
|-------------|----------------------|-----------------------------------------------------------|
| Baseline    | `baseline.sh`        | Confirm Falco pods running, capture alert count           |
| Break       | `break.sh`           | Inject bad nodeSelector, evict all Falco pods             |
| Detect      | `detect.md`          | L1 analyst identifies monitoring gap via observability    |
| Investigate | `investigate.md`     | Measure gap window, classify severity, document for GRC   |
| Fix         | `fix.sh`             | Remove bad nodeSelector, restore Falco scheduling         |
| Remediate   | `remediate.md`       | Why EDR matters, what Falco detects, POA&M guidance       |
| Verify      | `verify.sh`          | Confirm pods restored, run live detection test            |
| Report      | `report-template.md` | Fill-in POA&M evidence template for DE.CM-03              |

---

## Why This Matters

NIST SI-4 requires active monitoring of information systems to detect attacks and
indicators of potential attacks. A DaemonSet misconfiguration that silences all
runtime detection is a direct SI-4 failure. The control is not degraded — it is
absent.

CIS 13.7 requires deploying host-based intrusion detection on all endpoints. When
Falco is down, this control has zero coverage. Every node in the cluster is running
without a host-based detection layer.

For DE.CM-03, the CSF requirement is that computing hardware, software, and services
are monitored. Containers running with no Falco coverage are not monitored at the
syscall level. This is a complete gap in the continuous monitoring program.

In a FedRAMP Moderate environment, this finding requires a POA&M entry with a
documented gap window, compensating controls (if any were active during the gap),
and a corrective action plan with a remediation date. The auditor will ask: how long
was the system unmonitored, and what were you doing about it?

---

## References

- NIST 800-53 Rev 5: SI-4 Information System Monitoring
- NIST CSF 2.0: DE.CM-03
- CIS Controls v8: 13.7 Deploy Host-Based Intrusion Detection Solution
- Falco project: https://falco.org/docs/
- Falcosidekick: https://github.com/falcosecurity/falcosidekick
