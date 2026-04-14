# L7-04 — DE.CM-03: Remediate — Why EDR Matters

## What Falco Actually Does

Falco is a syscall-level runtime threat detection engine. It attaches to the Linux
kernel via eBPF or kernel module and monitors every system call made by every process
on the host. Every container that runs on a Kubernetes node has its syscalls
inspected by Falco in real time.

This is what host-based intrusion detection means in the cloud-native context. Not
a signature scanner. Not a network probe. A kernel-level observer that sees what
programs actually do — not what their image says they should do.

### What Falco detects

**Shell spawn in container:**
A container that exec's `/bin/bash` or `/bin/sh` is a major indicator of compromise.
Containers should not spawn interactive shells in production. Falco fires on this
within milliseconds.

**Privilege escalation:**
A process that calls `setuid(0)` or runs with capabilities it should not have.
A pod that was launched with `runAsNonRoot: true` that somehow gains root. Falco
catches this at the syscall boundary.

**Sensitive file access:**
Reading `/etc/shadow`, `/proc/1/environ`, `/root/.ssh/authorized_keys`. These are
the files an attacker reads after gaining initial access. Falco flags them by path.

**Crypto mining:**
Outbound connections to Stratum protocol pools on port 3333/14444. CPU-intensive
workloads that match mining signatures. Falco has dedicated rules for this because
compromised clusters are frequently used for mining.

**Container escape:**
Syscalls that indicate a process attempting to break out of the container namespace
— `mount`, `unshare`, `pivot_root` from unexpected processes. Kernel exploit
attempts show characteristic syscall patterns that Falco rules target.

**Credential theft:**
Accessing Kubernetes service account tokens from `/var/run/secrets/kubernetes.io/`,
reading cloud credential files, accessing AWS instance metadata endpoints from
processes that have no business reason to do so.

---

## What Happens Without Falco

Without Falco, your detection plane has a layer-sized hole.

Network-level controls (Calico, NetworkPolicy, GuardDuty VPC flow logs) still work.
They see what goes in and out of the network boundary.

What they cannot see: what happens inside a running container. A compromised pod
that reads `/etc/shadow`, spawns a reverse shell, and connects to a C2 server on
an allowed port — all of that is invisible at the network layer if the egress port
is permitted. Falco would have caught the shell spawn and the file access before
the exfiltration even started.

Without Falco, you are relying on:
- Network egress controls to catch the exfiltration (too late)
- Pod logs to show you what ran (only if the attacker didn't clear them)
- Your incident response team noticing something is wrong (too slow)

---

## CIS 13.7 — Deploy Host-Based Intrusion Detection Solution

CIS Controls v8, Control 13.7 is explicit: "Deploy a host-based intrusion detection
solution on enterprise assets, where appropriate and/or supported."

In a Kubernetes environment:
- The "host" is the Kubernetes node
- "Enterprise assets" includes every container running on those nodes
- Falco is the open source implementation of this control for cloud-native workloads

When Falco is down, CIS 13.7 has zero coverage. Not reduced coverage. Zero. There
is no backup host-based detection mechanism. This is why the finding is HIGH severity.

---

## NIST SI-4 — Information System Monitoring

NIST 800-53 SI-4 requires that the organization:
- Monitors the information system to detect attacks and indicators of potential attacks
- Identifies unauthorized use of the information system
- Deploys monitoring devices strategically within the information system

SI-4 (2) specifically addresses automated tools: "The organization employs automated
tools to support near-real-time analysis of events." Falco is this tool. Without it,
SI-4 (2) is not met.

In a FedRAMP Moderate assessment, an auditor will ask to see evidence that SI-4
controls are operational. "We run Falco" is the answer. "We had Falco down for two
hours and didn't notice" is a finding that goes in the POA&M.

---

## Documenting a Monitoring Gap in a POA&M

A Plan of Action and Milestones (POA&M) entry for a monitoring gap requires these
fields:

**Control ID:** DE.CM-03 / SI-4
**Finding Title:** Runtime monitoring (Falco) offline — EDR coverage gap
**Severity:** HIGH
**Status:** OPEN / CLOSED (depending on whether fix is complete)
**Gap Start:** The timestamp when the last Falco pod terminated
**Gap End:** The timestamp when fix.sh confirmed all pods returned to Running
**Gap Duration:** Calculated from start/end
**Nodes Affected:** All N nodes (0 of N Falco pods running)
**Detection Method:** How did you notice? (Grafana silence, Alertmanager, kubectl)
**Detection Lag:** How long between gap start and detection? This is the real metric.
**Compensating Controls:** What was still active during the gap?
  - Kubernetes audit logs (yes — API server still logged all API calls)
  - NetworkPolicy (yes — still enforced, outbound restricted)
  - Pod Security Standards (yes — still enforced, admission policy unchanged)
  - Falcosidekick (yes — still running, but had no events to forward)
  - SIEM/Splunk (yes — still running, but Falco feed was empty)
**Risk Accepted During Gap:** Syscall-level activity unmonitored. Any container
  escape, privilege escalation, or shell spawn during this window is undetected
  and unlogged. Risk accepted by: ______________ (ISSO name)
**Root Cause:** Misconfiguration of DaemonSet nodeSelector (seclab-break: evict)
**Corrective Action:** Remove bad nodeSelector. Implement Alertmanager rule to
  fire within 5 minutes if Falco pod count drops below node count.
**Corrective Action Due Date:** _______________
**Verified:** Yes — verify.sh confirmed pod count and live detection test passed

---

## Preventive Controls — How to Stop This from Recurring

**Alertmanager rule:** Add a PrometheusRule that fires if Falco pods drop to zero:
```yaml
- alert: FalcoPodNotRunning
  expr: kube_daemonset_status_number_ready{daemonset="falco", namespace="falco"} == 0
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "Falco DaemonSet has no running pods — runtime detection offline"
    description: "DE.CM-03 / SI-4 violation: Falco has been down for more than 5 minutes."
```

**RBAC restriction:** Lock down who can patch the Falco DaemonSet. Only the platform
engineering team should have write access to the `falco` namespace.

**Kyverno policy:** Block modifications to the Falco DaemonSet nodeSelector in
production. Any change requires a pipeline approval, not a direct kubectl patch.

**Periodic validation:** Run `verify.sh` as a scheduled job. If the pod count ever
drops below node count, alert immediately. Do not wait for a human to notice silence.
