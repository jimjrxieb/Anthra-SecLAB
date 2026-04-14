# L7-04 — DE.CM-03: Investigate — EDR Coverage Gap

## Investigation Objective

You have confirmed Falco is down. Now answer four questions before touching anything:

1. How long has Falco been down?
2. What changed that caused this?
3. What was NOT detected during the gap?
4. What is the risk level and who needs to know?

Work through each step in order. Do not run fix.sh until you have documented the
gap window. GRC needs a start time and an end time. "We fixed it" is not acceptable
without "here is how long the gap was."

---

## Step 1 — How Long Has Falco Been Down?

Find the pod termination time. The gap started when the last Falco pod terminated.

```bash
# Check DaemonSet events for when pods were evicted
kubectl describe daemonset falco -n falco | grep -A 20 "Events:"
```

```bash
# Check pod termination timestamps (may show in pod list with age)
kubectl get pods -n falco -l app.kubernetes.io/name=falco -o wide
```

```bash
# Check events in the falco namespace for FailedScheduling or pod deletion
kubectl get events -n falco --sort-by=.metadata.creationTimestamp | tail -20
```

```bash
# If you have Prometheus with longer retention, query the last scrape time
# Look for when up{job="falco"} dropped to 0 or disappeared
```

Record: **Gap start time: _______________**

---

## Step 2 — What Changed?

Inspect the DaemonSet spec to find the root cause.

```bash
# Check the current nodeSelector — this is where the bad config lives
kubectl get daemonset falco -n falco -o jsonpath='{.spec.template.spec.nodeSelector}' && echo ""
```

Expected output when broken:
```json
{"seclab-break":"evict"}
```

This nodeSelector requires a node with label `seclab-break=evict`. No node has it.
That is why no Falco pod can schedule.

```bash
# Check rollout history for recent changes
kubectl rollout history daemonset/falco -n falco
```

```bash
# Check what nodes actually have for labels
kubectl get nodes --show-labels | head -5
```

```bash
# Verify the impossible label does not exist on any node
kubectl get nodes -l seclab-break=evict
```

The last command should return nothing. That confirms the nodeSelector is unsatisfiable
and the root cause is a misconfiguration in the DaemonSet template spec.

**Root cause:** Bad nodeSelector `{seclab-break: evict}` injected into Falco DaemonSet.
No node satisfies the selector. Kubernetes cannot schedule any Falco pod.

---

## Step 3 — What Was NOT Detected During the Gap?

Falco monitors at the syscall level. During the gap, these detection categories were
entirely absent:

| Category | Example Falco Rule | Risk During Gap |
|----------|--------------------|-----------------|
| Shell spawn in container | `Terminal shell in container` | Attacker exec'd into pod — invisible |
| Privilege escalation | `Launch Privileged Container` | Priv-esc attempt — invisible |
| Credential access | `Read sensitive file untrusted` | /etc/shadow, /proc/*/maps read — invisible |
| Crypto mining | `Detect crypto miners using the Stratum protocol` | Outbound mining — invisible |
| Container escape | `Container escape via runc` | Kernel exploit attempt — invisible |
| Unusual network | `Unexpected outbound connection` | C2 beacon — invisible |

Check for any suspicious activity that may have occurred during the gap:

```bash
# Check anthra pod logs for anything unusual during the gap window
kubectl logs -n anthra --since=1h -l app.kubernetes.io/part-of=anthra 2>/dev/null | \
  grep -iE "error|exec|shell|curl|wget|chmod|sudo" | tail -20 || \
  echo "No suspicious patterns found in pod logs (does not rule out unlogged activity)"
```

```bash
# Check for any pods that were exec'd into during the gap
kubectl get events -n anthra --sort-by=.metadata.creationTimestamp | \
  grep -i exec | tail -10 || echo "No exec events in recent history"
```

Note: Absence of evidence is not evidence of absence. Falco was the detection layer.
Without Falco, you cannot prove nothing happened — you can only prove nothing was logged.
This distinction matters for your GRC documentation.

---

## Step 4 — Classification and Escalation

### Finding Classification

| Field           | Value                                                           |
|-----------------|-----------------------------------------------------------------|
| Control         | DE.CM-03 — Computing hardware, software, services monitored     |
| CIS v8          | 13.7 — Deploy Host-Based Intrusion Detection Solution           |
| NIST 800-53     | SI-4 — Information System Monitoring                            |
| Severity        | HIGH                                                            |
| Rank            | C — Requires investigation before fix; GRC documentation first  |
| Status          | OPEN — control absent, fix pending                              |
| Gap start       | _______________                                                 |
| Gap end         | _______________ (set this after fix.sh completes)               |
| Gap duration    | _______________                                                 |

**Why C-rank, not D?** This is not a simple misconfiguration fix. It requires:
- Documenting the gap window (GRC obligation)
- Assessing what may have occurred during the gap (security obligation)
- Determining whether any compensating controls were active
- Possibly notifying a security team lead depending on gap duration

D-rank means "fix it and log it." C-rank means "investigate first, then fix, then document
formally." A monitoring gap of more than 30 minutes requires C-rank handling minimum.

### Escalation Decision

| Gap Duration | Action Required |
|--------------|-----------------|
| < 15 minutes | Fix immediately, note in team channel, brief log entry |
| 15 min – 2 hours | Fix, write formal incident note, POA&M entry, notify team lead |
| > 2 hours | Fix, incident report, POA&M entry, notify ISSO/security manager |
| > 24 hours | Fix, major incident, POA&M entry, possible auditor notification |

### GRC: Document the Monitoring Gap Window

This is required for your POA&M entry:

```
Control:        DE.CM-03 / SI-4
Finding:        Falco DaemonSet evicted — runtime detection offline
Gap Start:      _______________
Gap End:        _______________
Duration:       _______________
Nodes Affected: All (N nodes, 0 Falco pods running)
Detection:      Manual investigation via kubectl / Grafana silence
Root Cause:     Bad nodeSelector {seclab-break: evict} in DaemonSet spec
Compensating:   _______________  (list any controls active during gap — audit logging, network policy, etc.)
Activity During Gap: No evidence of exploitation found in available logs
                     (absence of evidence is not conclusive — EDR was absent)
Remediation:    Remove bad nodeSelector, verify pod count matches node count
Corrective Action: Add Alertmanager rule to fire when Falco pods = 0
```

---

## NEXT STEP

With the gap documented, run `fix.sh` to restore Falco coverage and end the monitoring gap.
Record the fix time as your gap end time. Then go to `verify.sh` to confirm detection
is restored before updating the POA&M.
