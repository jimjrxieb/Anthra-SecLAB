# L7-07 — DE.AE-07: Detect Phase

## How You Got Here

Partial log collection failures are harder to spot than total outages. When all
Fluent Bit pods die, the dashboards go silent and someone notices. When one pod
fails on one node, the overall graph still shows activity and looks mostly normal.
Your monitoring must compare DaemonSet desired vs ready — not just check for
non-zero log volume.

**Path A — Grafana log volume dashboard:** You were reviewing the per-node log
volume dashboard and noticed one node's line dropped to zero approximately 20
minutes ago. Every other node is still reporting. The overall cluster log volume
looks slightly low but not obviously broken. Without per-node breakdown, this
would be invisible.

**Path B — kubectl DaemonSet check:** You ran `kubectl get pods -n logging` as
part of a routine check or your Day 1 baseline, and the Fluent Bit pod count did
not match the node count. A DaemonSet runs exactly one pod per node. If the
counts differ, a node is uncovered and its logs are not being collected.

Either way: you found this by actively verifying coverage, not by waiting for an
alert. The absence of logs from one node is the detection. Your job in this phase
is to confirm which node is uncovered, how long it has been silent, and what
events occurred on that node during the gap.

---

## Step 1 — Check Fluent Bit Pod Count vs Node Count

The most direct check: does the number of Fluent Bit pods match the number of nodes?
A DaemonSet runs exactly one pod per node. If the counts differ, a node is uncovered.

```bash
# Count cluster nodes
NODE_COUNT=$(kubectl get nodes --no-headers | wc -l | tr -d ' ')
echo "Total nodes: ${NODE_COUNT}"

# Count Fluent Bit pods
FB_COUNT=$(kubectl get pods -n logging \
  -l app.kubernetes.io/name=fluent-bit \
  --no-headers | wc -l | tr -d ' ')
echo "Fluent Bit pods: ${FB_COUNT}"

# Compare
if [[ "${FB_COUNT}" -lt "${NODE_COUNT}" ]]; then
  echo "MISMATCH: ${NODE_COUNT} nodes, only ${FB_COUNT} Fluent Bit pods"
  echo "          One or more nodes have no log collection. AU-2 GAP DETECTED."
else
  echo "OK: Pod count matches node count."
fi
```

Expected output after break.sh:
```
Total nodes: 3
Fluent Bit pods: 2
MISMATCH: 3 nodes, only 2 Fluent Bit pods
          One or more nodes have no log collection. AU-2 GAP DETECTED.
```

---

## Step 2 — Identify Which Node Is Silent

A count mismatch tells you there is a gap. Now find which node.

```bash
# Show all cluster nodes
echo "=== NODES ==="
kubectl get nodes --no-headers | awk '{print $1, $2}'

echo ""
echo "=== FLUENT BIT PODS WITH NODE ASSIGNMENT ==="
kubectl get pods -n logging \
  -l app.kubernetes.io/name=fluent-bit \
  -o wide --no-headers \
  | awk '{printf "  %-55s NODE: %s\n", $1, $7}'
```

Compare the node list to the pod list. The node that does not appear in the pod's
NODE column is the silent node. Write it down — it is the affected asset for your
investigation notes.

---

## Step 3 — Identify What Ran on the Silent Node

Knowing which node is silent tells you which pods were unmonitored during the gap.

```bash
# Replace <SILENT_NODE> with the node name from step 2
SILENT_NODE="<SILENT_NODE>"

echo "Pods on ${SILENT_NODE} (unmonitored during gap):"
kubectl get pods --all-namespaces \
  --field-selector "spec.nodeName=${SILENT_NODE}" \
  --no-headers \
  | awk '{printf "  %-20s  %-50s  STATUS: %s\n", $1, $2, $4}'
```

For each pod in the output, ask:
- Does this pod handle sensitive data?
- Does this pod process authentication events?
- Does this pod make external network connections?

Any yes answer means the gap window includes unlogged security-relevant events.

---

## Step 4 — Check Grafana for the Log Volume Drop

If Grafana is deployed with Loki, you can see the gap visually.

In Grafana Explore view:
1. Set time range to last 30 minutes
2. Query by node: `{namespace="anthra"} | node_name="<SILENT_NODE>"`
3. Look for a flat line starting at the time break.sh ran

Alternatively, check log rate by source:

```bash
# If you have access to Loki's API
LOKI_URL="http://localhost:3100"  # adjust to your Loki service URL

# Query log volume per source for the last 30 minutes
curl -s "${LOKI_URL}/loki/api/v1/query_range" \
  --data-urlencode 'query=sum by (node_name) (rate({namespace="anthra"}[5m]))' \
  --data-urlencode "start=$(date -d '30 minutes ago' +%s)000000000" \
  --data-urlencode "end=$(date +%s)000000000" \
  2>/dev/null | python3 -m json.tool | grep -A 2 "node_name" | head -30 \
  || echo "(Loki API not reachable — use kubectl log checks below)"
```

---

## Step 5 — Estimate the Gap Window

You need to document when the gap started and how long it lasted. This goes in
the AU-2 incident record.

```bash
# Check when the gap started (from break.sh output)
if [[ -f /tmp/l7-07-gap-start.txt ]]; then
  GAP_START=$(cat /tmp/l7-07-gap-start.txt)
  NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "Gap started:   ${GAP_START}"
  echo "Current time:  ${NOW}"
  echo ""
  echo "Gap duration:  (calculate from timestamps above)"
else
  echo "Gap start file not found."
  echo "Estimate from the DaemonSet event log:"
  kubectl describe daemonset -n logging \
    -l app.kubernetes.io/name=fluent-bit \
    | grep -A 5 "Events:"
fi
```

```bash
# Check DaemonSet events for pod deletion/restart activity
kubectl get events -n logging \
  --sort-by='.lastTimestamp' \
  | grep -i -E "fluent|daemonset|pod" \
  | tail -10
```

---

## Step 6 — Classify the Severity

| Condition | Severity |
|-----------|---------|
| Brief gap, < 5 minutes, no sensitive pods on node | LOW |
| Gap 5-30 minutes, non-critical pods on node | MEDIUM |
| Gap 30+ minutes, anthra pods on node | HIGH |
| Gap during active incident or known threat activity | CRITICAL |
| Node cordoned, gap ongoing, investigation required | CRITICAL |

In this scenario with the node cordoned (EXTENDED_BREAK=true), the gap is ongoing
and the anthra namespace pods on that node are unmonitored. Classification: HIGH
to CRITICAL depending on whether there is active threat activity.

---

## What the GRC Auditor Asks

AU-2 requires that the organization identify what events need to be logged and
ensure those events are collected. A Fluent Bit gap directly creates an AU-2 gap:
events occurred, those events were not collected.

The auditor question is: "Can you demonstrate continuous log collection from all
monitored assets?" A gap window — even 20 minutes — must be disclosed, documented,
and have a compensating control or plan of remediation.

What the auditor will want to see:
1. When was the gap detected?
2. How long did it last?
3. What pods were on the affected node?
4. Were any of those pods processing data subject to this control baseline?
5. What was done to prevent recurrence?

---

## Key Teaching Point

Missing log data is not "nothing happened." It is "we cannot know what happened."
Those are very different statements in an audit or incident response context.

When you find a log gap, your job is not to assume silence means safety. Your job is
to document the gap, identify what was running during the gap, and report that the
audit trail is incomplete for that window. The investigation may close as "no evidence
of breach" — but the gap itself must be documented.

CySA+ tests this distinction: absence of logs is not the same as absence of events.

---

## Next Step

Proceed to `investigate.md` to determine the full scope of the gap, which events
may be missing, and what compensating controls apply during the remediation period.
