# L7-07 — DE.AE-07: Investigate Phase

## L1 Analyst Task: Scope the Gap, Identify What Was Not Logged

You have detected a missing Fluent Bit pod. Now you need to answer the questions
that an incident commander or GRC reviewer will ask. How long was the gap? What ran
on that node? What events may have been missed? This phase produces the data for
your POA&M entry.

---

## Investigation Questions

Work through each question in order. Record your answers — they go directly into
the report-template.md.

---

### Question 1: Which node is affected?

You identified the silent node in detect.md. Confirm it here and document it formally.

```bash
# List all nodes
kubectl get nodes --no-headers | awk '{print $1, $2}'

echo ""

# List Fluent Bit pods with their node assignments
kubectl get pods -n logging \
  -l app.kubernetes.io/name=fluent-bit \
  -o wide --no-headers \
  | awk '{printf "  Pod: %-55s Node: %s\n", $1, $7}'
```

From the output, identify the node that has NO Fluent Bit pod. This is the affected node.

Record:
- Affected node: _______________
- Node status (kubectl get node): _______________
- Is node cordoned? (STATUS = SchedulingDisabled): _______________

---

### Question 2: What pods ran on the affected node during the gap?

Every pod on the affected node was unmonitored during the gap. List them.

```bash
AFFECTED_NODE="<AFFECTED_NODE>"  # Replace with node name from question 1

echo "All pods on ${AFFECTED_NODE}:"
kubectl get pods --all-namespaces \
  --field-selector "spec.nodeName=${AFFECTED_NODE}" \
  --no-headers \
  | awk '{printf "  NS: %-20s  POD: %-50s  STATUS: %s\n", $1, $2, $4}'
```

For each pod, assess security relevance:

| Pod | Namespace | Handles Auth Events? | Handles Sensitive Data? | External Network? |
|-----|-----------|---------------------|------------------------|-------------------|
| [fill] | [fill] | Y/N | Y/N | Y/N |

A pod with ANY yes answer means that pod's activity during the gap is unaudited.

---

### Question 3: When did the gap start and how long did it last?

The gap window determines which events are unrecoverable.

```bash
# Check the gap start time recorded by break.sh
if [[ -f /tmp/l7-07-gap-start.txt ]]; then
  GAP_START=$(cat /tmp/l7-07-gap-start.txt)
  echo "Gap start: ${GAP_START}"
else
  echo "Gap start file not found."
  echo "Check DaemonSet events for pod deletion time:"
fi

# DaemonSet events
kubectl get events -n logging \
  --sort-by='.lastTimestamp' \
  | grep -i -E "daemonset|fluent|deleted|kill" \
  | tail -10
```

```bash
# If Fluent Bit pod has restarted, check restart count and last start time
kubectl get pods -n logging \
  -l app.kubernetes.io/name=fluent-bit \
  -o wide 2>/dev/null \
  | awk '{printf "  %-55s RESTARTS: %-5s AGE: %s\n", $1, $4, $5}'
```

Record:
- Gap start time: _______________
- Gap end time (pod restart or fix.sh): _______________
- Gap duration: _______________ minutes/hours
- Node cordoned? (gap still open): _______________

---

### Question 4: What events could have occurred during the gap?

Do not assume nothing happened. List what COULD have occurred on that node during
the gap window, based on what pods were running.

```bash
# Check what the API pod was doing just before and after the gap
# (these are from the pods that DID have Fluent Bit coverage)
API_POD=$(kubectl get pods -n anthra \
  -l app.kubernetes.io/component=api \
  --no-headers 2>/dev/null | awk '{print $1}' | head -1)

if [[ -n "${API_POD}" ]]; then
  echo "Most recent API log lines (from covered pods):"
  kubectl logs -n anthra "${API_POD}" --timestamps=true \
    --tail=20 2>/dev/null || echo "  (no logs available)"
fi
```

Event categories that may have occurred on the uncovered node during the gap:

| Event Category | Why It Matters |
|----------------|---------------|
| HTTP requests to API | Could include authentication attempts, data exfiltration |
| Authentication events | Cannot verify who logged in or failed to log in |
| Process execution | Cannot detect shell spawns or unexpected exec activity |
| File system writes | Cannot detect file modification or creation |
| Network connections | Cannot detect unexpected outbound connections |
| Error events | Cannot establish whether anomalies occurred |

---

### Question 5: Is the gap still open?

Check whether Fluent Bit has recovered on the affected node.

```bash
# Current Fluent Bit pod count vs node count
NODE_COUNT=$(kubectl get nodes --no-headers | wc -l | tr -d ' ')
FB_COUNT=$(kubectl get pods -n logging \
  -l app.kubernetes.io/name=fluent-bit \
  --no-headers | wc -l | tr -d ' ')
echo "Nodes: ${NODE_COUNT} | Fluent Bit pods: ${FB_COUNT}"

if [[ "${FB_COUNT}" -lt "${NODE_COUNT}" ]]; then
  echo "STATUS: GAP IS STILL OPEN. Log collection is incomplete."
  echo "        Run fix.sh to restore full coverage."
else
  echo "STATUS: Pod count matches node count. Gap appears closed."
  echo "        Run verify.sh to confirm log flow has resumed."
fi
```

```bash
# If node is cordoned, the DaemonSet cannot reschedule
AFFECTED_NODE="<AFFECTED_NODE>"
kubectl get node "${AFFECTED_NODE}" -o jsonpath='{.spec.unschedulable}' \
  && echo "(node is cordoned — DaemonSet cannot reschedule here)" \
  || echo "(node is not cordoned)"
```

---

### Question 6: What compensating controls are available during the gap?

If the gap is ongoing or was long enough that investigation is needed, document
what alternatives exist for reconstructing activity during the gap window.

Potential compensating evidence sources:

| Source | What It Shows | Limitations |
|--------|--------------|-------------|
| API application logs (in-pod buffer) | Recent requests | Only available if pod is still running with same instance |
| Kubernetes audit log (kube-apiserver) | kubectl actions, API calls | Does not capture application-level events |
| Network flow data (if CNI supports it) | Connection metadata | No payload, no application context |
| Host-level journald (on node) | Process starts, kernel events | Requires node access |
| Downstream service logs | Any service that received requests from affected pods | Limited to inter-service calls |

If none of these alternatives can reconstruct the gap window, the finding must
state: "Events during [gap start] to [gap end] on [affected node] are unrecoverable
and cannot be audited."

---

## Investigation Summary

Fill in this table before proceeding to fix.sh:

| Question | Answer |
|----------|--------|
| Affected node | [From question 1] |
| Node cordoned? | [YES / NO] |
| Gap start time | [From question 3] |
| Gap duration | [From question 3] |
| Pods on affected node | [From question 2] |
| Security-relevant pods affected? | [YES / NO — list them] |
| Gap still open? | [YES — run fix.sh / NO — run verify.sh] |
| Compensating evidence available? | [From question 6] |

---

## Next Step

If the gap is still open: run `fix.sh` to uncordon the node and restore Fluent Bit.
If the gap has closed: run `verify.sh` to confirm all nodes have coverage.
Then return to `remediate.md` for the AU-2 GRC documentation requirements.
