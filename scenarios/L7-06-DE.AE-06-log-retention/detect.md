# L7-06 — DE.AE-06: Detect Phase

## L1 Analyst Task: Identify the Log Retention Gap

You are a Level 1 analyst. An incident was reported this morning. The suspicious
activity occurred 48 hours ago. You need to pull logs from that window to start
your investigation. Your job in this phase is to discover that the logs no longer
exist — and to understand why.

This is not about finding an attacker. This is about finding the gap where an
attacker would be invisible because the evidence was rotated away before anyone
looked.

---

## Step 1 — Try to Query Logs from 48 Hours Ago

Start with what you would normally do in an investigation.

If you are using `kubectl logs`:

```bash
# Get the API pod name
API_POD=$(kubectl get pods -n anthra -l app.kubernetes.io/component=api \
  --no-headers | awk '{print $1}' | head -1)
echo "API pod: ${API_POD}"

# Attempt to pull logs — kubectl logs only shows what is still on the node
kubectl logs -n anthra "${API_POD}" --timestamps=true | head -20
```

What to observe:
- How far back do the timestamps go?
- Is there a 48-hour window in the output?
- What is the oldest timestamp you can see?

If you are using Loki/Grafana:
- Open Grafana and navigate to the Explore view
- Set the time range to `now-48h` to `now-46h`
- Query: `{namespace="anthra"}`
- Observe: are there any results?

---

## Step 2 — Confirm the Retention Window

Once you suspect a retention problem, confirm it by checking how far back logs
actually go.

```bash
# Find the oldest log timestamp from the API pod
API_POD=$(kubectl get pods -n anthra -l app.kubernetes.io/component=api \
  --no-headers 2>/dev/null | awk '{print $1}' | head -1)

kubectl logs -n anthra "${API_POD}" --timestamps=true 2>/dev/null \
  | head -1 \
  | awk '{print "Oldest available log:", $1}'
```

```bash
# Find the newest log timestamp (for comparison)
kubectl logs -n anthra "${API_POD}" --timestamps=true 2>/dev/null \
  | tail -1 \
  | awk '{print "Most recent log:", $1}'
```

Calculate the retention window:
```
Retention window = (most recent timestamp) - (oldest timestamp)
```

What you expect to find after the break: retention window of approximately 24 hours.
What AU-11 requires: 90 days minimum.

---

## Step 3 — Check the Retention Configuration

Now that you know logs are missing, find out why. Check where the retention is
configured.

```bash
# Check Fluent Bit ConfigMap for buffer settings
FB_CM=$(kubectl get configmap -n logging --no-headers \
  | grep -i fluent | awk '{print $1}' | head -1)
echo "Fluent Bit ConfigMap: ${FB_CM}"

kubectl get configmap -n logging "${FB_CM}" -o yaml 2>/dev/null \
  | grep -A 2 -i -E "mem_buf_limit|storage|retention"
```

```bash
# Check if Loki is deployed and what its retention is set to
kubectl get pods --all-namespaces --no-headers \
  | grep -i loki \
  | awk '{print "Loki pod found in namespace:", $1}'

# If Loki namespace is found, check its config
LOKI_NS=$(kubectl get pods --all-namespaces --no-headers \
  | grep -i loki | awk '{print $1}' | head -1)
if [[ -n "${LOKI_NS}" ]]; then
  LOKI_CM=$(kubectl get configmap -n "${LOKI_NS}" --no-headers \
    | grep -i loki | awk '{print $1}' | head -1)
  kubectl get configmap -n "${LOKI_NS}" "${LOKI_CM}" -o jsonpath='{.data}' \
    | python3 -c "import sys,json; d=json.load(sys.stdin); \
      [print(v) for k,v in d.items() if 'retention' in v.lower()]" \
    | grep -i retention || echo "(retention not explicitly configured)"
fi
```

```bash
# Check kubelet log rotation limits on a node
kubectl describe node $(kubectl get nodes --no-headers | awk '{print $1}' | head -1) \
  | grep -i -E "containerlog|log-max" || echo "(using kubelet defaults: 10Mi, 5 files)"
```

---

## Step 4 — Quantify the Gap

Calculate what is missing. This goes in your investigation notes and your POA&M.

```
Event time:              [Time of suspicious activity — 48 hours ago]
Current retention:       [From step 2 — approximately 24 hours]
Gap duration:            48 hours - 24 hours = 24 hours of unrecoverable logs
Frameworks violated:     AU-11 (90d), CIS 8.10 (90d), DE.AE-06
Affected log sources:    anthra namespace (api, ui, chroma pods)
```

Fill in this table for your detect.md notes:

| Check | Finding |
|-------|---------|
| Oldest log available | [Timestamp from step 2] |
| Retention window observed | [Hours/days] |
| AU-11 requirement (FedRAMP) | 90 days |
| Gap vs requirement | [90 days - observed retention] |
| Loki retention setting | [24h / not configured / not deployed] |
| Fluent Bit Mem_Buf_Limit | [Value or "not set"] |

---

## Step 5 — Classify the Severity

Use this rubric:

| Condition | Severity |
|-----------|---------|
| Retention >= 90 days | Compliant — no finding |
| Retention 30-89 days | MEDIUM — partial gap, below FedRAMP floor |
| Retention 7-29 days | HIGH — significant gap, investigation impact |
| Retention < 7 days | CRITICAL — logs unavailable for any meaningful incident |
| Active incident with log gap | CRITICAL regardless of retention length |

In this scenario, the retention is approximately 24 hours. With an incident being
investigated 48 hours later, this is CRITICAL — the evidence period falls entirely
outside the retention window.

---

## What the GRC Auditor Asks

If you are preparing for a FedRAMP authorization or annual assessment, the AU-11
control assessment question is:

"How long are audit records retained, and where is this requirement documented?"

The auditor does not accept "our logging tool was running" as evidence of AU-11
compliance. They will query for logs from 91 days ago. If nothing comes back,
AU-11 is marked NOT SATISFIED.

Be prepared to show:
1. The retention configuration (Loki config, Fluent Bit output config)
2. A log query returning records from 90+ days ago
3. The organization's retention policy document stating the 90-day requirement

---

## Key Teaching Point

Log retention failure is invisible until an investigation starts. The logging system
shows green on every dashboard. Fluent Bit is healthy. The pipeline is running.
Everything looks correct — right until the moment you need logs from 48 hours ago
and there are none.

This is why AU-11 compliance requires a deliberate configuration choice, not just
deployment of a logging agent. The agent collects. The backend retains. Without a
configured, tested, and verified retention window, "logging is running" is a statement
about collection — not about evidence availability.

---

## What the CySA+ Exam Tests Here

CySA+ Objective 2.4: Given a scenario, analyze data as part of security monitoring
activities.

The scenario tests whether you understand that:
1. Log collection and log retention are two distinct controls
2. A functioning collector with no durable backend does not satisfy AU-11
3. Retention gaps must be documented and reported, not silently accepted
4. The investigator's job includes determining whether evidence was available,
   not just whether it is present today

---

## Next Step

Proceed to `investigate.md` to analyze the retention policy, framework requirements,
and calculate the full scope of the compliance gap.
