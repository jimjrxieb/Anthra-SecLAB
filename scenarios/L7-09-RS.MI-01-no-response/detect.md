# L7-09 — Detect: Detection Without Response

**Phase:** DETECT
**Persona:** Level 1 Analyst (SOC / GRC / SRE)
**Objective:** Find the Falco alert, trace where it was routed, identify the response gap

---

## How You Got Here

Detection fired. Notification did not. The gap is in the routing, not the
detection — and that is exactly why you need to trace the full path.

**Path A — You noticed no alert arrived:** You exec'd into a pod (or were
reviewing access logs and saw someone else exec), then checked Splunk and
AlertManager. No alert arrived, even though the action should have triggered
Falco's `Terminal shell in container` rule. You went looking for the alert in
Falco logs directly and found it there — logged, but never routed anywhere.

**Path B — Day 1 checklist flagged the gap proactively:** Your baseline checklist
included verifying Falcosidekick outputs. You checked the Falcosidekick
configuration and found it either unconfigured (no outputs defined) or failing
silently (misconfigured Slack webhook, unreachable Splunk HEC endpoint). You
flagged it before an actual event proved the gap.

Either way: Falco detected the event. You can verify this by reading Falco logs
directly. The problem is that the alert never reached a human — because the
routing layer (Falcosidekick outputs) was not configured or was broken. Your job
in this phase is to confirm the detection exists in Falco logs, trace where it
was supposed to go, and identify exactly where the chain broke.

---

## Step 1 — Find the Alert in Falco Logs

Falco logs to stdout. That output is captured by the Kubernetes log aggregator and
is readable via `kubectl logs`. Start here.

```bash
# Find the Falco pod
FALCO_POD=$(kubectl get pods -n falco \
  -l app.kubernetes.io/name=falco \
  --no-headers | awk '{print $1}' | head -1)

echo "Falco pod: ${FALCO_POD}"

# Read the last 50 log lines
kubectl logs -n falco "${FALCO_POD}" --tail=50
```

Look for a log line that contains: `Terminal shell in container` or `Spawned shell` or
a line with `priority: WARNING` or `priority: HIGH` associated with a shell process.

A typical Falco alert looks like this in stdout:
```
{"output":"2026-04-12T01:23:45.000000000+0000: Warning A shell was spawned in a
container with an attached terminal (user=root user_loginuid=-1 k8s.ns=anthra
k8s.pod=portfolio-anthra-...  container=api shell=sh parent=runc cmdline=sh -c
echo 'attacker-simulation' > /tmp/evidence.txt k8s.ns=anthra
image=...)","priority":"Warning","rule":"Terminal shell in container",...}
```

**What you are confirming:**
- [ ] The alert IS in the Falco log (detection worked)
- [ ] The alert has the correct rule name
- [ ] The alert shows the correct container and namespace
- [ ] The alert has a timestamp near your exec time

---

## Step 2 — Check Falcosidekick for Forwarding

Falcosidekick receives alerts from Falco and routes them to configured outputs.
Check whether Falcosidekick actually forwarded this alert.

```bash
# Find Falcosidekick pod
SIDEKICK_POD=$(kubectl get pods -n falco \
  -l app.kubernetes.io/name=falcosidekick \
  --no-headers | awk '{print $1}' | head -1)

echo "Falcosidekick pod: ${SIDEKICK_POD}"

# Check Falcosidekick logs
kubectl logs -n falco "${SIDEKICK_POD}" --tail=30
```

**What you are looking for in Falcosidekick logs:**

If outputs are configured, you see:
```
[info]  Slack    : OK
[info]  Webhook  : 2 events forwarded
```

If outputs are NOT configured, you see only startup messages:
```
[info]  Starting Falcosidekick
[info]  No outputs configured
[info]  Falcosidekick is up and listening on :2801
```

---

## Step 3 — Audit Falcosidekick Configuration

Read the Falcosidekick configuration to understand what outputs are configured.

```bash
# Option A: Check via Helm values
helm get values falco -n falco 2>/dev/null | grep -A 20 "falcosidekick:"

# Option B: Check via ConfigMap
kubectl get configmap -n falco \
  -l app.kubernetes.io/name=falcosidekick \
  -o jsonpath='{.items[0].data}' 2>/dev/null | python3 -m json.tool 2>/dev/null || \
kubectl describe configmap -n falco \
  $(kubectl get configmap -n falco -l app.kubernetes.io/name=falcosidekick \
    --no-headers | awk '{print $1}' | head -1) 2>/dev/null

# Option C: Check Falcosidekick environment variables
kubectl exec -n falco "${SIDEKICK_POD}" -- env 2>/dev/null | \
  grep -iE "(slack|webhook|pagerduty|alertmanager|output|enabled)" | sort
```

For each output category, the key question is whether `enabled: true` is set AND
whether the destination (URL, token, channel) is populated with a real value.

An output with `enabled: false` or an empty destination is a non-output. The alert
goes nowhere.

---

## Step 4 — Map the Alert Routing Chain

Draw the chain on paper or in a text file:

```
Falco detects exec
    |
    v
Falco alert (stdout + /var/log/falco) -- in Falco pod log
    |
    v
Falcosidekick receives alert -- via HTTP on port 2801
    |
    v
[CONFIGURED OUTPUTS]
    |-- Slack: [configured / not configured]
    |-- Webhook: [configured / not configured]
    |-- PagerDuty: [configured / not configured]
    |-- Alertmanager: [configured / not configured]
    |-- Splunk: [configured / not configured]
    |
    v
Human analyst receives notification
    Time from exec to notification: [X seconds / infinity]
```

If every output is "not configured," the chain terminates at Falcosidekick. The alert
exists. No human is notified. MTTN = infinity.

---

## Step 5 — The Finding

You now have enough information to state the finding.

**Technical finding:**
Falco detected a `Terminal shell in container` event in the `anthra` namespace at
[timestamp]. Falcosidekick received the alert but has no output channels configured.
The alert was not forwarded to any human-readable destination. No notification was
generated.

**Control mapping:**
- RS.MI-01: Incidents cannot be contained if they are never communicated to the team
  that would perform containment. The detection-to-containment chain is broken.
- IR-4: Incident handling requires detection AND response. Detection without response
  capability satisfies the first phase of IR-4 and fails every subsequent phase.
- CIS 17.2: No established contact or routing path for security incident notification.

**Severity:** HIGH. In a production environment, this gap allows an attacker to
complete an objective (exec, exfiltrate, plant persistence) before detection leads
to any human response. MTTD is fast. MTTN is infinite. MTTR is infinite.

---

## What You Are Looking For

| Indicator | Finding |
|-----------|---------|
| Alert in Falco logs | Detection works — Falco is functioning correctly |
| No forwarding in Falcosidekick logs | Alert routing not configured |
| No Slack / webhook / SIEM event | No human notification possible |
| Dashboard-only visibility | Requires someone already watching — not alerting |
| MTTN = unknown / infinite | IR-4 cannot be satisfied without a notification path |

---

## Next Step

Proceed to `investigate.md` to analyze the MTTD vs MTTN gap, assess what an attacker
could accomplish during the notification gap, and draft the IR procedure gap analysis.
