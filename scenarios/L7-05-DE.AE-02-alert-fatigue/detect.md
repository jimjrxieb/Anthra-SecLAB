# L7-05 — DE.AE-02: Detect Phase

## L1 Analyst Task: Identify the Alert Fatigue Condition

You are a Level 1 analyst. The Falco dashboard is open. Alerts are flooding in.
Your job in this phase is to recognize the problem — not just "alerts are firing"
but "we have an alert quality problem that requires tuning."

---

## Step 1 — Measure Alert Volume

Before you can say there is a noise problem, you need numbers.

Run the baseline alert count:

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=200 --prefix=false \
  | grep -oP '"rule":"[^"]*"' | sed 's/"rule":"//;s/"//' \
  | sort | uniq -c | sort -rn | head -10
```

Expected output format:
```
  152 Read sensitive file untrusted
   98 Terminal shell in container
   74 Launch Package Management Process in Container
   41 Write below root in container
   18 Outbound connection to C2 server
```

What to record:
- Total alert count in the sample window
- How many distinct rules fired
- Which single rule has the highest count

If the top rule has more than 20% of all alerts, that rule is a tuning candidate.

---

## Step 2 — Identify the Top 3 Noisiest Rules

From the output above, write down the top 3 rules by count. For each rule, answer:

**Rule 1 (highest count): _______________**
- What does this rule detect?
- Is there a legitimate process in Portfolio that would trigger it?
- When was the last time this rule produced a confirmed true positive?

**Rule 2: _______________**
- Same questions.

**Rule 3: _______________**
- Same questions.

Typical findings in an untuned Portfolio environment:

| Rule | Why It Fires | True Positive? |
|------|-------------|----------------|
| Read sensitive file untrusted | Health probes reading /proc, /etc | Rarely |
| Terminal shell in container | kubectl exec by developer | Sometimes |
| Launch Package Management Process | pip in init containers | No |
| Write below root | Config file writes at startup | No |
| Outbound connection | curl health check to internal endpoint | No |

---

## Step 3 — Check Whether Any Alert Is a Real Threat

This is the most important step. Before classifying this as "just noise," you
must verify that real threats are not hiding in the flood.

```bash
# Look for alerts with severity CRITICAL or ERROR
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=200 --prefix=false \
  | grep -E '"priority":"(Critical|Error|Warning)"' \
  | grep -oP '"rule":"[^"]*"' \
  | sort | uniq -c | sort -rn
```

```bash
# Look for any exec events that are NOT from known probe containers
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=200 --prefix=false \
  | grep '"rule":"Terminal shell in container"' \
  | grep -v '"container.name":"falco"' \
  | head -5
```

```bash
# Look for outbound connections that are NOT to internal cluster IPs
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=200 --prefix=false \
  | grep '"rule":"Outbound' \
  | head -5
```

What to look for:
- Shell spawns from the API or UI container with unexpected usernames
- File reads targeting /etc/shadow, /etc/kubernetes/, or TLS cert paths
- Outbound connections to external IPs (not 10.x.x.x or 172.x.x.x)
- Package manager invocations outside of init containers

If you find any of those — that is a potential true positive. Escalate before tuning.

---

## Step 4 — Calculate the False Positive Rate

False positive rate = (false positive alerts / total alerts) x 100

To estimate this without manually reviewing every alert:

```bash
# Total alerts in sample
TOTAL=$(kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=200 \
  --prefix=false 2>/dev/null | grep -c '"rule":' || echo 0)

# Known false-positive rules in an untuned Portfolio environment
FP=$(kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=200 \
  --prefix=false 2>/dev/null \
  | grep -cE '"rule":"(Launch Package Management Process in Container|Read sensitive file untrusted|Write below root in container)"' \
  || echo 0)

echo "Total alerts:     ${TOTAL}"
echo "Estimated FP:     ${FP}"
if [[ "${TOTAL}" -gt 0 ]]; then
  echo "FP rate:          $(echo "scale=1; ${FP} * 100 / ${TOTAL}" | bc)%"
fi
```

Benchmark: a well-tuned SIEM targets under 10% false positive rate. If you are
above 50%, you have an alert fatigue problem. If you are above 80%, the detection
layer is analytically useless for the environment.

---

## Step 5 — Classify the Severity

Use this rubric to classify the finding:

| Condition | Severity |
|-----------|---------|
| Alert rate > 500/hr AND FP rate < 30% | Low (high volume, high quality) |
| Alert rate > 500/hr AND FP rate > 80% | HIGH (volume defeats analysis) |
| Alert rate < 100/hr AND FP rate > 80% | Medium (noise, manageable) |
| No custom rules for application-specific threats | Medium (detection gap) |
| Both high volume AND no custom rules | HIGH |

Alert fatigue is classified as HIGH when it creates a reliable path for threats
to avoid analyst attention. This is that condition.

---

## What the CySA+ Exam Tests Here

CySA+ Objective 2.3: Analyze output from common vulnerability assessment tools.

This objective includes SIEM and IDS output analysis. The exam tests whether you
understand:

1. The difference between a detection that fires and a detection that provides value
2. How to calculate and interpret false positive rate
3. When to tune (suppress) a rule vs. when to investigate further
4. How to document tuning decisions so they can be audited

The wrong answer on the exam: "Turn off all Falco rules to reduce noise."
The right answer: "Tune specific rules with documented exceptions, verify signal
is preserved, document the justification for each suppression."

---

## Key Teaching Point

Detection tools do not fail by going silent. They fail by going loud.

A Falco instance generating 500 alerts/hour that are 95% false positives is not
a functioning detection layer. It is a detection-shaped object. The analyst has
learned to treat the output as background noise, and that learned behavior is
indistinguishable from the behavior they would exhibit if Falco were off.

This is why CIS 8.11 mandates threshold tuning. Not because alerts are bad. Because
unreviewed alerts are worse than no alerts — they create the false confidence that
detection is happening while ensuring it is not.

---

## Next Step

Proceed to `investigate.md` to analyze false positive sources and tuning candidates.
