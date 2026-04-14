# L7-05 — DE.AE-02: Investigate Phase

## L1 Analyst Task: Characterize the Alert Population and Document for AU-6

Detection found the noise. Investigation answers why. Your job is to build the case
for tuning: which rules fire most, why they fire, whether the triggers are legitimate,
and what the portfolio lacks in custom detection coverage.

---

## Step 1 — Which Rules Fire Most? (Rule + Count)

```bash
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=300 --prefix=false \
  | grep -oP '"rule":"[^"]*"' \
  | sed 's/"rule":"//;s/"//' \
  | sort | uniq -c | sort -rn
```

Record the output in this table (fill in from your environment):

| Rank | Alert Count | Rule Name | Priority |
|------|-------------|-----------|---------|
| 1    |             |           |         |
| 2    |             |           |         |
| 3    |             |           |         |
| 4    |             |           |         |
| 5    |             |           |         |

---

## Step 2 — Are the Triggering Processes Legitimate?

For each top rule, identify what process is actually triggering it.

```bash
# For a specific rule, show the triggering process name and container
RULE="Read sensitive file untrusted"
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=200 --prefix=false \
  | python3 -c "
import sys, json
for line in sys.stdin:
  try:
    evt = json.loads(line)
    if evt.get('rule') == '${RULE}':
      fields = evt.get('output_fields', {})
      print(f\"proc={fields.get('proc.name','?')} container={fields.get('container.name','?')} file={fields.get('fd.name','?')}\")
  except:
    pass
" | sort | uniq -c | sort -rn | head -20
```

Run this for each of your top 3 rules. Expected findings:

**Launch Package Management Process in Container**
- Triggering process: `pip`, `pip3`
- Container: typically the init container or dependency installer
- Is this legitimate? YES — init containers install dependencies at startup
- False positive? YES — pip in an init container is expected behavior

**Read sensitive file untrusted**
- Triggering process: often `curl`, `python`, or the app binary itself
- What file? `/proc/self/status`, `/etc/os-release`, `/etc/hostname`
- Is this legitimate? YES — health probes read these; apps read them at startup
- False positive? YES — these are routine reads by known processes

**Terminal shell in container**
- Triggering process: `sh`, `bash`
- What invoked it? Could be kubectl exec (developer), or could be the app
- Is this legitimate? DEPENDS — needs individual review
- False positive? SOMETIMES — flag these for manual review, do not bulk-suppress

---

## Step 3 — What Is the False Positive Rate?

Calculate the FP rate from the rules you identified in Step 2:

```bash
TOTAL=$(kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=300 \
  --prefix=false 2>/dev/null | grep -c '"rule":' || echo 0)

# Adjust this list to your top confirmed FP rules
FP=$(kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=300 \
  --prefix=false 2>/dev/null \
  | grep -cE '"rule":"(Launch Package Management Process in Container|Read sensitive file untrusted)"' \
  || echo 0)

echo "Total: ${TOTAL} | FP: ${FP} | Rate: $(echo "scale=1; ${FP} * 100 / ${TOTAL}" | bc)%"
```

Document this rate. It is your before metric for the POA&M.

---

## Step 4 — What Is Missing? (Detection Gaps for Portfolio)

This is the second half of the investigation. Default Falco rules detect generic
Kubernetes threats. They do not detect Portfolio-specific threat patterns.

Run these queries to confirm what is NOT being detected:

```bash
# Test: would a shell exec in the API container get a meaningful alert?
# Expected: fires generic "Terminal shell in container" — no Portfolio context
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50 --prefix=false \
  | grep '"rule":"Terminal shell in container"' \
  | grep '"container.name":"api"' \
  | head -5
```

```bash
# Test: does reading /etc/passwd in the API container trigger a specific alert?
# Expected: may fire "Read sensitive file untrusted" — generic, no context
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50 --prefix=false \
  | grep '"fd.name":"/etc/passwd"' \
  | head -5
```

```bash
# Test: outbound connection from API container to non-DNS, non-internal port?
# Expected in default rules: may not fire at all without custom rule
kubectl logs -n falco -l app.kubernetes.io/name=falco --tail=50 --prefix=false \
  | grep '"rule":"Outbound"' \
  | grep '"container.name":"api"' \
  | head -5
```

Gap analysis summary for Portfolio:

| Threat Pattern | Default Falco Coverage | Gap |
|----------------|----------------------|-----|
| Shell exec in API pod | Generic rule, not Portfolio-specific | Medium |
| /etc/passwd read in API pod | Covered by "Read sensitive file untrusted" — buried in noise | High |
| Outbound connection from API to external IP | Partially covered | Medium |
| API pod spawning child process unexpectedly | Not specifically targeted | High |
| Crypto miner behavior (CPU-intensive subprocess) | Generic detection only | Medium |

---

## Step 5 — Document the Alert Review Process (AU-6 Compliance)

NIST AU-6 requires a documented audit review process. The auditor will ask:

1. How frequently are audit logs reviewed?
2. Who is responsible for reviewing them?
3. What is the escalation path when a true positive is found?
4. How are false positive suppression decisions documented and approved?

Draft your AU-6 review process statement here:

```
ORGANIZATION: [Your org name]
SYSTEM: k3d-seclab / anthra namespace
CONTROL: AU-6 — Audit Record Review, Analysis, and Reporting

Review frequency:    [Daily / Weekly — choose and justify]
Review owner:        [Name or role of the analyst responsible]
Review method:       Falcosidekick dashboard + Splunk (gp_security index)
True positive path:  L1 analyst flags → L2 triage → incident ticket created
FP suppression path: L1 proposes exception → L2 approves → change documented in
                     Falco custom rules ConfigMap → reviewed quarterly

Documented exceptions as of [date]:
- [Rule name]: suppressed for [process] in [container] because [business reason]
- [Rule name]: suppressed for [process] in [container] because [business reason]

Next quarterly review date: [date]
```

File this documentation in your GRC system under AU-6 evidence. The auditor needs
to see that this process exists and is followed — not just that Falco is installed.

---

## Step 6 — Classify the Finding for the POA&M

| Field | Value |
|-------|-------|
| Finding ID | SEC-[YYYY]-[NNN] |
| Title | Falco alert tuning not implemented for anthra namespace |
| Control | AU-6, DE.AE-02, CIS 8.11 |
| Severity | MEDIUM |
| Root cause | No custom Falco rules; default ruleset generates high FP rate |
| Business impact | Analyst alert fatigue; real threats not distinguished from noise |
| False positive rate | [Fill in from Step 3] |
| Projected alerts/hour | [Fill in from baseline.sh] |
| Remediation | Deploy custom rules ConfigMap; document exceptions for AU-6 |
| Target remediation date | [30 days from finding date] |
| Compensating control | Manual log review at increased frequency during tuning period |

---

## Next Step

Proceed to `fix.sh` to deploy the custom rules ConfigMap and apply Falco exceptions.
