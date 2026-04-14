# L7-06 — DE.AE-06: Investigate Phase

## L1 Analyst Task: Analyze the Retention Policy and Compliance Gap

You have confirmed that logs older than 24 hours are gone. Now you need to answer
the investigation questions that an incident commander or GRC reviewer will ask.
This phase produces the data for your POA&M entry.

---

## Investigation Questions

Work through each question in order. Record your answers — they go directly into
the report-template.md.

---

### Question 1: What is the current retention configuration?

Document the specific setting that caused the short retention. This is the root cause.

```bash
# Loki retention (if deployed)
LOKI_NS=$(kubectl get pods --all-namespaces --no-headers \
  | grep -i loki | awk '{print $1}' | head -1)

if [[ -n "${LOKI_NS}" ]]; then
  LOKI_CM=$(kubectl get configmap -n "${LOKI_NS}" --no-headers \
    | grep -i loki | awk '{print $1}' | head -1)
  echo "Loki ConfigMap: ${LOKI_NS}/${LOKI_CM}"
  echo ""
  echo "Retention settings:"
  kubectl get configmap -n "${LOKI_NS}" "${LOKI_CM}" \
    -o jsonpath='{.data}' 2>/dev/null \
    | python3 -c "
import sys, json
d = json.load(sys.stdin)
for k, v in d.items():
    for line in v.split('\n'):
        if 'retention' in line.lower() or 'chunk_retain' in line.lower():
            print(' ', line)
" || echo "  (could not parse — check configmap manually)"
fi
```

```bash
# Fluent Bit buffer config
FB_CM=$(kubectl get configmap -n logging --no-headers \
  | grep -i fluent | awk '{print $1}' | head -1)
kubectl get configmap -n logging "${FB_CM}" -o jsonpath='{.data}' \
  2>/dev/null | grep -i -E "mem_buf|storage.type|path" \
  || echo "  (Fluent Bit uses default in-memory buffer, no durable storage)"
```

Record:
- Loki retention_period: _______________
- Fluent Bit Mem_Buf_Limit: _______________
- Fluent Bit output backend: _______________

---

### Question 2: When was the retention policy last reviewed?

Look for documentation. If none exists, that itself is a finding.

```bash
# Check for a policy document in the cluster (some teams store in ConfigMaps)
kubectl get configmap --all-namespaces --no-headers \
  | grep -i -E "retention|audit-policy|log-policy" \
  | awk '{printf "  %s / %s\n", $1, $2}' \
  || echo "  No retention policy ConfigMap found."
```

Questions to ask the team:
- Is there a documented log retention policy? Where is it stored?
- When was it last reviewed and by whom?
- Does the policy match the actual configuration (24h setting vs stated policy)?
- Was the retention policy included in the most recent security plan review?

If the answer to any of these is "I don't know" or "we don't have one" — document it.
That absence is a separate AU-11 finding: not just misconfiguration, but missing policy.

---

### Question 3: Which frameworks apply to this system?

This determines the required retention period. Different frameworks have different
minimums. The highest applicable requirement sets the floor.

For the anthra cluster (simulating a FedRAMP Moderate workload):

| Framework | Applies? | Retention Requirement |
|-----------|---------|----------------------|
| FedRAMP Moderate | YES | 90 days online |
| NIST 800-53 AU-11 | YES | Org-defined (90 days per security plan) |
| CIS Controls v8 8.10 | YES | 90 days |
| PCI-DSS v4.0 | If processing card data | 12 months (3 online, 9 archived) |
| HIPAA | If processing PHI | 6 years |
| SOC 2 | If SOC 2 audit scope | Typically 90 days |

For this lab: FedRAMP Moderate applies. Minimum is **90 days online**.

The current configuration (24 hours) falls short by **89 days and 0 hours**.

---

### Question 4: How many days of logs actually exist?

Calculate the real retention window from the oldest available log.

```bash
# For each anthra pod, find oldest and newest log timestamps
for POD in $(kubectl get pods -n anthra --no-headers | awk '{print $1}' | head -5); do
  OLDEST=$(kubectl logs -n anthra "${POD}" --timestamps=true 2>/dev/null \
    | head -1 | awk '{print $1}' || echo "no logs")
  NEWEST=$(kubectl logs -n anthra "${POD}" --timestamps=true 2>/dev/null \
    | tail -1 | awk '{print $1}' || echo "no logs")
  echo "  ${POD}:"
  echo "    Oldest: ${OLDEST}"
  echo "    Newest: ${NEWEST}"
done
```

Record:
- Oldest available log timestamp: _______________
- Current timestamp: _______________
- Actual retention window: _______________ (hours/days)
- Required retention: 90 days
- Compliance gap: _______________ (90 days minus actual window)

---

### Question 5: What events may be unrecoverable?

This is the impact assessment. For the period before the retention window (the gap),
what types of events were not retained?

For the anthra namespace during a 24-hour retention window, unrecoverable events
include any of the following that occurred more than 24 hours ago:

| Event Type | Source Pod | Security Relevance |
|------------|-----------|-------------------|
| API authentication events | api | AU-2 requires auth event logging |
| API request logs (method, path, response) | api | AU-2 requires access events |
| UI session events | ui | User activity tracking |
| Vector database query events | chroma | Data access audit trail |
| Error events and exceptions | api, ui | Anomaly detection baseline |
| Startup and shutdown events | all | Change detection |

For an incident where suspicious activity occurred 48h ago:
- Estimated events lost: ALL events from that 48h window except the most recent 24h
- Recovery possibility: NONE (logs are rotated, no backup)
- Impact on investigation: Cannot establish timeline, cannot confirm or deny activity

---

### Question 6: What was the business impact?

Translate the technical gap into business terms for the POA&M.

If an investigation is required:
- Investigation is impaired — cannot establish complete timeline
- Forensic analysis cannot confirm or deny attacker activity during the gap
- Incident scope cannot be determined with certainty
- Reporting to regulators (if required) must disclose evidence unavailability

If no active investigation:
- AU-11 is not satisfied — this will be a finding in the next FedRAMP assessment
- Organization cannot demonstrate compliance for any event older than 24h
- Any incident in the past that occurred more than 24h ago has no log evidence

---

## Investigation Summary

Fill in this table before proceeding to remediate.md:

| Question | Answer |
|----------|--------|
| Current retention setting | [From question 1] |
| Last policy review | [From question 2] |
| Most restrictive framework | FedRAMP Moderate — 90 days |
| Actual retention observed | [From question 4 — in hours/days] |
| Compliance gap | [90 days - actual retention] |
| Unrecoverable events exist? | YES — all events older than [retention window] |
| Active investigation impacted? | [YES / NO] |

---

## Next Step

Proceed to `fix.sh` to set retention to 90 days and restore compliance.
Then return to `remediate.md` for the GRC documentation requirements.
