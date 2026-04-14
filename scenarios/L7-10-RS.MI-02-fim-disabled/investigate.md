# L7-10 RS.MI-02 — Investigate: FIM Gap on Writable Container Paths

**Role:** L1 Security Analyst
**CSF:** RESPOND / RS.MI-02
**CIS v8:** 3.14
**NIST 800-53:** SI-7

You have confirmed: files exist in `/tmp` of the Portfolio API container,
and Falco did not alert on any of those writes. Now determine what was written,
when, by what process, and whether any data could have been exfiltrated.
Then classify the finding and decide the rank.

---

## Step 1 — What Was Written?

Inspect each file in `/tmp` and assess its nature.

```bash
NAMESPACE="anthra"
API_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l app.kubernetes.io/component=api \
  -o jsonpath='{.items[0].metadata.name}')

# Full listing with timestamps
echo "--- /tmp contents with timestamps ---"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- ls -lat /tmp/

# Type-check each file
echo ""
echo "--- File types ---"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
  find /tmp -maxdepth 1 -type f -exec file {} \; 2>/dev/null || true

# Read each file (be cautious with binary content)
echo ""
echo "--- File contents ---"
for FNAME in backdoor.sh staged-data.txt; do
  echo "=== /tmp/${FNAME} ==="
  kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
    cat "/tmp/${FNAME}" 2>/dev/null || echo "  (file not present)"
  echo ""
done
```

**What you are looking for:**
- Scripts (`.sh`, `.py`, `.pl`) — tools the attacker intends to execute
- Text files (`.txt`, `.csv`, `.json`) — data staged for exfiltration
- Binaries — curl, wget, netcat, or other tools downloaded post-compromise
- Base64 blobs — encoded data ready to exfiltrate via HTTP parameter

**For this scenario you will find:**
- `backdoor.sh` — a shell script that would exfiltrate data via curl
- `staged-data.txt` — text content simulating sensitive data

---

## Step 2 — When Were the Files Written?

Establish a timeline. This is required for the incident report.

```bash
NAMESPACE="anthra"
API_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l app.kubernetes.io/component=api \
  -o jsonpath='{.items[0].metadata.name}')

# File modification times
echo "--- File timestamps ---"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
  find /tmp -maxdepth 1 -type f -exec stat -c "%y %n" {} \; 2>/dev/null || true

# When did the pod start?
echo ""
echo "--- Pod start time ---"
kubectl get pod "${API_POD}" -n "${NAMESPACE}" \
  -o jsonpath='Started: {.status.containerStatuses[0].state.running.startedAt}{"\n"}'

# When was the break.sh exec?
echo ""
echo "--- Recent exec events (audit trail, if available) ---"
kubectl get events -n "${NAMESPACE}" \
  --field-selector reason=Exec \
  --sort-by='.lastTimestamp' 2>/dev/null | tail -10 \
  || echo "  No exec events in current event log (short TTL — check Falco for audit trail)"
```

**What you are looking for:**
- File creation timestamps relative to pod start time
- Whether files were written before or after the break.sh run
- Any gap between file creation and detection (this is the dwell time)

---

## Step 3 — What Process Wrote the Files?

In a real incident, you would query Falco (if it had been capturing), Tetragon, or
auditd to identify the PID and process that made the writes. In this scenario,
Falco was not capturing — that is the gap.

```bash
# If Tetragon is deployed, check for file write events
kubectl get pods -n kube-system -l "app.kubernetes.io/name=tetragon" 2>/dev/null \
  || echo "Tetragon not deployed in this cluster"

# Check Falco for any exec events (even without /tmp write rules, some exec rules may fire)
FALCO_POD=$(kubectl get pods -n falco \
  -l app.kubernetes.io/name=falco \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -n "${FALCO_POD}" ]]; then
  echo "--- Falco: exec events in anthra namespace ---"
  kubectl logs -n falco "${FALCO_POD}" --tail=500 2>/dev/null \
    | grep -i "anthra\|portfolio-app-api\|exec" | tail -20 \
    || echo "  No relevant exec events found in Falco logs"
fi

# Check process tree (if still active)
echo ""
echo "--- Current processes in API pod ---"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
  ps aux 2>/dev/null || echo "  ps not available in this container"
```

**Key teaching:** Without FIM, you can identify **what** was staged but not
**what process** staged it. For RS.MI-02 (eradication), knowing the process
matters — if the staging mechanism is still running, cleanup alone is not enough.
You need to confirm the attack vector is closed.

---

## Step 4 — Could Data Have Been Exfiltrated?

Assess whether the staged data has already left the container.

```bash
NAMESPACE="anthra"
API_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l app.kubernetes.io/component=api \
  -o jsonpath='{.items[0].metadata.name}')

# Check network connectivity from the pod (what can it reach?)
echo "--- Network reachability test ---"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
  /bin/sh -c "curl -s --connect-timeout 5 http://attacker.example.com/test 2>&1 | head -5" \
  || echo "  Connection to attacker.example.com failed (as expected — DNS does not resolve)"

# Check NetworkPolicy — does one restrict egress?
echo ""
echo "--- NetworkPolicies in anthra namespace ---"
kubectl get networkpolicy -n "${NAMESPACE}" -o wide 2>/dev/null \
  || echo "  No NetworkPolicies found (unrestricted egress — HIGH risk)"

# Check if the backdoor script has execute permission
echo ""
echo "--- backdoor.sh permissions ---"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
  ls -la /tmp/backdoor.sh 2>/dev/null || echo "  backdoor.sh not found"
```

**Interpret the results:**

| Condition                              | Exfil risk assessment                                   |
|----------------------------------------|---------------------------------------------------------|
| NetworkPolicy blocks egress to unknown | MEDIUM — exfil was likely prevented                     |
| No NetworkPolicy / unrestricted egress | HIGH — assume exfiltration is possible or occurred      |
| Script has +x, no egress restriction   | HIGH — staged payload could execute                     |
| DNS does not resolve attacker domain   | Lower (domain does not exist) — but real attacks use IPs |

For this lab scenario: `attacker.example.com` does not resolve. The exfil
would have failed. But in a real incident, the domain would resolve. The risk
assessment must assume the worst-case posture.

---

## Step 5 — Is the Data Sensitive?

Classify what was staged.

```bash
NAMESPACE="anthra"
API_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l app.kubernetes.io/component=api \
  -o jsonpath='{.items[0].metadata.name}')

# Read staged-data.txt — is it PII, credentials, or application data?
echo "--- staged-data.txt classification ---"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
  cat /tmp/staged-data.txt 2>/dev/null || echo "  File not found"

# Check for credentials or tokens in /tmp
echo ""
echo "--- Credential patterns in /tmp ---"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
  find /tmp -type f -exec grep -l -i "token\|password\|secret\|key\|credential" {} \; \
  2>/dev/null || echo "  No credential patterns found in /tmp"
```

**Severity decision based on data classification:**

| Data in /tmp                              | Severity   | Rank escalation |
|-------------------------------------------|------------|-----------------|
| Application scratch (harmless temp files) | LOW        | No change       |
| Application output (query results, etc.)  | MEDIUM     | No change (C)   |
| PII, PHI, or financial data               | HIGH       | Escalate to B   |
| Credentials, tokens, secrets              | CRITICAL   | Escalate to S   |

For this scenario: `staged-data.txt` contains simulated pipeline output.
Severity: MEDIUM-HIGH.

---

## Step 6 — Classify the Finding

```
Finding: FIM not covering writable container paths (/tmp)
Asset: portfolio-anthra-portfolio-app-api (namespace: anthra)
Affected path: /tmp (emptyDir, writable by design)
Files found: backdoor.sh, staged-data.txt
Data sensitivity: MEDIUM (simulated pipeline output)
FIM coverage: NONE — no Falco rule targets /tmp in anthra namespace
Exfil risk: MEDIUM (no NetworkPolicy restricting egress)
CSF: RS.MI-02 — Incidents are eradicated
CIS v8: 3.14 — Log Sensitive Data Access
NIST 800-53: SI-7 — Software, Firmware, and Information Integrity
Severity: MEDIUM-HIGH
Rank: C — deterministic fix (Falco rule), but rule deployment touches
           cluster-wide security configuration (requires approval)
```

**Rank justification:** The fix is a targeted Falco rule — deterministic and
reversible. However, modifying the Falco ConfigMap and restarting Falco affects
the security monitoring stack for the entire cluster. That is enough scope to
require C-rank approval before proceeding.

---

## Pre-Fix Checklist

Before running fix.sh, confirm:

- [ ] Files in /tmp identified and contents reviewed
- [ ] File timestamps established (evidence timeline)
- [ ] Process attribution attempted (Tetragon / Falco exec audit)
- [ ] Exfiltration risk assessed (NetworkPolicy review)
- [ ] Data sensitivity classified
- [ ] Finding classified (rank, severity, CSF/CIS/NIST documented)
- [ ] Evidence package saved to /tmp/L7-10-evidence-*/
- [ ] C-rank approval obtained (or proceeding under lab conditions)

**NEXT STEP:** Run `fix.sh` (after approval in a real environment)
