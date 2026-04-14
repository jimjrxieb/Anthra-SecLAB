# L7-10 RS.MI-02 — Detect: FIM Gap on Writable Container Paths

**Role:** L1 Security Analyst
**CSF:** RESPOND / RS.MI-02
**CIS v8:** 3.14
**NIST 800-53:** SI-7

## How You Got Here

`readOnlyRootFilesystem: true` is a PROTECT control. It stops writes to the root
filesystem. FIM — File Integrity Monitoring via Falco rules — is a DETECT control.
It alerts when writes happen to sensitive paths. You verified one. You did not
verify the other. That is the gap.

**Path A — Security review of a running container:** During a security review,
you exec'd into the Portfolio API pod and checked `/tmp`. You found files there
that should not exist — or you simply noticed that a writable mount exists with no
monitoring coverage. You then checked Falco logs for any alert on `/tmp` writes
in the `anthra` namespace and found nothing. The write happened. Falco did not
see it.

**Path B — Baseline Falco rule coverage check:** Your Day 1 baseline included
reviewing the active Falco rules for coverage of writable container paths. You
checked for rules covering `/tmp` writes scoped to the `anthra` namespace or the
`portfolio-app-api` container, and found none in the default ruleset. The gap was
logged as a detection coverage finding at assessment time.

Either way: this is not a `readOnlyRootFilesystem` problem — that control is
working. The problem is that the writable `/tmp` mount has no detection coverage.
Anything written there is invisible to your security tooling. Your job in this
phase is to confirm the gap, document what Falco should be detecting but is not,
and gather evidence before proceeding to investigate.md.

---

## Step 1 — Check Falco Logs: Did Anything Fire for /tmp Writes?

This is the first question. If Falco fired, there is an alert trail. If it did not,
that is the finding.

```bash
# Get the Falco pod name
FALCO_POD=$(kubectl get pods -n falco \
  -l app.kubernetes.io/name=falco \
  -o jsonpath='{.items[0].metadata.name}')

echo "Falco pod: ${FALCO_POD}"

# Check recent Falco logs for any /tmp alerts
kubectl logs -n falco "${FALCO_POD}" --tail=200 | grep -i "tmp"

# Check for anything related to anthra or portfolio
kubectl logs -n falco "${FALCO_POD}" --tail=200 | grep -i "anthra\|portfolio"
```

**What you are looking for:** Any `WARNING` or `ERROR` level output from Falco
mentioning `/tmp`, the `anthra` namespace, or the `portfolio-app-api` container.

**Expected result in the broken state:** Nothing. No alerts. The write happened
and Falco did not see it because no rule covers `/tmp` writes in the `anthra`
namespace with default configuration.

**If Falco does fire:** Document the rule name. The scenario may already be
partially remediated, or a custom rule was added previously.

---

## Step 2 — Manually Inspect /tmp in the API Pod

If Falco did not alert, you need to confirm what is there by looking directly.

```bash
NAMESPACE="anthra"
API_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l app.kubernetes.io/component=api \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}')

echo "Pod: ${API_POD}"
echo ""

# List /tmp contents
echo "--- /tmp contents ---"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- ls -la /tmp/

# Check file contents if anything is there
echo ""
echo "--- Any shell scripts in /tmp? ---"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
  find /tmp -name "*.sh" -o -name "*.py" -o -name "*.txt" 2>/dev/null | head -20

# Check for any recently modified files
echo ""
echo "--- Files modified in the last 60 minutes ---"
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- \
  find /tmp -newer /tmp -mmin -60 2>/dev/null || echo "  No recently modified files found (or /tmp is empty)"
```

**What you are looking for:** Unexpected files — shell scripts, text files,
binary tools. Files that the application itself would not create.

**For this scenario:** You will find `backdoor.sh` and `staged-data.txt`
from the break.sh simulation.

---

## Step 3 — Search Falco Rules for /tmp Coverage

Understand the gap at the rule level, not just the output level.

```bash
# List all Falco ConfigMaps
kubectl get configmap -n falco

# Search for any /tmp rules
kubectl get configmap -n falco -o yaml | grep -i "tmp"

# Search for rules scoped to the anthra namespace
kubectl get configmap -n falco -o yaml | grep -i "anthra"

# Check what write rules exist at all
kubectl get configmap -n falco -o yaml | grep -A 5 "is_open_write"
```

**What you are looking for:** Any rule that:
1. Triggers on `evt.type in (open, openat, openat2)` with `evt.is_open_write=true`
2. Filters on `fd.name startswith /tmp/`
3. Scopes to `k8s.ns.name = "anthra"`

**Expected result:** No such rule exists. The default Falco ruleset covers
`/etc`, `/usr`, `/bin`, `/sbin`, and similar system paths. It does not cover
application-specific writable emptyDir mounts.

---

## Step 4 — Confirm the emptyDir Mount

Verify that `/tmp` being writable is configuration, not a mistake.

```bash
NAMESPACE="anthra"
API_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l app.kubernetes.io/component=api \
  -o jsonpath='{.items[0].metadata.name}')

# Check security context
echo "--- Security context ---"
kubectl get pod "${API_POD}" -n "${NAMESPACE}" \
  -o jsonpath='{range .spec.containers[*]}Container: {.name}{"\n"}  readOnlyRootFilesystem: {.securityContext.readOnlyRootFilesystem}{"\n"}{end}'

# Check volume mounts
echo ""
echo "--- Volume mounts ---"
kubectl get pod "${API_POD}" -n "${NAMESPACE}" \
  -o jsonpath='{range .spec.containers[*]}Container: {.name}{"\n"}{range .volumeMounts[*]}  {.mountPath}  readOnly={.readOnly}{"\n"}{end}{end}'

# Check volumes
echo ""
echo "--- Volumes ---"
kubectl get pod "${API_POD}" -n "${NAMESPACE}" \
  -o jsonpath='{range .spec.volumes[*]}Volume: {.name}  type={.emptyDir}{"\n"}{end}'
```

**What you are looking for:**
- `readOnlyRootFilesystem: true` — PREVENT layer is in place
- `/tmp` mounted with `readOnly` absent or false — writable by design
- Volume type `emptyDir` on the `/tmp` mount — expected, not a misconfiguration

**Key insight:** This is not a broken configuration. The `/tmp` writable mount
is intentional. The missing layer is the FIM rule that watches it.

---

## Key Teaching: PREVENT vs DETECT

| Control Type | Mechanism                     | What It Covers         | What It Misses    |
|--------------|-------------------------------|------------------------|-------------------|
| PREVENT      | `readOnlyRootFilesystem: true` | /app, /etc, /usr, /bin | /tmp, emptyDir mounts |
| DETECT       | Falco FIM rule                 | Paths explicitly named  | Anything not in a rule |

The correct posture is both:
- `readOnlyRootFilesystem: true` stops writes to the application tree
- A targeted Falco rule detects writes to `/tmp` in the anthra/api context

Neither control alone is sufficient. Together they provide defense in depth.

---

## Evidence to Capture

```bash
EVIDENCE_DIR="/tmp/L7-10-evidence-$(date +%Y%m%d-%H%M%S)"
mkdir -p "${EVIDENCE_DIR}"

NAMESPACE="anthra"
API_POD=$(kubectl get pods -n "${NAMESPACE}" \
  -l app.kubernetes.io/component=api \
  -o jsonpath='{.items[0].metadata.name}')

# /tmp contents (the evidence of what was staged)
kubectl exec -n "${NAMESPACE}" "${API_POD}" -- ls -la /tmp/ \
  > "${EVIDENCE_DIR}/tmp-contents.txt" 2>&1 || true

# Falco ConfigMap dump (proof of missing rule)
kubectl get configmap -n falco -o yaml \
  > "${EVIDENCE_DIR}/falco-configmaps.yaml" 2>&1 || true

# Falco recent logs (confirm no alerts fired)
FALCO_POD=$(kubectl get pods -n falco \
  -l app.kubernetes.io/name=falco \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [[ -n "${FALCO_POD}" ]]; then
  kubectl logs -n falco "${FALCO_POD}" --tail=200 \
    > "${EVIDENCE_DIR}/falco-logs.txt" 2>&1 || true
fi

# Security context (readOnlyRootFilesystem confirmation)
kubectl get pod "${API_POD}" -n "${NAMESPACE}" -o yaml \
  > "${EVIDENCE_DIR}/pod-spec.yaml" 2>&1 || true

echo "Evidence saved to: ${EVIDENCE_DIR}"
ls -la "${EVIDENCE_DIR}"
```

---

## Decision Point

| Condition                                              | Action                           |
|--------------------------------------------------------|----------------------------------|
| /tmp has unexpected files, no Falco alert              | C-rank — investigate.md, propose fix |
| /tmp is empty, no Falco rule covers it                 | C-rank — gap documented, propose fix |
| Falco already has a /tmp rule for anthra               | Scenario already remediated — verify rule quality |
| /tmp has files, Falco did fire                         | Partially remediated — review rule and investigate files |

**NEXT STEP:** Open `investigate.md`
