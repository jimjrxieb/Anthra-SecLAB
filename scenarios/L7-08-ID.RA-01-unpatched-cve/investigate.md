# L7-08 — Investigate: Unpatched CVE in Container Image

**Phase:** INVESTIGATE
**CySA+ Reference:** OBJ 1.3 — Explain the importance of vulnerability management
**Objective:** Triage CVEs by exploitability in context, score blast radius, draft POA&M

---

## Context

You have a list of CRITICAL and HIGH CVEs from the Trivy scan. The next step is not
to panic and roll back immediately. The next step is to triage. Not all CRITICAL CVEs
carry equal risk in every environment. Environmental score modifies base score.
Context determines priority.

This is the work CySA+ OBJ 1.3 tests. Scanning is the input. Triage is the job.

---

## Step 1 — Get the Full CVE Detail

Run Trivy with JSON output so you have structured data to work with:

```bash
trivy image python:3.9-slim --severity CRITICAL,HIGH --format json --quiet 2>/dev/null | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
print(f'{'CVE ID':<25} {'SEV':<10} {'INSTALLED':<20} {'FIXED':<20} {'TITLE':<50}')
print('-' * 125)
for result in data.get('Results', []):
    for vuln in result.get('Vulnerabilities', []):
        sev = vuln.get('Severity', '')
        if sev in ('CRITICAL', 'HIGH'):
            cve = vuln.get('VulnerabilityID', 'N/A')
            installed = vuln.get('InstalledVersion', 'N/A')
            fixed = vuln.get('FixedVersion', 'not fixed')
            title = vuln.get('Title', 'No title')[:50]
            print(f'{cve:<25} {sev:<10} {installed:<20} {fixed:<20} {title:<50}')
"
```

For each CRITICAL CVE, answer three questions:

1. Is this network-accessible? (does the vulnerable code path require an HTTP request?)
2. Does it require authentication? (is the API endpoint protected?)
3. Is there a known exploit? (EPSS > 0.4 = treat as exploited)

---

## Step 2 — CVSS Base vs Environmental Score

**CVSS Base Score** is calculated by the CVE reporter. It assumes the worst-case
environment: the vulnerable service is network-exposed, unauthenticated, and
directly reachable.

**CVSS Environmental Score** lets you adjust for your actual environment. Modifiers:

| Metric                        | Our Context                                          | Effect on Score |
|-------------------------------|------------------------------------------------------|-----------------|
| Attack Vector: Network        | API is in a Kubernetes namespace with NetworkPolicy  | Reduces score   |
| Authentication: None required | API requires JWT or service mesh mTLS               | Reduces score   |
| Confidentiality Impact: High  | Database credentials accessible in pod memory        | Keeps score     |
| Availability Impact: High     | Pod is already in CrashLoopBackOff                   | Increases score |

If CVSS base is 9.8 but the vulnerable library is never called from any reachable
code path, the environmental score may legitimately be 4-5. Document your reasoning.
Do not just accept the base score without environmental context.

However: in this lab, `python:3.9-slim` carries CVEs in OpenSSL and core libraries
that ARE reachable because the Python interpreter and pip use them at startup.
You cannot simply claim "not reachable" for system library CVEs in a running container.

---

## Step 3 — Triage Decision Matrix

For each CRITICAL CVE, work through this matrix:

```
Is the vulnerability in a library loaded at runtime?
  YES → Exploitable surface exists
    Is the vulnerable function called by the application?
      YES → HIGH priority — remediate immediately
      UNKNOWN → Treat as YES — you cannot prove safety without code audit
    Is there a known exploit in the wild? (EPSS > 0.4)
      YES → Escalate to URGENT — FedRAMP requires 15-day remediation clock
  NO → Exploitable surface is reduced
    Document compensating control and schedule for next patch cycle
```

---

## Step 4 — Blast Radius Assessment

Who is affected if this container is compromised?

```bash
# What service account does this pod use?
kubectl get pod -n anthra \
  -l app.kubernetes.io/component=api \
  -o jsonpath='{range .items[0]}{.spec.serviceAccountName}{"\n"}{end}'

# What namespaces can that service account reach?
kubectl get clusterrolebindings -o wide 2>/dev/null | grep portfolio || echo "No cluster-level bindings found"

# What secrets are mounted in the pod?
kubectl get pod -n anthra \
  -l app.kubernetes.io/component=api \
  -o jsonpath='{range .items[0]}{range .spec.volumes[*]}{.name}: {.secret.secretName}{"\n"}{end}{end}' 2>/dev/null || true

# What network policies apply to this namespace?
kubectl get networkpolicies -n anthra
```

Blast radius considerations for a compromised API container:
- Can the attacker reach the ChromaDB pod (vector database)?
- Can the attacker reach the UI pod and inject content?
- Does the service account have get/list/watch on secrets cluster-wide?
- Are there mounted secrets (DB credentials, API keys) accessible at /var/run/secrets?

---

## Step 5 — GRC: Draft the POA&M Entry

NIST SI-2 requires documentation of identified flaws and remediation timelines.
FedRAMP Moderate requires this be captured in the Plan of Action and Milestones.

Fill in the following for each CRITICAL CVE:

```
POAM-ID:       L7-08-[DATE]-001
Control:       SI-2 (Flaw Remediation)
Finding:       CRITICAL CVE in python:3.9-slim container image deployed to
               portfolio-anthra-portfolio-app-api in namespace anthra
CVE:           [CVE ID from Trivy output]
CVSS Base:     [score from Trivy output]
EPSS (30d):    [score from FIRST API — https://api.first.org/data/v1/epss?cve=CVE-ID]
Exposure:      Network-accessible API container; CVE in runtime library (OpenSSL/glibc)
Blast Radius:  [from Step 4 above]
Compensating:  [NetworkPolicy, mTLS, WAF — if any are in place]
Required Fix:  Pin image to a patched version or current debian-slim with updated packages
FedRAMP SLA:   CRITICAL = 15 calendar days from identification
Identified:    [today's date]
Due By:        [today + 15 days]
Status:        Open — remediation in progress (rollback initiated)
```

---

## Step 6 — Record the Finding

Even in a lab, practice the habit of recording findings before fixing them.
A finding that is fixed but not recorded is a finding that will recur, because the
root cause (no CI scanning gate) is never documented and therefore never addressed.

Root cause of this finding is not the CVE. CVEs exist. Root cause is:
- No `trivy image` gate in CI/CD before image deployment
- No image digest pinning to prevent silent drift
- No periodic re-scan of running images against updated CVE databases

The fix.sh rolls back the image. The real remediation (remediate.md) addresses the
root cause so this cannot happen again.

---

## CySA+ OBJ 1.3 Teaching Point

The exam distinguishes between:

**Vulnerability Identification** — scanning found something (Trivy output)
**Vulnerability Validation** — you confirmed it is real and applicable (triage)
**Vulnerability Recording** — you documented it in the risk register (POA&M)

All three steps are required for ID.RA-01 compliance. Scanning alone does not close
the loop. A scan report sitting in a directory that nobody reads is not a vulnerability
management program. It is a vulnerability discovery program with no management.

---

## Next Step

Proceed to `fix.sh` to rollback the deployment and restore the original image.
Then read `remediate.md` for the full vulnerability management lifecycle and the
correct long-term fix.
