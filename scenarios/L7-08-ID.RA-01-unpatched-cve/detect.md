# L7-08 — Detect: Unpatched CVE in Container Image

**Phase:** DETECT
**Persona:** Level 1 Analyst (SOC / GRC / SRE)
**Objective:** Run a vulnerability scan, read the output correctly, and check pod health

---

## How You Got Here

This is your vulnerability management tooling doing its job. CVSS score and EPSS
probability tell you urgency. Your job is to read the output and act on it.

**Path A — CI pipeline blocked (most common in a mature pipeline):** A scheduled
Trivy image scan ran as part of the CI/CD pipeline against the Portfolio API
image. It flagged one or more CRITICAL CVEs. The pipeline sent an alert or filed
a ticket. You are now working that finding.

**Path B — Day 1 Baseline scan:** Your baseline included running `trivy image`
against all images in the `anthra` namespace. The CRITICAL count was non-zero.
You recorded it as a finding during the initial assessment and are now working it
as a formal remediation task.

**Path C — Assessment cycle scan:** A vulnerability management scan (Trivy,
Grype) ran as part of your regular assessment cadence. The report shows a
CRITICAL finding against the API image that was not present in the previous scan.
A dependency update or new CVE disclosure surfaced it.

Either way: you were not paged by a runtime alert. A vulnerability scanner
examined the image and found a known CVE in a package the image carries. Your job
now is to confirm what is running, understand the severity, check whether the pod
is healthy, and determine urgency before proceeding to investigate.md.

---

## Step 1 — Check What Is Actually Running

```bash
kubectl get pods -n anthra
```

Expected output (one of two scenarios):

**Scenario A — Pod is Running:**
```
NAME                                              READY   STATUS    RESTARTS   AGE
portfolio-anthra-portfolio-app-api-xxxx-yyyy      1/1     Running   0          2m
```

**Scenario B — Pod is Crashing:**
```
NAME                                              READY   STATUS             RESTARTS   AGE
portfolio-anthra-portfolio-app-api-xxxx-yyyy      0/1     CrashLoopBackOff   3          2m
```

If the pod is crashing, check the logs:

```bash
kubectl logs -n anthra deployment/portfolio-anthra-portfolio-app-api --previous 2>/dev/null || \
kubectl logs -n anthra deployment/portfolio-anthra-portfolio-app-api
```

Look for: `ModuleNotFoundError`, `ImportError`, Python version mismatch, missing
dependencies. A crashed pod means a vulnerable image also broke the application.
Both findings matter.

---

## Step 2 — Find What Image Is Running

```bash
kubectl get deployment portfolio-anthra-portfolio-app-api -n anthra \
  -o jsonpath='{.spec.template.spec.containers[0].image}'
echo ""
```

You should see: `python:3.9-slim`

Notice what is missing: there is no digest pin (no `@sha256:...`). The tag
`3.9-slim` resolves to whatever Docker Hub serves at pull time. This means:

- You cannot reproduce what is actually running from the tag alone
- The image may have changed silently since the last deployment
- Trivy will scan the image Docker Hub currently serves for this tag

---

## Step 3 — Scan the Image with Trivy

Run the scan. This is the primary detection step.

```bash
trivy image python:3.9-slim --severity CRITICAL,HIGH
```

Trivy will pull the image (if not cached) and scan all OS packages and Python
packages installed in the image layers.

**Reading the output:**

The table format shows:
```
Library    Vulnerability    Severity    Installed Version    Fixed Version    Title
```

Focus on the Severity column first. Find all CRITICAL rows.

**What does CVSS 9.8 mean?**

CVSS (Common Vulnerability Scoring System) scores vulnerabilities on a 0-10 scale:

| Score Range | Severity | What It Means                                        |
|-------------|----------|------------------------------------------------------|
| 9.0 - 10.0  | CRITICAL | Remotely exploitable, no authentication required     |
| 7.0 - 8.9   | HIGH     | Significant impact, may require local access or auth |
| 4.0 - 6.9   | MEDIUM   | Exploitable under specific conditions                |
| 0.1 - 3.9   | LOW      | Limited impact, difficult to exploit                 |

A CVSS 9.8 means: this vulnerability can be exploited over the network without
authentication, results in full compromise (confidentiality, integrity, and
availability all affected), and requires no user interaction.

**What does CVSS 7.5 mean?**

Severity: HIGH. Likely network-accessible but may have partial impact (e.g., only
confidentiality — not full compromise). Still requires remediation within 30 days
per FedRAMP Moderate requirements.

---

## Step 4 — Check for EPSS Scores

EPSS (Exploit Prediction Scoring System) answers a different question than CVSS.

- CVSS answers: "How bad could this be if exploited?"
- EPSS answers: "How likely is this to be exploited in the next 30 days?"

A CVE with CVSS 9.8 and EPSS 0.02 (2%) means: theoretically catastrophic, but
unlikely to be targeted soon. Still remediate — but understand the difference.

A CVE with CVSS 6.5 and EPSS 0.73 (73%) means: moderate severity, but attackers
are actively exploiting this right now. Treat it as urgent regardless of CVSS.

To check EPSS for a specific CVE:
```bash
# Using Trivy's JSON output format to find CVE IDs
trivy image python:3.9-slim --severity CRITICAL --format json --quiet 2>/dev/null | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
for result in data.get('Results', []):
    for vuln in result.get('Vulnerabilities', []):
        if vuln.get('Severity') == 'CRITICAL':
            print(vuln.get('VulnerabilityID'), '-', vuln.get('Title', 'No title')[:60])
"
```

Then look up EPSS scores at: https://api.first.org/data/v1/epss?cve=CVE-XXXX-XXXXX

---

## Step 5 — Summarize the Finding

At this point you have:

1. The image tag (`python:3.9-slim`)
2. The CRITICAL CVE count and specific CVE IDs
3. Whether the pod is running or crashing
4. An initial read on CVSS scores

Write this down. You will need it for investigate.md.

**Quick capture:**

```bash
echo "=== L7-08 Finding Capture ===" && \
echo "Image: $(kubectl get deployment portfolio-anthra-portfolio-app-api \
  -n anthra -o jsonpath='{.spec.template.spec.containers[0].image}')" && \
echo "Pod status: $(kubectl get pods -n anthra \
  --no-headers 2>/dev/null | grep api | awk '{print $3}' | head -1)" && \
echo "Trivy CRITICAL count:" && \
trivy image python:3.9-slim --severity CRITICAL --format json --quiet 2>/dev/null | \
  python3 -c "
import json,sys
data=json.load(sys.stdin)
total=sum(len([v for v in r.get('Vulnerabilities',[]) if v.get('Severity')=='CRITICAL'])
          for r in (data.get('Results') or []))
print(f'  {total} CRITICAL CVEs found')
"
```

---

## What You Are Looking For

| Indicator                          | Finding                                                    |
|------------------------------------|------------------------------------------------------------|
| Image tag without digest           | Unpinned image — CI/CD gap, CIS 7.4 violation              |
| CRITICAL CVEs present              | SI-2 remediation clock starts now                          |
| Pod in CrashLoopBackOff            | Dual finding: vulnerability + availability incident        |
| No Trivy scan provenance in labels | Image was not scanned in CI before deployment              |
| Fixed Version column shows a fix   | A patched version exists — remediation is available        |

---

## Next Step

Proceed to `investigate.md` to triage the specific CVEs, score by environmental
context, and draft the POA&M entry.
