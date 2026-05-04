# SI-2: Flaw Remediation
**Family:** System and Information Integrity  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
The organization identifies, reports, and corrects information system flaws; tests software and firmware updates related to flaw remediation for effectiveness and potential side effects before installation; installs security-relevant software updates within organizationally-defined time periods; and incorporates flaw remediation into the organizational configuration management process.

## Why It Matters at L7
At the application layer, unpatched dependencies and container base images are among the most exploited attack surfaces — CVE chaining through outdated libraries is the backbone of supply chain attacks. SLA-driven remediation ensures critical flaws like RCE and authentication bypasses are closed before threat actors can weaponize published exploits. Without automated scanning and enforced patch timelines, vulnerability debt compounds silently until a breach surfaces it.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Does the organization maintain a formal patch management policy that defines remediation SLAs by CVSS severity (Critical ≤24h, High ≤72h, Medium ≤30d, Low ≤90d)?
- Is there a vulnerability register or tracking system (Jira, ServiceNow, spreadsheet) where open CVEs are logged with owner, target remediation date, and status?
- What automated scanning tools are in place (Trivy, Dependabot, Snyk, Renovate) and how frequently do they execute against production-bound images and repositories?
- How are exceptions to patch SLAs handled? Is there a documented exception process requiring risk acceptance and compensating control documentation?
- Are SBOM (Software Bill of Materials) artifacts generated for deployed container images and applications, and are they retained for audit purposes?
- Is patch deployment gated through a change management process (scan → triage → PR → test → deploy), and is evidence of that pipeline retained?
- How does the organization handle end-of-life software or dependencies that no longer receive security updates?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| Patch management policy with SLA table by CVSS severity | IT/Security Policy repository | PDF, Word, Confluence page |
| Vulnerability register showing open/closed CVEs with remediation dates | ITSM (Jira, ServiceNow) or spreadsheet | CSV export, PDF report |
| Recent Trivy or SCA scan results for production images | CI/CD pipeline artifacts, S3/GCS | JSON, HTML report, PDF |
| SBOM artifacts for deployed applications | Build pipeline, artifact registry | CycloneDX JSON, SPDX |
| Patch exception log with risk acceptance signatures | Change management system | PDF, signed document |
| Evidence of automated PR creation for dependency updates | GitHub/GitLab, Dependabot/Renovate | PR history screenshot, audit log |

### Gap Documentation Template
**Control:** SI-2  
**Finding:** No documented patch management SLA policy; critical CVEs are remediated on an ad hoc basis with no defined timeframe.  
**Risk:** Attackers can exploit published CVEs between disclosure and remediation. Without SLAs, high-severity vulnerabilities may remain open for weeks, dramatically increasing the window of exposure.  
**Recommendation:** Establish and enforce a written patch management policy defining SLAs by CVSS severity (Critical ≤24h, High ≤72h, Medium ≤30d, Low ≤90d). Integrate automated scanning into CI/CD and gate deployments on scan pass.  
**Owner:** CISO / Application Security Lead  

### CISO Communication
> Our vulnerability remediation program currently lacks enforceable timelines, which means high-severity software flaws may remain open for weeks after disclosure. Published exploits for unpatched libraries are the leading initial access vector in application-layer breaches. To close this gap, we are implementing automated dependency scanning in our build pipeline with severity-based SLAs, and a formal exception process requiring executive sign-off for any deviation. This directly reduces our breach probability and provides the audit trail required for compliance reviews.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, cloud CLI, SIEM, scanning tools, direct remediation.

### Assessment Commands
```bash
# Scan a container image for CVEs — all severities, show fixed versions
trivy image --severity CRITICAL,HIGH,MEDIUM,LOW \
  --format table \
  nginx:latest

# Scan filesystem (repo) for dependency CVEs
trivy fs --severity CRITICAL,HIGH \
  --format json \
  --output /tmp/jsa-evidence/SI-2/trivy-fs-$(date +%Y%m%d).json \
  .

# Check for unpinned base images in Dockerfiles
find . -name "Dockerfile*" | xargs grep -n "FROM.*:latest" 2>/dev/null && \
  echo "[FAIL] Unpinned :latest base images found" || \
  echo "[PASS] No :latest base images detected"

# Audit npm dependencies
npm audit --json 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
vulns = d.get('vulnerabilities', {})
critical = sum(1 for v in vulns.values() if v.get('severity') == 'critical')
high     = sum(1 for v in vulns.values() if v.get('severity') == 'high')
print(f'Critical: {critical}  High: {high}  Total: {len(vulns)}')
" 2>/dev/null || echo "npm audit: not a Node.js project or npm not available"

# Audit Python dependencies
pip-audit --format json 2>/dev/null | python3 -c "
import sys, json
vulns = json.load(sys.stdin)
print(f'pip-audit: {len(vulns)} vulnerable packages')
for v in vulns[:10]:
    print(f\"  {v.get('name')} {v.get('version')} — {v.get('vulns',[{}])[0].get('id','?')}\")
" 2>/dev/null || echo "pip-audit not available; install with: pip install pip-audit"

# Go module vulnerability check
go list -json -m all 2>/dev/null | govulncheck ./... 2>/dev/null || \
  echo "govulncheck: not available or not a Go project"
```

### Detection / Testing
```bash
# Find images running in cluster with known CVEs (requires Trivy operator)
kubectl get vulnerabilityreports -A --sort-by='.report.summary.critical' 2>/dev/null | head -20

# Check for images with no digest (unpinned)
kubectl get pods -A -o json 2>/dev/null | python3 -c "
import sys, json
pods = json.load(sys.stdin)
for pod in pods['items']:
  ns = pod['metadata']['namespace']
  name = pod['metadata']['name']
  for c in pod['spec'].get('containers', []):
    img = c.get('image', '')
    if '@sha256:' not in img:
      print(f'[UNPINNED] {ns}/{name}: {img}')
"

# Identify pods running images older than 90 days (using image pull timestamps — approximate)
# Check image creation dates via registry inspection
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.spec.containers[*].image}{"\n"}{end}' 2>/dev/null | \
  sort -u | head -20

# SLA compliance check — find open CVEs in vulnerability register older than SLA thresholds
# Critical: 24h, High: 72h, Medium: 30d, Low: 90d
CUTOFF=$(date -d "90 days ago" +%Y-%m-%d 2>/dev/null || date -v-90d +%Y-%m-%d)
echo "Checking for LOW-severity CVEs older than 90 days (cutoff: $CUTOFF)"

# Check Dependabot alert age via GitHub CLI
gh api repos/:owner/:repo/dependabot/alerts --jq \
  '.[] | select(.state=="open") | "\(.severity) opened:\(.created_at) \(.dependency.package.name)"' \
  2>/dev/null | head -20 || echo "gh CLI not configured or Dependabot not enabled"
```

### Remediation
```bash
# Update a specific npm dependency
npm update <package-name>
npm audit fix

# Pin base image to digest in Dockerfile
# Get current digest
docker pull nginx:1.25 && \
  docker inspect nginx:1.25 --format '{{index .RepoDigests 0}}'
# Replace FROM nginx:1.25 with FROM nginx@sha256:<digest>

# Renovate config — add to repo root as renovate.json
cat > renovate.json << 'EOF'
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:base"],
  "vulnerabilityAlerts": {
    "enabled": true,
    "labels": ["security"]
  },
  "packageRules": [
    {
      "matchUpdateTypes": ["patch"],
      "automerge": true
    }
  ]
}
EOF

# Generate SBOM with Trivy
trivy image --format cyclonedx \
  --output /tmp/jsa-evidence/SI-2/sbom-$(date +%Y%m%d).json \
  <your-image>:tag

# Kubernetes node OS patch check
kubectl get nodes -o wide
# For EKS managed node groups — update via AWS CLI
# aws eks update-nodegroup-version --cluster-name <cluster> --nodegroup-name <ng>

# Pin Kubernetes image version (patch Deployment)
# Edit in git, not via kubectl (ArgoCD managed)
# image: nginx:1.25.4  ->  image: nginx:1.25.5
```

### Validation
```bash
# Verify no CRITICAL CVEs in image post-patch
trivy image --severity CRITICAL --exit-code 1 <your-image>:tag
# Expected: exit code 0 — no critical vulnerabilities found

# Verify Dependabot is enabled on the repo
gh api repos/:owner/:repo/vulnerability-alerts 2>/dev/null && \
  echo "[PASS] Dependabot enabled" || echo "[FAIL] Dependabot not enabled"

# Verify no unpinned images in cluster
kubectl get pods -A -o json | python3 -c "
import sys, json
pods = json.load(sys.stdin)
unpinned = []
for pod in pods['items']:
  for c in pod['spec'].get('containers', []):
    if '@sha256:' not in c.get('image', '') and ':latest' in c.get('image', ''):
      unpinned.append(c['image'])
if unpinned:
  print('[FAIL] Unpinned images:', unpinned)
else:
  print('[PASS] No :latest unpinned images in cluster')
"

# Confirm SBOM artifact exists
ls -lh /tmp/jsa-evidence/SI-2/sbom-*.json 2>/dev/null && \
  echo "[PASS] SBOM artifact present" || echo "[FAIL] No SBOM artifact found"
# Expected: File present with non-zero size
```

### Evidence Capture
```bash
EVIDENCE_DIR="/tmp/jsa-evidence/SI-2/$(date +%Y%m%d)"
mkdir -p "$EVIDENCE_DIR"

# Image scan — JSON for machine parsing
trivy image --format json \
  --output "$EVIDENCE_DIR/trivy-image-scan.json" \
  <your-image>:tag 2>/dev/null

# Filesystem scan
trivy fs --format json \
  --output "$EVIDENCE_DIR/trivy-fs-scan.json" \
  . 2>/dev/null

# npm audit
npm audit --json > "$EVIDENCE_DIR/npm-audit.json" 2>/dev/null || true

# pip-audit
pip-audit --format json > "$EVIDENCE_DIR/pip-audit.json" 2>/dev/null || true

# SBOM
trivy image --format cyclonedx \
  --output "$EVIDENCE_DIR/sbom-cyclonedx.json" \
  <your-image>:tag 2>/dev/null

# Cluster image inventory
kubectl get pods -A -o json > "$EVIDENCE_DIR/cluster-pods.json" 2>/dev/null

# Summary
cat > "$EVIDENCE_DIR/SI-2-summary.txt" << EOF
SI-2 Flaw Remediation Evidence
Date: $(date)
Auditor: $(whoami)

Files captured:
$(ls -1 "$EVIDENCE_DIR")
EOF

echo "[DONE] Evidence written to $EVIDENCE_DIR"
```
