# 01b-vuln-scan-audit.md — Vulnerability Scanning Deep-Dive Audit

| Field | Value |
|---|---|
| **NIST Controls** | RA-5 (vulnerability scanning), SA-11 (developer security testing), SI-3 (malicious code protection) |
| **Tools** | OWASP ZAP / Trivy / Grype / Semgrep / kube-bench / Kubescape |
| **Enterprise Equiv** | Rapid7 InsightAppSec ($100K+) / Qualys ($80K+) / Checkmarx ($150K+) |
| **Time** | 60 minutes (audit) + scan time varies |
| **Rank** | D (read-only audit — scans only, no changes) |

---

## Purpose

Verify that vulnerability scanning is covering the full attack surface: web applications (DAST), code (SAST), dependencies, container images, and Kubernetes cluster configuration. Every gap in scan coverage is a blind spot an attacker can exploit.

---

## 1. OWASP ZAP — DAST Review

### Check Installation

```bash
# Check for ZAP installation
for ZAP_PATH in /usr/share/zaproxy/zap.sh /opt/zaproxy/zap.sh $(which zaproxy 2>/dev/null); do
  [[ -x "$ZAP_PATH" ]] && { echo "[PRESENT] ZAP: $ZAP_PATH"; break; }
done

# Check Docker image
docker images | grep -E "zaproxy|owasp/zap" || echo "[MISSING] ZAP Docker image"

# Check ZAP version
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap.sh -version 2>/dev/null | head -3
```

### Run Baseline Scan (Lab)

```bash
# Baseline scan — passive only, no active attack
# Good for initial assessment, won't break anything
TARGET_URL="${TARGET_URL:-http://localhost:8080}"

docker run --rm ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
  -t "$TARGET_URL" \
  -r /tmp/zap-baseline-$(date +%Y%m%d).html \
  -J /tmp/zap-baseline-$(date +%Y%m%d).json \
  --autooff

# Review results
cat /tmp/zap-baseline-$(date +%Y%m%d).json | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
sites=d.get('site',[])
for site in sites:
    alerts=site.get('alerts',[])
    high=[a for a in alerts if a['riskdesc'].startswith('High')]
    medium=[a for a in alerts if a['riskdesc'].startswith('Medium')]
    print(f'Target: {site[\"@name\"]}')
    print(f'  High:   {len(high)} findings')
    print(f'  Medium: {len(medium)} findings')
    for a in high:
        print(f'    [HIGH] {a[\"name\"]}')
"
```

### Check CI Pipeline Integration

```bash
# Is ZAP in CI pipeline?
find . -name "*.yml" -o -name "*.yaml" 2>/dev/null | \
  xargs grep -l "zaproxy\|zap-baseline\|zap-full-scan" 2>/dev/null | \
  head -5 || echo "[MISSING] ZAP not found in CI pipeline files"

# Check GitHub Actions
find .github/ -name "*.yml" 2>/dev/null | \
  xargs grep -l "zap" 2>/dev/null | head -3
```

---

## 2. Trivy — Container and FS Scanning

```bash
# Verify Trivy version
trivy --version 2>/dev/null || { echo "[MISSING] Trivy not installed"; }

# Scan current directory for vulnerabilities
trivy fs --security-checks vuln,config \
  --format json \
  --output /tmp/trivy-fs-$(date +%Y%m%d).json \
  . 2>/dev/null

# Summarize results
trivy fs --security-checks vuln,config \
  --severity HIGH,CRITICAL \
  . 2>/dev/null | tail -20

# Scan a specific Docker image
IMAGE="${TARGET_IMAGE:-nginx:latest}"
trivy image --severity HIGH,CRITICAL "$IMAGE" 2>/dev/null

# Check CI gate
find . -name "*.yml" -o -name "*.yaml" 2>/dev/null | \
  xargs grep -l "trivy" 2>/dev/null | \
  head -5 || echo "[MISSING] Trivy not in CI pipeline"

# Check for exit-code 1 on HIGH/CRITICAL (gate is enforced?)
grep -r "trivy.*--exit-code 1\|trivy.*exit-code.*1" \
  .github/ .gitlab-ci.yml Jenkinsfile 2>/dev/null | \
  head -3 || echo "[WARN] Trivy CI gate may not be enforced (no --exit-code 1 found)"
```

---

## 3. Semgrep — SAST Coverage

```bash
# Verify Semgrep
semgrep --version 2>/dev/null || { echo "[MISSING] Semgrep not installed"; }

# Run OWASP Top 10 scan
semgrep --config p/owasp-top-ten \
  --json \
  --output /tmp/semgrep-owasp-$(date +%Y%m%d).json \
  . 2>/dev/null

# Summarize by severity
python3 -c "
import json
with open('/tmp/semgrep-owasp-$(date +%Y%m%d).json') as f:
    d = json.load(f)
results = d.get('results', [])
counts = {}
for r in results:
    sev = r.get('extra',{}).get('severity','UNKNOWN')
    counts[sev] = counts.get(sev, 0) + 1
print('Semgrep findings:')
for sev,count in sorted(counts.items()):
    print(f'  {sev}: {count}')
print(f'  TOTAL: {len(results)}')
" 2>/dev/null || echo "No results file yet"

# Check for pre-commit integration
[[ -f .pre-commit-config.yaml ]] && \
  grep -q "semgrep" .pre-commit-config.yaml && \
  echo "[PRESENT] Semgrep in pre-commit" || \
  echo "[MISSING] Semgrep not in pre-commit hooks"

# Check for CI integration
find . -name "*.yml" -o -name "*.yaml" 2>/dev/null | \
  xargs grep -l "semgrep" 2>/dev/null | head -3 || \
  echo "[MISSING] Semgrep not in CI pipeline"
```

---

## 4. kube-bench — CIS Kubernetes Benchmark

```bash
# Run kube-bench (requires privileged access to host)
docker run --rm \
  --pid=host \
  -v /etc:/etc:ro \
  -v /var:/var:ro \
  aquasec/kube-bench:v0.7.1 \
  --json 2>/dev/null > /tmp/kube-bench-$(date +%Y%m%d).json

# Summarize results
python3 -c "
import json
with open('/tmp/kube-bench-$(date +%Y%m%d).json') as f:
    d = json.load(f)
tests = d.get('Tests', [])
for t in tests:
    fails = [r for r in t.get('Results',[]) if r.get('Status') == 'FAIL']
    warns = [r for r in t.get('Results',[]) if r.get('Status') == 'WARN']
    print(f\"{t['Section']} {t['Desc']}: {len(fails)} FAIL, {len(warns)} WARN\")
    for f_item in fails[:5]:
        print(f\"  [FAIL] {f_item['TestNumber']}: {f_item['TestDesc']}\")
" 2>/dev/null

# Or run as K8s Job (doesn't require docker on host)
kubectl apply -f ../03-templates/kube-bench/job.yaml 2>/dev/null
sleep 30
kubectl logs -n kube-bench -l job-name=kube-bench 2>/dev/null | \
  grep -E "^\[FAIL\]|^\[WARN\]" | head -20
```

---

## 5. Kubescape — NSA Framework Scan

```bash
# Run NSA framework scan
kubescape scan framework NSA \
  --format json \
  --output /tmp/kubescape-nsa-$(date +%Y%m%d).json 2>/dev/null

# Summary
kubescape scan framework NSA 2>/dev/null | tail -20

# Check specific critical controls
kubescape scan control C-0013 2>/dev/null  # Non-root containers
kubescape scan control C-0035 2>/dev/null  # Deny all network policy
kubescape scan control C-0036 2>/dev/null  # Cluster-admin bindings
```

---

## Coverage Matrix

After running all scans, fill in this matrix:

| Scan Type | Tool | Last Run | Findings (H/M/L) | CI Gate? | Coverage |
|---|---|---|---|---|---|
| DAST | OWASP ZAP | _________ | ___/___/___ | Yes / No | ______% |
| SAST | Semgrep | _________ | ___/___/___ | Yes / No | ______% |
| Container | Trivy | _________ | ___/___/___ | Yes / No | ______% |
| CIS K8s | kube-bench | _________ | ___/___/___ | CronJob? | ______% |
| NSA K8s | Kubescape | _________ | ___/___/___ | N/A | ______% |

---

## Run Automated Audit

```bash
./01-auditors/audit-vuln-scan-coverage.sh
```

---

## If You Find Gaps

- Missing DAST → ZAP baseline in CI: `02-fixers/` + `playbooks/02a-fix-RA5-vuln-scan.md`
- Missing SAST → Semgrep pre-commit: `02a-fix-RA5-vuln-scan.md`
- CIS failures → `02-fixers/fix-cis-failures.sh`
- No container scanning gate → `02a-fix-RA5-vuln-scan.md`
