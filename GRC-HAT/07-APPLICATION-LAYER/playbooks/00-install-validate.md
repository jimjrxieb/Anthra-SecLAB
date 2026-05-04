# 00-install-validate.md — L7 Application Layer Tool Installation

| Field | Value |
|---|---|
| **NIST Controls** | AU-2 (event logging), AU-6 (audit review), SI-4 (monitoring), RA-5 (vulnerability scanning), SA-11 (developer security testing) |
| **Tools** | Microsoft Sentinel + KQL / Splunk + SPL / Wazuh / Defender for Endpoint / OWASP ZAP / Semgrep / Trivy / kube-bench / Kubescape |
| **Enterprise Equiv** | Splunk ES ($500K+) / CrowdStrike ($300K+) / Rapid7 ($200K+) / Checkmarx ($150K+) |
| **Time** | 4 hours (all tools) / 30 minutes (individual tools) |
| **Rank** | D (scripted, no decisions required) |

---

## What You're Installing

| Tool | Purpose | Open Source | Enterprise Equiv |
|---|---|---|---|
| Microsoft Sentinel | Cloud SIEM — KQL analytics, incident management | Free tier | Splunk ES / IBM QRadar |
| Splunk (free/dev) | On-prem SIEM — SPL correlation searches | Free dev license | Splunk ES $500K+ |
| Wazuh | HIDS + FIM + active response | Yes | CrowdStrike Falcon |
| Defender for Endpoint | EDR — Windows + Linux | MS 365 license | CrowdStrike / SentinelOne |
| OWASP ZAP | DAST web application scanner | Yes | Burp Suite Pro / Rapid7 InsightAppSec |
| Semgrep | SAST code scanning | Yes (free tier) | Checkmarx / Veracode |
| Trivy | Container + FS vulnerability scanner | Yes | Prisma Cloud / Qualys |
| kube-bench | CIS Kubernetes benchmark runner | Yes | Aqua Security Platform |
| Kubescape | NSA/CISA K8s hardening scanner | Yes | Aqua/Palo Alto Prisma |

---

## 1. Microsoft Sentinel

### Create Log Analytics Workspace + Sentinel

```bash
# Prerequisite: az CLI logged in
az login

# Create resource group (skip if exists)
az group create \
  --name "${SENTINEL_RG:-jsa-seclab-rg}" \
  --location eastus

# Create Log Analytics workspace
az monitor log-analytics workspace create \
  --workspace-name "${SENTINEL_WORKSPACE:-jsa-sentinel-ws}" \
  --resource-group "${SENTINEL_RG:-jsa-seclab-rg}" \
  --location eastus \
  --retention-time 90

# Enable Sentinel on the workspace
az security insights solution create \
  --resource-group "${SENTINEL_RG:-jsa-seclab-rg}" \
  --workspace-name "${SENTINEL_WORKSPACE:-jsa-sentinel-ws}"

echo "Sentinel workspace created"
```

### Validate

```bash
az monitor log-analytics workspace show \
  --workspace-name "${SENTINEL_WORKSPACE}" \
  --resource-group "${SENTINEL_RG}" \
  --query '{state:provisioningState, retention:retentionInDays}'
```

---

## 2. Splunk (Docker — Dev/Lab)

```bash
# Pull Splunk Enterprise (dev license — 500MB/day ingest)
docker pull splunk/splunk:9.2.0

# Run Splunk
docker run -d \
  --name splunk \
  -p 8000:8000 \
  -p 8088:8088 \
  -p 8089:8089 \
  -p 514:514/udp \
  -e SPLUNK_START_ARGS='--accept-license' \
  -e SPLUNK_PASSWORD='SecLab2024!' \
  -v splunk-data:/opt/splunk/var \
  splunk/splunk:9.2.0

# Wait for startup (60-90 seconds)
sleep 90

# Validate
curl -sk https://localhost:8089/services/server/info \
  -u admin:SecLab2024! \
  --output-mode json | python3 -m json.tool | grep serverName
```

Access Splunk: http://localhost:8000 (admin / SecLab2024!)

### Deploy Templates

```bash
# Copy inputs.conf and savedsearches.conf to Splunk
docker cp 03-templates/splunk/inputs.conf splunk:/opt/splunk/etc/apps/search/local/
docker cp 03-templates/splunk/savedsearches.conf splunk:/opt/splunk/etc/apps/search/local/
docker exec splunk /opt/splunk/bin/splunk reload saved-searches -auth admin:SecLab2024!
```

---

## 3. Wazuh (Docker Compose — All-in-One)

```bash
# Download Wazuh Docker deployment
curl -sO https://packages.wazuh.com/4.7/docker/docker-compose.yml

# Generate credentials
echo "admin" > /tmp/wazuh-pass.txt

# Start Wazuh (manager + dashboard + indexer)
docker-compose up -d

# Wait for startup (2-3 minutes)
sleep 120

# Validate
curl -sk -u admin:admin \
  https://localhost/api/security/user/authenticate \
  -X GET
```

Access Wazuh dashboard: https://localhost (admin / admin)

### Deploy Custom Config

```bash
docker cp 03-templates/wazuh/ossec.conf wazuh.manager:/var/ossec/etc/ossec.conf
docker cp 03-templates/wazuh/local_rules.xml wazuh.manager:/var/ossec/etc/rules/local_rules.xml
docker exec wazuh.manager /var/ossec/bin/wazuh-control restart
```

---

## 4. Microsoft Defender for Endpoint (Linux)

```bash
# Add Microsoft repository
curl -sSL https://packages.microsoft.com/keys/microsoft.asc | \
  gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/microsoft.gpg > /dev/null

# Ubuntu/Debian
echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/22.04/prod jammy main" | \
  sudo tee /etc/apt/sources.list.d/microsoft-prod.list

sudo apt-get update
sudo apt-get install -y mdatp

# Onboard to tenant (requires onboarding package from MDE portal)
# Portal: security.microsoft.com > Settings > Endpoints > Onboarding
# Download: MicrosoftDefenderATPOnboardingLinux.zip
sudo python3 MicrosoftDefenderATPOnboardingLinux.py

# Validate
mdatp health | grep -E "healthy|real_time_protection|device_id"
```

---

## 5. OWASP ZAP

```bash
# Docker (recommended — clean environment per scan)
docker pull ghcr.io/zaproxy/zaproxy:stable

# Validate
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap.sh -version

# Quick baseline scan
docker run --rm ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://target-app:8080 \
  -r /tmp/zap-baseline-report.html

# Full scan (AJAX spider)
docker run --rm ghcr.io/zaproxy/zaproxy:stable \
  zap-full-scan.py -t http://target-app:8080 \
  -r /tmp/zap-full-report.html
```

---

## 6. Semgrep

```bash
# Install via pip
pip install semgrep

# Validate
semgrep --version

# Run OWASP Top 10 scan on current directory
semgrep --config p/owasp-top-ten .

# Run all security packs
semgrep --config p/security-audit .

# Install pre-commit hook
pip install pre-commit
cat >> .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: 'v1.45.0'
    hooks:
      - id: semgrep
        args: ['--config', 'p/security-audit', '--error']
EOF
pre-commit install
```

---

## 7. Trivy

```bash
# Install
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | \
  sh -s -- -b /usr/local/bin v0.50.4

# Validate
trivy --version

# Scan Docker image
trivy image nginx:1.25.3

# Scan filesystem
trivy fs --security-checks vuln,config .

# Scan Kubernetes cluster
trivy k8s --report summary cluster
```

---

## 8. kube-bench

```bash
# Run via Docker (no install required)
docker pull aquasec/kube-bench:v0.7.1

# Run benchmark
docker run --rm \
  --pid=host \
  -v /etc:/etc:ro \
  -v /var:/var:ro \
  -v /usr/bin/kubectl:/usr/bin/kubectl:ro \
  aquasec/kube-bench:v0.7.1 \
  --json > /tmp/kube-bench-$(date +%Y%m%d).json

# Or run as a Kubernetes Job
kubectl apply -f 03-templates/kube-bench/job.yaml
kubectl logs -n kube-bench -l job-name=kube-bench | jq '.'
```

---

## 9. Kubescape

```bash
# Install
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash

# Validate
kubescape version

# Run NSA framework scan
kubescape scan framework NSA --format json --output /tmp/kubescape-nsa-$(date +%Y%m%d).json

# Run all frameworks
kubescape scan --format json --output /tmp/kubescape-all-$(date +%Y%m%d).json
```

---

## Validation: All Tools

```bash
# Run this after installing all tools
echo "=== L7 Tool Validation ==="
command -v az &>/dev/null && echo "[OK] az CLI" || echo "[MISSING] az CLI"
docker ps | grep -q splunk && echo "[OK] Splunk running" || echo "[MISSING] Splunk container"
docker ps | grep -q wazuh && echo "[OK] Wazuh running" || echo "[MISSING] Wazuh container"
command -v mdatp &>/dev/null && mdatp health | grep -q "true" && echo "[OK] MDE" || echo "[CHECK] MDE"
docker images | grep -q zaproxy && echo "[OK] ZAP image" || echo "[MISSING] ZAP image"
command -v semgrep &>/dev/null && echo "[OK] Semgrep" || echo "[MISSING] Semgrep"
command -v trivy &>/dev/null && echo "[OK] Trivy" || echo "[MISSING] Trivy"
docker images | grep -q kube-bench && echo "[OK] kube-bench image" || echo "[MISSING] kube-bench image"
command -v kubescape &>/dev/null && echo "[OK] Kubescape" || echo "[MISSING] Kubescape"
```

---

## Next Step

Once all tools are installed and validated:

```bash
./tools/run-all-audits.sh
```

Then proceed to `01-assess.md` to baseline the environment.
