# SI-3: Malicious Code Protection
**Family:** System and Information Integrity  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
The organization implements malicious code protection mechanisms at information system entry and exit points to detect and eradicate malicious code, updating malicious code protection mechanisms whenever new releases are available, and configuring the mechanisms to perform periodic scans of the information system and real-time scans of files from external sources.

## Why It Matters at L7
At the application layer, malicious code enters through dependency supply chains, container image pulls, web uploads, and CI/CD pipeline artifacts — not just email attachments. EDR agents (Defender for Endpoint, Wazuh), WAF inspection, and container image scanning form overlapping layers that catch threats at different points in the delivery chain. A gap in any layer means attacker code can execute before a human analyst sees an alert.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Is Microsoft Defender for Endpoint (MDE) or an equivalent EDR deployed on all application servers, container hosts, and endpoints? What is the coverage percentage and how is it tracked?
- What is the process for maintaining current antivirus/EDR definition updates? What is the maximum acceptable definition age before a host is considered non-compliant?
- Is a WAF deployed in front of customer-facing applications, and is it operating in prevention mode (block) rather than detection mode (count)?
- Are container images scanned for malware and known malicious binaries before being promoted to production, and is this enforced as a CI gate?
- Is Wazuh or another HIDS deployed, and are active response rules configured to block or quarantine malicious activity automatically?
- How does the organization handle false positives from malware detection — is there a documented review and exception process?
- Are Falco runtime rules deployed to detect anomalous container behavior such as unexpected shell execution, network connections from containers, or suspicious process spawning?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| EDR deployment coverage report (hosts enrolled vs. total) | MDE portal, Wazuh dashboard, SIEM | PDF, CSV export, dashboard screenshot |
| Defender/Wazuh definition update policy and current definition age | EDR management console | Screenshot, JSON health export |
| WAF policy document showing rule groups and operating mode | AWS WAF console, Cloudflare, Azure WAF | PDF, console screenshot |
| CI/CD pipeline configuration showing malware scan gate | GitHub Actions, Jenkins, GitLab CI | YAML config, pipeline run log |
| Falco DaemonSet health and rule inventory | Kubernetes cluster | kubectl output, PDF |
| Most recent malware detection event log (anonymized) | SIEM, EDR console | PDF, CSV |

### Gap Documentation Template
**Control:** SI-3  
**Finding:** Microsoft Defender for Endpoint is installed on 70% of production hosts; 30% of application servers have no EDR agent, and Wazuh active response is disabled.  
**Risk:** Hosts without EDR coverage provide an undetected execution environment for malware. Disabled active response means detected threats require manual containment, increasing dwell time.  
**Recommendation:** Achieve 100% EDR enrollment on all production hosts within 30 days. Enable Wazuh active response with firewall-drop for confirmed malware rule triggers. Document residual exceptions with compensating controls.  
**Owner:** Security Operations / Platform Engineering  

### CISO Communication
> Our malicious code protection coverage has gaps — a subset of production servers lacks endpoint detection agents, and our web application firewall is operating in detection-only mode rather than blocking mode. This means attacks that would be blocked or alerted on other platforms may execute undetected on uncovered hosts and reach application backends through the WAF. Closing these gaps requires deploying EDR agents to all remaining hosts and switching the WAF to prevention mode for validated rule groups, both of which can be completed within the next sprint cycle.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, cloud CLI, SIEM, scanning tools, direct remediation.

### Assessment Commands
```bash
# --- Microsoft Defender for Endpoint (Linux) ---

# Full health check
mdatp health 2>/dev/null

# Key health fields
mdatp health --field real_time_protection_enabled
mdatp health --field definitions_updated
mdatp health --field definitions_version
mdatp health --field device_id
mdatp health --field org_id

# Service status
systemctl is-active mdatp && echo "[PASS] MDE service active" || echo "[FAIL] MDE service not active"
pgrep -x wdavdaemon && echo "[PASS] wdavdaemon running" || echo "[WARN] wdavdaemon process not found"

# Definition freshness check (flag if > 7 days)
DEF_DATE=$(mdatp health --field definitions_updated 2>/dev/null | tr -d '"')
if [[ -n "$DEF_DATE" ]]; then
  DEF_EPOCH=$(date -d "$DEF_DATE" +%s 2>/dev/null || echo "0")
  NOW_EPOCH=$(date +%s)
  DEF_AGE_DAYS=$(( (NOW_EPOCH - DEF_EPOCH) / 86400 ))
  [[ $DEF_AGE_DAYS -le 7 ]] && \
    echo "[PASS] Definitions current (${DEF_AGE_DAYS}d old)" || \
    echo "[FAIL] Definitions stale (${DEF_AGE_DAYS}d old) — update required"
fi

# --- Wazuh (HIDS) ---
WAZUH_SVC="wazuh-manager"
systemctl is-active wazuh-manager &>/dev/null || WAZUH_SVC="wazuh-agent"
systemctl status "$WAZUH_SVC" --no-pager -l | head -20

# Agent enrollment (on manager)
[[ -f /var/ossec/etc/client.keys ]] && {
  echo "Enrolled agents: $(wc -l < /var/ossec/etc/client.keys)"
  awk '{print $2, $3}' /var/ossec/etc/client.keys
} || echo "[WARN] No client.keys found"

# Active response check
[[ -x /var/ossec/active-response/bin/firewall-drop ]] && \
  echo "[PRESENT] firewall-drop active response" || \
  echo "[MISSING] firewall-drop not found"
grep -A5 "<active-response>" /var/ossec/etc/ossec.conf 2>/dev/null | head -20

# --- Falco (runtime detection) ---
kubectl get daemonset -n falco falco -o jsonpath='{.status.numberReady}/{.status.desiredNumberScheduled}' 2>/dev/null | \
  awk -F/ '{if ($1==$2) print "[PASS] Falco: "$1"/"$2" nodes covered"; else print "[FAIL] Falco: "$1"/"$2" nodes covered"}'

# Count Falco rules
kubectl exec -n falco ds/falco -- falco --list 2>/dev/null | grep -c "rule:" || \
  find /etc/falco -name "*.yaml" -exec grep -c "^- rule:" {} + 2>/dev/null | awk '{s+=$1}END{print "Falco rules:",s}'
```

### Detection / Testing
```bash
# Trigger a test detection via MDE (Linux)
# mdatp threat test — creates EICAR-like test file
mdatp threat test 2>/dev/null && \
  echo "Check MDE portal for test detection alert" || \
  echo "mdatp test not available or MDE not installed"

# EICAR test file detection check (standard AV test)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar-test.txt
sleep 5
[[ -f /tmp/eicar-test.txt ]] && \
  echo "[FAIL] EICAR test file not removed — real-time protection may be off" || \
  echo "[PASS] EICAR test file detected and removed"

# Test Falco detection — spawn a shell in a container (known Falco rule trigger)
# Run this in a non-production test pod only
# kubectl exec -n test <pod> -- /bin/bash -c "id" 2>/dev/null

# Check WAF mode (AWS WAF)
aws wafv2 list-web-acls --scope REGIONAL --output json 2>/dev/null | \
  python3 -c "
import sys, json
acls = json.load(sys.stdin)
for acl in acls.get('WebACLs', []):
    print(f\"WAF ACL: {acl['Name']} — {acl['ARN']}\")
"

# Check individual WAF rule group default actions
aws wafv2 get-web-acl \
  --name <ACL_NAME> \
  --scope REGIONAL \
  --id <ACL_ID> \
  --output json 2>/dev/null | \
  python3 -c "
import sys, json
acl = json.load(sys.stdin)
for rule in acl.get('WebACL', {}).get('Rules', []):
    name = rule.get('Name')
    action = rule.get('Action', rule.get('OverrideAction', {}))
    print(f'Rule: {name}  Action: {action}')
"

# Container image malware scan with Trivy
trivy image --scanners vuln,secret,misconfig nginx:latest 2>/dev/null | tail -20
```

### Remediation
```bash
# Update MDE definitions
mdatp definitions update 2>/dev/null && \
  echo "Definitions updated" || echo "Update failed — check MDE service"

# Enable Wazuh active response (edit ossec.conf)
# Add to /var/ossec/etc/ossec.conf inside <ossec_config>:
cat >> /var/ossec/etc/ossec.conf << 'EOF'
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5712,100100</rules_id>
  <timeout>600</timeout>
</active-response>
EOF
systemctl restart wazuh-manager 2>/dev/null || systemctl restart wazuh-agent

# Switch AWS WAF rule group from COUNT to BLOCK
# NOTE: Get ACL_ID and LOCK_TOKEN from describe, not from list-web-acls
ACL_ID=$(aws wafv2 list-web-acls --scope REGIONAL --query "WebACLs[?Name=='<ACL_NAME>'].Id" --output text)
LOCK_TOKEN=$(aws wafv2 get-web-acl --name <ACL_NAME> --scope REGIONAL --id "$ACL_ID" \
  --query 'LockToken' --output text)
# Update rule action — change OverrideAction from Count to None (uses rule group default=Block)
# This must be done via update-web-acl with full rule set JSON — use console or IaC for safety

# Install Falco via Helm
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set falco.grpc.enabled=true \
  --set falco.grpcOutput.enabled=true

# CI/CD: add Trivy scan gate to GitHub Actions
# .github/workflows/security-scan.yml
cat > /tmp/trivy-gate.yml << 'EOF'
name: Container Security Scan
on: [push, pull_request]
jobs:
  trivy-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@0.16.1
        with:
          image-ref: "${{ env.IMAGE_NAME }}"
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH
          exit-code: 1
EOF
```

### Validation
```bash
# Verify MDE real-time protection is on
mdatp health --field real_time_protection_enabled 2>/dev/null | grep -q "true" && \
  echo "[PASS] MDE real-time protection enabled" || \
  echo "[FAIL] MDE real-time protection disabled"

# Verify Wazuh agents connected (on manager)
/var/ossec/bin/agent_control -l 2>/dev/null | grep -c "Active" | \
  xargs -I{} echo "Active Wazuh agents: {}"
# Expected: count > 0, all enrolled agents show Active

# Verify Falco is running on all nodes
kubectl get pods -n falco -l app.kubernetes.io/name=falco 2>/dev/null
# Expected: one pod per node, all in Running state

# Verify active response is configured
grep -q "<active-response>" /var/ossec/etc/ossec.conf 2>/dev/null && \
  echo "[PASS] Active response configured" || \
  echo "[FAIL] No active response configuration found"
# Expected: PASS
```

### Evidence Capture
```bash
EVIDENCE_DIR="/tmp/jsa-evidence/SI-3/$(date +%Y%m%d)"
mkdir -p "$EVIDENCE_DIR"

# MDE health (Linux)
mdatp health > "$EVIDENCE_DIR/mde-health.txt" 2>/dev/null || \
  echo "MDE not installed" > "$EVIDENCE_DIR/mde-health.txt"

# Wazuh agent inventory
/var/ossec/bin/agent_control -l > "$EVIDENCE_DIR/wazuh-agents.txt" 2>/dev/null || \
  echo "Wazuh not available" > "$EVIDENCE_DIR/wazuh-agents.txt"

# Wazuh rule count
RULE_FILES=$(find /var/ossec/ruleset/rules/ -name "*.xml" 2>/dev/null | wc -l)
TOTAL_RULES=$(grep -rh "<rule " /var/ossec/ruleset/rules/ 2>/dev/null | wc -l)
echo "Rule files: $RULE_FILES  Total rules: $TOTAL_RULES" > "$EVIDENCE_DIR/wazuh-rules.txt"

# Falco DaemonSet status
kubectl get daemonset -n falco -o json > "$EVIDENCE_DIR/falco-daemonset.json" 2>/dev/null || \
  echo "Falco not deployed" > "$EVIDENCE_DIR/falco-status.txt"

# WAF ACL inventory
aws wafv2 list-web-acls --scope REGIONAL --output json > "$EVIDENCE_DIR/waf-acls.json" 2>/dev/null || \
  echo "AWS WAF not accessible" > "$EVIDENCE_DIR/waf-acls.txt"

# Summary
cat > "$EVIDENCE_DIR/SI-3-summary.txt" << EOF
SI-3 Malicious Code Protection Evidence
Date: $(date)
Auditor: $(whoami)
Host: $(hostname)

Files captured:
$(ls -1 "$EVIDENCE_DIR")
EOF

echo "[DONE] Evidence written to $EVIDENCE_DIR"
```
