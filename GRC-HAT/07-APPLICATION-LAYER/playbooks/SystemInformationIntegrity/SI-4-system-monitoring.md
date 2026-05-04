# SI-4: System Monitoring
**Family:** System and Information Integrity  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
The organization monitors the information system to detect attacks and indicators of potential attacks in accordance with monitoring objectives, and identifies unauthorized use of the information system through the use of automated tools and manual review.

## Why It Matters at L7
Application-layer attacks — SQL injection, broken authentication, privilege escalation through API abuse — generate signals in logs, but only if those logs are collected, normalized, and searched. A SIEM with coverage gaps is more dangerous than no SIEM, because it creates false confidence that attacks would be caught. Knowing what is monitored, and what is not, is the first step to closing detection gaps.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- What SIEM platform is deployed (Microsoft Sentinel, Splunk, Elastic, Sumo Logic), and which data connectors are actively forwarding logs to it?
- Is there a monitoring coverage map documenting what systems and log sources are connected to the SIEM versus what exists in the environment? What percentage of assets are covered?
- Are EDR alerts (Defender for Endpoint, Wazuh) forwarded to the SIEM, and are alert correlation rules in place to detect patterns across multiple sources?
- Are Kubernetes and container runtime events (Falco, audit logs) ingested by the SIEM, and are detection rules tuned for container escape, privileged container launch, and lateral movement?
- What is the defined alert triage SLA — how long between a SIEM alert firing and a SOC analyst beginning investigation?
- Are there documented detection use cases covering unauthorized access, privilege escalation, data exfiltration, and lateral movement at the application layer?
- When was the last gap analysis conducted on monitoring coverage, and were results tracked to closure?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| SIEM data connector inventory (source, status, last event time) | Sentinel / Splunk admin console | PDF, CSV, dashboard screenshot |
| Monitoring coverage map (assets monitored vs. total asset inventory) | CMDB, SIEM asset inventory | PDF, spreadsheet |
| Alert rule / detection inventory with coverage categories | SIEM rule catalog | CSV export, PDF |
| SOC alert triage SLA documentation | SOC runbook, policy document | PDF, Confluence page |
| Sample alert records from the past 30 days (anonymized) | SIEM alert log | PDF, CSV |
| Falco DaemonSet deployment and rule count | Kubernetes cluster | kubectl output, PDF |

### Gap Documentation Template
**Control:** SI-4  
**Finding:** Kubernetes API server audit logs and Falco runtime alerts are not forwarded to the SIEM, leaving container-layer threats undetected by the SOC.  
**Risk:** Container escapes, privileged pod launches, and API server abuse are invisible to analysts. Attackers who compromise the container layer can pivot to the host or cluster without triggering any monitored detection rule.  
**Recommendation:** Configure Falco to forward alerts to Sentinel/Splunk via syslog or webhook. Enable Kubernetes audit log connector in the SIEM. Create detection rules for container escape and privileged container events.  
**Owner:** Security Operations / Platform Engineering  

### CISO Communication
> Our security monitoring program has coverage gaps at the container and Kubernetes layers. Application servers and endpoints forward logs to our SIEM, but container runtime events — which is where modern application-layer attacks unfold — are not currently ingested. This means the SOC would not see a container escape or a compromised workload moving laterally across pods. Closing this gap requires a one-time connector configuration and a small set of detection rules, after which our monitoring posture covers the full application stack.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, cloud CLI, SIEM, scanning tools, direct remediation.

### Assessment Commands
```bash
# --- SIEM Connector Health (Microsoft Sentinel via CLI) ---
# List data connectors and their status
az sentinel data-connector list \
  --resource-group <RG> \
  --workspace-name <WORKSPACE> \
  --output table 2>/dev/null || echo "az CLI not configured or Sentinel not available"

# --- Splunk connector health ---
# Check Splunk Universal Forwarder status
systemctl is-active SplunkForwarder 2>/dev/null && \
  echo "[PASS] Splunk forwarder active" || echo "[FAIL] Splunk forwarder not active"
/opt/splunkforwarder/bin/splunk list monitor 2>/dev/null | head -20

# --- Wazuh SIEM forwarding ---
# Check if Wazuh is configured to forward to SIEM (syslog or webhook)
grep -A10 "<syslog_output>" /var/ossec/etc/ossec.conf 2>/dev/null | head -15
grep -A10 "<integration>" /var/ossec/etc/ossec.conf 2>/dev/null | head -20

# --- Falco health ---
kubectl get daemonset -n falco falco \
  -o jsonpath='{.status.numberReady}/{.status.desiredNumberScheduled}' 2>/dev/null | \
  awk -F/ '{
    if ($1==$2) print "[PASS] Falco: "$1"/"$2" nodes covered"
    else print "[FAIL] Falco: "$1"/"$2" nodes covered — gap in runtime detection"
  }'

# Count Falco rules deployed
kubectl exec -n falco ds/falco -- \
  sh -c 'find /etc/falco -name "*.yaml" | xargs grep -c "^- rule:" 2>/dev/null | awk -F: "{s+=\$2}END{print \"Total Falco rules: \"s}"' \
  2>/dev/null || echo "Falco exec not available"

# --- Kubernetes audit log status ---
# Check if audit policy is configured (control plane)
kubectl get cm -n kube-system kube-apiserver-config 2>/dev/null | head -5
# On kubeadm clusters:
[[ -f /etc/kubernetes/audit-policy.yaml ]] && \
  echo "[PASS] K8s audit policy exists" || \
  echo "[FAIL] No audit policy at /etc/kubernetes/audit-policy.yaml"

# Check if audit logs are being written
ls -lh /var/log/kubernetes/audit/ 2>/dev/null || \
  echo "[WARN] Audit log path not found — may be at different path or not enabled"

# --- MDE alert forwarding check ---
mdatp health --field edr_device_tags 2>/dev/null
mdatp health --field cloud_enabled 2>/dev/null | grep -q "true" && \
  echo "[PASS] MDE cloud connectivity enabled" || \
  echo "[FAIL] MDE cloud reporting disabled"
```

### Detection / Testing
```bash
# KQL — Microsoft Sentinel: check data connector freshness
# Run in Sentinel Log Analytics workspace:
cat << 'KQL'
// Check last event time per data connector table
union withsource=TableName *
| summarize LastEvent = max(TimeGenerated), EventCount = count() by TableName
| where LastEvent < ago(24h)
| order by LastEvent asc
KQL

# KQL — detect privileged container launch
cat << 'KQL'
// Falco: privileged container events in Sentinel
AzureDiagnostics
| where Category == "kube-audit"
| where log_s has "privileged"
| project TimeGenerated, log_s
| limit 50
KQL

# SPL — Splunk: detect Wazuh high-severity alerts
cat << 'SPL'
index=wazuh rule.level>=12
| stats count by agent.name, rule.description, _time
| sort -count
| head 20
SPL

# SPL — Splunk: Falco runtime alerts
cat << 'SPL'
index=falco priority=CRITICAL OR priority=ERROR
| table _time, hostname, rule, output
| sort -_time
| head 20
SPL

# Test Falco detection rule fires (safe test in non-prod)
# Spawn shell in container — triggers "Terminal shell in container" rule
kubectl run falco-test --image=ubuntu:22.04 --restart=Never \
  --command -- sleep 60 -n test 2>/dev/null
kubectl exec -n test falco-test -- /bin/sh -c "id" 2>/dev/null
# Verify alert in Falco logs:
kubectl logs -n falco ds/falco --tail=20 2>/dev/null | grep "Terminal shell"
# Cleanup
kubectl delete pod falco-test -n test 2>/dev/null
```

### Remediation
```bash
# Configure Wazuh to forward alerts to Splunk via syslog
cat >> /var/ossec/etc/ossec.conf << 'EOF'
<syslog_output>
  <server>splunk-hec.internal</server>
  <port>514</port>
  <format>default</format>
  <level>7</level>
</syslog_output>
EOF
systemctl restart wazuh-manager

# Configure Falco to forward alerts to SIEM via falcosidekick
helm upgrade --install falcosidekick falcosecurity/falcosidekick \
  --namespace falco \
  --set config.splunk.hostport="https://splunk-hec.internal:8088" \
  --set config.splunk.token="<HEC_TOKEN>" \
  --set config.splunk.checkcert=true

# Enable Kubernetes audit logging (kubeadm) — edit /etc/kubernetes/manifests/kube-apiserver.yaml
# Add these flags to the kube-apiserver command:
# --audit-policy-file=/etc/kubernetes/audit-policy.yaml
# --audit-log-path=/var/log/kubernetes/audit/audit.log
# --audit-log-maxage=30
# --audit-log-maxbackup=10
# --audit-log-maxsize=100

# Sample minimal audit policy
cat > /etc/kubernetes/audit-policy.yaml << 'EOF'
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets", "configmaps"]
  - level: Metadata
    resources:
      - group: ""
        resources: ["pods", "services"]
  - level: None
    users: ["system:kube-scheduler", "system:kube-controller-manager"]
EOF
```

### Validation
```bash
# Verify Falco is generating alerts (check log for recent events)
kubectl logs -n falco ds/falco --tail=50 2>/dev/null | grep -E "Notice|Warning|Critical|Error" | \
  wc -l | xargs -I{} echo "Recent Falco events: {}"
# Expected: count > 0 (some activity expected in any active cluster)

# Verify Wazuh syslog output is configured
grep -q "<syslog_output>" /var/ossec/etc/ossec.conf 2>/dev/null && \
  echo "[PASS] Wazuh syslog forwarding configured" || \
  echo "[FAIL] No syslog_output configured in ossec.conf"

# Verify audit log file is being written
[[ -f /var/log/kubernetes/audit/audit.log ]] && \
  [[ -s /var/log/kubernetes/audit/audit.log ]] && \
  echo "[PASS] K8s audit log is being written" || \
  echo "[FAIL] K8s audit log missing or empty"
# Expected: PASS

# Verify Splunk forwarder is monitoring key paths
/opt/splunkforwarder/bin/splunk list monitor 2>/dev/null | \
  grep -E "/var/ossec/logs|/var/log/falco|audit.log" | \
  wc -l | xargs -I{} echo "Critical log paths monitored by Splunk forwarder: {}"
# Expected: 3+
```

### Evidence Capture
```bash
EVIDENCE_DIR="/tmp/jsa-evidence/SI-4/$(date +%Y%m%d)"
mkdir -p "$EVIDENCE_DIR"

# Falco DaemonSet status
kubectl get daemonset -n falco -o json > "$EVIDENCE_DIR/falco-daemonset.json" 2>/dev/null || \
  echo "Falco not deployed" > "$EVIDENCE_DIR/falco-status.txt"

# Falco recent alerts (last 100 lines)
kubectl logs -n falco ds/falco --tail=100 > "$EVIDENCE_DIR/falco-recent-alerts.txt" 2>/dev/null || true

# Wazuh ossec.conf (syslog/integration section)
grep -A20 "<syslog_output>\|<integration>" /var/ossec/etc/ossec.conf \
  > "$EVIDENCE_DIR/wazuh-forwarding-config.txt" 2>/dev/null || \
  echo "Wazuh not available" > "$EVIDENCE_DIR/wazuh-forwarding-config.txt"

# K8s audit policy
cp /etc/kubernetes/audit-policy.yaml "$EVIDENCE_DIR/k8s-audit-policy.yaml" 2>/dev/null || \
  echo "No audit policy found" > "$EVIDENCE_DIR/k8s-audit-policy.txt"

# Audit log last 20 lines (size check)
tail -20 /var/log/kubernetes/audit/audit.log \
  > "$EVIDENCE_DIR/k8s-audit-sample.json" 2>/dev/null || \
  echo "Audit log not found" > "$EVIDENCE_DIR/k8s-audit-sample.txt"

# Splunk forwarder monitor list
/opt/splunkforwarder/bin/splunk list monitor \
  > "$EVIDENCE_DIR/splunk-monitored-paths.txt" 2>/dev/null || \
  echo "Splunk forwarder not installed" > "$EVIDENCE_DIR/splunk-monitored-paths.txt"

# Summary
cat > "$EVIDENCE_DIR/SI-4-summary.txt" << EOF
SI-4 System Monitoring Evidence
Date: $(date)
Auditor: $(whoami)
Host: $(hostname)

Files captured:
$(ls -1 "$EVIDENCE_DIR")
EOF

echo "[DONE] Evidence written to $EVIDENCE_DIR"
```
