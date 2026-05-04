# SI-7: Software, Firmware, and Information Integrity
**Family:** System and Information Integrity  
**NIST 800-53 Rev 5**  
**Layer:** Application (L7)

## Control Statement
The organization employs integrity verification tools to detect unauthorized changes to software, firmware, and information, and takes defined corrective actions when integrity violations are discovered.

## Why It Matters at L7
Application-layer persistence commonly involves modifying system files, replacing binaries, or injecting malicious code into containers after initial access. Without FIM and image signing, an attacker can silently replace `/usr/bin/sudo` or deploy a backdoored image and remain undetected indefinitely. Integrity verification closes the gap between when a compromise occurs and when it is discovered — the gap that determines whether an incident becomes a breach.

---

## GRC Analyst Perspective
> **No code access.** Tools: interviews, documentation review, SIEM dashboards, audit reports, evidence packages.

### Audit Questions
- Is File Integrity Monitoring (FIM) deployed and actively monitoring critical system paths including `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, and system binary directories?
- Are FIM alerts forwarded to the SIEM, and are there detection rules that alert on unauthorized changes to monitored paths?
- Is there a documented FIM policy defining which paths are monitored, what constitutes an authorized change, and what the response procedure is for an unauthorized change alert?
- Are container images signed using a supply chain integrity tool (Sigstore/cosign, Notary), and is image signature verification enforced at admission time in the Kubernetes cluster?
- Is there a process for periodically verifying the integrity of deployed container images against their registered digests in the image registry?
- How are authorized changes to monitored files distinguished from unauthorized changes — is there an approved change management ticket correlated to FIM alerts?
- Is AIDE or an equivalent integrity database used as a secondary check, and is the database stored in a location where an attacker cannot tamper with it?

### Evidence to Request
| Evidence Item | Source | Acceptable Format |
|---|---|---|
| FIM policy document listing monitored paths and response procedures | Security policy repository | PDF, Confluence page |
| Wazuh/AIDE FIM configuration showing monitored paths and realtime settings | Wazuh console, /var/ossec/etc/ossec.conf | Configuration export, PDF |
| FIM alert history for the past 30 days (authorized vs. unauthorized) | SIEM, Wazuh alerts | PDF, CSV export |
| Image signing policy and cosign verification configuration | Repository, Kyverno policy | YAML, PDF |
| Kyverno or admission webhook policy requiring signed images | Kubernetes cluster | kubectl output, YAML |
| AIDE database last initialization date and most recent check results | System (aide --check output) | Text file, PDF |

### Gap Documentation Template
**Control:** SI-7  
**Finding:** Wazuh FIM is configured but monitoring only 2 paths; critical paths `/etc/sudoers` and `/etc/ssh/sshd_config` are not monitored. Container images are not signed and no admission control enforces signature verification.  
**Risk:** Privilege escalation via sudoers modification and SSH backdoors via sshd_config changes go undetected. Unsigned images can be substituted by an attacker with registry write access without triggering any control.  
**Recommendation:** Expand FIM to cover all 7 critical paths with realtime monitoring for credential/auth files. Implement cosign signing in CI/CD and enforce verification with a Kyverno ClusterPolicy requiring image signatures.  
**Owner:** Platform Engineering / Security Operations  

### CISO Communication
> Our file integrity monitoring covers some system paths but currently has gaps in the most sensitive areas — specifically the files that control who has administrative access and how remote access works. Additionally, none of our container images are cryptographically signed, which means a compromised registry or build pipeline could push a malicious image without triggering any control. Closing these gaps requires a configuration update to our existing monitoring tool and a one-time image signing implementation in our CI/CD pipeline — neither of which requires new tooling or budget.

---

## Cybersecurity Engineer Perspective
> **Code access available.** Tools: kubectl, cloud CLI, SIEM, scanning tools, direct remediation.

### Assessment Commands
```bash
# --- Wazuh FIM Assessment ---

# Verify syscheck is enabled
grep -A5 "<syscheck>" /var/ossec/etc/ossec.conf 2>/dev/null | head -10

# List all monitored paths
grep "<directories" /var/ossec/etc/ossec.conf 2>/dev/null

# Count monitored paths
FIM_PATHS=$(grep -c "<directories" /var/ossec/etc/ossec.conf 2>/dev/null || echo "0")
echo "FIM paths configured: $FIM_PATHS (minimum: 5 required)"

# Check critical paths coverage
for CRITICAL_PATH in "/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/ssh/sshd_config" "/etc/crontab"; do
  grep -q "$CRITICAL_PATH" /var/ossec/etc/ossec.conf 2>/dev/null && \
    echo "[PRESENT] FIM: $CRITICAL_PATH" || \
    echo "[MISSING] FIM not covering: $CRITICAL_PATH"
done

# Check realtime monitoring count
REALTIME=$(grep -c 'realtime="yes"' /var/ossec/etc/ossec.conf 2>/dev/null || echo "0")
echo "Realtime FIM entries: $REALTIME (critical auth files should be realtime)"

# --- AIDE Assessment ---
[[ -f /var/lib/aide/aide.db ]] && \
  echo "[PASS] AIDE database exists: $(stat -c '%y' /var/lib/aide/aide.db 2>/dev/null)" || \
  echo "[MISSING] AIDE database not initialized"

aide --check 2>/dev/null | tail -10 || echo "AIDE not installed or database not found"

# --- Container Image Signing Assessment ---

# Check if cosign is available
command -v cosign &>/dev/null && \
  echo "[PASS] cosign $(cosign version 2>/dev/null | head -1)" || \
  echo "[MISSING] cosign not installed"

# Check Kyverno policy for image signature verification
kubectl get clusterpolicy -A 2>/dev/null | grep -iE "sign|verify|image" || \
  echo "[MISSING] No Kyverno image signing policy found"

# Check for Connaisseur admission webhook
kubectl get deployment -n connaisseur 2>/dev/null && \
  echo "[PRESENT] Connaisseur image verification webhook" || \
  echo "[NOT FOUND] Connaisseur not deployed"

# Verify a specific image signature
# cosign verify --certificate-identity=<identity> --certificate-oidc-issuer=<issuer> <image>
```

### Detection / Testing
```bash
# Trigger a test FIM alert — create file in monitored path
TEST_FILE="/etc/test-fim-$(date +%s).txt"
touch "$TEST_FILE"
sleep 10
# Check for FIM alert
tail -50 /var/ossec/logs/alerts/alerts.json 2>/dev/null | \
  python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        if 'syscheck' in d:
            path = d.get('syscheck', {}).get('path', '')
            if 'test-fim' in path:
                print(f'[DETECTED] FIM alert: {path}')
    except:
        pass
" | head -5
# Cleanup
rm -f "$TEST_FILE"

# Verify an unsigned image fails admission (requires Kyverno policy)
kubectl run unsigned-test \
  --image=nginx:latest \
  --restart=Never \
  -n default 2>&1 | grep -E "denied|Error|failed" && \
  echo "[PASS] Unsigned image blocked by admission control" || \
  echo "[FAIL] Unsigned image not blocked — no image signing enforcement"

# Check recent FIM alerts in Wazuh logs
tail -100 /var/ossec/logs/alerts/alerts.json 2>/dev/null | \
  python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        if 'syscheck' in d:
            agent = d.get('agent', {}).get('name', 'unknown')
            path  = d.get('syscheck', {}).get('path', 'unknown')
            event = d.get('syscheck', {}).get('event', 'changed')
            print(f'FIM [{event}] agent:{agent} path:{path}')
    except:
        pass
" | head -20
```

### Remediation
```bash
# --- Fix Wazuh FIM paths ---
# Add missing critical paths to ossec.conf syscheck section
# Edit /var/ossec/etc/ossec.conf — add inside <syscheck>:
python3 - << 'PYEOF'
import re

conf_path = "/var/ossec/etc/ossec.conf"
try:
    with open(conf_path, "r") as f:
        content = f.read()
except FileNotFoundError:
    print("ossec.conf not found — Wazuh not installed")
    exit(0)

new_dirs = """
  <!-- JSA FIM — NIST SI-7 critical paths -->
  <directories realtime="yes" report_changes="yes" check_all="yes">/etc/passwd,/etc/shadow,/etc/sudoers</directories>
  <directories realtime="yes" report_changes="yes" check_all="yes">/etc/ssh/sshd_config</directories>
  <directories report_changes="yes" check_all="yes">/etc/crontab,/etc/cron.d</directories>
  <directories report_changes="yes" check_all="yes">/etc/kubernetes</directories>
  <directories report_changes="yes" check_all="yes">/usr/bin,/usr/sbin,/bin,/sbin</directories>
"""

if new_dirs.strip() in content:
    print("FIM paths already configured")
else:
    content = content.replace("</syscheck>", new_dirs + "\n  </syscheck>", 1)
    with open(conf_path, "w") as f:
        f.write(content)
    print("FIM paths added to ossec.conf — restart Wazuh to apply")
PYEOF

systemctl restart wazuh-manager 2>/dev/null || systemctl restart wazuh-agent

# --- Initialize AIDE ---
apt-get install -y aide aide-common 2>/dev/null || yum install -y aide 2>/dev/null

cat > /etc/aide/aide.conf.d/99-jsa-security.conf << 'EOF'
# JSA FIM policy — NIST SI-7
/etc/passwd     FULL
/etc/shadow     FULL
/etc/sudoers    FULL
/etc/ssh/sshd_config FULL
/etc/hosts      FULL
/etc/resolv.conf FULL
/usr/bin        CONTENT_EX
/usr/sbin       CONTENT_EX
/bin            CONTENT_EX
/sbin           CONTENT_EX
/etc/kubernetes FULL
/etc/init.d     FULL
/etc/crontab    FULL
/etc/cron.d     FULL
!/var
!/tmp
!/proc
!/sys
!/dev
EOF

aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
echo "AIDE database initialized — baseline captured"

# --- Container Image Signing with cosign ---
# Sign an image (requires OIDC identity or key pair)
# Key pair approach (for air-gap or non-OIDC environments):
cosign generate-key-pair  # creates cosign.key and cosign.pub
cosign sign --key cosign.key <registry>/<image>:<tag>

# Verify
cosign verify --key cosign.pub <registry>/<image>:<tag>

# --- Kyverno: enforce image signature verification ---
cat > /tmp/kyverno-require-signed-images.yaml << 'EOF'
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-images
  annotations:
    policies.kyverno.io/title: Require Signed Images
    policies.kyverno.io/category: Software Supply Chain Security
    policies.kyverno.io/description: >-
      Requires all container images to be signed with cosign.
      Implements NIST SI-7 integrity verification.
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: verify-image-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
      verifyImages:
        - imageReferences:
            - "<registry>/*"
          attestors:
            - count: 1
              entries:
                - keys:
                    publicKeys: |-
                      -----BEGIN PUBLIC KEY-----
                      <YOUR_COSIGN_PUBLIC_KEY>
                      -----END PUBLIC KEY-----
EOF
kubectl apply -f /tmp/kyverno-require-signed-images.yaml
```

### Validation
```bash
# Verify Wazuh FIM covers all 5 critical paths
REQUIRED_PATHS=("/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/ssh/sshd_config" "/etc/crontab")
PASS=0
for path in "${REQUIRED_PATHS[@]}"; do
  grep -q "$path" /var/ossec/etc/ossec.conf 2>/dev/null && \
    PASS=$((PASS+1)) || echo "[MISSING] $path"
done
echo "Critical paths covered: $PASS / ${#REQUIRED_PATHS[@]}"
# Expected: 5 / 5

# Verify realtime is enabled for auth files
grep 'realtime="yes"' /var/ossec/etc/ossec.conf 2>/dev/null | \
  grep -E "passwd|shadow|sudoers|sshd_config" && \
  echo "[PASS] Auth files have realtime FIM" || \
  echo "[FAIL] Auth files not in realtime FIM"

# Verify AIDE database exists and is recent
[[ -f /var/lib/aide/aide.db ]] && \
  echo "[PASS] AIDE database: $(stat -c '%y' /var/lib/aide/aide.db 2>/dev/null | cut -d. -f1)" || \
  echo "[FAIL] AIDE database not found"
# Expected: PASS with recent date

# Verify Kyverno image signing policy is enforced
kubectl get clusterpolicy require-signed-images \
  -o jsonpath='{.spec.validationFailureAction}' 2>/dev/null | \
  grep -q "Enforce" && \
  echo "[PASS] Image signing policy in Enforce mode" || \
  echo "[FAIL] Image signing policy not enforced"
# Expected: PASS
```

### Evidence Capture
```bash
EVIDENCE_DIR="/tmp/jsa-evidence/SI-7/$(date +%Y%m%d)"
mkdir -p "$EVIDENCE_DIR"

# Wazuh FIM config (syscheck section)
grep -A50 "<syscheck>" /var/ossec/etc/ossec.conf 2>/dev/null \
  > "$EVIDENCE_DIR/wazuh-fim-config.txt" || \
  echo "Wazuh not available" > "$EVIDENCE_DIR/wazuh-fim-config.txt"

# Recent FIM alerts
tail -100 /var/ossec/logs/alerts/alerts.json 2>/dev/null | \
  python3 -c "
import sys, json
alerts = []
for line in sys.stdin:
    try:
        d = json.loads(line)
        if 'syscheck' in d:
            alerts.append({'time': d.get('timestamp'), 'path': d.get('syscheck', {}).get('path'), 'event': d.get('syscheck', {}).get('event')})
    except:
        pass
print(json.dumps(alerts, indent=2))
" > "$EVIDENCE_DIR/fim-alerts-recent.json" 2>/dev/null || true

# AIDE check results
aide --check > "$EVIDENCE_DIR/aide-check-results.txt" 2>/dev/null || \
  echo "AIDE not installed or database not found" > "$EVIDENCE_DIR/aide-check-results.txt"

# Kyverno image signing policy
kubectl get clusterpolicy require-signed-images -o yaml \
  > "$EVIDENCE_DIR/kyverno-image-signing-policy.yaml" 2>/dev/null || \
  echo "Kyverno image signing policy not deployed" > "$EVIDENCE_DIR/kyverno-image-signing-policy.txt"

# cosign public key (do NOT capture private key)
[[ -f cosign.pub ]] && cp cosign.pub "$EVIDENCE_DIR/cosign-public-key.pub"

# Summary
cat > "$EVIDENCE_DIR/SI-7-summary.txt" << EOF
SI-7 Software and Information Integrity Evidence
Date: $(date)
Auditor: $(whoami)
Host: $(hostname)

FIM paths configured: $(grep -c "<directories" /var/ossec/etc/ossec.conf 2>/dev/null || echo "unknown")
Realtime entries: $(grep -c 'realtime="yes"' /var/ossec/etc/ossec.conf 2>/dev/null || echo "unknown")
AIDE database: $(ls -lh /var/lib/aide/aide.db 2>/dev/null || echo "not found")

Files captured:
$(ls -1 "$EVIDENCE_DIR")
EOF

echo "[DONE] Evidence written to $EVIDENCE_DIR"
```
