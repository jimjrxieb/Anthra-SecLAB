# Layer 3 Network — Validate Fixes

| Field | Value |
|-------|-------|
| NIST Controls | SC-7, AC-4, SI-3, SI-4 |
| Tools | tools/run-all-audits.sh, 01-auditors/ |
| Time Estimate | 30–45 minutes |
| Rank | D |

---

## Objective

Re-run all auditors and confirm every FAIL item from 01-assess has been resolved. Compare before/after evidence. This is the proof of work — not that fixes were applied, but that the controls are verified as functioning.

---

## Step 1: Re-Run All Auditors

```bash
bash tools/run-all-audits.sh
# Combined report: /tmp/jsa-evidence/l3-full-audit-*/l3-audit-report.txt
```

Expected result: Zero FAIL items. WARNs are acceptable if documented and risk-accepted.

---

## Step 2: Before/After Evidence Comparison

### Firewall (SC-7)

```bash
# Compare rule counts and policies
BEFORE=$(ls -t /tmp/jsa-evidence/firewall-audit-* 2>/dev/null | tail -1)
AFTER=$(ls -t /tmp/jsa-evidence/firewall-audit-* 2>/dev/null | head -1)

echo "=== Before ==="
grep "PASS\|FAIL\|WARN" "$BEFORE/audit.log" 2>/dev/null | wc -l

echo "=== After ==="
grep "PASS\|FAIL\|WARN" "$AFTER/audit.log" 2>/dev/null | wc -l

# Specific: verify INPUT policy is now DROP
iptables -L INPUT --line-numbers -n 2>/dev/null | head -1
# Expected: Chain INPUT (policy DROP)
```

### Suricata (SI-3)

```bash
# Verify rule count is above baseline
grep "post_count" /tmp/jsa-evidence/suricata-rule-update-*/rule-counts.txt 2>/dev/null | tail -1

# Confirm live detection still works
curl -s http://testmynids.org/uid/index.html > /dev/null
sleep 2
tail -20 /var/log/suricata/eve.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('event_type') == 'alert':
            print('DETECTION OK:', e['alert']['signature'])
    except: pass
"
```

### Segmentation (AC-4)

```bash
# Confirm FORWARD policy is DROP (no cross-zone traffic by default)
iptables -L FORWARD --line-numbers -n | head -1
# Expected: Chain FORWARD (policy DROP)

# Confirm K8s NetworkPolicy if applicable
kubectl get networkpolicy --all-namespaces --no-headers 2>/dev/null | wc -l
```

---

## Step 3: Scenario Traffic Tests

Run these tests to verify the controls work against realistic attack patterns.

### Test 1: SSH from unauthorized source (should be blocked and logged)

```bash
# Attempt SSH from current host to itself — only passes if localhost is in admin CIDR
# This tests that the DROP rule is in place for non-admin sources
# Replace TARGET_IP with a host you control outside your admin CIDR
TARGET_IP="<your-test-host>"
ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$TARGET_IP" echo "connected" 2>&1 || \
  echo "Connection blocked (expected)"

# Verify the block appeared in logs
grep "JSA-SSH-DENY\|JSA-INPUT-DROP" /var/log/kern.log 2>/dev/null | tail -5
```

### Test 2: Suricata detects lateral movement probe (SID 1000030 — SMB sweep)

```bash
# Simulate rapid SMB connections (requires hping3 or nmap)
# Replace with an internal test host IP
nmap -sS -p 445 --max-rate 20 192.168.1.0/24 2>/dev/null &
sleep 5
kill %1 2>/dev/null

# Check for SID 1000030
tail -100 /var/log/suricata/eve.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        a = e.get('alert', {})
        if a.get('signature_id') == 1000030:
            print('PASS: SMB sweep detected:', a.get('signature'))
    except: pass
"
```

### Test 3: Zeek captures DNS after Suricata alert

```bash
dig @8.8.8.8 example.top
sleep 2
grep "\.top" /opt/zeek/logs/current/dns.log 2>/dev/null | tail -3
# Expected: DNS query visible in Zeek dns.log
```

---

## Step 4: Confirm Improvements

| Control | Before | After |
|---------|--------|-------|
| SC-7: Default INPUT policy | ACCEPT (FAIL) | DROP (PASS) |
| SC-7: SSH from 0.0.0.0/0 | Open (FAIL) | Admin CIDR only (PASS) |
| SC-7: Firewall logging | Disabled (WARN) | Enabled (PASS) |
| SI-3: Rule count | <30K (WARN) | ≥30K (PASS) |
| SI-3: Custom local.rules | Empty (WARN) | 7 sections, 20+ rules (PASS) |
| SI-4: EVE JSON enabled | Disabled (FAIL) | Enabled (PASS) |
| AC-4: K8s NetworkPolicy | None (FAIL) | default-deny applied (PASS) |

Fill in actual before/after values from audit evidence.

---

## Step 5: Archive Evidence

```bash
# Collect all evidence from this engagement
mkdir -p evidence/$(date +%Y%m%d)-validation

# Copy relevant evidence packages
cp -r /tmp/jsa-evidence/l3-full-audit-* evidence/$(date +%Y%m%d)-validation/ 2>/dev/null
cp -r /tmp/jsa-evidence/firewall-audit-* evidence/$(date +%Y%m%d)-validation/ 2>/dev/null
cp -r /tmp/jsa-evidence/suricata-audit-* evidence/$(date +%Y%m%d)-validation/ 2>/dev/null
cp -r /tmp/jsa-evidence/suricata-rule-update-* evidence/$(date +%Y%m%d)-validation/ 2>/dev/null
cp -r /tmp/jsa-evidence/default-deny-* evidence/$(date +%Y%m%d)-validation/ 2>/dev/null
cp -r /tmp/jsa-evidence/mgmt-ports-* evidence/$(date +%Y%m%d)-validation/ 2>/dev/null

ls evidence/$(date +%Y%m%d)-validation/
```

This evidence package is the audit trail for SC-7, SI-3, SI-4, AC-4 compliance verification.
