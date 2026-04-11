# 03-validate.md — L4 Transport Layer Validation

| Field | Value |
|---|---|
| **NIST Controls** | SC-8, SC-13, SC-23, IA-5 |
| **Tools** | testssl.sh, OpenSSL, cert-manager, curl |
| **Time** | 30 minutes |
| **Rank** | D (scripted, comparison against baseline) |

---

## Purpose

After applying fixes from `02-fix-SC8-tls.md` and `02a-fix-IA5-certs.md`, this playbook generates
before/after evidence and confirms all SC-8, SC-13, SC-23, and IA-5 findings are resolved.

---

## 1. Re-Run All Auditors

```bash
# Full L4 audit (all 3 auditors with evidence archive)
./tools/run-all-audits.sh HOST:PORT

# Individual auditors
./01-auditors/audit-tls-config.sh HOST:PORT
./01-auditors/audit-cert-lifecycle.sh
./01-auditors/audit-mtls-status.sh production
```

Expected after remediation:
- `[PASS]` SSLv3, TLS 1.0, TLS 1.1 rejected
- `[PASS]` TLS 1.2 and TLS 1.3 accepted
- `[PASS]` Certificate valid for 30+ days
- `[PASS]` HSTS present with max-age=31536000; includeSubDomains
- `[PASS]` cert-manager pods running
- `[PASS]` ClusterIssuers READY

---

## 2. testssl.sh Re-Scan

Full cipher re-scan to confirm no weak ciphers remain.

```bash
# Full severity scan
/opt/testssl/testssl.sh --severity HIGH HOST:PORT

# Expected: No HIGH or CRITICAL findings
# Cipher grades: all A (no B, C, D, or F)

# Before/after comparison
BEFORE_JSON="/tmp/jsa-evidence/testssl-before.json"
AFTER_JSON="/tmp/jsa-evidence/testssl-after-$(date +%Y%m%d).json"

/opt/testssl/testssl.sh \
  --jsonfile "$AFTER_JSON" \
  --severity HIGH \
  --quiet HOST:PORT

echo "After-state JSON saved: $AFTER_JSON"
```

---

## 3. Protocol Acceptance Verification

Quick pass/fail for each protocol:

```bash
HOST_PORT="HOST:PORT"

echo "=== Protocol Acceptance Test ==="

check_proto() {
    local flag="$1"
    local label="$2"
    local expected="$3"
    local result
    result=$(echo | timeout 5 openssl s_client -connect "$HOST_PORT" "$flag" 2>&1 | \
             grep -c "BEGIN CERTIFICATE" || true)
    if [[ "$expected" == "rejected" ]] && [[ "$result" -eq 0 ]]; then
        echo "[PASS] $label: rejected (SC-8 compliant)"
    elif [[ "$expected" == "accepted" ]] && [[ "$result" -gt 0 ]]; then
        echo "[PASS] $label: accepted (required)"
    else
        echo "[FAIL] $label: unexpected result — expected $expected"
    fi
}

check_proto "-ssl3"   "SSLv3"   "rejected"
check_proto "-tls1"   "TLS 1.0" "rejected"
check_proto "-tls1_1" "TLS 1.1" "rejected"
check_proto "-tls1_2" "TLS 1.2" "accepted"
check_proto "-tls1_3" "TLS 1.3" "accepted"
```

---

## 4. Cipher Suite Before/After Comparison

```bash
# Get current cipher list
echo | openssl s_client -connect HOST:PORT -cipher 'ALL' 2>&1 | grep "Cipher    :"

# Expected: only ECDHE+AESGCM or ECDHE+CHACHA20
# Unexpected: RC4, DES, CBC, NULL, EXPORT — should be gone

# nmap cipher enumeration (shows all accepted ciphers with grades)
nmap --script ssl-enum-ciphers -p 443 HOST 2>/dev/null | grep -E "^\|.*TLS|grade"
# Expected: all grade A
```

---

## 5. HSTS Verification

```bash
# Check HSTS header
curl -sI "https://HOST" | grep -i "strict-transport-security"
# Expected: strict-transport-security: max-age=31536000; includeSubDomains

# Verify HTTP redirects to HTTPS (not bypassing HSTS)
curl -sI "http://HOST" | grep -i "location"
# Expected: Location: https://HOST (301 or 302)
```

---

## 6. cert-manager State Verification

```bash
# All ClusterIssuers READY
kubectl get clusterissuers
# Expected: READY=True for all

# All Certificates READY
kubectl get certificates --all-namespaces
# Expected: READY=True, not expired, not expiring within 30 days

# cert-manager pods healthy
kubectl get pods -n cert-manager
# Expected: 3 pods Running (cert-manager, cert-manager-cainjector, cert-manager-webhook)

# No failed CertificateRequests
kubectl get certificaterequests --all-namespaces | grep -v "Approved\|True"
# Expected: empty (no failed or pending requests)
```

---

## 7. Evidence Archive

```bash
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/l4-validated-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

# Protocol test results
for proto in ssl3 tls1 tls1_1 tls1_2 tls1_3; do
    FLAG=$(echo "$proto" | sed 's/tls1$/tls1/;s/tls1_/-tls1_/')
    echo | timeout 5 openssl s_client -connect HOST:PORT "-${proto//_1/_1}" 2>&1 \
        > "${EVIDENCE_DIR}/proto-${proto}.txt" 2>/dev/null || true
done

# Certificate state
kubectl get certificates --all-namespaces -o yaml > "${EVIDENCE_DIR}/certificates-final.yaml" 2>/dev/null || true
kubectl get clusterissuers -o yaml > "${EVIDENCE_DIR}/clusterissuers-final.yaml" 2>/dev/null || true

# HSTS header
curl -sI "https://HOST" > "${EVIDENCE_DIR}/headers-final.txt" 2>/dev/null || true

# testssl.sh final report
/opt/testssl/testssl.sh --severity HIGH \
    --jsonfile "${EVIDENCE_DIR}/testssl-final.json" \
    HOST:PORT 2>/dev/null || true

echo "Validation evidence archived: ${EVIDENCE_DIR}"
ls -1 "$EVIDENCE_DIR"
```

---

## Validation Checklist (sign off before closing)

- [ ] All 3 auditors run with no FAIL findings
- [ ] testssl.sh shows no HIGH+ severity findings
- [ ] All cipher grades are A
- [ ] SSLv3, TLS 1.0, TLS 1.1 rejected
- [ ] TLS 1.2 and TLS 1.3 accepted
- [ ] HSTS present with max-age ≥ 31536000 and includeSubDomains
- [ ] All cert-manager Certificates READY
- [ ] All ClusterIssuers READY
- [ ] No expired or expiring (<30 days) certificates
- [ ] Evidence archived with before/after comparison
- [ ] Control mapping updated in `control-map.md`

---

## Next Steps

- Monitoring setup: `04-triage-alerts.md`
- CISO reporting: include before/after evidence, control compliance status, open findings count
