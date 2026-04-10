#!/usr/bin/env bash
# validate-staging.sh — Full staging validation (manual + automated)
#
# The OSS-Copilot philosophy: understand the method, then scale it with tools.
# This script runs every check twice — once by hand (curl/kubectl), once with
# enterprise-equivalent OSS tools. Same findings, different scale.
#
# Manual checks prove you understand the logic.
# Automated checks prove you can operationalize it.
# The delta between them is what you talk about in interviews.
#
# Enterprise equivalents:
#   Manual checks     → What a senior pentester does in the first hour
#   ZAP               → Veracode DAST ($50-200K), Rapid7 InsightAppSec ($30-100K)
#   Nuclei            → Tenable.io ($25-65K), Qualys VMDR ($15-50K)
#   trivy             → Prisma Cloud ($100K+), Snyk Container ($25-100K)
#   kubescape         → Prisma Cloud compliance, Aqua CSPM
#   All of the above  → This script ($0)
#
# NIST 800-53 controls validated:
#   SC-7   Boundary Protection (headers, CORS, exposed paths, network segmentation)
#   SC-8   Transmission Confidentiality (TLS, HSTS, cookie flags)
#   RA-5   Vulnerability Monitoring and Scanning (ZAP, Nuclei, trivy)
#   SA-11  Developer Testing and Evaluation (DAST against live app)
#   AC-6   Least Privilege (SA tokens, metadata API, RBAC)
#   CM-6   Configuration Settings (security headers, server disclosure)
#   CM-7   Least Functionality (exposed debug/metrics/admin endpoints)
#   SI-10  Information Input Validation (XSS, SQLi, injection via ZAP active)
#   AU-2   Audit Events (verify logging pipeline is capturing)
#
# Usage:
#   ./scripts/security/validate-staging.sh
#   ./scripts/security/validate-staging.sh --target https://staging.example.com
#   ./scripts/security/validate-staging.sh --skip-automated   # manual only
#   ./scripts/security/validate-staging.sh --report           # write markdown report

set -euo pipefail

# ── Config ──────────────────────────────────────────────────────────────

TARGET="${1:-http://localhost:8080}"
NAMESPACE="${NAMESPACE:-portfolio}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_DIR="$(cd "$(dirname "$0")/../.." && pwd)/reports/validation-${TIMESTAMP}"
SKIP_AUTO=false
WRITE_REPORT=false

for arg in "$@"; do
    case "$arg" in
        --skip-automated) SKIP_AUTO=true ;;
        --report)         WRITE_REPORT=true ;;
        --target)         ;; # handled by positional
        *)                [[ "$arg" != "$TARGET" ]] || true ;;
    esac
done

mkdir -p "$REPORT_DIR"

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

PASS=0; WARN=0; FAIL=0; SKIP=0
REPORT_LINES=""
r() { REPORT_LINES+="$1"$'\n'; }

result() {
    local status="$1" check="$2" nist="$3" detail="${4:-}"
    case "$status" in
        PASS) echo -e "  ${GREEN}PASS${RESET}  [$nist] $check"; PASS=$((PASS+1)) ;;
        WARN) echo -e "  ${YELLOW}WARN${RESET}  [$nist] $check${detail:+ — $detail}"; WARN=$((WARN+1)) ;;
        FAIL) echo -e "  ${RED}FAIL${RESET}  [$nist] $check${detail:+ — $detail}"; FAIL=$((FAIL+1)) ;;
        SKIP) echo -e "  ${CYAN}SKIP${RESET}  [$nist] $check${detail:+ — $detail}"; SKIP=$((SKIP+1)) ;;
    esac
    r "| $status | $nist | $check | $detail |"
}

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║         STAGING VALIDATION — MANUAL + AUTOMATED            ║${RESET}"
echo -e "${BOLD}║                                                            ║${RESET}"
echo -e "${BOLD}║  Method first. Tools second. Same findings, different      ║${RESET}"
echo -e "${BOLD}║  scale. The tool automates the method — not replaces it.   ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo "  Target:    $TARGET"
echo "  Namespace: $NAMESPACE"
echo "  Time:      $(date -u '+%Y-%m-%d %H:%M UTC')"
echo "  Report:    $REPORT_DIR"
echo ""

r "# Staging Validation Report — $(date -u '+%Y-%m-%d %H:%M UTC')"
r ""
r "Target: \`$TARGET\` | Namespace: \`$NAMESPACE\`"
r ""
r "| Status | NIST | Check | Detail |"
r "|--------|------|-------|--------|"

# ════════════════════════════════════════════════════════════════════════
# PART 1: MANUAL VALIDATION (curl + kubectl)
# ════════════════════════════════════════════════════════════════════════
#
# What a senior engineer does in the first hour of a pentest.
# No tools needed. Just curl, kubectl, and knowing what to look for.

echo -e "${BOLD}━━━ PART 1: MANUAL VALIDATION (curl + kubectl) ━━━${RESET}"
echo -e "${DIM}  What a senior engineer checks by hand.${RESET}"
echo ""

# ── 1a. Security Headers (SC-7, CM-6) ──────────────────────────────────

echo -e "${BOLD}── Security Headers ──${RESET}"
HEADERS=$(curl -sI --connect-timeout 10 "$TARGET" 2>/dev/null || true)

if [[ -z "$HEADERS" ]]; then
    result FAIL "Target reachable" "SC-7" "Cannot reach $TARGET"
else
    result PASS "Target reachable" "SC-7"

    # Check each header — this is what ZAP rule 10020, 10021, 10035, 10038 do
    check_header() {
        local name="$1" nist="$2"
        if echo "$HEADERS" | grep -qi "^${name}:"; then
            local val=$(echo "$HEADERS" | grep -i "^${name}:" | head -1 | sed 's/[^:]*: //' | tr -d '\r')
            result PASS "$name present" "$nist" "$val"
        else
            result FAIL "$name missing" "$nist" "Add at gateway/ingress level"
        fi
    }

    check_header "X-Frame-Options"            "SC-7"   # ZAP 10020
    check_header "X-Content-Type-Options"     "CM-6"   # ZAP 10021
    check_header "Strict-Transport-Security"  "SC-8"   # ZAP 10035
    check_header "Content-Security-Policy"    "SC-7"   # ZAP 10038
    check_header "Referrer-Policy"            "CM-6"   # ZAP 10054

    # Version disclosure — this is what Nuclei tech-detect templates do
    if echo "$HEADERS" | grep -qiE "^server:.*[0-9]+\.[0-9]+"; then
        SERVER=$(echo "$HEADERS" | grep -i "^server:" | head -1 | sed 's/[^:]*: //' | tr -d '\r')
        result FAIL "Server version hidden" "CM-7" "Leaking: $SERVER"
    else
        result PASS "Server version hidden" "CM-7"
    fi

    if echo "$HEADERS" | grep -qi "^x-powered-by:"; then
        PB=$(echo "$HEADERS" | grep -i "^x-powered-by:" | head -1 | sed 's/[^:]*: //' | tr -d '\r')
        result FAIL "X-Powered-By hidden" "CM-7" "Leaking: $PB"
    else
        result PASS "X-Powered-By hidden" "CM-7"
    fi
fi

# ── 1b. Cookie Security (SC-8) ─────────────────────────────────────────

echo ""
echo -e "${BOLD}── Cookie Security ──${RESET}"
COOKIES=""
for path in "/" "/login" "/auth" "/api" "/chat"; do
    C=$(curl -sI --connect-timeout 5 "${TARGET}${path}" 2>/dev/null | grep -i "^set-cookie:" || true)
    COOKIES+="$C"
done

if [[ -z "$(echo "$COOKIES" | tr -d '[:space:]')" ]]; then
    result SKIP "Cookie flags" "SC-8" "No cookies set"
else
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        cookie_name=$(echo "$line" | sed 's/[^:]*: //' | cut -d'=' -f1 | tr -d '[:space:]')
        MISSING=""
        echo "$line" | grep -qi "secure"   || MISSING+="Secure "
        echo "$line" | grep -qi "httponly"  || MISSING+="HttpOnly "
        echo "$line" | grep -qi "samesite"  || MISSING+="SameSite "
        if [[ -n "$MISSING" ]]; then
            result FAIL "Cookie '$cookie_name' flags" "SC-8" "Missing: $MISSING"
        else
            result PASS "Cookie '$cookie_name' flags" "SC-8"
        fi
    done <<< "$COOKIES"
fi

# ── 1c. CORS (SC-7) ────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}── CORS ──${RESET}"
CORS=$(curl -sI -H "Origin: https://evil.attacker.com" --connect-timeout 5 "$TARGET" 2>/dev/null | grep -i "^access-control-allow-origin:" || true)

if [[ -z "$CORS" ]]; then
    result PASS "CORS not open" "SC-7" "No ACAO header returned"
elif echo "$CORS" | grep -q "\*"; then
    result FAIL "CORS wildcard" "SC-7" "Access-Control-Allow-Origin: *"
elif echo "$CORS" | grep -qi "evil.attacker.com"; then
    result FAIL "CORS reflects origin" "SC-7" "Mirrors arbitrary Origin header"
else
    CORS_VAL=$(echo "$CORS" | sed 's/[^:]*: //' | tr -d '\r')
    result PASS "CORS restricted" "SC-7" "$CORS_VAL"
fi

# ── 1d. Exposed Paths (CM-7) ───────────────────────────────────────────
# This is what Nuclei exposure templates check at scale

echo ""
echo -e "${BOLD}── Exposed Paths ──${RESET}"
FOUND_EXPOSED=false
for path in /.env /.git /debug /metrics /actuator /swagger /api-docs /admin /console /graphql /server-status; do
    CODE=$(curl -so /dev/null -w "%{http_code}" --connect-timeout 5 "${TARGET}${path}" 2>/dev/null || echo "000")
    if [[ "$CODE" != "000" && "$CODE" != "404" && "$CODE" != "405" ]]; then
        case "$path" in
            /.env|/.git)           result FAIL "$path exposed ($CODE)" "CM-7" "Sensitive file" ;;
            /debug|/actuator|/console|/server-status) result FAIL "$path exposed ($CODE)" "CM-7" "Debug endpoint" ;;
            /metrics)              result WARN "$path exposed ($CODE)" "CM-7" "Should be internal only" ;;
            *)                     result WARN "$path exposed ($CODE)" "CM-7" ;;
        esac
        FOUND_EXPOSED=true
    fi
done
[[ "$FOUND_EXPOSED" == "false" ]] && result PASS "No sensitive paths exposed" "CM-7"

# ── 1e. TLS (SC-8) ─────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}── TLS ──${RESET}"
if [[ "$TARGET" == https://* ]]; then
    TLS_INFO=$(curl -svI "$TARGET" 2>&1 | grep -E "SSL connection|subject:|expire|TLS" || true)
    if echo "$TLS_INFO" | grep -qi "TLSv1\.[23]"; then
        result PASS "TLS 1.2+" "SC-8"
    elif [[ -n "$TLS_INFO" ]]; then
        result WARN "TLS version" "SC-8" "Check version manually"
    else
        result SKIP "TLS check" "SC-8" "Could not extract TLS info"
    fi
else
    result SKIP "TLS check" "SC-8" "Target is HTTP, not HTTPS"
fi

# ── 1f. K8s: Metadata API (AC-6) ───────────────────────────────────────
# This is the SSRF check that no automated tool does well

echo ""
echo -e "${BOLD}── K8s Checks ──${RESET}"
if command -v kubectl &>/dev/null && kubectl cluster-info &>/dev/null 2>&1; then
    METADATA=$(kubectl run validate-metadata-probe --rm -i --restart=Never \
        --image=curlimages/curl:8.5.0 \
        --namespace "$NAMESPACE" \
        --timeout=20s \
        -- curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" http://169.254.169.254/latest/meta-data/ 2>&1 || echo "BLOCKED")

    kubectl delete pod validate-metadata-probe -n "$NAMESPACE" --ignore-not-found --wait=false &>/dev/null || true

    if echo "$METADATA" | grep -qE "^200"; then
        result FAIL "Metadata API blocked" "AC-6" "169.254.169.254 reachable from pods"
    else
        result PASS "Metadata API blocked" "AC-6"
    fi

    # SA token mount check
    SA_MOUNTED=$(kubectl get pods -n "$NAMESPACE" -o json 2>/dev/null | python3 -c "
import sys, json
pods = json.load(sys.stdin)
count = 0
for pod in pods.get('items', []):
    spec = pod.get('spec', {})
    if spec.get('automountServiceAccountToken') is not False:
        for c in spec.get('containers', []):
            for vm in c.get('volumeMounts', []):
                if 'serviceaccount' in vm.get('mountPath', '').lower():
                    count += 1
print(count)
" 2>/dev/null || echo "0")

    if [[ "$SA_MOUNTED" -gt 0 ]]; then
        result WARN "SA tokens mounted" "AC-6" "$SA_MOUNTED pod(s) — set automountServiceAccountToken: false if not needed"
    else
        result PASS "SA tokens not mounted" "AC-6"
    fi

    # Lateral movement: can the app namespace reach other namespaces?
    LATERAL=$(kubectl run validate-lateral-probe --rm -i --restart=Never \
        --image=curlimages/curl:8.5.0 \
        --namespace "$NAMESPACE" \
        --timeout=15s \
        -- curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" http://kubernetes.default.svc/api 2>&1 || echo "BLOCKED")

    kubectl delete pod validate-lateral-probe -n "$NAMESPACE" --ignore-not-found --wait=false &>/dev/null || true

    if echo "$LATERAL" | grep -qE "^(200|403)"; then
        # 403 = API reachable but RBAC denied (acceptable)
        [[ "$LATERAL" == *"200"* ]] && result FAIL "K8s API accessible" "AC-6" "Pods can reach API server without restriction" \
                                     || result PASS "K8s API RBAC enforced" "AC-6" "403 — reachable but denied"
    else
        result PASS "K8s API blocked by NetworkPolicy" "SC-7"
    fi
else
    result SKIP "K8s checks" "AC-6" "kubectl not available or cluster not reachable"
fi

# ── 1g. Logging Pipeline (AU-2) ────────────────────────────────────────

echo ""
echo -e "${BOLD}── Logging Pipeline ──${RESET}"
if command -v kubectl &>/dev/null && kubectl cluster-info &>/dev/null 2>&1; then
    # Is Fluent Bit running?
    FB_PODS=$(kubectl get pods -n monitoring -l app.kubernetes.io/name=fluent-bit --no-headers 2>/dev/null | grep -c Running || echo "0")
    if [[ "$FB_PODS" -gt 0 ]]; then
        result PASS "Fluent Bit running" "AU-2" "$FB_PODS pod(s)"
    else
        result WARN "Fluent Bit not detected" "AU-2" "Log collection may not be active"
    fi

    # Is Loki running?
    LOKI_PODS=$(kubectl get pods -n monitoring -l app.kubernetes.io/name=loki --no-headers 2>/dev/null | grep -c Running || echo "0")
    if [[ "$LOKI_PODS" -gt 0 ]]; then
        result PASS "Loki running" "AU-6" "$LOKI_PODS pod(s)"
    else
        result WARN "Loki not detected" "AU-6" "Log storage may not be active"
    fi

    # Is Grafana running?
    GRAFANA_PODS=$(kubectl get pods -n monitoring -l app.kubernetes.io/name=grafana --no-headers 2>/dev/null | grep -c Running || echo "0")
    if [[ "$GRAFANA_PODS" -gt 0 ]]; then
        result PASS "Grafana running" "AU-7"
    else
        result WARN "Grafana not detected" "AU-7" "Log visualization not available"
    fi
else
    result SKIP "Logging pipeline" "AU-2" "kubectl not available"
fi

# ════════════════════════════════════════════════════════════════════════
# PART 2: AUTOMATED VALIDATION (ZAP + Nuclei + trivy + kubescape)
# ════════════════════════════════════════════════════════════════════════
#
# Same checks, at scale. The tools automate what Part 1 does by hand.
# Every finding here should map to something you already checked manually.

if [[ "$SKIP_AUTO" == "false" ]]; then
    echo ""
    echo -e "${BOLD}━━━ PART 2: AUTOMATED VALIDATION (OSS tools) ━━━${RESET}"
    echo -e "${DIM}  Same checks, at scale. Every finding maps to Part 1.${RESET}"
    echo ""

    # ── 2a. ZAP Baseline (→ replaces manual header/cookie checks) ──────
    echo -e "${BOLD}── ZAP Baseline ──${RESET}"
    echo -e "${DIM}  Enterprise: Veracode DAST (\$50-200K), Rapid7 InsightAppSec (\$30-100K)${RESET}"

    if command -v docker &>/dev/null; then
        ZAP_TMP=$(mktemp -d)
        docker run --rm --network host \
            -v "$ZAP_TMP":/zap/wrk:rw \
            ghcr.io/zaproxy/zaproxy:stable \
            zap-baseline.py -t "$TARGET" -J zap.json -l WARN -I 2>/dev/null || true

        if [[ -f "$ZAP_TMP/zap.json" ]]; then
            cp "$ZAP_TMP/zap.json" "$REPORT_DIR/zap-baseline.json"
            ZAP_ALERTS=$(python3 -c "
import json
with open('$ZAP_TMP/zap.json') as f:
    data = json.load(f)
total = sum(len(s.get('alerts',[])) for s in data.get('site',[]))
print(total)
" 2>/dev/null || echo "0")
            result PASS "ZAP baseline ran" "RA-5" "$ZAP_ALERTS alert type(s) — see zap-baseline.json"
        else
            result WARN "ZAP produced no output" "RA-5"
        fi
        rm -rf "$ZAP_TMP"
    else
        result SKIP "ZAP baseline" "RA-5" "Docker not available"
    fi

    # ── 2b. Nuclei (→ replaces manual path/CVE checks) ─────────────────
    echo ""
    echo -e "${BOLD}── Nuclei ──${RESET}"
    echo -e "${DIM}  Enterprise: Tenable.io (\$25-65K), Qualys VMDR (\$15-50K)${RESET}"

    if command -v nuclei &>/dev/null; then
        nuclei -u "$TARGET" \
            -tags misconfig,exposure,tech \
            -severity medium,high,critical \
            -silent \
            -jsonl -o "$REPORT_DIR/nuclei.jsonl" 2>/dev/null || true

        if [[ -s "$REPORT_DIR/nuclei.jsonl" ]]; then
            NUCLEI_COUNT=$(wc -l < "$REPORT_DIR/nuclei.jsonl")
            result PASS "Nuclei scan ran" "RA-5" "$NUCLEI_COUNT finding(s) — see nuclei.jsonl"
        else
            result PASS "Nuclei scan ran" "RA-5" "0 findings"
        fi
    else
        result SKIP "Nuclei scan" "RA-5" "nuclei not installed (go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)"
    fi

    # ── 2c. Trivy (→ image vulnerability scan) ──────────────────────────
    echo ""
    echo -e "${BOLD}── Trivy Image Scan ──${RESET}"
    echo -e "${DIM}  Enterprise: Prisma Cloud (\$100K+), Snyk Container (\$25-100K)${RESET}"

    if command -v trivy &>/dev/null; then
        # Scan the images used in the namespace
        IMAGES=$(kubectl get pods -n "$NAMESPACE" -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' 2>/dev/null | sort -u || true)

        if [[ -n "$IMAGES" ]]; then
            VULN_TOTAL=0
            while IFS= read -r img; do
                [[ -z "$img" ]] && continue
                VULN_COUNT=$(trivy image --quiet --severity HIGH,CRITICAL --format json "$img" 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
total = sum(len(r.get('Vulnerabilities', []) or []) for r in data.get('Results', []))
print(total)
" 2>/dev/null || echo "0")
                VULN_TOTAL=$((VULN_TOTAL + VULN_COUNT))
                if [[ "$VULN_COUNT" -gt 0 ]]; then
                    result WARN "Image $img" "RA-5" "$VULN_COUNT HIGH/CRITICAL vulns"
                else
                    result PASS "Image $img" "RA-5" "0 HIGH/CRITICAL vulns"
                fi
            done <<< "$IMAGES"
            echo "$IMAGES" > "$REPORT_DIR/images-scanned.txt"
        else
            result SKIP "Trivy image scan" "RA-5" "No pods running in $NAMESPACE"
        fi
    else
        result SKIP "Trivy image scan" "RA-5" "trivy not installed"
    fi

    # ── 2d. Kubescape (→ K8s compliance scan) ───────────────────────────
    echo ""
    echo -e "${BOLD}── Kubescape ──${RESET}"
    echo -e "${DIM}  Enterprise: Prisma Cloud CSPM, Aqua CSPM${RESET}"

    if command -v kubescape &>/dev/null; then
        kubescape scan framework nsa \
            --include-namespaces "$NAMESPACE" \
            --format json \
            --output "$REPORT_DIR/kubescape.json" 2>/dev/null || true

        if [[ -f "$REPORT_DIR/kubescape.json" ]]; then
            KS_SCORE=$(python3 -c "
import json
with open('$REPORT_DIR/kubescape.json') as f:
    data = json.load(f)
print(round(data.get('summaryDetails', {}).get('complianceScore', 0), 1))
" 2>/dev/null || echo "?")
            result PASS "Kubescape NSA framework" "CM-6" "Compliance score: ${KS_SCORE}%"
        else
            result WARN "Kubescape produced no output" "CM-6"
        fi
    else
        result SKIP "Kubescape scan" "CM-6" "kubescape not installed"
    fi

else
    echo ""
    echo -e "${BOLD}━━━ PART 2: SKIPPED (--skip-automated) ━━━${RESET}"
    echo ""
fi

# ════════════════════════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}━━━ SUMMARY ━━━${RESET}"
echo ""
echo -e "  ${GREEN}PASS${RESET}: $PASS"
echo -e "  ${YELLOW}WARN${RESET}: $WARN"
echo -e "  ${RED}FAIL${RESET}: $FAIL"
echo -e "  ${CYAN}SKIP${RESET}: $SKIP"
echo ""

TOTAL=$((PASS + WARN + FAIL))
if [[ "$TOTAL" -gt 0 ]]; then
    SCORE=$(( (PASS * 100) / TOTAL ))
    echo -e "  Score: ${BOLD}${SCORE}%${RESET} ($PASS/$TOTAL checks passed)"
else
    SCORE=0
    echo -e "  Score: ${BOLD}N/A${RESET} (no checks ran)"
fi

echo ""
echo -e "${DIM}  Manual checks validate the method.${RESET}"
echo -e "${DIM}  Automated checks validate at scale.${RESET}"
echo -e "${DIM}  The delta between them is the conversation.${RESET}"
echo ""

# ── Write report ────────────────────────────────────────────────────────

r ""
r "## Summary"
r ""
r "| | Count |"
r "|---|---|"
r "| PASS | $PASS |"
r "| WARN | $WARN |"
r "| FAIL | $FAIL |"
r "| SKIP | $SKIP |"
r "| **Score** | **${SCORE}%** |"
r ""
r "## Tool Mapping"
r ""
r "| Manual Check | Automated Equivalent | Enterprise Equivalent |"
r "|---|---|---|"
r "| curl headers | ZAP rules 10020-10038 | Veracode DAST |"
r "| curl cookies | ZAP rules 10010-10011 | Rapid7 InsightAppSec |"
r "| curl paths | Nuclei exposure templates | Tenable.io |"
r "| kubectl metadata probe | (no tool does this well) | Manual pentest |"
r "| kubectl SA token check | kubescape C-0034 | Prisma Cloud |"
r "| kubectl lateral movement | (no tool does this well) | Manual pentest |"
r "| (not in manual) | trivy image scan | Snyk Container, Prisma Cloud |"
r "| (not in manual) | kubescape NSA framework | Aqua CSPM |"
r ""
r "*Generated by validate-staging.sh — OSS-Copilot*"

if [[ "$WRITE_REPORT" == "true" ]]; then
    echo "$REPORT_LINES" > "$REPORT_DIR/validation-report.md"
    echo "Report: $REPORT_DIR/validation-report.md"
fi

# Always write the report for evidence
echo "$REPORT_LINES" > "$REPORT_DIR/validation-report.md"
echo "Evidence: $REPORT_DIR/"

# Exit code reflects findings
if [[ "$FAIL" -gt 0 ]]; then
    exit 1
elif [[ "$WARN" -gt 0 ]]; then
    exit 0
else
    exit 0
fi
