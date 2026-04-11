#!/usr/bin/env bash
# audit-vuln-scan-coverage.sh — L7 Application Layer vulnerability scanning audit
# NIST: RA-5 (vulnerability scanning), SA-11 (developer security testing)
# Usage: ./audit-vuln-scan-coverage.sh
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }
SECTION() { echo -e "\n${BLUE}═══ $* ═══${NC}"; }

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/vuln-scan-coverage-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================"
echo " L7 Vulnerability Scan Coverage Audit — RA-5 / SA-11"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

FINDINGS=0

# ─── OWASP ZAP ────────────────────────────────────────────────────────────────
SECTION "OWASP ZAP (DAST)"

ZAP_FOUND=false
for ZAP_PATH in /usr/share/zaproxy/zap.sh /opt/zaproxy/zap.sh /usr/local/bin/zap.sh /usr/bin/zaproxy; do
    if [[ -x "$ZAP_PATH" ]]; then
        ZAP_FOUND=true
        PASS "ZAP found at $ZAP_PATH"
        echo "ZAP_PATH=$ZAP_PATH" > "$EVIDENCE_DIR/zap-presence.txt"
        break
    fi
done

if command -v zap.sh &>/dev/null; then
    ZAP_FOUND=true
    PASS "ZAP found in PATH: $(which zap.sh)"
elif command -v zaproxy &>/dev/null; then
    ZAP_FOUND=true
    PASS "zaproxy found in PATH: $(which zaproxy)"
fi

if ! $ZAP_FOUND; then
    # Check Docker-based ZAP
    if docker images 2>/dev/null | grep -q "zaproxy\|owasp/zap"; then
        ZAP_FOUND=true
        PASS "ZAP Docker image present"
        docker images | grep -E "zaproxy|owasp/zap" >> "$EVIDENCE_DIR/zap-presence.txt" 2>/dev/null || true
    else
        FAIL "ZAP not found (binary or Docker)"
        INFO "Install: docker pull ghcr.io/zaproxy/zaproxy:stable"
        FINDINGS=$((FINDINGS + 1))
    fi
fi

# Check for recent ZAP scan results
ZAP_REPORT_FOUND=false
for REPORT_DIR in /tmp /opt/zap-reports "${HOME}/zap-reports" ./zap-reports; do
    if find "$REPORT_DIR" -name "*.html" -newer /etc/hostname 2>/dev/null | grep -qi "zap\|spider\|scan"; then
        ZAP_REPORT_FOUND=true
        PASS "Recent ZAP scan results found in $REPORT_DIR"
        find "$REPORT_DIR" -name "*.html" -newer /etc/hostname 2>/dev/null | head -3
        break
    fi
done

if ! $ZAP_REPORT_FOUND; then
    WARN "No recent ZAP scan results found — DAST may not be running regularly"
    FINDINGS=$((FINDINGS + 1))
fi

# CI gate check
echo ""
echo "Checking for ZAP in CI pipelines..."
ZAP_IN_CI=false
for CI_FILE in .github/workflows/*.yml .gitlab-ci.yml Jenkinsfile .circleci/config.yml; do
    if find . -name "$(basename "$CI_FILE")" 2>/dev/null | xargs grep -l "zap\|zaproxy" 2>/dev/null | head -1 | grep -q .; then
        ZAP_IN_CI=true
        PASS "ZAP found in CI configuration"
        break
    fi
done

$ZAP_IN_CI || { WARN "ZAP not found in CI pipeline files"; FINDINGS=$((FINDINGS + 1)); }

# ─── Trivy ────────────────────────────────────────────────────────────────────
SECTION "Trivy (Container + FS Scanning)"

if command -v trivy &>/dev/null; then
    TRIVY_VER=$(trivy --version 2>/dev/null | head -1)
    PASS "Trivy installed: $TRIVY_VER"
    echo "$TRIVY_VER" > "$EVIDENCE_DIR/trivy-version.txt"

    # CI gate check
    TRIVY_IN_CI=false
    for CI_DIR in . .github/workflows; do
        if find "$CI_DIR" -name "*.yml" -o -name "*.yaml" 2>/dev/null | xargs grep -l "trivy" 2>/dev/null | head -1 | grep -q .; then
            TRIVY_IN_CI=true
            PASS "Trivy found in CI pipeline"
            find "$CI_DIR" -name "*.yml" -o -name "*.yaml" 2>/dev/null | xargs grep -l "trivy" 2>/dev/null | head -3 | sed 's/^/  /'
            break
        fi
    done
    $TRIVY_IN_CI || { WARN "Trivy not found in CI pipeline — no automated image scanning gate"; FINDINGS=$((FINDINGS + 1)); }
else
    FAIL "Trivy not installed"
    INFO "Install: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.50.0"
    FINDINGS=$((FINDINGS + 1))
fi

# ─── Grype ────────────────────────────────────────────────────────────────────
SECTION "Grype (Image Vulnerability Scanner)"

if command -v grype &>/dev/null; then
    GRYPE_VER=$(grype version 2>/dev/null | head -1)
    PASS "Grype installed: $GRYPE_VER"
    echo "$GRYPE_VER" > "$EVIDENCE_DIR/grype-version.txt"

    # Check for scheduled scan
    if crontab -l 2>/dev/null | grep -qi "grype"; then
        PASS "Grype scheduled scan found in crontab"
    else
        WARN "No Grype cron schedule found — scans may not be automated"
        FINDINGS=$((FINDINGS + 1))
    fi
else
    WARN "Grype not installed (optional — Trivy preferred)"
    INFO "Install: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
fi

# ─── Semgrep ──────────────────────────────────────────────────────────────────
SECTION "Semgrep (SAST)"

if command -v semgrep &>/dev/null; then
    SEMGREP_VER=$(semgrep --version 2>/dev/null | head -1)
    PASS "Semgrep installed: $SEMGREP_VER"
    echo "$SEMGREP_VER" > "$EVIDENCE_DIR/semgrep-version.txt"

    # Check for .semgrep.yml or semgrep config
    SEMGREP_CONFIG=false
    for CONFIG in .semgrep.yml .semgrep.yaml semgrep.yml; do
        if [[ -f "$CONFIG" ]]; then
            SEMGREP_CONFIG=true
            PASS "Semgrep config found: $CONFIG"
        fi
    done

    # Check in CI
    if find . -name "*.yml" -o -name "*.yaml" 2>/dev/null | xargs grep -l "semgrep" 2>/dev/null | head -1 | grep -q .; then
        PASS "Semgrep found in CI pipeline"
        find . -name "*.yml" -o -name "*.yaml" 2>/dev/null | xargs grep -l "semgrep" 2>/dev/null | head -3 | sed 's/^/  /'
    else
        $SEMGREP_CONFIG || { WARN "Semgrep not in CI and no config file found"; FINDINGS=$((FINDINGS + 1)); }
    fi

    # Check for pre-commit hook
    if [[ -f .pre-commit-config.yaml ]] && grep -q "semgrep" .pre-commit-config.yaml 2>/dev/null; then
        PASS "Semgrep in pre-commit hooks"
    else
        WARN "Semgrep not in pre-commit hooks — developers can bypass"
        FINDINGS=$((FINDINGS + 1))
    fi
else
    FAIL "Semgrep not installed"
    INFO "Install: pip install semgrep"
    FINDINGS=$((FINDINGS + 1))
fi

# ─── kube-bench ───────────────────────────────────────────────────────────────
SECTION "kube-bench (CIS Kubernetes Benchmark)"

if command -v kube-bench &>/dev/null; then
    PASS "kube-bench installed: $(kube-bench version 2>/dev/null | head -1)"
    echo "kube-bench installed" > "$EVIDENCE_DIR/kube-bench-presence.txt"
elif docker images 2>/dev/null | grep -q "kube-bench\|aquasec/kube-bench"; then
    PASS "kube-bench Docker image present"
    docker images | grep -E "kube-bench|aquasec/kube-bench" > "$EVIDENCE_DIR/kube-bench-presence.txt"
else
    WARN "kube-bench not found — CIS Kubernetes benchmark cannot be run"
    FINDINGS=$((FINDINGS + 1))
    INFO "Install: docker pull aquasec/kube-bench:latest"
fi

# Check for recent kube-bench results
BENCH_FOUND=false
for BENCH_DIR in /tmp /var/log "${HOME}"; do
    if find "$BENCH_DIR" -name "kube-bench-*.txt" -o -name "kube-bench-*.json" 2>/dev/null | head -1 | grep -q .; then
        BENCH_FOUND=true
        LATEST=$(find "$BENCH_DIR" -name "kube-bench-*.txt" -o -name "kube-bench-*.json" 2>/dev/null | sort | tail -1)
        PASS "Recent kube-bench results: $LATEST"
        BENCH_AGE=$(( ( $(date +%s) - $(stat -c %Y "$LATEST" 2>/dev/null || echo "0") ) / 86400 ))
        [[ $BENCH_AGE -gt 30 ]] && WARN "kube-bench results are ${BENCH_AGE} days old — re-run recommended"
        break
    fi
done

$BENCH_FOUND || { WARN "No recent kube-bench results found — CIS benchmark not recently run"; FINDINGS=$((FINDINGS + 1)); }

# ─── Coverage Summary ─────────────────────────────────────────────────────────
echo ""
echo "======================================================"
echo " Scan Coverage Summary"
echo "======================================================"
{
    echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "audit: vuln-scan-coverage"
    echo "findings: $FINDINGS"
    echo ""
    echo "Coverage matrix:"
    command -v trivy &>/dev/null && echo "  [PRESENT] Trivy — container/FS scanning" || echo "  [MISSING] Trivy — container/FS scanning"
    command -v semgrep &>/dev/null && echo "  [PRESENT] Semgrep — SAST" || echo "  [MISSING] Semgrep — SAST"
    $ZAP_FOUND && echo "  [PRESENT] ZAP — DAST" || echo "  [MISSING] ZAP — DAST"
    command -v grype &>/dev/null && echo "  [PRESENT] Grype — image scanning" || echo "  [MISSING] Grype — image scanning"
    command -v kube-bench &>/dev/null && echo "  [PRESENT] kube-bench — CIS benchmark" || echo "  [MISSING] kube-bench — CIS benchmark"
    echo ""
    echo "evidence_dir: $EVIDENCE_DIR"
} | tee "$EVIDENCE_DIR/audit-summary.txt"

[[ $FINDINGS -gt 0 ]] && exit 1 || exit 0
