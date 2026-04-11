#!/usr/bin/env bash
# audit-secrets-exposure.sh — L6 Presentation Layer secrets exposure audit
# NIST: SC-28 (protection of info at rest), SI-10 (info input validation)
# Usage: ./audit-secrets-exposure.sh [--dir <path>]
#        Runs: gitleaks, ConfigMap scan, .env git tracking, pre-commit hook check
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }

SCAN_DIR="$(pwd)"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir) SCAN_DIR="$2"; shift 2 ;;
        *) shift ;;
    esac
done

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/secrets-exposure-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================"
echo " L6 Secrets Exposure Audit — SC-28 / SI-10"
echo " Scan directory: ${SCAN_DIR}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

FINDINGS=0

# ─── gitleaks ─────────────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════"
echo " gitleaks: Secret Detection in Repository"
echo "═══════════════════════════════════════════════════════"

if ! command -v gitleaks &>/dev/null; then
    WARN "gitleaks not installed — skipping git history scan"
    INFO "Install: https://github.com/gitleaks/gitleaks"
    INFO "  brew install gitleaks"
    INFO "  or: docker run ghcr.io/gitleaks/gitleaks:latest detect --source=."
else
    GITLEAKS_REPORT="${EVIDENCE_DIR}/gitleaks-report.json"

    # Detect mode: scan working directory (staged + unstaged + committed)
    INFO "Running gitleaks detect on: ${SCAN_DIR}"
    if gitleaks detect \
        --source="$SCAN_DIR" \
        --report-path="$GITLEAKS_REPORT" \
        --report-format=json \
        --exit-code=1 \
        2>/dev/null; then
        PASS "gitleaks: No secrets detected in repository"
    else
        LEAK_COUNT=$(python3 -c "
import json
try:
    with open('${GITLEAKS_REPORT}') as f:
        data = json.load(f)
    print(len(data) if isinstance(data, list) else 'unknown')
except:
    print('unknown')
" 2>/dev/null || echo "unknown")

        FAIL "gitleaks: ${LEAK_COUNT} secret(s) detected"
        INFO "WHY: Committed secrets persist in git history and cannot be revoked without history rewrite"
        INFO "Report: ${GITLEAKS_REPORT}"

        # Show summary of leak types
        python3 -c "
import json
try:
    with open('${GITLEAKS_REPORT}') as f:
        leaks = json.load(f)
    rule_counts = {}
    for leak in leaks:
        rule = leak.get('RuleID', leak.get('ruleId', 'unknown'))
        rule_counts[rule] = rule_counts.get(rule, 0) + 1
    for rule, count in sorted(rule_counts.items(), key=lambda x: -x[1]):
        print(f'  {count}x {rule}')
except Exception as e:
    print(f'  Could not parse report: {e}')
" 2>/dev/null || true

        FINDINGS=$((FINDINGS + 1))
    fi
fi
echo ""

# ─── K8s ConfigMap Secret Patterns ────────────────────────────────────────
echo "═══════════════════════════════════════════════════════"
echo " K8s ConfigMap: Secret-like Data Check"
echo "═══════════════════════════════════════════════════════"

SECRET_PATTERN_KEYS=(
    "password" "passwd" "secret" "api_key" "apikey" "api-key"
    "token" "private_key" "private-key" "credentials" "credential"
    "database_url" "db_password" "aws_secret" "aws_access_key"
)

if ! command -v kubectl &>/dev/null; then
    WARN "kubectl not found — skipping ConfigMap checks"
elif ! kubectl cluster-info &>/dev/null 2>&1; then
    WARN "kubectl not connected to a cluster — skipping ConfigMap checks"
else
    CM_REPORT="${EVIDENCE_DIR}/configmap-secrets.txt"
    : > "$CM_REPORT"

    CONFIGMAPS=$(kubectl get configmaps -A -o json 2>/dev/null || echo '{"items":[]}')
    CM_COUNT=$(echo "$CONFIGMAPS" | python3 -c "
import json,sys
print(len(json.load(sys.stdin).get('items',[])))
" 2>/dev/null || echo "0")

    INFO "ConfigMaps found: ${CM_COUNT}"

    SUSPICIOUS_COUNT=0
    echo "$CONFIGMAPS" | python3 -c "
import json,sys,re

data = json.load(sys.stdin)
secret_keys = [
    'password','passwd','secret','api_key','apikey','api-key',
    'token','private_key','private-key','credentials','credential',
    'database_url','db_password','aws_secret','aws_access_key',
    'client_secret','refresh_token','access_token','auth_token'
]

# Pattern for values that look like secrets (not placeholder text)
secret_value_pattern = re.compile(
    r'^(?!.*<.*>)(?!.*\$\{)(?!.*example)(?!.*placeholder)'
    r'.{8,}$',  # at least 8 chars, not obviously a template
    re.IGNORECASE
)

findings = []
for cm in data.get('items', []):
    ns = cm['metadata']['namespace']
    name = cm['metadata']['name']
    cm_data = cm.get('data', {}) or {}

    for key, value in cm_data.items():
        key_lower = key.lower().replace('-','_')
        if any(sk in key_lower for sk in secret_keys):
            if value and secret_value_pattern.match(str(value)):
                # Mask the value for output
                masked = value[:4] + '****' if len(value) > 4 else '****'
                findings.append(f'{ns}/{name} key={key} value={masked}')

if findings:
    print(f'SUSPICIOUS_COUNT:{len(findings)}')
    for f in findings:
        print(f'  FINDING: {f}')
else:
    print('SUSPICIOUS_COUNT:0')
" 2>/dev/null | tee -a "$CM_REPORT" | while IFS= read -r line; do
        if echo "$line" | grep -q "SUSPICIOUS_COUNT:0"; then
            PASS "No secret-like keys found in ConfigMaps"
        elif echo "$line" | grep -q "SUSPICIOUS_COUNT:"; then
            COUNT=$(echo "$line" | cut -d: -f2)
            FAIL "Found ${COUNT} ConfigMap(s) with secret-like keys"
            INFO "WHY: ConfigMaps are not encrypted — use K8s Secrets + ESO for sensitive data"
            FINDINGS=$((FINDINGS + 1))
        elif echo "$line" | grep -q "FINDING:"; then
            INFO "${line#*FINDING: }"
        fi
    done || WARN "Could not parse ConfigMap data"
fi
echo ""

# ─── .env Files Tracked in Git ────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════"
echo " Git-Tracked .env Files"
echo "═══════════════════════════════════════════════════════"

ENV_FILE_REPORT="${EVIDENCE_DIR}/tracked-env-files.txt"
: > "$ENV_FILE_REPORT"

if [[ -d "${SCAN_DIR}/.git" ]] || git -C "$SCAN_DIR" rev-parse --git-dir &>/dev/null 2>&1; then
    TRACKED_ENV=$(git -C "$SCAN_DIR" ls-files 2>/dev/null | grep -E '\.env$|\.env\.' || true)

    if [[ -n "$TRACKED_ENV" ]]; then
        ENV_COUNT=$(echo "$TRACKED_ENV" | grep -c '.' || echo "0")
        FAIL "${ENV_COUNT} .env file(s) tracked in git"
        INFO "WHY: .env files contain secrets that should NEVER be committed to source control"
        INFO "Fix: git rm --cached <file> && echo '<file>' >> .gitignore"
        echo "$TRACKED_ENV" | while IFS= read -r env_file; do
            INFO "  Tracked: $env_file"
            echo "TRACKED: $env_file" >> "$ENV_FILE_REPORT"
        done
        FINDINGS=$((FINDINGS + 1))
    else
        PASS "No .env files tracked in git"
        echo "PASS: No .env files tracked" >> "$ENV_FILE_REPORT"
    fi

    # Also check for .env in git history (even if removed from index)
    HISTORY_ENV=$(git -C "$SCAN_DIR" log --all --full-history --name-only \
        --pretty=format: 2>/dev/null \
        | grep -E '\.env$|\.env\.' | sort -u || true)

    if [[ -n "$HISTORY_ENV" ]]; then
        WARN ".env files found in git history (even if currently removed):"
        echo "$HISTORY_ENV" | head -10 | while IFS= read -r f; do
            INFO "  History: $f"
            echo "HISTORY: $f" >> "$ENV_FILE_REPORT"
        done
        INFO "WHY: Git history preserves deleted files — rotate any secrets that were committed"
        INFO "Fix: git filter-repo --path <file> --invert-paths (rewrites history)"
    fi
else
    WARN "Not a git repository: ${SCAN_DIR} — skipping git tracking checks"
fi
echo ""

# ─── Pre-commit Hook Check ────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════"
echo " Pre-commit Hook: Secret Detection Configuration"
echo "═══════════════════════════════════════════════════════"

HOOK_REPORT="${EVIDENCE_DIR}/pre-commit-hooks.txt"
: > "$HOOK_REPORT"

# Check .pre-commit-config.yaml
PRECOMMIT_CONFIG="${SCAN_DIR}/.pre-commit-config.yaml"
if [[ -f "$PRECOMMIT_CONFIG" ]]; then
    INFO "Found .pre-commit-config.yaml"
    echo "FOUND: .pre-commit-config.yaml" >> "$HOOK_REPORT"

    # Check for secret detection hooks
    HAS_GITLEAKS=$(grep -l "gitleaks" "$PRECOMMIT_CONFIG" 2>/dev/null || true)
    HAS_DETECT_SECRETS=$(grep -l "detect-secrets" "$PRECOMMIT_CONFIG" 2>/dev/null || true)
    HAS_TRUFFLEHOG=$(grep -l "trufflehog" "$PRECOMMIT_CONFIG" 2>/dev/null || true)

    if [[ -n "$HAS_GITLEAKS" || -n "$HAS_DETECT_SECRETS" || -n "$HAS_TRUFFLEHOG" ]]; then
        PASS "Secret detection hook configured in .pre-commit-config.yaml"
        grep -E "gitleaks|detect-secrets|trufflehog" "$PRECOMMIT_CONFIG" 2>/dev/null \
            | while IFS= read -r line; do
                INFO "  $line"
                echo "$line" >> "$HOOK_REPORT"
            done
    else
        WARN ".pre-commit-config.yaml exists but no secret detection hook found"
        INFO "WHY: Without secret scanning in pre-commit, developers can accidentally commit secrets"
        INFO "Fix: Add gitleaks hook — see templates/sops/.sops.yaml for example"
        FINDINGS=$((FINDINGS + 1))
    fi
else
    WARN "No .pre-commit-config.yaml found in ${SCAN_DIR}"
    INFO "WHY: Pre-commit hooks are the last line of defense before secrets hit git"
    INFO "Fix: pip install pre-commit && pre-commit install"
    INFO "     Add gitleaks hook: https://github.com/gitleaks/gitleaks#pre-commit"
    echo "MISSING: .pre-commit-config.yaml" >> "$HOOK_REPORT"
    FINDINGS=$((FINDINGS + 1))
fi

# Check .git/hooks/pre-commit exists and is executable
GIT_HOOK="${SCAN_DIR}/.git/hooks/pre-commit"
if [[ -f "$GIT_HOOK" && -x "$GIT_HOOK" ]]; then
    PASS "Git pre-commit hook installed and executable"
    echo "PASS: .git/hooks/pre-commit exists and executable" >> "$HOOK_REPORT"
elif [[ -f "$GIT_HOOK" ]]; then
    WARN "Git pre-commit hook exists but not executable"
    INFO "Fix: chmod +x .git/hooks/pre-commit"
else
    WARN "No .git/hooks/pre-commit hook installed"
    INFO "Fix: pre-commit install (if using pre-commit framework)"
    echo "MISSING: .git/hooks/pre-commit" >> "$HOOK_REPORT"
fi
echo ""

# ─── detect-secrets baseline check ───────────────────────────────────────
echo "═══════════════════════════════════════════════════════"
echo " detect-secrets: Baseline Check"
echo "═══════════════════════════════════════════════════════"

if command -v detect-secrets &>/dev/null; then
    INFO "detect-secrets found — scanning ${SCAN_DIR}"
    DS_REPORT="${EVIDENCE_DIR}/detect-secrets-report.json"
    detect-secrets scan --base64-limit 4 "$SCAN_DIR" > "$DS_REPORT" 2>/dev/null || true

    DS_COUNT=$(python3 -c "
import json
try:
    with open('${DS_REPORT}') as f:
        data = json.load(f)
    results = data.get('results', {})
    total = sum(len(v) for v in results.values())
    print(total)
except:
    print(0)
" 2>/dev/null || echo "0")

    if [[ "$DS_COUNT" -gt 0 ]]; then
        FAIL "detect-secrets: ${DS_COUNT} potential secret(s) found"
        INFO "Report: ${DS_REPORT}"
        FINDINGS=$((FINDINGS + 1))
    else
        PASS "detect-secrets: No secrets found"
    fi
elif command -v detect-secrets-hook &>/dev/null; then
    INFO "detect-secrets-hook available (pre-commit mode)"
else
    WARN "detect-secrets not installed"
    INFO "Install: pip install detect-secrets"
fi
echo ""

# ─── Summary ──────────────────────────────────────────────────────────────
echo "======================================================"
echo " Secrets Exposure Audit Summary"
echo " Total findings: ${FINDINGS}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"

cat > "${EVIDENCE_DIR}/summary.txt" <<EOF
L6 Secrets Exposure Audit Summary
Date: $(date)
Scan Directory: ${SCAN_DIR}
Total Findings: ${FINDINGS}
NIST Controls: SC-28 (Protection of Information at Rest), SI-10 (Info Input Validation)

Files:
- gitleaks-report.json: gitleaks secret scan results
- configmap-secrets.txt: K8s ConfigMap secret-like key findings
- tracked-env-files.txt: .env files tracked in git
- pre-commit-hooks.txt: pre-commit hook configuration check
- detect-secrets-report.json: detect-secrets scan results
EOF

if [[ $FINDINGS -gt 0 ]]; then
    echo ""
    WARN "Remediation: see 02-fixers/fix-plaintext-secrets.sh"
    WARN "Priority: rotate any exposed secrets IMMEDIATELY, then fix the process"
fi
