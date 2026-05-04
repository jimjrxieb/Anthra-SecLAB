#!/usr/bin/env bash
# audit-suricata-config.sh — Suricata IDS/IPS Configuration Audit
# NIST Controls: SI-3 (Malicious Code Protection), SI-4 (System Monitoring)
#
# CSF 2.0: DE.CM-01 (Networks monitored)
# CIS v8: 13.3 (Deploy Network-Based IPS)
# NIST: SI-3 (Malicious Code Protection)
#
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'
PASS="${GREEN}[PASS]${NC}"; WARN="${YELLOW}[WARN]${NC}"; FAIL="${RED}[FAIL]${NC}"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/suricata-audit-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"
LOG="$EVIDENCE_DIR/audit.log"

pass_count=0; warn_count=0; fail_count=0

log() { echo -e "$1" | tee -a "$LOG"; }
pass() { log "${PASS} $1"; ((pass_count++)); }
warn() { log "${WARN} $1"; ((warn_count++)); }
fail() { log "${FAIL} $1"; ((fail_count++)); }

# Locate suricata.yaml — common paths
find_suricata_yaml() {
  for p in /etc/suricata/suricata.yaml /usr/local/etc/suricata/suricata.yaml \
            /opt/suricata/etc/suricata.yaml /etc/suricata.yaml; do
    [[ -f "$p" ]] && echo "$p" && return
  done
  echo ""
}

# Locate EVE log — common paths
find_eve_log() {
  for p in /var/log/suricata/eve.json /var/log/suricata/fast.log \
            /opt/suricata/var/log/suricata/eve.json; do
    [[ -f "$p" ]] && echo "$p" && return
  done
  echo ""
}

log "${BOLD}========================================${NC}"
log "${BOLD}Layer 3 — Suricata Configuration Audit${NC}"
log "Timestamp: $(date)"
log "Host: $(hostname)"
log "Evidence: $EVIDENCE_DIR"
log "${BOLD}========================================${NC}"

# ─── Check 1: Suricata process running ───────────────────────────────────────
log "\n${BOLD}--- Process Status ---${NC}"
if pgrep -x suricata &>/dev/null; then
  SURICATA_PID=$(pgrep -x suricata | head -1)
  pass "SI-4: Suricata is running (PID: ${SURICATA_PID})"
  ps aux | grep -v grep | grep suricata > "$EVIDENCE_DIR/suricata-process.txt" || true
else
  fail "SI-4: Suricata is NOT running — IDS is blind"
  log "  To start: sudo systemctl start suricata"
fi

# Check version
if command -v suricata &>/dev/null; then
  suricata --build-info > "$EVIDENCE_DIR/suricata-build-info.txt" 2>&1 || true
  SURICATA_VER=$(suricata --build-info 2>/dev/null | grep "^Suricata version" | awk '{print $NF}' || echo "unknown")
  log "  Version: ${SURICATA_VER}"
fi

# ─── Check 2: EVE JSON output enabled ────────────────────────────────────────
log "\n${BOLD}--- EVE JSON Configuration ---${NC}"
SURICATA_YAML=$(find_suricata_yaml)
if [[ -z "$SURICATA_YAML" ]]; then
  fail "SI-4: suricata.yaml not found at any standard path"
else
  pass "Config file found: ${SURICATA_YAML}"
  cp "$SURICATA_YAML" "$EVIDENCE_DIR/suricata.yaml.evidence" 2>/dev/null || true

  # Check eve-log enabled
  if grep -A5 "eve-log:" "$SURICATA_YAML" | grep -q "enabled: yes"; then
    pass "SI-4: EVE JSON logging is enabled"
  else
    fail "SI-4: EVE JSON logging is NOT enabled — SIEM integration impossible without this"
  fi

  # Check eve-log types include alert
  if grep -q "alert" "$SURICATA_YAML"; then
    pass "SI-4: Alert type included in EVE JSON output"
  else
    fail "SI-4: Alert type missing from EVE JSON output — IDS alerts not logged"
  fi

  # Check dns logging
  if grep -q "- dns" "$SURICATA_YAML"; then
    pass "SI-4: DNS events included in EVE JSON output"
  else
    warn "SI-4: DNS events not found in EVE JSON config — DNS visibility gap"
  fi

  # Check tls logging
  if grep -q "- tls" "$SURICATA_YAML"; then
    pass "SI-4: TLS metadata included in EVE JSON output"
  else
    warn "SI-4: TLS metadata not in EVE JSON — encrypted traffic inspection gap"
  fi

  # Check HOME_NET is customized
  HOME_NET_LINE=$(grep "HOME_NET" "$SURICATA_YAML" | head -1 || echo "")
  if echo "$HOME_NET_LINE" | grep -qE "192\.168|10\.|172\.(1[6-9]|2[0-9]|3[01])"; then
    pass "SI-4: HOME_NET is configured with private RFC1918 ranges"
    echo "$HOME_NET_LINE" >> "$EVIDENCE_DIR/home-net.txt"
  else
    warn "SI-4: HOME_NET may be using default value — verify it matches your network"
    echo "$HOME_NET_LINE" >> "$EVIDENCE_DIR/home-net.txt"
  fi
fi

# ─── Check 3: Rule count ─────────────────────────────────────────────────────
log "\n${BOLD}--- Rule Health ---${NC}"
RULE_DIRS=("/etc/suricata/rules" "/var/lib/suricata/rules" "/usr/local/etc/suricata/rules")
TOTAL_RULES=0
for RULE_DIR in "${RULE_DIRS[@]}"; do
  if [[ -d "$RULE_DIR" ]]; then
    COUNT=$(find "$RULE_DIR" -name "*.rules" -exec grep -c "^alert\|^drop\|^pass" {} \; 2>/dev/null | \
            awk '{sum+=$1} END {print sum+0}')
    TOTAL_RULES=$((TOTAL_RULES + COUNT))
    log "  Rules in ${RULE_DIR}: ${COUNT}"
  fi
done

echo "Total rules: ${TOTAL_RULES}" > "$EVIDENCE_DIR/rule-count.txt"
if [[ $TOTAL_RULES -ge 30000 ]]; then
  pass "SI-3: Rule count is ${TOTAL_RULES} (>=30K healthy baseline)"
elif [[ $TOTAL_RULES -ge 5000 ]]; then
  warn "SI-3: Rule count is ${TOTAL_RULES} — below 30K healthy baseline, run suricata-update"
elif [[ $TOTAL_RULES -gt 0 ]]; then
  fail "SI-3: Rule count is only ${TOTAL_RULES} — critically low, IDS detection coverage is minimal"
else
  fail "SI-3: No rules found — IDS is running but has nothing to detect"
fi

# ─── Check 4: Custom local.rules ─────────────────────────────────────────────
log "\n${BOLD}--- Custom Rules ---${NC}"
LOCAL_RULES_PATHS=("/etc/suricata/rules/local.rules" "/var/lib/suricata/rules/local.rules")
LOCAL_FOUND=false
for LR in "${LOCAL_RULES_PATHS[@]}"; do
  if [[ -f "$LR" ]]; then
    LOCAL_FOUND=true
    LOCAL_COUNT=$(grep -c "^alert\|^drop\|^pass" "$LR" 2>/dev/null || echo "0")
    if [[ $LOCAL_COUNT -gt 0 ]]; then
      pass "SI-3: Custom local.rules exists with ${LOCAL_COUNT} active rule(s): ${LR}"
      cp "$LR" "$EVIDENCE_DIR/local.rules.evidence" 2>/dev/null || true
    else
      warn "SI-3: local.rules exists but has no active rules (all commented?): ${LR}"
    fi
    break
  fi
done
if [[ "$LOCAL_FOUND" == false ]]; then
  warn "SI-3: No local.rules file found — site-specific detections not deployed"
fi

# ─── Check 5: Rule freshness ─────────────────────────────────────────────────
log "\n${BOLD}--- Rule Freshness ---${NC}"
RULES_MTIME=""
for RULE_DIR in "${RULE_DIRS[@]}"; do
  if [[ -d "$RULE_DIR" ]]; then
    NEWEST=$(find "$RULE_DIR" -name "*.rules" -printf '%T@\n' 2>/dev/null | sort -rn | head -1 || echo "0")
    RULES_MTIME=$(echo "$NEWEST" | cut -d. -f1)
    break
  fi
done

if [[ -n "$RULES_MTIME" ]] && [[ "$RULES_MTIME" -gt 0 ]]; then
  NOW=$(date +%s)
  AGE_DAYS=$(( (NOW - RULES_MTIME) / 86400 ))
  echo "Rule file age: ${AGE_DAYS} days" >> "$EVIDENCE_DIR/rule-freshness.txt"
  if [[ $AGE_DAYS -le 7 ]]; then
    pass "SI-3: Rules updated within 7 days (${AGE_DAYS} days old)"
  elif [[ $AGE_DAYS -le 30 ]]; then
    warn "SI-3: Rules are ${AGE_DAYS} days old — update recommended (>7 days)"
  else
    fail "SI-3: Rules are ${AGE_DAYS} days old — stale signatures miss current threats"
  fi
fi

# ─── Check 6: Live detection test ────────────────────────────────────────────
log "\n${BOLD}--- Live Detection Test ---${NC}"
log "  Running: curl http://testmynids.org/uid/index.html"
log "  This triggers ET OPEN rule 2100498 (TESTING NIDS)"

EVE_LOG=$(find_eve_log)
PRE_COUNT=0
if [[ -n "$EVE_LOG" ]] && [[ -f "$EVE_LOG" ]]; then
  PRE_COUNT=$(wc -l < "$EVE_LOG" 2>/dev/null || echo "0")
fi

if command -v curl &>/dev/null; then
  curl -s --max-time 10 http://testmynids.org/uid/index.html -o /dev/null 2>/dev/null || \
    warn "curl failed — network may be blocked, manual verification needed"
  sleep 2

  if [[ -n "$EVE_LOG" ]] && [[ -f "$EVE_LOG" ]]; then
    POST_COUNT=$(wc -l < "$EVE_LOG" 2>/dev/null || echo "0")
    NEW_ALERTS=$((POST_COUNT - PRE_COUNT))

    # Look for the test alert specifically
    DETECTION=$(tail -100 "$EVE_LOG" | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line.strip())
        if e.get('event_type') == 'alert' and 'testmynids' in str(e.get('alert',{}).get('signature','')).lower():
            print(e.get('alert',{}).get('signature','?'))
            break
    except: pass
" 2>/dev/null || echo "")

    if [[ -n "$DETECTION" ]]; then
      pass "SI-4: Live detection working — alert triggered: ${DETECTION}"
    elif [[ $NEW_ALERTS -gt 0 ]]; then
      pass "SI-4: ${NEW_ALERTS} new eve.json entries after test — detection appears active"
    else
      fail "SI-4: No new alerts after testmynids.org request — detection may be broken"
    fi
    tail -50 "$EVE_LOG" > "$EVIDENCE_DIR/eve-json-tail.txt" 2>/dev/null || true
  else
    warn "SI-4: eve.json not found — cannot verify live detection"
    log "  Expected paths: /var/log/suricata/eve.json"
  fi
else
  warn "curl not available — skipping live detection test"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
log "\n${BOLD}========================================${NC}"
log "${BOLD}Summary${NC}"
log "  ${GREEN}PASS${NC}: ${pass_count}"
log "  ${YELLOW}WARN${NC}: ${warn_count}"
log "  ${RED}FAIL${NC}: ${fail_count}"
log "Evidence: $EVIDENCE_DIR"
log "${BOLD}========================================${NC}"

[[ $fail_count -gt 0 ]] && exit 1 || exit 0
