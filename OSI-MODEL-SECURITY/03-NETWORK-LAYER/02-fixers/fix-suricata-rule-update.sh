#!/usr/bin/env bash
# fix-suricata-rule-update.sh — Update Suricata Rules and Deploy Custom Signatures
# NIST Controls: SI-3 (Malicious Code Protection), SI-5 (Security Alerts)
# Covers: suricata-update (standard), so-rule-update (Security Onion)
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/suricata-rule-update-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"
LOG="$EVIDENCE_DIR/update.log"

log() { echo -e "$1" | tee -a "$LOG"; }
log_step() { log "\n${BOLD}[STEP $1]${NC} $2"; }
log_ok()   { log "${GREEN}[OK]${NC}    $1"; }
log_warn() { log "${YELLOW}[WARN]${NC}  $1"; }
log_fail() { log "${RED}[FAIL]${NC}  $1"; }

log "${BOLD}========================================${NC}"
log "${BOLD}Suricata Rule Update — NIST SI-3${NC}"
log "Timestamp: $(date)"
log "Evidence: $EVIDENCE_DIR"
log "${BOLD}========================================${NC}"

# ─── Pre-flight: root check ───────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  log_fail "Must run as root (sudo $0)"
  exit 1
fi

# ─── Locate config and rules ─────────────────────────────────────────────────
SURICATA_YAML=""
for p in /etc/suricata/suricata.yaml /usr/local/etc/suricata/suricata.yaml; do
  [[ -f "$p" ]] && SURICATA_YAML="$p" && break
done

RULES_DIR=""
for p in /etc/suricata/rules /var/lib/suricata/rules /usr/local/etc/suricata/rules; do
  [[ -d "$p" ]] && RULES_DIR="$p" && break
done

LOCAL_RULES="${RULES_DIR}/local.rules"
TEMPLATE_LOCAL="$(dirname "$0")/../03-templates/suricata/local.rules"

# ─── STEP 1: Record pre-fix rule count ───────────────────────────────────────
log_step 1 "Recording pre-update rule count"
PRE_COUNT=0
if [[ -n "$RULES_DIR" ]] && [[ -d "$RULES_DIR" ]]; then
  PRE_COUNT=$(find "$RULES_DIR" -name "*.rules" -exec grep -c "^alert\|^drop\|^pass" {} \; 2>/dev/null | \
              awk '{sum+=$1} END {print sum+0}')
  log_ok "Pre-update rule count: ${PRE_COUNT}"
else
  log_warn "Rules directory not found — count will start from 0"
fi
echo "pre_count=${PRE_COUNT}" > "$EVIDENCE_DIR/rule-counts.txt"

# ─── STEP 2: Run rule update ─────────────────────────────────────────────────
log_step 2 "Running rule update"

if command -v so-rule-update &>/dev/null; then
  # Security Onion environment
  log "  Detected Security Onion — using so-rule-update"
  so-rule-update 2>&1 | tee "$EVIDENCE_DIR/so-rule-update.log" || {
    log_warn "so-rule-update returned non-zero — check $EVIDENCE_DIR/so-rule-update.log"
  }

elif command -v suricata-update &>/dev/null; then
  # Standard suricata-update
  log "  Using suricata-update"

  # Enable ET Open if not already configured
  if suricata-update list-enabled-sources 2>/dev/null | grep -q "et/open"; then
    log "  ET Open already enabled"
  else
    log "  Enabling ET Open rule source"
    suricata-update enable-source et/open 2>&1 | tee -a "$EVIDENCE_DIR/suricata-update.log" || true
  fi

  suricata-update 2>&1 | tee "$EVIDENCE_DIR/suricata-update.log" || {
    log_warn "suricata-update returned non-zero — check $EVIDENCE_DIR/suricata-update.log"
  }
  log_ok "suricata-update completed"

else
  log_warn "Neither suricata-update nor so-rule-update found"
  log "  Install with: pip3 install suricata-update"
  log "  Continuing with custom rule deployment only"
fi

# ─── STEP 3: Deploy custom local.rules ───────────────────────────────────────
log_step 3 "Deploying custom local.rules"

if [[ -z "$RULES_DIR" ]]; then
  log_warn "Rules directory not found — cannot deploy local.rules"
else
  # Backup existing local.rules
  if [[ -f "$LOCAL_RULES" ]]; then
    BACKUP="${LOCAL_RULES}.backup-${TIMESTAMP}"
    cp "$LOCAL_RULES" "$BACKUP"
    log_ok "Backup: ${BACKUP}"
    cp "$LOCAL_RULES" "$EVIDENCE_DIR/local.rules.pre-update"
  fi

  # Deploy from template if available
  if [[ -f "$TEMPLATE_LOCAL" ]]; then
    cp "$TEMPLATE_LOCAL" "$LOCAL_RULES"
    log_ok "Deployed local.rules from template: ${TEMPLATE_LOCAL}"
    CUSTOM_COUNT=$(grep -c "^alert\|^drop\|^pass" "$LOCAL_RULES" 2>/dev/null || echo "0")
    log_ok "  Custom rules active: ${CUSTOM_COUNT}"
  else
    log_warn "Template not found at ${TEMPLATE_LOCAL}"
    log "  Expected: 03-templates/suricata/local.rules"
    # Ensure local.rules at minimum exists and is referenced
    if [[ ! -f "$LOCAL_RULES" ]]; then
      touch "$LOCAL_RULES"
      log "  Created empty ${LOCAL_RULES}"
    fi
  fi

  # Verify local.rules is referenced in suricata.yaml
  if [[ -n "$SURICATA_YAML" ]]; then
    if grep -q "local.rules" "$SURICATA_YAML"; then
      log_ok "local.rules is referenced in ${SURICATA_YAML}"
    else
      log_warn "local.rules not referenced in suricata.yaml — adding reference"
      echo "  - local.rules" >> "$SURICATA_YAML"
    fi
  fi
fi

# ─── STEP 4: Reload Suricata ─────────────────────────────────────────────────
log_step 4 "Reloading Suricata rules"

if pgrep -x suricata &>/dev/null; then
  SURICATA_PID=$(pgrep -x suricata | head -1)
  log "  Sending USR2 signal to PID ${SURICATA_PID} (live rule reload)"
  kill -USR2 "$SURICATA_PID" 2>/dev/null || {
    log_warn "kill -USR2 failed — attempting systemctl restart"
    systemctl restart suricata 2>/dev/null || service suricata restart 2>/dev/null || {
      log_warn "Could not restart Suricata — start manually: sudo systemctl start suricata"
    }
  }
  sleep 3
  if pgrep -x suricata &>/dev/null; then
    log_ok "Suricata is running after reload"
  else
    log_fail "Suricata is NOT running after reload — check /var/log/suricata/suricata.log"
  fi
else
  log_warn "Suricata is not running — starting service"
  systemctl start suricata 2>/dev/null || service suricata start 2>/dev/null || {
    log_warn "Could not start Suricata automatically"
  }
fi

# ─── STEP 5: Verify post-update rule count ───────────────────────────────────
log_step 5 "Verifying post-update rule count"

POST_COUNT=0
if [[ -n "$RULES_DIR" ]] && [[ -d "$RULES_DIR" ]]; then
  POST_COUNT=$(find "$RULES_DIR" -name "*.rules" -exec grep -c "^alert\|^drop\|^pass" {} \; 2>/dev/null | \
               awk '{sum+=$1} END {print sum+0}')
  DELTA=$((POST_COUNT - PRE_COUNT))
  log_ok "Post-update rule count: ${POST_COUNT} (delta: +${DELTA})"
  echo "post_count=${POST_COUNT}" >> "$EVIDENCE_DIR/rule-counts.txt"
  echo "delta=${DELTA}" >> "$EVIDENCE_DIR/rule-counts.txt"

  if [[ $POST_COUNT -gt $PRE_COUNT ]]; then
    log_ok "Rule count increased — update applied successfully"
  elif [[ $POST_COUNT -eq $PRE_COUNT ]] && [[ $PRE_COUNT -gt 0 ]]; then
    log_warn "Rule count unchanged — may already be current"
  else
    log_warn "Rule count did not increase — verify update ran successfully"
  fi
fi

# ─── STEP 6: Live detection test ─────────────────────────────────────────────
log_step 6 "Live detection test"
log "  Triggering ET OPEN rule 2100498 (TESTING NIDS)..."

EVE_LOG=""
for p in /var/log/suricata/eve.json /opt/suricata/var/log/suricata/eve.json; do
  [[ -f "$p" ]] && EVE_LOG="$p" && break
done

PRE_EVE=0
[[ -n "$EVE_LOG" ]] && PRE_EVE=$(wc -l < "$EVE_LOG" 2>/dev/null || echo "0")

if command -v curl &>/dev/null; then
  curl -s --max-time 10 http://testmynids.org/uid/index.html -o /dev/null 2>/dev/null || \
    log_warn "  curl failed — check network connectivity"
  sleep 3

  if [[ -n "$EVE_LOG" ]] && [[ -f "$EVE_LOG" ]]; then
    POST_EVE=$(wc -l < "$EVE_LOG" 2>/dev/null || echo "0")
    NEW=$((POST_EVE - PRE_EVE))

    ALERT=$(tail -100 "$EVE_LOG" | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line.strip())
        if e.get('event_type') == 'alert':
            sig = e.get('alert',{}).get('signature','')
            if 'testmynids' in sig.lower() or '2100498' in str(e.get('alert',{}).get('signature_id','')):
                print(sig)
                break
    except: pass
" 2>/dev/null || echo "")

    if [[ -n "$ALERT" ]]; then
      log_ok "Detection confirmed: ${ALERT}"
    elif [[ $NEW -gt 0 ]]; then
      log_ok "${NEW} new EVE JSON entries — detection appears active"
    else
      log_warn "No new alerts after test request — detection may not be working"
    fi
    tail -20 "$EVE_LOG" > "$EVIDENCE_DIR/eve-post-test.txt" 2>/dev/null || true
  else
    log_warn "eve.json not found — cannot verify live detection"
  fi
else
  log_warn "curl not available — skipping live detection test"
fi

# ─── Evidence package ────────────────────────────────────────────────────────
log "\n${BOLD}Evidence Package:${NC} $EVIDENCE_DIR"
ls -la "$EVIDENCE_DIR/" | tee -a "$LOG"

log "\n${BOLD}========================================${NC}"
log "${BOLD}Suricata Rule Update Complete${NC}"
log "  Pre-update:  ${PRE_COUNT} rules"
log "  Post-update: ${POST_COUNT} rules"
log "${BOLD}========================================${NC}"
