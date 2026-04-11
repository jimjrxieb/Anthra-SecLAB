#!/usr/bin/env bash
# audit-zeek-config.sh — Zeek Network Monitoring Audit
# NIST Controls: AU-2 (Event Logging), SI-4 (System Monitoring), AU-9 (Log Protection)
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'
PASS="${GREEN}[PASS]${NC}"; WARN="${YELLOW}[WARN]${NC}"; FAIL="${RED}[FAIL]${NC}"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/zeek-audit-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"
LOG="$EVIDENCE_DIR/audit.log"

pass_count=0; warn_count=0; fail_count=0

log() { echo -e "$1" | tee -a "$LOG"; }
pass() { log "${PASS} $1"; ((pass_count++)); }
warn() { log "${WARN} $1"; ((warn_count++)); }
fail() { log "${FAIL} $1"; ((fail_count++)); }

# Locate Zeek log directory — covers package installs, source builds, Security Onion
find_zeek_log_dir() {
  for p in /var/log/zeek /opt/zeek/logs/current /usr/local/zeek/logs/current \
            /nsm/zeek/logs/current /data/zeek/logs/current; do
    [[ -d "$p" ]] && echo "$p" && return
  done
  # Try zeekctl if available
  if command -v zeekctl &>/dev/null; then
    local d
    d=$(zeekctl config 2>/dev/null | grep "^logdir" | awk '{print $3}')
    [[ -d "$d/current" ]] && echo "$d/current" && return
    [[ -d "$d" ]] && echo "$d" && return
  fi
  echo ""
}

find_zeek_etc() {
  for p in /opt/zeek/share/zeek/site /usr/local/zeek/share/zeek/site \
            /etc/zeek /usr/share/zeek/site; do
    [[ -d "$p" ]] && echo "$p" && return
  done
  echo ""
}

log "${BOLD}========================================${NC}"
log "${BOLD}Layer 3 — Zeek Configuration Audit${NC}"
log "Timestamp: $(date)"
log "Host: $(hostname)"
log "Evidence: $EVIDENCE_DIR"
log "${BOLD}========================================${NC}"

# ─── Check 1: Zeek process running ───────────────────────────────────────────
log "\n${BOLD}--- Process Status ---${NC}"
ZEEK_RUNNING=false

if command -v zeekctl &>/dev/null; then
  ZEEKCTL_STATUS=$(zeekctl status 2>/dev/null || echo "zeekctl status failed")
  echo "$ZEEKCTL_STATUS" > "$EVIDENCE_DIR/zeekctl-status.txt"
  if echo "$ZEEKCTL_STATUS" | grep -qi "running"; then
    pass "SI-4: Zeek is running (zeekctl status reports running)"
    ZEEK_RUNNING=true
  else
    fail "SI-4: Zeek is NOT running per zeekctl — $(echo "$ZEEKCTL_STATUS" | head -2)"
  fi
elif pgrep -x zeek &>/dev/null || pgrep -x bro &>/dev/null; then
  pass "SI-4: Zeek process is running"
  ps aux | grep -E "[z]eek|[b]ro" > "$EVIDENCE_DIR/zeek-process.txt" || true
  ZEEK_RUNNING=true
else
  fail "SI-4: Zeek is NOT running — network flow visibility is absent"
fi

# Version check
if command -v zeek &>/dev/null; then
  zeek --version > "$EVIDENCE_DIR/zeek-version.txt" 2>&1 || true
  ZEEK_VER=$(zeek --version 2>/dev/null | head -1 || echo "unknown")
  log "  Version: ${ZEEK_VER}"
fi

# ─── Check 2: conn.log being generated ───────────────────────────────────────
log "\n${BOLD}--- Log Generation ---${NC}"
ZEEK_LOG_DIR=$(find_zeek_log_dir)

if [[ -z "$ZEEK_LOG_DIR" ]]; then
  warn "AU-2: Zeek log directory not found at standard paths"
  log "  Searched: /var/log/zeek, /opt/zeek/logs/current, /usr/local/zeek/logs/current"
else
  log "  Log directory: ${ZEEK_LOG_DIR}"
  ls -la "$ZEEK_LOG_DIR" > "$EVIDENCE_DIR/zeek-log-listing.txt" 2>&1 || true

  # conn.log check
  if [[ -f "$ZEEK_LOG_DIR/conn.log" ]]; then
    CONN_SIZE=$(wc -l < "$ZEEK_LOG_DIR/conn.log" 2>/dev/null || echo "0")
    CONN_AGE_MIN=$(( ($(date +%s) - $(stat -c %Y "$ZEEK_LOG_DIR/conn.log" 2>/dev/null || echo "0")) / 60 ))
    if [[ $CONN_SIZE -gt 10 ]]; then
      pass "AU-2: conn.log exists and has ${CONN_SIZE} records (last modified ${CONN_AGE_MIN}m ago)"
    else
      warn "AU-2: conn.log exists but has only ${CONN_SIZE} lines — Zeek may not be capturing traffic"
    fi
    head -5 "$ZEEK_LOG_DIR/conn.log" > "$EVIDENCE_DIR/conn-log-sample.txt" 2>/dev/null || true
  else
    fail "AU-2: conn.log not found in ${ZEEK_LOG_DIR} — connection visibility absent"
  fi

  # dns.log check (SI-4 DNS visibility)
  if [[ -f "$ZEEK_LOG_DIR/dns.log" ]]; then
    DNS_COUNT=$(wc -l < "$ZEEK_LOG_DIR/dns.log" 2>/dev/null || echo "0")
    pass "SI-4: dns.log exists with ${DNS_COUNT} records — DNS query visibility active"
    head -5 "$ZEEK_LOG_DIR/dns.log" > "$EVIDENCE_DIR/dns-log-sample.txt" 2>/dev/null || true
  else
    fail "SI-4: dns.log not found — DNS logging not enabled (MITRE T1071.004 blind spot)"
  fi

  # http.log check
  if [[ -f "$ZEEK_LOG_DIR/http.log" ]]; then
    HTTP_COUNT=$(wc -l < "$ZEEK_LOG_DIR/http.log" 2>/dev/null || echo "0")
    pass "SI-4: http.log exists with ${HTTP_COUNT} records"
  else
    warn "SI-4: http.log not found — HTTP metadata logging not enabled"
  fi

  # ssl.log check
  if [[ -f "$ZEEK_LOG_DIR/ssl.log" ]]; then
    pass "SI-4: ssl.log exists — TLS session metadata being captured"
  else
    warn "SI-4: ssl.log not found — encrypted traffic metadata not logged"
  fi

  # Notice log
  if [[ -f "$ZEEK_LOG_DIR/notice.log" ]]; then
    NOTICE_COUNT=$(wc -l < "$ZEEK_LOG_DIR/notice.log" 2>/dev/null || echo "0")
    pass "SI-4: notice.log exists with ${NOTICE_COUNT} detection notices"
    head -20 "$ZEEK_LOG_DIR/notice.log" > "$EVIDENCE_DIR/notice-log-sample.txt" 2>/dev/null || true
  else
    warn "SI-4: notice.log not found — Zeek policy detections may not be loaded"
  fi
fi

# ─── Check 3: DNS logging enabled in local.zeek ──────────────────────────────
log "\n${BOLD}--- Configuration Review ---${NC}"
ZEEK_SITE=$(find_zeek_etc)
if [[ -z "$ZEEK_SITE" ]]; then
  warn "AU-2: Zeek site directory not found — cannot verify local.zeek configuration"
else
  LOCAL_ZEEK="$ZEEK_SITE/local.zeek"
  if [[ -f "$LOCAL_ZEEK" ]]; then
    cp "$LOCAL_ZEEK" "$EVIDENCE_DIR/local.zeek.evidence" 2>/dev/null || true

    if grep -q "protocols/dns" "$LOCAL_ZEEK"; then
      pass "SI-4: DNS protocol analyzer loaded in local.zeek"
    else
      fail "SI-4: DNS not loaded in local.zeek — add: @load protocols/dns"
    fi

    if grep -q "protocols/http" "$LOCAL_ZEEK"; then
      pass "SI-4: HTTP protocol analyzer loaded"
    else
      warn "SI-4: HTTP not loaded in local.zeek"
    fi

    if grep -q "protocols/ssl\|protocols/tls" "$LOCAL_ZEEK"; then
      pass "SI-4: SSL/TLS analyzer loaded"
    else
      warn "SI-4: SSL/TLS not loaded in local.zeek"
    fi

    if grep -q "hash-all-files\|files/extract-all-files" "$LOCAL_ZEEK"; then
      pass "SI-7: File hashing enabled — file integrity monitoring active"
    else
      warn "SI-7: File hashing not enabled — cannot detect file-based IOCs in traffic"
    fi
  else
    warn "AU-2: local.zeek not found at ${ZEEK_SITE}/local.zeek"
  fi
fi

# ─── Check 4: Log rotation ───────────────────────────────────────────────────
log "\n${BOLD}--- Log Rotation ---${NC}"

# Check for archived logs (rotation creates dated directories)
ARCHIVE_DIRS=""
for BASE in /var/log/zeek /opt/zeek/logs /usr/local/zeek/logs; do
  if [[ -d "$BASE" ]]; then
    ARCHIVE_DIRS=$(find "$BASE" -maxdepth 1 -type d -name "20*" 2>/dev/null | wc -l)
    break
  fi
done

if [[ "${ARCHIVE_DIRS:-0}" -gt 1 ]]; then
  pass "AU-9: Log rotation active — ${ARCHIVE_DIRS} archive directories found"
else
  warn "AU-9: No archive directories found — log rotation may not be configured"
  log "  Without rotation, logs fill disk and are overwritten"
fi

# Check zeekctl rotation config
if command -v zeekctl &>/dev/null; then
  ROTATION=$(zeekctl config 2>/dev/null | grep -i "rotat\|archive" || echo "")
  if [[ -n "$ROTATION" ]]; then
    pass "AU-9: zeekctl rotation config found"
    echo "$ROTATION" > "$EVIDENCE_DIR/zeekctl-rotation.txt"
  else
    warn "AU-9: zeekctl rotation settings not confirmed"
  fi
fi

# Check retention (disk space)
if [[ -n "$ZEEK_LOG_DIR" ]]; then
  DISK_USAGE=$(du -sh "$ZEEK_LOG_DIR" 2>/dev/null | cut -f1 || echo "unknown")
  log "  Current log size: ${DISK_USAGE}"
  echo "Log dir size: ${DISK_USAGE}" >> "$EVIDENCE_DIR/disk-usage.txt"
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
