#!/usr/bin/env bash
set -euo pipefail

# SC-7 ARP Spoofing — Detect
#
# Detects ARP spoofing/poisoning using two methods:
#   1. arpwatch — monitors ARP table changes, alerts on flip-flops and new stations
#   2. tshark — captures and analyzes ARP traffic for duplicate IP-to-MAC mappings
#
# REQUIREMENTS:
#   - arpwatch (apt-get install arpwatch)
#   - tshark (apt-get install tshark) — Wireshark CLI
#   - Root/sudo privileges for packet capture
#
# USAGE:
#   sudo ./detect.sh <interface> [duration_seconds]
#
# EXAMPLE:
#   sudo ./detect.sh eth0 60
#   (Monitors for ARP anomalies on eth0 for 60 seconds)

# --- Argument Validation ---

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <interface> [duration_seconds]"
    echo "Example: $0 eth0 60"
    exit 1
fi

IFACE="$1"
DURATION="${2:-60}"
EVIDENCE_DIR="/tmp/sc7-arp-evidence-$(date +%Y%m%d-%H%M%S)"

# Verify running as root
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo)."
    exit 1
fi

# Verify interface exists
if ! ip link show "$IFACE" &>/dev/null; then
    echo "[ERROR] Interface $IFACE does not exist."
    exit 1
fi

# Create evidence directory
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "SC-7 ARP Spoofing — Detection"
echo "============================================"
echo ""
echo "[*] Interface:    $IFACE"
echo "[*] Duration:     ${DURATION}s"
echo "[*] Evidence dir: $EVIDENCE_DIR"
echo ""

# --- Method 1: ARP Table Snapshot ---
# Baseline the current ARP table so we can diff after monitoring

echo "[*] Method 1: ARP table baseline snapshot"
echo "-------------------------------------------"
arp -n > "$EVIDENCE_DIR/arp-table-before.txt"
cat "$EVIDENCE_DIR/arp-table-before.txt"
echo ""

# Check for duplicate MACs mapped to different IPs (immediate indicator)
echo "[*] Checking for duplicate MAC addresses in ARP table..."
DUPES=$(arp -n | awk 'NR>1 && $3 != "(incomplete)" {print $3}' | sort | uniq -d)
if [[ -n "$DUPES" ]]; then
    echo "[ALERT] Duplicate MAC addresses detected — possible ARP spoofing!"
    echo "Duplicate MACs: $DUPES"
    arp -n | grep -F "$DUPES" | tee "$EVIDENCE_DIR/duplicate-macs.txt"
else
    echo "[OK] No duplicate MAC addresses in current ARP table."
fi
echo ""

# --- Method 2: arpwatch ---
# arpwatch maintains a database of IP-MAC pairs and alerts on changes

echo "[*] Method 2: arpwatch monitoring"
echo "-------------------------------------------"

if command -v arpwatch &>/dev/null; then
    ARPWATCH_LOG="$EVIDENCE_DIR/arpwatch.log"

    echo "[*] Starting arpwatch on $IFACE for ${DURATION}s..."
    echo "[*] arpwatch will detect: new stations, flip-flops, changed MAC addresses"

    # Run arpwatch in the foreground, logging to our evidence file
    # -d = don't become daemon, -f = database file, -i = interface
    arpwatch -d -i "$IFACE" -f "$EVIDENCE_DIR/arp.dat" > "$ARPWATCH_LOG" 2>&1 &
    ARPWATCH_PID=$!

    # Let it run for the specified duration
    sleep "$DURATION"

    # Stop arpwatch
    kill "$ARPWATCH_PID" 2>/dev/null || true
    wait "$ARPWATCH_PID" 2>/dev/null || true

    echo "[*] arpwatch results:"
    if [[ -s "$ARPWATCH_LOG" ]]; then
        # Look for indicators of ARP spoofing
        if grep -qiE "flip.flop|changed.ethernet|reused.old.ethernet" "$ARPWATCH_LOG"; then
            echo "[ALERT] ARP anomalies detected by arpwatch!"
            grep -iE "flip.flop|changed.ethernet|reused.old.ethernet" "$ARPWATCH_LOG" | tee "$EVIDENCE_DIR/arpwatch-alerts.txt"
        else
            echo "[OK] No ARP anomalies detected by arpwatch."
        fi
        echo ""
        echo "[*] Full arpwatch log saved to: $ARPWATCH_LOG"
    else
        echo "[OK] No events captured during monitoring window."
    fi
else
    echo "[SKIP] arpwatch not installed. Install with: apt-get install arpwatch"
fi
echo ""

# --- Method 3: tshark ARP Analysis ---
# Capture ARP traffic and look for spoofing indicators

echo "[*] Method 3: tshark ARP traffic analysis"
echo "-------------------------------------------"

if command -v tshark &>/dev/null; then
    PCAP_FILE="$EVIDENCE_DIR/arp-capture.pcap"
    ARP_ANALYSIS="$EVIDENCE_DIR/arp-analysis.txt"

    echo "[*] Capturing ARP traffic on $IFACE for ${DURATION}s..."

    # Capture only ARP traffic
    tshark -i "$IFACE" -f "arp" -a "duration:$DURATION" -w "$PCAP_FILE" 2>/dev/null &
    TSHARK_PID=$!

    # Wait for capture to complete
    wait "$TSHARK_PID" 2>/dev/null || true

    echo "[*] Capture complete. Analyzing..."

    # Count ARP packets
    ARP_COUNT=$(tshark -r "$PCAP_FILE" 2>/dev/null | wc -l)
    echo "[*] Total ARP packets captured: $ARP_COUNT"

    if [[ "$ARP_COUNT" -gt 0 ]]; then
        # Show ARP reply summary (replies are used in spoofing)
        echo ""
        echo "[*] ARP replies (opcode 2) — these are what ARP spoofing generates:"
        tshark -r "$PCAP_FILE" -Y "arp.opcode == 2" -T fields \
            -e arp.src.hw_mac -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4 \
            2>/dev/null | sort | uniq -c | sort -rn | head -20 | tee "$EVIDENCE_DIR/arp-replies.txt"
        echo ""

        # Detect gratuitous ARP (same source and destination IP — used in spoofing)
        echo "[*] Gratuitous ARP packets (indicator of ARP spoofing):"
        GRAT_COUNT=$(tshark -r "$PCAP_FILE" -Y "arp.isgratuitous == 1" 2>/dev/null | wc -l)
        echo "    Count: $GRAT_COUNT"

        if [[ "$GRAT_COUNT" -gt 10 ]]; then
            echo "[ALERT] High volume of gratuitous ARP detected — likely ARP spoofing in progress!"
            tshark -r "$PCAP_FILE" -Y "arp.isgratuitous == 1" -T fields \
                -e arp.src.hw_mac -e arp.src.proto_ipv4 \
                2>/dev/null | sort | uniq -c | sort -rn | tee "$EVIDENCE_DIR/gratuitous-arp.txt"
        fi
        echo ""

        # Detect duplicate IP with different MAC (definitive spoofing indicator)
        echo "[*] Checking for IP addresses claimed by multiple MACs:"
        tshark -r "$PCAP_FILE" -Y "arp.opcode == 2" -T fields \
            -e arp.src.proto_ipv4 -e arp.src.hw_mac \
            2>/dev/null | sort -u | awk -F'\t' '{
                if (ip[$1] != "" && ip[$1] != $2) {
                    print "[ALERT] IP " $1 " claimed by multiple MACs: " ip[$1] " AND " $2
                }
                ip[$1] = $2
            }' | tee "$EVIDENCE_DIR/ip-mac-conflicts.txt"

        # Full analysis saved for evidence
        tshark -r "$PCAP_FILE" -V 2>/dev/null > "$ARP_ANALYSIS"
        echo "[*] Full packet analysis saved to: $ARP_ANALYSIS"
    else
        echo "[OK] No ARP traffic captured during monitoring window."
    fi
else
    echo "[SKIP] tshark not installed. Install with: apt-get install tshark"
fi
echo ""

# --- Method 4: Post-Monitoring ARP Table Diff ---

echo "[*] Method 4: ARP table change detection"
echo "-------------------------------------------"
arp -n > "$EVIDENCE_DIR/arp-table-after.txt"

if ! diff -q "$EVIDENCE_DIR/arp-table-before.txt" "$EVIDENCE_DIR/arp-table-after.txt" &>/dev/null; then
    echo "[ALERT] ARP table changed during monitoring window!"
    diff "$EVIDENCE_DIR/arp-table-before.txt" "$EVIDENCE_DIR/arp-table-after.txt" | tee "$EVIDENCE_DIR/arp-table-diff.txt"
else
    echo "[OK] ARP table unchanged during monitoring window."
fi
echo ""

# --- Evidence Summary ---

echo "============================================"
echo "Evidence Summary"
echo "============================================"
echo "[*] All evidence saved to: $EVIDENCE_DIR"
echo "[*] Files:"
ls -la "$EVIDENCE_DIR/"
echo ""
echo "[*] Detection complete."
