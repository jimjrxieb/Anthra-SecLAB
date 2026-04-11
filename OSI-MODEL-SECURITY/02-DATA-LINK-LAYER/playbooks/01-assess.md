# Layer 2 Data Link — Assessment

| Field | Value |
|-------|-------|
| NIST Controls | SC-7, AC-3, AC-4, SI-4, IA-2 |
| Tools | arpwatch, ip neigh, bridge, tshark |
| Time Estimate | 1 hour |
| Rank | D |

---

## Objective

Establish the Layer 2 security baseline. Run all auditors, identify gaps, and rank findings by implementation priority before any fix work begins. You do not harden what you have not mapped.

---

## Run All Auditors

```bash
# Run all L2 auditors in sequence
sudo ./tools/run-all-audits.sh eth0

# OR run individually for targeted review:
sudo ./01-auditors/audit-arp-integrity.sh eth0
sudo ./01-auditors/audit-vlan-config.sh
sudo ./01-auditors/audit-802.1x-status.sh eth0
```

Evidence automatically saved to `/tmp/jsa-evidence/` with timestamps.

---

## Assessment Checklist

Work through each control area. Mark each item with: PASS / WARN / FAIL / N/A

### ARP Table Integrity (SC-7, SI-4)

| # | Check | Expected | Status |
|---|-------|----------|--------|
| 1 | No duplicate MAC addresses in ARP table | No duplicates | |
| 2 | No FAILED or INCOMPLETE ARP entries | None, or explainable | |
| 3 | ARP table entries match known host inventory | All IPs mapped to known MACs | |
| 4 | Gratuitous ARP testing tool available (arping) | arping installed | |

### arpwatch Service Status (SI-4)

| # | Check | Expected | Status |
|---|-------|----------|--------|
| 5 | arpwatch service is running | systemctl: active | |
| 6 | arpwatch monitoring correct interface | Process bound to eth0 | |
| 7 | arpwatch database exists and has entries | arp.dat with MAC-IP pairs | |
| 8 | arpwatch logs forwarding to syslog | /var/log/arpwatch.log populated | |
| 9 | arpwatch events forwarding to SIEM | rsyslog forward configured | |

### VLAN Configuration (SC-7, AC-4)

| # | Check | Expected | Status |
|---|-------|----------|--------|
| 10 | 802.1q kernel module loaded | lsmod shows 8021q | |
| 11 | VLAN interfaces exist (if VLAN network) | ip -d link shows VLAN subinterfaces | |
| 12 | Bridge VLAN filtering enabled | /sys/class/net/br*/bridge/vlan_filtering = 1 | |
| 13 | Native VLAN is not VLAN 1 | PVID on trunk ports != 1 | |
| 14 | DTP (dynamic trunk negotiation) disabled | No negotiation frames from access ports | |

### 802.1X Enforcement (IA-2, AC-3)

| # | Check | Expected | Status |
|---|-------|----------|--------|
| 15 | wpa_supplicant running (Linux) OR dot3svc running (Windows) | Service active | |
| 16 | EAP authentication state: AUTHENTICATED | wpa_cli status shows AUTHENTICATED | |
| 17 | wpa_supplicant config has EAP method defined | /etc/wpa_supplicant/*.conf contains eap= | |
| 18 | NetworkManager has 802.1X profile (if NM in use) | nmcli connection has 802-1x config | |

### Trunk Port Security (SC-7, AC-4)

| # | Check | Expected | Status |
|---|-------|----------|--------|
| 19 | Trunk ports restrict allowed VLANs | Only required VLANs permitted | |
| 20 | Unused ports disabled | No active ports without connected devices | |
| 21 | MAC address table overflow protection | Port security or rate limiting configured | |

### MAC Address Table Overflow Protection (SI-4)

| # | Check | Expected | Status |
|---|-------|----------|--------|
| 22 | Port security configured (switch) OR ebtables/nftables (Linux) | MAC limit enforced per port | |
| 23 | Storm control enabled on access ports | Broadcast/multicast storm threshold set | |

---

## Finding Classification

Use the NIST finding framework to classify each FAIL item:

| Severity | Criteria | Example |
|----------|----------|---------|
| Critical | Exploitable now, direct impact | Duplicate MACs in ARP table (active spoofing) |
| High | Control absent, exploitable with low effort | arpwatch not running (no ARP visibility) |
| Medium | Control present but misconfigured | Native VLAN is VLAN 1 (hopping risk exists) |
| Low | Best practice gap, low exploitation likelihood | arping not installed (limits testing capability) |

---

## Implementation Priority Ranking

After completing the checklist, prioritize remediation in this order:

**Priority 1 — Fix Today (Critical/High)**
- Active duplicate MACs (live spoofing in progress) — investigate immediately
- arpwatch not running — deploy via `02-fixers/fix-arp-monitoring.sh`
- 802.1X absent on segments with untrusted endpoints — escalate to network team

**Priority 2 — Fix This Week (High/Medium)**
- No SIEM forwarding for arpwatch events — add rsyslog rule
- Native VLAN is VLAN 1 — change on all trunk ports
- Bridge VLAN filtering disabled — enable on all Linux bridges

**Priority 3 — Fix Next Sprint (Medium/Low)**
- DTP not disabled on access ports — add `switchport nonegotiate`
- Port security not configured — implement MAC limits
- 802.1X not configured but network is trusted — document exception

---

## Assessment Evidence

Save all evidence to the engagement directory:

```bash
# Create evidence directory
mkdir -p evidence/$(date +%Y%m%d)-l2-assessment/

# Collect
ip neigh show > evidence/$(date +%Y%m%d)-l2-assessment/arp-table.txt
ip -d link show > evidence/$(date +%Y%m%d)-l2-assessment/interfaces.txt
systemctl status arpwatch --no-pager > evidence/$(date +%Y%m%d)-l2-assessment/arpwatch-status.txt
lsmod | grep 8021q > evidence/$(date +%Y%m%d)-l2-assessment/8021q-module.txt
```

---

## Next Step

- FAIL on ARP integrity: `01a-arp-spoofing-audit.md` (deep dive)
- FAIL on arpwatch: `02-fix-SC7-arp-protection.md`
- FAIL on VLAN: `02a-fix-AC3-vlan-segmentation.md`
- All PASS/WARN: `03-validate.md` to document baseline
