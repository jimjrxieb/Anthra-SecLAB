# OSI-MODEL-SECURITY SecLAB Restructure — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Align SecLAB OSI-MODEL-SECURITY to mirror GP-CONSULTING/09-OSI-MODEL-SECURITY directory structure with CySA+ daily ops tooling, dual-stack templates (Microsoft Sentinel + Splunk/open-source), and generic best-practice auditors/fixers.

**Architecture:** Each OSI layer gets `01-auditors/`, `02-fixers/`, `03-templates/`, `tools/`, and a full playbook cycle (00-install through 04-triage). Existing scenarios with governance.md are preserved. Fixers focus on "tool isn't catching what it should — update it or write a custom signature" with working examples.

**Tech Stack:** Microsoft Sentinel + KQL (CySA+ default), Splunk (alternative), Suricata, Zeek, testssl.sh, Entra ID, Azure Key Vault, HashiCorp Vault, Defender, Wazuh, ZAP, Semgrep, Trivy

**Spec:** `docs/superpowers/specs/2026-04-10-osi-model-restructure-design.md`

---

## File Conventions

All shell scripts follow this pattern from GP-CONSULTING:

```bash
#!/usr/bin/env bash
set -euo pipefail

# <TITLE>
#
# PURPOSE: <what it does>
# NIST CONTROLS: <control IDs>
# WHERE TO RUN: <host>
# USAGE: ./<script>.sh
#
# WARNING: This script is for authorized security testing only.

# --- Colors ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; WARN=0; FAIL=0

pass()  { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }

# --- Evidence ---
EVIDENCE_DIR="/tmp/jsa-evidence/<script>-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"
```

All playbooks follow this header pattern:

```markdown
# Layer N <Name> — <Playbook Title>

| Field | Value |
|-------|-------|
| NIST Controls | <IDs> |
| Tools | <tool list> |
| Enterprise Equivalent | <paid tools this replaces> |
| Time Estimate | <X hours> |
| Rank | <E/D/C> |

## What This Does
<1-2 paragraph business justification>

## Why This Matters
<compliance + risk context>

## Prerequisites
- <explicit requirements>

## Where You Run This
<host designation>
```

All templates include WHY comments mapping to NIST controls:

```
# WHY: NIST SC-7 requires boundary protection at managed interfaces.
# Without this setting, traffic bypasses inspection entirely.
<config directive>
```

---

## Task 0: GP-CONSULTING Rename

**Files:**
- Rename: `GP-CONSULTING/09-OSI-MODEL-SECURITY/07-APPLICATION-LAYER/playbooks/01a-siem-audit.md` → `01a-splunk-audit.md`

- [ ] **Step 1: Rename the file**

```bash
cd /home/jimmie/linkops-industries/GP-copilot
mv GP-CONSULTING/09-OSI-MODEL-SECURITY/07-APPLICATION-LAYER/playbooks/01a-siem-audit.md \
   GP-CONSULTING/09-OSI-MODEL-SECURITY/07-APPLICATION-LAYER/playbooks/01a-splunk-audit.md
```

- [ ] **Step 2: Update internal title**

Change the first heading in the renamed file from referencing "SIEM" generically to "Splunk" specifically. The title should be:

```markdown
# Layer 7 Application — Splunk SIEM Audit
```

- [ ] **Step 3: Verify**

```bash
ls GP-CONSULTING/09-OSI-MODEL-SECURITY/07-APPLICATION-LAYER/playbooks/01a-*
# Expected: 01a-splunk-audit.md (no 01a-siem-audit.md)
```

- [ ] **Step 4: Commit**

```bash
git add GP-CONSULTING/09-OSI-MODEL-SECURITY/07-APPLICATION-LAYER/playbooks/
git commit -m "rename: 01a-siem-audit.md → 01a-splunk-audit.md for dual SIEM clarity"
```

---

## Task 1: Layer 1 — Physical (01-PHYSICAL-LAYER)

Physical layer is tabletop-only (cloud/physical boundary). Minimal scripting — auditors are checklists, fixers are procedure docs, templates are assessment forms.

**Files:**
- Create: `01-PHYSICAL-LAYER/01-auditors/audit-physical-access.sh`
- Create: `01-PHYSICAL-LAYER/01-auditors/audit-environmental-controls.sh`
- Create: `01-PHYSICAL-LAYER/02-fixers/fix-access-policy.md`
- Create: `01-PHYSICAL-LAYER/02-fixers/fix-environmental-monitoring.md`
- Create: `01-PHYSICAL-LAYER/03-templates/pe-assessment-checklist.md`
- Create: `01-PHYSICAL-LAYER/tools/run-all-audits.sh`
- Replace: `01-PHYSICAL-LAYER/playbooks/01-assess.md`
- Replace: `01-PHYSICAL-LAYER/playbooks/02-implement.md` → delete
- Replace: `01-PHYSICAL-LAYER/playbooks/03-break-fix.md` → delete
- Replace: `01-PHYSICAL-LAYER/playbooks/04-ciso-report.md` → delete
- Create: `01-PHYSICAL-LAYER/playbooks/00-install-validate.md`
- Create: `01-PHYSICAL-LAYER/playbooks/01-assess.md` (rewrite)
- Create: `01-PHYSICAL-LAYER/playbooks/02-fix-PE3-physical-access.md`
- Create: `01-PHYSICAL-LAYER/playbooks/03-validate.md`
- Create: `01-PHYSICAL-LAYER/playbooks/04-triage-alerts.md`

- [ ] **Step 1: Create directory structure**

```bash
BASE="/home/jimmie/linkops-industries/GP-copilot/GP-PROJECTS/01-instance/slot-3/Anthra-SecLAB/OSI-MODEL-SECURITY/01-PHYSICAL-LAYER"
mkdir -p "$BASE/01-auditors" "$BASE/02-fixers" "$BASE/03-templates" "$BASE/tools"
```

- [ ] **Step 2: Create auditors**

`01-auditors/audit-physical-access.sh` — Checklist-based auditor for PE-3 physical access controls. Since physical controls can't be scripted against cloud infra, this script outputs an interactive checklist that the analyst completes manually and saves evidence.

```bash
#!/usr/bin/env bash
set -euo pipefail

# PE-3 Physical Access Control Auditor
#
# PURPOSE: Interactive checklist for physical access control assessment.
#          Physical controls cannot be automated — this guides the walkthrough
#          and records evidence for compliance.
# NIST CONTROLS: PE-3 Physical Access Control
# WHERE TO RUN: Analyst workstation (during site visit or tabletop)
# USAGE: ./audit-physical-access.sh

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; WARN=0; FAIL=0

pass()  { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }

EVIDENCE_DIR="/tmp/jsa-evidence/physical-access-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "PE-3 Physical Access Control — Audit"
echo "============================================"
echo ""
info "This is an interactive checklist. Answer y/n for each item."
info "Evidence will be saved to: $EVIDENCE_DIR"
echo ""

ask() {
    local question="$1"
    local control="$2"
    read -rp "$question (y/n): " answer
    if [[ "$answer" == "y" || "$answer" == "Y" ]]; then
        pass "$control"
        echo "PASS: $control" >> "$EVIDENCE_DIR/results.txt"
    else
        fail "$control"
        echo "FAIL: $control" >> "$EVIDENCE_DIR/results.txt"
    fi
}

echo "--- Facility Entry Controls ---"
ask "Is badge/key card access required for facility entry?" "PE-3(a) Badge access at entry points"
ask "Are visitor logs maintained with sign-in/sign-out times?" "PE-3(b) Visitor access records"
ask "Are visitors escorted in restricted areas?" "PE-3(c) Visitor escort requirement"
ask "Is there a reception/guard station at primary entry?" "PE-3(d) Physical access monitoring"

echo ""
echo "--- Server Room / Data Center ---"
ask "Is the server room access restricted to authorized personnel only?" "PE-3(e) Server room access control"
ask "Is there a separate access log for server room entry?" "PE-3(f) Server room access logging"
ask "Are access attempts (granted and denied) logged electronically?" "PE-3(g) Electronic access logging"
ask "Is the access list reviewed at least quarterly?" "PE-3(h) Access list review"

echo ""
echo "--- CCTV and Monitoring ---"
ask "Are cameras covering entry/exit points?" "PE-6(a) CCTV at entry points"
ask "Is CCTV footage retained for at least 90 days?" "PE-6(b) CCTV retention"
ask "Are camera feeds monitored in real-time or reviewed daily?" "PE-6(c) CCTV monitoring"

echo ""
echo "============================================"
echo "Summary: $PASS PASS / $WARN WARN / $FAIL FAIL"
echo "============================================"
echo "Evidence saved to: $EVIDENCE_DIR/results.txt"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
```

`01-auditors/audit-environmental-controls.sh` — Same interactive pattern for PE-14 environmental protection (temperature, humidity, fire suppression, water damage, power).

```bash
#!/usr/bin/env bash
set -euo pipefail

# PE-14 Environmental Controls Auditor
#
# PURPOSE: Interactive checklist for environmental protection assessment.
# NIST CONTROLS: PE-14 Environmental Controls
# WHERE TO RUN: Analyst workstation (during site visit or tabletop)
# USAGE: ./audit-environmental-controls.sh

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; WARN=0; FAIL=0

pass()  { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }

EVIDENCE_DIR="/tmp/jsa-evidence/environmental-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "PE-14 Environmental Controls — Audit"
echo "============================================"
echo ""
info "Interactive checklist. Answer y/n for each item."
info "Evidence saved to: $EVIDENCE_DIR"
echo ""

ask() {
    local question="$1"
    local control="$2"
    read -rp "$question (y/n): " answer
    if [[ "$answer" == "y" || "$answer" == "Y" ]]; then
        pass "$control"
        echo "PASS: $control" >> "$EVIDENCE_DIR/results.txt"
    else
        fail "$control"
        echo "FAIL: $control" >> "$EVIDENCE_DIR/results.txt"
    fi
}

echo "--- Temperature and Humidity ---"
ask "Is server room temperature maintained between 64-75°F (18-24°C)?" "PE-14(a) Temperature range"
ask "Is humidity maintained between 40-60% RH?" "PE-14(b) Humidity range"
ask "Are temperature/humidity sensors deployed with alerting?" "PE-14(c) Environmental monitoring"
ask "Are alerts sent when thresholds are exceeded?" "PE-14(d) Threshold alerting"

echo ""
echo "--- Fire Suppression ---"
ask "Is a fire suppression system installed (clean agent, FM-200, or equivalent)?" "PE-13(a) Fire suppression"
ask "Is the fire suppression system tested annually?" "PE-13(b) Fire suppression testing"
ask "Are smoke detectors installed in the server room?" "PE-13(c) Smoke detection"
ask "Are fire extinguishers accessible and inspected?" "PE-13(d) Fire extinguishers"

echo ""
echo "--- Power ---"
ask "Is UPS (Uninterruptible Power Supply) deployed?" "PE-11(a) UPS"
ask "Is a backup generator available with automatic transfer switch?" "PE-11(b) Generator"
ask "Is UPS tested under load at least annually?" "PE-11(c) UPS load testing"
ask "Are power circuits redundant (A+B feeds)?" "PE-11(d) Redundant power"

echo ""
echo "--- Water Damage ---"
ask "Are water leak sensors deployed under raised floor / near pipes?" "PE-15(a) Water detection"
ask "Is the server room above ground level or flood-protected?" "PE-15(b) Flood protection"

echo ""
echo "============================================"
echo "Summary: $PASS PASS / $WARN WARN / $FAIL FAIL"
echo "============================================"
echo "Evidence saved to: $EVIDENCE_DIR/results.txt"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
```

- [ ] **Step 3: Create fixers**

`02-fixers/fix-access-policy.md` — Generic best-practice remediation for physical access gaps. Not a script — physical controls require policy changes, not automation.

```markdown
# PE-3 Physical Access — Remediation Guide

## When This Control Fails

PE-3 fails when: no badge system exists, visitor logs are not maintained, access lists are not reviewed, or server room access is not restricted. These are policy and procedure gaps, not tool failures.

## How to Fix

### Badge System Not in Place
1. Deploy electronic access control (HID, Lenel, Honeywell, cloud-based like Verkada or Openpath)
2. Issue badges to all authorized personnel
3. Configure access levels: general facility, restricted areas, server room
4. Enable logging on all readers (granted + denied attempts)
5. Set auto-lock timers on all controlled doors

### Visitor Logs Missing
1. Implement sign-in/sign-out process at reception
2. Require government-issued ID for visitor entry
3. Assign escort for restricted areas
4. Issue temporary visitor badges with expiration
5. Retain logs for minimum 90 days

### Access List Not Reviewed
1. Export current access list from badge system
2. Compare against current employee roster and authorized contractor list
3. Remove terminated employees and expired contractors
4. Document review date, reviewer, and changes made
5. Schedule quarterly review (calendar invite to facility manager + security)

## Evidence for Auditors
- Badge system access logs (CSV export, 90-day window)
- Visitor log samples (most recent quarter)
- Access list review documentation (date, reviewer, actions taken)
- Photos of badge readers, camera positions, signage
```

`02-fixers/fix-environmental-monitoring.md` — Same pattern for PE-14 environmental gaps.

```markdown
# PE-14 Environmental Controls — Remediation Guide

## When This Control Fails

PE-14 fails when: no temperature/humidity monitoring exists, fire suppression is untested or absent, UPS is not deployed or tested, or water detection sensors are missing.

## How to Fix

### No Environmental Monitoring
1. Deploy temperature and humidity sensors in server room
   - Products: APC NetBotz, Vertiv Liebert, Paessler PRTG sensors, or open-source (Nagios + USB sensors)
2. Configure alert thresholds:
   - Temperature: alert at 78°F (26°C), critical at 85°F (29°C)
   - Humidity: alert below 35% or above 65%, critical below 20% or above 80%
3. Route alerts to facility manager and on-call (email + SMS/PagerDuty)
4. Retain readings for 1 year minimum

### Fire Suppression Not Tested
1. Schedule annual fire suppression test with vendor
2. Document test date, results, and next test date
3. Verify smoke detector batteries and function quarterly
4. Verify fire extinguisher inspection tags are current (annual)

### UPS Not Deployed or Tested
1. Size UPS for server room load + 20% headroom
2. Configure automatic shutdown scripts (NUT, APC PowerChute) triggered by UPS low-battery
3. Schedule annual load test (document runtime at load)
4. Test automatic transfer switch (ATS) if generator is present

### Water Detection Missing
1. Deploy leak sensors under raised floor, near HVAC drip pans, near plumbing
2. Route alerts to facility manager
3. Verify drainage exists for HVAC condensation

## Evidence for Auditors
- Monitoring dashboard screenshots (temperature/humidity trends, 30 days)
- Fire suppression test report (most recent annual)
- UPS load test results (most recent annual)
- Sensor placement diagram
```

- [ ] **Step 4: Create templates**

`03-templates/pe-assessment-checklist.md` — Blank assessment template combining both PE-3 and PE-14 for use during site visits.

```markdown
# Physical & Environmental Security Assessment

**Site:** ________________
**Assessor:** ________________
**Date:** ________________

## PE-3 Physical Access Control

| # | Check | Status | Notes |
|---|-------|--------|-------|
| 1 | Badge/keycard required at facility entry | | |
| 2 | Visitor sign-in/sign-out with ID verification | | |
| 3 | Visitors escorted in restricted areas | | |
| 4 | Server room: separate access control | | |
| 5 | Server room: electronic access logging | | |
| 6 | Access list reviewed quarterly | | |
| 7 | CCTV at entry/exit points | | |
| 8 | CCTV footage retained 90+ days | | |

## PE-14 Environmental Controls

| # | Check | Status | Notes |
|---|-------|--------|-------|
| 1 | Temperature: 64-75°F (18-24°C) maintained | | |
| 2 | Humidity: 40-60% RH maintained | | |
| 3 | Sensors with alerting deployed | | |
| 4 | Fire suppression installed and tested annually | | |
| 5 | Smoke detectors functional | | |
| 6 | UPS deployed and load-tested annually | | |
| 7 | Backup generator with ATS (if applicable) | | |
| 8 | Water leak sensors deployed | | |

## Summary

| Family | Pass | Fail | N/A |
|--------|------|------|-----|
| PE-3 Physical Access | | | |
| PE-14 Environmental | | | |

**Findings requiring remediation:**

1. ________________
2. ________________
3. ________________
```

- [ ] **Step 5: Create tools/run-all-audits.sh**

```bash
#!/usr/bin/env bash
set -euo pipefail

# Layer 1 Physical — Run All Auditors
#
# PURPOSE: Run all L1 auditors in sequence, produce combined summary.
# NIST CONTROLS: PE-3, PE-14
# USAGE: ./run-all-audits.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDITOR_DIR="$SCRIPT_DIR/../01-auditors"

echo "============================================"
echo "Layer 1 Physical — Full Audit"
echo "============================================"
echo ""

TOTAL_PASS=0; TOTAL_FAIL=0

run_audit() {
    local script="$1"
    local name="$2"
    echo "--- $name ---"
    if [[ -x "$AUDITOR_DIR/$script" ]]; then
        "$AUDITOR_DIR/$script" && ((TOTAL_PASS++)) || ((TOTAL_FAIL++))
    else
        echo "[SKIP] $script not found or not executable"
    fi
    echo ""
}

run_audit "audit-physical-access.sh" "PE-3 Physical Access Control"
run_audit "audit-environmental-controls.sh" "PE-14 Environmental Controls"

echo "============================================"
echo "Combined: $TOTAL_PASS auditors PASS / $TOTAL_FAIL auditors FAIL"
echo "============================================"

[[ $TOTAL_FAIL -eq 0 ]] && exit 0 || exit 1
```

- [ ] **Step 6: Replace playbooks**

Delete old playbooks and create new cycle:

```bash
BASE="/home/jimmie/linkops-industries/GP-copilot/GP-PROJECTS/01-instance/slot-3/Anthra-SecLAB/OSI-MODEL-SECURITY/01-PHYSICAL-LAYER"
rm -f "$BASE/playbooks/02-implement.md" "$BASE/playbooks/03-break-fix.md" "$BASE/playbooks/04-ciso-report.md"
```

Create these playbooks following the GP-CONSULTING header pattern:

**`playbooks/00-install-validate.md`** — Physical layer has no software to install. This playbook documents what tools/forms to prepare before a site visit (badge system access, camera monitoring access, environmental monitoring dashboard credentials). Confirms analyst has access to the systems needed for assessment.

**`playbooks/01-assess.md`** — Rewrite existing assess playbook to match GP-CONSULTING depth. Keep the existing checklist content (it's already strong) but add the GP-CONSULTING header format, "What This Does" and "Why This Matters" sections, and implementation priority ranking.

**`playbooks/02-fix-PE3-physical-access.md`** — Remediation playbook for PE-3 findings. Steps to implement badge access, visitor management, access list reviews. References `02-fixers/fix-access-policy.md` for detailed procedures.

**`playbooks/03-validate.md`** — Re-run all auditors after fixes. Confirm PASS count improved. Document before/after state for compliance evidence.

**`playbooks/04-triage-alerts.md`** — Daily monitoring of physical security alerts: badge access denied events, after-hours access, environmental threshold alerts. How to investigate and escalate.

- [ ] **Step 7: Commit**

```bash
git add OSI-MODEL-SECURITY/01-PHYSICAL-LAYER/
git commit -m "seclab: add L1 physical layer auditors, fixers, templates, playbook cycle"
```

---

## Task 2: Layer 2 — Data Link (02-DATA-LINK-LAYER)

**Files:**
- Create: `02-DATA-LINK-LAYER/01-auditors/audit-arp-integrity.sh`
- Create: `02-DATA-LINK-LAYER/01-auditors/audit-vlan-config.sh`
- Create: `02-DATA-LINK-LAYER/01-auditors/audit-802.1x-status.sh`
- Create: `02-DATA-LINK-LAYER/02-fixers/fix-arp-monitoring.sh`
- Create: `02-DATA-LINK-LAYER/02-fixers/fix-port-security.md`
- Create: `02-DATA-LINK-LAYER/03-templates/arpwatch/arpwatch.conf`
- Create: `02-DATA-LINK-LAYER/03-templates/defender-iot/network-detection-policy.json`
- Create: `02-DATA-LINK-LAYER/tools/run-all-audits.sh`
- Replace: playbooks (delete old 4, create new cycle)
- Create: `02-DATA-LINK-LAYER/playbooks/00-install-validate.md`
- Create: `02-DATA-LINK-LAYER/playbooks/01-assess.md` (rewrite)
- Create: `02-DATA-LINK-LAYER/playbooks/01a-arp-spoofing-audit.md`
- Create: `02-DATA-LINK-LAYER/playbooks/02-fix-SC7-arp-protection.md`
- Create: `02-DATA-LINK-LAYER/playbooks/02a-fix-AC3-vlan-segmentation.md`
- Create: `02-DATA-LINK-LAYER/playbooks/03-validate.md`
- Create: `02-DATA-LINK-LAYER/playbooks/04-triage-alerts.md`

- [ ] **Step 1: Create directory structure**

```bash
BASE="/home/jimmie/linkops-industries/GP-copilot/GP-PROJECTS/01-instance/slot-3/Anthra-SecLAB/OSI-MODEL-SECURITY/02-DATA-LINK-LAYER"
mkdir -p "$BASE/01-auditors" "$BASE/02-fixers" "$BASE/03-templates/arpwatch" "$BASE/03-templates/defender-iot"
```

- [ ] **Step 2: Create auditors**

`01-auditors/audit-arp-integrity.sh` — Check ARP table for duplicates (spoofing indicator), verify arpwatch is running, check for static ARP entries on critical gateways.

```bash
#!/usr/bin/env bash
set -euo pipefail

# ARP Integrity Auditor
#
# PURPOSE: Check ARP tables for spoofing indicators, verify monitoring tools.
# NIST CONTROLS: SC-7 Boundary Protection (L2 boundary)
# WHERE TO RUN: Network segment host or analyst workstation
# USAGE: ./audit-arp-integrity.sh

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; WARN=0; FAIL=0

pass()  { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }

EVIDENCE_DIR="/tmp/jsa-evidence/arp-integrity-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "ARP Integrity — Audit"
echo "============================================"
echo ""

# Check 1: ARP table for duplicate MAC addresses (spoofing indicator)
info "Checking ARP table for duplicate MACs..."
if command -v arp &>/dev/null; then
    arp -an > "$EVIDENCE_DIR/arp-table.txt" 2>&1
    DUPES=$(arp -an | awk '{print $4}' | sort | uniq -d | grep -v '<incomplete>' || true)
    if [[ -z "$DUPES" ]]; then
        pass "No duplicate MAC addresses in ARP table"
    else
        fail "Duplicate MAC addresses detected (possible ARP spoofing):"
        echo "$DUPES" | tee -a "$EVIDENCE_DIR/arp-dupes.txt"
    fi
elif command -v ip &>/dev/null; then
    ip neigh show > "$EVIDENCE_DIR/arp-table.txt" 2>&1
    DUPES=$(ip neigh show | awk '{print $5}' | sort | uniq -d | grep -v "^$" || true)
    if [[ -z "$DUPES" ]]; then
        pass "No duplicate MAC addresses in neighbor table"
    else
        fail "Duplicate MAC addresses detected (possible ARP spoofing):"
        echo "$DUPES" | tee -a "$EVIDENCE_DIR/arp-dupes.txt"
    fi
else
    warn "Neither arp nor ip command found — cannot check ARP table"
fi

# Check 2: arpwatch running
info "Checking if arpwatch is running..."
if command -v arpwatch &>/dev/null; then
    if pgrep -x arpwatch &>/dev/null; then
        pass "arpwatch is running"
    else
        fail "arpwatch is installed but not running"
        echo "  FIX: sudo systemctl start arpwatch && sudo systemctl enable arpwatch"
    fi
else
    warn "arpwatch not installed"
    echo "  FIX: sudo apt install arpwatch  # Debian/Ubuntu"
    echo "  FIX: sudo yum install arpwatch  # RHEL/CentOS"
fi

# Check 3: Gratuitous ARP detection
info "Checking for gratuitous ARP detection capability..."
if command -v arpwatch &>/dev/null && pgrep -x arpwatch &>/dev/null; then
    if [[ -f /var/lib/arpwatch/arp.dat ]]; then
        ENTRIES=$(wc -l < /var/lib/arpwatch/arp.dat)
        pass "arpwatch database has $ENTRIES known MAC-IP pairs"
    else
        warn "arpwatch database file not found — fresh install?"
    fi
else
    fail "No gratuitous ARP detection running (arpwatch, arpalert, or Defender IoT)"
fi

echo ""
echo "============================================"
echo "Summary: $PASS PASS / $WARN WARN / $FAIL FAIL"
echo "============================================"
echo "Evidence saved to: $EVIDENCE_DIR"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
```

`01-auditors/audit-vlan-config.sh` — Check VLAN tagging on interfaces, verify trunk port configuration, identify untagged traffic on trunk ports (VLAN hopping risk).

```bash
#!/usr/bin/env bash
set -euo pipefail

# VLAN Configuration Auditor
#
# PURPOSE: Audit VLAN segmentation, trunk ports, and native VLAN config.
# NIST CONTROLS: AC-3 Access Enforcement, AC-4 Information Flow
# WHERE TO RUN: Switch/router or Linux host with VLAN interfaces
# USAGE: ./audit-vlan-config.sh

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; WARN=0; FAIL=0

pass()  { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }

EVIDENCE_DIR="/tmp/jsa-evidence/vlan-config-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "VLAN Configuration — Audit"
echo "============================================"
echo ""

# Check 1: VLAN interfaces exist (Linux)
info "Checking for VLAN interfaces..."
if command -v ip &>/dev/null; then
    VLANS=$(ip -d link show | grep -c "vlan protocol" || true)
    if [[ "$VLANS" -gt 0 ]]; then
        pass "Found $VLANS VLAN interface(s)"
        ip -d link show | grep -A1 "vlan protocol" | tee "$EVIDENCE_DIR/vlan-interfaces.txt"
    else
        warn "No VLAN interfaces found on this host — may be handled at switch level"
    fi
fi

# Check 2: 8021q kernel module loaded
info "Checking 8021q kernel module..."
if lsmod 2>/dev/null | grep -q 8021q; then
    pass "8021q kernel module loaded (VLAN tagging supported)"
else
    warn "8021q kernel module not loaded"
    echo "  FIX: sudo modprobe 8021q && echo 8021q >> /etc/modules"
fi

# Check 3: Bridge VLAN filtering (if bridges exist)
info "Checking bridge VLAN filtering..."
if command -v bridge &>/dev/null; then
    BRIDGES=$(ip link show type bridge 2>/dev/null | grep -c "state" || true)
    if [[ "$BRIDGES" -gt 0 ]]; then
        bridge vlan show > "$EVIDENCE_DIR/bridge-vlan.txt" 2>&1
        if grep -q "PVID" "$EVIDENCE_DIR/bridge-vlan.txt"; then
            pass "Bridge VLAN configuration found"
        else
            warn "Bridges exist but no VLAN filtering configured"
        fi
    else
        info "No bridges found — skipping bridge VLAN check"
    fi
fi

# Check 4: Native VLAN not VLAN 1
info "Checking native VLAN configuration..."
if [[ -f "$EVIDENCE_DIR/bridge-vlan.txt" ]]; then
    if grep -q "PVID.*vid 1 " "$EVIDENCE_DIR/bridge-vlan.txt" 2>/dev/null; then
        fail "Native VLAN is VLAN 1 — should be changed to unused VLAN ID"
        echo "  WHY: Default VLAN 1 is targeted by VLAN hopping attacks (DTP, double tagging)"
        echo "  FIX: Change native VLAN to an unused VLAN ID (e.g., 999)"
    else
        pass "Native VLAN is not default VLAN 1"
    fi
else
    info "Cannot determine native VLAN from this host — check switch config"
fi

echo ""
echo "============================================"
echo "Summary: $PASS PASS / $WARN WARN / $FAIL FAIL"
echo "============================================"
echo "Evidence saved to: $EVIDENCE_DIR"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
```

`01-auditors/audit-802.1x-status.sh` — Check if 802.1X port-based network access control is configured (wpa_supplicant on Linux, netsh on Windows). Verify authentication state.

```bash
#!/usr/bin/env bash
set -euo pipefail

# 802.1X Port-Based Access Control Auditor
#
# PURPOSE: Verify 802.1X network access control configuration.
# NIST CONTROLS: AC-3 Access Enforcement, IA-2 Identification and Authentication
# WHERE TO RUN: Endpoint host
# USAGE: ./audit-802.1x-status.sh

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; WARN=0; FAIL=0

pass()  { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }

EVIDENCE_DIR="/tmp/jsa-evidence/802.1x-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "802.1X Network Access Control — Audit"
echo "============================================"
echo ""

# Platform detection
if command -v wpa_cli &>/dev/null; then
    info "Platform: Linux (wpa_supplicant)"
    
    # Check wpa_supplicant running
    if pgrep -x wpa_supplicant &>/dev/null; then
        pass "wpa_supplicant is running"
        wpa_cli status > "$EVIDENCE_DIR/wpa-status.txt" 2>&1
        
        # Check EAP method
        EAP_STATUS=$(wpa_cli status 2>/dev/null | grep "EAP state" || echo "unknown")
        if echo "$EAP_STATUS" | grep -qi "success\|completed"; then
            pass "802.1X authentication: $EAP_STATUS"
        else
            warn "802.1X authentication state: $EAP_STATUS"
        fi
    else
        fail "wpa_supplicant is not running — 802.1X not active"
        echo "  FIX: Configure /etc/wpa_supplicant/wpa_supplicant.conf with EAP-TLS or PEAP"
    fi

elif command -v netsh &>/dev/null || command -v netsh.exe &>/dev/null; then
    info "Platform: Windows"
    
    # Check dot3svc service
    DOT3=$(sc query dot3svc 2>/dev/null | grep "STATE" || echo "unknown")
    if echo "$DOT3" | grep -qi "RUNNING"; then
        pass "Wired AutoConfig (dot3svc) service is running"
    else
        fail "Wired AutoConfig (dot3svc) service is not running"
        echo "  FIX: sc start dot3svc"
    fi
    
    netsh lan show interfaces > "$EVIDENCE_DIR/lan-interfaces.txt" 2>&1
else
    warn "Cannot determine 802.1X status — neither wpa_cli nor netsh found"
fi

echo ""
echo "============================================"
echo "Summary: $PASS PASS / $WARN WARN / $FAIL FAIL"
echo "============================================"
echo "Evidence saved to: $EVIDENCE_DIR"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
```

- [ ] **Step 3: Create fixers**

`02-fixers/fix-arp-monitoring.sh` — Install and configure arpwatch. This is a generic best-practice fixer: "ARP spoofing detection isn't running — here's how to set it up."

```bash
#!/usr/bin/env bash
set -euo pipefail

# ARP Monitoring — Fix
#
# PURPOSE: Deploy arpwatch for ARP spoofing detection.
#          Generic best-practice setup — not environment-specific.
# NIST CONTROLS: SC-7 Boundary Protection, SI-4 Monitoring
# WHERE TO RUN: Network host that needs ARP monitoring
# USAGE: sudo ./fix-arp-monitoring.sh [interface]
#
# EXAMPLE:
#   sudo ./fix-arp-monitoring.sh eth0

IFACE="${1:-eth0}"

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] Run as root (sudo)."
    exit 1
fi

EVIDENCE_DIR="/tmp/jsa-evidence/arp-monitoring-fix-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "ARP Monitoring — Fix (Deploy arpwatch)"
echo "============================================"
echo ""

# Step 1: Install arpwatch
echo "[*] Step 1: Install arpwatch..."
if command -v arpwatch &>/dev/null; then
    echo "[OK] arpwatch already installed"
else
    if command -v apt &>/dev/null; then
        apt update -qq && apt install -y arpwatch
    elif command -v yum &>/dev/null; then
        yum install -y arpwatch
    else
        echo "[ERROR] Package manager not detected. Install arpwatch manually."
        exit 1
    fi
fi

# Step 2: Configure interface
echo "[*] Step 2: Configure arpwatch for interface $IFACE..."
CONF="/etc/default/arpwatch"
if [[ -f "$CONF" ]]; then
    cp "$CONF" "$EVIDENCE_DIR/arpwatch-default-before.txt"
    # Set interface
    sed -i "s/^INTERFACES=.*/INTERFACES=\"$IFACE\"/" "$CONF" 2>/dev/null || \
        echo "INTERFACES=\"$IFACE\"" >> "$CONF"
    echo "[OK] Set INTERFACES=$IFACE in $CONF"
else
    echo "INTERFACES=\"$IFACE\"" > "$CONF"
    echo "[OK] Created $CONF with INTERFACES=$IFACE"
fi

# Step 3: Enable and start
echo "[*] Step 3: Enable and start arpwatch..."
systemctl enable arpwatch 2>/dev/null || true
systemctl restart arpwatch

# Step 4: Verify
echo "[*] Step 4: Verify..."
if pgrep -x arpwatch &>/dev/null; then
    echo "[PASS] arpwatch is running"
    echo "[INFO] arpwatch will log new/changed MAC-IP pairs to syslog"
    echo "[INFO] Monitor with: tail -f /var/log/syslog | grep arpwatch"
else
    echo "[FAIL] arpwatch failed to start — check: journalctl -u arpwatch"
    exit 1
fi

echo ""
echo "============================================"
echo "How to Create a Custom ARP Alert"
echo "============================================"
echo ""
echo "arpwatch logs to syslog. To create a custom alert when a new station"
echo "appears on the network (potential rogue device):"
echo ""
echo "  # Example: Forward arpwatch 'new station' events to Sentinel/Splunk"
echo "  # In rsyslog (/etc/rsyslog.d/arpwatch.conf):"
echo '  :programname, isequal, "arpwatch" /var/log/arpwatch.log'
echo ""
echo "  # Then configure your SIEM to monitor /var/log/arpwatch.log"
echo "  # Alert on: 'new station' and 'flip flop' (MAC change) events"
echo ""
echo "Evidence saved to: $EVIDENCE_DIR"
```

`02-fixers/fix-port-security.md` — Markdown guide for switch port security (can't be scripted generically across vendors). Covers Cisco, Juniper, and Linux bridge examples.

```markdown
# Port Security — Remediation Guide

## When This Control Fails

Port security fails when: any device can plug into a switch port and get network access, MAC flooding is possible, or rogue devices can join trusted VLANs.

## How to Fix — By Platform

### Cisco IOS

```
! Enable port security on access port
interface GigabitEthernet0/1
  switchport mode access
  switchport access vlan 10
  switchport port-security
  switchport port-security maximum 2
  switchport port-security violation restrict
  switchport port-security mac-address sticky
  
! WHY: NIST AC-3 requires enforcement of access at L2.
! 'maximum 2' allows a phone + workstation.
! 'violation restrict' drops + logs (better than shutdown for availability).
! 'sticky' learns MACs dynamically and writes to running config.
```

### Juniper (ELS)

```
set interfaces ge-0/0/1 unit 0 family ethernet-switching port-security maximum-mac-addresses 2
set interfaces ge-0/0/1 unit 0 family ethernet-switching port-security mac-limit action drop
```

### Linux Bridge (lab environments)

```bash
# Limit MACs learned on bridge port
bridge link set dev eth1 learning on
# Use ebtables to restrict:
ebtables -A FORWARD -i eth1 --among-src ! 00:11:22:33:44:55 -j DROP
```

### Creating a Custom Detection Signature (arpwatch)

To detect MAC flooding (many new MACs in short time):

```bash
# Count 'new station' events per minute in arpwatch log
# Alert if > 10 new stations in 60 seconds (MAC flood indicator)
grep "new station" /var/log/arpwatch.log | \
  awk -F'[ :]' '{print $1,$2,$3,$4}' | \
  uniq -c | sort -rn | head -5
# If top count > 10, investigate the source interface.
```

## Evidence for Auditors
- Switch port security config per port (show port-security interface)
- arpwatch logs showing MAC-IP tracking
- VLAN assignment per port documentation
```

- [ ] **Step 4: Create templates**

`03-templates/arpwatch/arpwatch.conf` — Gold-standard arpwatch configuration with WHY comments.

```bash
# /etc/default/arpwatch
#
# WHY: NIST SI-4 requires monitoring of information systems for unauthorized access.
# arpwatch detects ARP spoofing, rogue devices, and MAC address changes — the L2
# indicators that IDS/IPS at L3+ cannot see.

# Interface to monitor
# WHY: Must be set to the interface where ARP traffic is visible (not a tunnel or loopback)
INTERFACES="eth0"

# Email for alerts (new station, flip flop, changed ethernet address)
# WHY: Immediate notification on rogue device detection
# Set to your SOC distribution list or leave blank for syslog-only
MAILTO="soc@example.com"

# Run as non-root (arpwatch user)
# WHY: NIST AC-6 least privilege — monitoring tools should not run as root
RUNAS="arpwatch"

# Database file
# WHY: arpwatch builds a MAC-IP history database for baseline comparison
# Backup this file — it represents your known-good network inventory
DATAFILE="/var/lib/arpwatch/arp.dat"
```

`03-templates/defender-iot/network-detection-policy.json` — Microsoft Defender for IoT network detection policy template.

```json
{
  "_comment": "Microsoft Defender for IoT — Network Detection Policy Template",
  "_nist_controls": "SC-7, SI-4, AC-3",
  "_purpose": "Baseline network detection policy for L2 anomaly monitoring",
  
  "policy_name": "L2-ARP-Anomaly-Detection",
  "description": "Detect ARP spoofing, rogue devices, and VLAN hopping at the data link layer",
  
  "detection_rules": [
    {
      "name": "ARP Spoofing Detected",
      "description": "Two or more devices claiming the same IP address via ARP",
      "severity": "High",
      "category": "Network Anomaly",
      "mitre_technique": "T1557.002",
      "nist_control": "SC-7",
      "enabled": true
    },
    {
      "name": "New Unauthorized Device",
      "description": "MAC address not in approved device inventory appeared on network",
      "severity": "Medium",
      "category": "Unauthorized Access",
      "mitre_technique": "T1200",
      "nist_control": "AC-3",
      "enabled": true
    },
    {
      "name": "VLAN Hopping Attempt",
      "description": "Double-tagged 802.1Q frame detected (DTP exploitation)",
      "severity": "Critical",
      "category": "Network Attack",
      "mitre_technique": "T1599",
      "nist_control": "AC-4",
      "enabled": true
    }
  ],
  
  "alert_destinations": [
    {
      "type": "sentinel",
      "workspace_id": "REPLACE_WITH_WORKSPACE_ID",
      "enabled": true
    },
    {
      "type": "syslog",
      "server": "REPLACE_WITH_SYSLOG_SERVER",
      "port": 514,
      "enabled": false
    }
  ]
}
```

- [ ] **Step 5: Create tools/run-all-audits.sh**

Same pattern as Layer 1 but invoking: `audit-arp-integrity.sh`, `audit-vlan-config.sh`, `audit-802.1x-status.sh`.

- [ ] **Step 6: Replace playbooks**

Delete old playbooks, create new cycle:

**`00-install-validate.md`** — Install arpwatch, Wireshark/tshark, Defender for IoT agent (if Azure). Validate each tool detects ARP traffic. Reference existing `tools/setup-l2-tools.sh` for the attacker container setup.

**`01-assess.md`** — Rewrite with GP-CONSULTING header format. Keep checklist depth from existing but add SC-7 (ARP/L2 boundary), AC-3 (VLAN enforcement), AC-4 (L2 flow control), SI-4 (L2 monitoring) sections with implementation priority ranking.

**`01a-arp-spoofing-audit.md`** — Deep-dive: run arpwatch audit, check for gratuitous ARP, review arpwatch database for flip-flops, verify syslog forwarding to SIEM.

**`02-fix-SC7-arp-protection.md`** — Deploy arpwatch, configure syslog forwarding, add SIEM detection rule for ARP anomalies. References `02-fixers/fix-arp-monitoring.sh`.

**`02a-fix-AC3-vlan-segmentation.md`** — VLAN design principles, native VLAN change, DTP disable, trunk port hardening. References `02-fixers/fix-port-security.md`.

**`03-validate.md`** — Re-run all auditors, confirm improvement. Test with a controlled ARP spoof from the attacker container to verify detection fires.

**`04-triage-alerts.md`** — Daily review of arpwatch syslog entries, Defender for IoT alerts, Sentinel L2 incidents. Investigation workflow for "new station" and "flip flop" events.

- [ ] **Step 7: Commit**

```bash
git add OSI-MODEL-SECURITY/02-DATA-LINK-LAYER/
git commit -m "seclab: add L2 data link auditors, fixers, templates, playbook cycle"
```

---

## Task 3: Layer 3 — Network (03-NETWORK-LAYER)

**Files:**
- Create: `03-NETWORK-LAYER/01-auditors/audit-firewall-rules.sh`
- Create: `03-NETWORK-LAYER/01-auditors/audit-suricata-config.sh`
- Create: `03-NETWORK-LAYER/01-auditors/audit-zeek-config.sh`
- Create: `03-NETWORK-LAYER/01-auditors/audit-network-segmentation.sh`
- Create: `03-NETWORK-LAYER/02-fixers/fix-suricata-rule-update.sh`
- Create: `03-NETWORK-LAYER/02-fixers/fix-suricata-custom-signature.md`
- Create: `03-NETWORK-LAYER/02-fixers/fix-default-deny.sh`
- Create: `03-NETWORK-LAYER/02-fixers/fix-management-ports.sh`
- Create: `03-NETWORK-LAYER/03-templates/suricata/suricata.yaml`
- Create: `03-NETWORK-LAYER/03-templates/suricata/local.rules`
- Create: `03-NETWORK-LAYER/03-templates/zeek/local.zeek`
- Create: `03-NETWORK-LAYER/03-templates/network-policies/default-deny.yaml`
- Create: `03-NETWORK-LAYER/03-templates/windows-firewall/hardened-gpo.md`
- Create: `03-NETWORK-LAYER/03-templates/azure-nsg/nsg-baseline.json`
- Create: `03-NETWORK-LAYER/tools/run-all-audits.sh`
- Replace: playbooks (delete old 4, create new cycle)

The L3 auditors and fixers mirror GP-CONSULTING's patterns but are generic best-practice. Key difference: dual-stack templates include both Windows Firewall/Azure NSG (CySA+ default) and iptables/nftables (open-source alternative).

- [ ] **Step 1: Create directory structure**

```bash
BASE="/home/jimmie/linkops-industries/GP-copilot/GP-PROJECTS/01-instance/slot-3/Anthra-SecLAB/OSI-MODEL-SECURITY/03-NETWORK-LAYER"
mkdir -p "$BASE/01-auditors" "$BASE/02-fixers" "$BASE/tools"
mkdir -p "$BASE/03-templates/suricata" "$BASE/03-templates/zeek"
mkdir -p "$BASE/03-templates/network-policies" "$BASE/03-templates/windows-firewall" "$BASE/03-templates/azure-nsg"
```

- [ ] **Step 2: Create auditors**

Model after GP-CONSULTING auditors but generic. Each auditor checks:

**`audit-firewall-rules.sh`** — Platform-detect (iptables/nftables/Windows Firewall/Azure NSG CLI). Check: default policy is DROP/DENY, management ports restricted, egress filtering exists, logging enabled, no 0.0.0.0/0 ACCEPT rules on management ports. Output: PASS/WARN/FAIL with remediation hints. Same color-coded pattern as GP-CONSULTING's auditors.

**`audit-suricata-config.sh`** — Mirror GP-CONSULTING's `audit-suricata-config.sh` pattern. Check: Suricata running, EVE JSON enabled, rule count (30K+ baseline), custom local.rules exist, HOME_NET configured, live detection test (curl testmynids.org). Generic — no environment-specific paths.

**`audit-zeek-config.sh`** — Check: Zeek running, conn.log generating, DNS log enabled, log rotation configured. Same pattern as GP-CONSULTING.

**`audit-network-segmentation.sh`** — Check: multiple subnets/VLANs exist, cross-zone deny rules in place, K8s NetworkPolicy (if applicable), no flat network indicators. Works on Linux (ip route, iptables FORWARD) and documents Azure NSG checks.

- [ ] **Step 3: Create fixers**

**`fix-suricata-rule-update.sh`** — Generic Suricata rule update procedure. Runs `suricata-update` or `so-rule-update`, verifies rule count increased, restarts Suricata, tests detection. Same evidence collection as GP-CONSULTING's `fix-rule-update.sh`.

**`fix-suricata-custom-signature.md`** — "How to create a custom Suricata signature" with a working example. This is the core of the fixer philosophy: tool isn't catching what it should, here's how to write a rule.

```markdown
# Suricata Custom Signature — How to Create

## When You Need This

Suricata's default ET Open rules cover known threats. When you need to detect:
- An internal application protocol or behavior specific to your environment
- A new threat not yet in public rulesets
- A policy violation (cleartext credentials, unauthorized service)

## Anatomy of a Suricata Rule

```
action protocol source_ip source_port -> dest_ip dest_port (options;)
```

| Field | Values | Purpose |
|-------|--------|---------|
| action | alert, drop, pass, reject | What to do on match |
| protocol | tcp, udp, icmp, http, dns, tls | Protocol to inspect |
| source/dest | $HOME_NET, $EXTERNAL_NET, any, CIDR | Network scope |
| options | msg, content, sid, rev, classtype, metadata | Detection logic |

## Working Example: Detect Cleartext Password Submission

**Scenario:** Your web application has a login form. You want to detect if credentials are ever submitted over HTTP (not HTTPS) — a CySA+ audit finding.

```
# SID range: 1000000-1099999 (local/site-specific rules)
# WHY: NIST SC-8 requires confidentiality of transmitted information.
# Cleartext password submission violates SC-8 and IA-5(1)(c).

alert http $HOME_NET any -> any any (
    msg:"LOCAL - Cleartext password submission over HTTP";
    flow:to_server,established;
    content:"POST"; http_method;
    content:"password"; http_client_body; nocase;
    content:!"https"; http_header; 
    classtype:policy-violation;
    sid:1000001; rev:1;
    metadata:nist SC-8, mitre_technique T1557, deployment Perimeter;
)
```

**What each option does:**
- `flow:to_server,established` — Only match client→server on established connections
- `content:"POST"; http_method` — Only POST requests (form submissions)
- `content:"password"; http_client_body; nocase` — Body contains "password" field
- `classtype:policy-violation` — Classification for alert categorization
- `metadata:nist SC-8` — NIST control mapping for compliance reporting

## How to Deploy

1. Add the rule to `/etc/suricata/rules/local.rules`
2. Test syntax: `suricata -T -c /etc/suricata/suricata.yaml`
3. Reload rules: `kill -USR2 $(pidof suricata)` (live reload, no restart needed)
4. Verify: `tail -f /var/log/suricata/eve.json | jq 'select(.alert.signature_id==1000001)'`

## More Examples

### Detect DNS query to known-bad TLD
```
alert dns $HOME_NET any -> any any (
    msg:"LOCAL - DNS query to suspicious TLD (.top)";
    dns.query; content:".top"; endswith; nocase;
    classtype:bad-unknown;
    sid:1000002; rev:1;
    metadata:nist SI-4, mitre_technique T1071.004;
)
```

### Detect SSH brute force (threshold)
```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
    msg:"LOCAL - SSH brute force attempt";
    flow:to_server;
    threshold:type both, track by_src, count 5, seconds 60;
    classtype:attempted-admin;
    sid:1000003; rev:1;
    metadata:nist AC-7, mitre_technique T1110;
)
```

## Testing Your Signature

After deploying, generate matching traffic and verify the alert fires:

```bash
# For the cleartext password rule:
curl -X POST http://target/login -d "username=test&password=test123"

# Check alerts:
tail -1 /var/log/suricata/eve.json | jq '.alert'
# Expected: signature "LOCAL - Cleartext password submission over HTTP"
```
```

**`fix-default-deny.sh`** — Apply default-deny firewall policy. Platform-aware (iptables/Windows Firewall). Includes SSH client detection to prevent self-lockout (same safety as GP-CONSULTING's fix-management-ports.sh).

**`fix-management-ports.sh`** — Restrict SSH/RDP to admin CIDR only. Platform-aware. Rate limiting. Logging. Same lockout prevention.

- [ ] **Step 4: Create templates**

**`suricata/suricata.yaml`** — Gold-standard config mirroring GP-CONSULTING's template. EVE JSON enabled, HOME_NET set to placeholder, rule sources configured, logging tuned. Every directive annotated with WHY and NIST control.

**`suricata/local.rules`** — Copy GP-CONSULTING's local.rules template (7 sections: auth attacks, DNS evasion, suspicious DNS, lateral movement, database exposure, cleartext protocols, C2 indicators). Each rule has NIST + MITRE metadata.

**`zeek/local.zeek`** — Baseline Zeek script with protocol logging, DNS logging, connection logging. WHY comments per @load.

**`network-policies/default-deny.yaml`** — K8s NetworkPolicy template for default-deny ingress+egress with WHY comments.

**`windows-firewall/hardened-gpo.md`** — Windows Firewall hardening via Group Policy. CySA+ default stack. Inbound default block, management port restriction, logging to Windows Event Log, PowerShell commands for validation.

**`azure-nsg/nsg-baseline.json`** — ARM template for baseline Azure NSG: deny all inbound default, allow management from admin CIDR only, enable NSG flow logs.

- [ ] **Step 5: Create tools/run-all-audits.sh**

Invoke: `audit-firewall-rules.sh`, `audit-suricata-config.sh`, `audit-zeek-config.sh`, `audit-network-segmentation.sh`.

- [ ] **Step 6: Replace playbooks**

Delete old playbooks, create:

**`00-install-validate.md`** — Install Suricata, Zeek (or Security Onion for both). Configure Azure NSG if cloud. Validate with testmynids.org detection test. Mirror GP-CONSULTING's 00-install but include Windows Firewall setup alongside Linux.

**`01-assess.md`** — Rewrite with GP-CONSULTING depth. SC-7, AC-4, SI-3, SI-4 checklists. Implementation priority ranking.

**`01a-suricata-audit.md`** — Mirror GP-CONSULTING's 01a-suricata-audit.md. Deep-dive: diff active config against template, rule freshness, live detection tests, suppression review.

**`01b-zeek-flow-audit.md`** — Flow analysis deep-dive. Conn.log health, DNS logging, baseline traffic patterns.

**`02-fix-SI3-ids-rules.md`** — Update IDS rules, deploy custom signatures. References fixers.

**`02a-fix-SC7-firewall.md`** — Full firewall hardening. Management port restriction, default deny, logging.

**`03-validate.md`** — Re-run all auditors, confirm fixes held, test with scenario traffic.

**`04-triage-alerts.md`** — Daily SOC workflow: morning dashboard review, IDS alert investigation, flow anomaly investigation, escalation. Mirror GP-CONSULTING's 04-triage-alerts.md pattern.

- [ ] **Step 7: Update control-map.md**

Add columns for auditor script, fixer script, and template file that map to each NIST control row. Keep existing content, add the new tool mappings.

- [ ] **Step 8: Commit**

```bash
git add OSI-MODEL-SECURITY/03-NETWORK-LAYER/
git commit -m "seclab: add L3 network auditors, fixers, dual-stack templates, playbook cycle"
```

---

## Task 4: Layer 4 — Transport (04-TRANSPORT-LAYER)

**Files:**
- Create: `04-TRANSPORT-LAYER/01-auditors/audit-tls-config.sh`
- Create: `04-TRANSPORT-LAYER/01-auditors/audit-cert-lifecycle.sh`
- Create: `04-TRANSPORT-LAYER/01-auditors/audit-mtls-status.sh`
- Create: `04-TRANSPORT-LAYER/02-fixers/fix-weak-ciphers.sh`
- Create: `04-TRANSPORT-LAYER/02-fixers/fix-expired-cert.sh`
- Create: `04-TRANSPORT-LAYER/02-fixers/fix-tls-custom-check.md`
- Create: `04-TRANSPORT-LAYER/03-templates/tls/nginx-tls.conf`
- Create: `04-TRANSPORT-LAYER/03-templates/tls/envoy-tls.yaml`
- Create: `04-TRANSPORT-LAYER/03-templates/cert-manager/clusterissuer.yaml`
- Create: `04-TRANSPORT-LAYER/03-templates/cert-manager/certificate.yaml`
- Create: `04-TRANSPORT-LAYER/03-templates/openssl/openssl.cnf`
- Create: `04-TRANSPORT-LAYER/03-templates/defender-cloud/tls-policy.md`
- Create: `04-TRANSPORT-LAYER/tools/run-all-audits.sh`
- Replace: playbooks

- [ ] **Step 1: Create directory structure**

```bash
BASE="/home/jimmie/linkops-industries/GP-copilot/GP-PROJECTS/01-instance/slot-3/Anthra-SecLAB/OSI-MODEL-SECURITY/04-TRANSPORT-LAYER"
mkdir -p "$BASE/01-auditors" "$BASE/02-fixers" "$BASE/tools"
mkdir -p "$BASE/03-templates/tls" "$BASE/03-templates/cert-manager" "$BASE/03-templates/openssl" "$BASE/03-templates/defender-cloud"
```

- [ ] **Step 2: Create auditors**

**`audit-tls-config.sh`** — Uses testssl.sh and openssl s_client to check: TLS version (1.2+ required), cipher suites (no RC4/DES/3DES), HSTS header, certificate validity, key size (2048+ RSA, 256+ ECDSA). Generic — takes a host:port argument.

```bash
#!/usr/bin/env bash
set -euo pipefail

# TLS Configuration Auditor
#
# PURPOSE: Validate TLS configuration against NIST SC-8 and SC-13 requirements.
# NIST CONTROLS: SC-8 Transmission Confidentiality, SC-13 Cryptographic Protection
# WHERE TO RUN: Analyst workstation with network access to target
# USAGE: ./audit-tls-config.sh <host:port>
# EXAMPLE: ./audit-tls-config.sh app.example.com:443

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <host:port>"
    echo "Example: $0 app.example.com:443"
    exit 1
fi

HOST="${TARGET%%:*}"
PORT="${TARGET##*:}"
[[ "$PORT" == "$HOST" ]] && PORT=443

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; WARN=0; FAIL=0

pass()  { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info()  { echo -e "${CYAN}[INFO]${NC} $1"; }

EVIDENCE_DIR="/tmp/jsa-evidence/tls-audit-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "============================================"
echo "TLS Configuration — Audit"
echo "Target: $HOST:$PORT"
echo "============================================"
echo ""

# Check 1: TLS connectivity
info "Testing TLS connectivity..."
if ! echo | openssl s_client -connect "$HOST:$PORT" -servername "$HOST" </dev/null > "$EVIDENCE_DIR/tls-connect.txt" 2>&1; then
    fail "Cannot establish TLS connection to $HOST:$PORT"
    exit 1
fi
pass "TLS connection established"

# Check 2: TLS version — reject SSLv3, TLS 1.0, TLS 1.1
info "Checking TLS versions..."
for proto in ssl3 tls1 tls1_1; do
    if echo | openssl s_client -connect "$HOST:$PORT" -"$proto" -servername "$HOST" </dev/null 2>&1 | grep -q "BEGIN CERTIFICATE"; then
        fail "Server accepts deprecated protocol: $proto"
    else
        pass "Server rejects: $proto"
    fi
done

# Check TLS 1.2 and 1.3 support
for proto in tls1_2 tls1_3; do
    if echo | openssl s_client -connect "$HOST:$PORT" -"$proto" -servername "$HOST" </dev/null 2>&1 | grep -q "BEGIN CERTIFICATE"; then
        pass "Server supports: $proto"
    else
        info "Server does not support: $proto"
    fi
done

# Check 3: Certificate validity
info "Checking certificate validity..."
CERT_INFO=$(echo | openssl s_client -connect "$HOST:$PORT" -servername "$HOST" 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null)
echo "$CERT_INFO" > "$EVIDENCE_DIR/cert-info.txt"

EXPIRY=$(echo "$CERT_INFO" | grep "notAfter" | cut -d= -f2)
if [[ -n "$EXPIRY" ]]; then
    EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$EXPIRY" +%s 2>/dev/null || echo 0)
    NOW_EPOCH=$(date +%s)
    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
    if [[ $DAYS_LEFT -lt 0 ]]; then
        fail "Certificate EXPIRED ($DAYS_LEFT days ago)"
    elif [[ $DAYS_LEFT -lt 30 ]]; then
        warn "Certificate expires in $DAYS_LEFT days"
    else
        pass "Certificate valid for $DAYS_LEFT days"
    fi
fi

# Check 4: Key size
info "Checking key size..."
KEY_INFO=$(echo | openssl s_client -connect "$HOST:$PORT" -servername "$HOST" 2>/dev/null | openssl x509 -noout -text 2>/dev/null | grep "Public-Key:" || true)
if echo "$KEY_INFO" | grep -q "2048\|3072\|4096"; then
    pass "RSA key size: $KEY_INFO"
elif echo "$KEY_INFO" | grep -q "256\|384\|521"; then
    pass "ECDSA key size: $KEY_INFO"
else
    warn "Key size: $KEY_INFO — verify meets minimum (RSA 2048, ECDSA 256)"
fi

# Check 5: HSTS header
info "Checking HSTS header..."
if command -v curl &>/dev/null; then
    HSTS=$(curl -sI "https://$HOST:$PORT/" 2>/dev/null | grep -i "strict-transport-security" || true)
    if [[ -n "$HSTS" ]]; then
        pass "HSTS header present: $HSTS"
    else
        fail "HSTS header missing — browsers will allow HTTP downgrade"
        echo "  FIX: Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header"
    fi
fi

echo ""
echo "============================================"
echo "Summary: $PASS PASS / $WARN WARN / $FAIL FAIL"
echo "============================================"
echo ""
echo "For deep-dive analysis, run testssl.sh:"
echo "  testssl.sh --severity HIGH $HOST:$PORT"
echo ""
echo "Evidence saved to: $EVIDENCE_DIR"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
```

**`audit-cert-lifecycle.sh`** — Check cert-manager (K8s) or manual certificate inventory. Expiring certs, missing auto-renewal, ClusterIssuer health.

**`audit-mtls-status.sh`** — Check Istio/Linkerd mTLS PeerAuthentication. If no service mesh, report as gap.

- [ ] **Step 3: Create fixers**

**`fix-weak-ciphers.sh`** — Disable TLS 1.0/1.1, enforce ECDHE+AESGCM ciphers. Platform-aware (nginx, Apache, Windows IIS via PowerShell).

**`fix-expired-cert.sh`** — Force cert-manager renewal or manual openssl cert renewal procedure.

**`fix-tls-custom-check.md`** — "How to create a custom TLS compliance check" — using testssl.sh and openssl to verify specific cipher requirements, with working example of a CI gate script.

- [ ] **Step 4: Create templates**

Dual-stack: `tls/nginx-tls.conf` (open-source), `defender-cloud/tls-policy.md` (Microsoft Defender for Cloud TLS recommendations + Azure App Service TLS settings). Plus `cert-manager/`, `openssl/` configs mirroring GP-CONSULTING with WHY comments.

- [ ] **Step 5: Create tools/run-all-audits.sh and replace playbooks**

Playbook cycle: `00-install-validate.md` (install testssl.sh, cert-manager, openssl), `01-assess.md`, `01a-tls-audit.md`, `01b-cert-lifecycle-audit.md`, `02-fix-SC8-tls.md`, `02a-fix-IA5-certs.md`, `03-validate.md`, `04-triage-alerts.md`.

- [ ] **Step 6: Commit**

```bash
git add OSI-MODEL-SECURITY/04-TRANSPORT-LAYER/
git commit -m "seclab: add L4 transport auditors, fixers, dual-stack templates, playbook cycle"
```

---

## Task 5: Layer 5 — Session (05-SESSION-LAYER)

**Files:**
- Create: `05-SESSION-LAYER/01-auditors/audit-rbac-privileges.sh`
- Create: `05-SESSION-LAYER/01-auditors/audit-service-accounts.sh`
- Create: `05-SESSION-LAYER/01-auditors/audit-session-policy.sh`
- Create: `05-SESSION-LAYER/01-auditors/audit-mfa-status.sh`
- Create: `05-SESSION-LAYER/02-fixers/fix-session-timeout.sh`
- Create: `05-SESSION-LAYER/02-fixers/fix-mfa-enforcement.md`
- Create: `05-SESSION-LAYER/02-fixers/fix-overprivileged-sa.sh`
- Create: `05-SESSION-LAYER/02-fixers/fix-conditional-access-policy.md`
- Create: `05-SESSION-LAYER/03-templates/entra-id/conditional-access-baseline.json`
- Create: `05-SESSION-LAYER/03-templates/entra-id/mfa-enforcement-policy.json`
- Create: `05-SESSION-LAYER/03-templates/keycloak/realm-export.json`
- Create: `05-SESSION-LAYER/03-templates/keycloak/client-config.json`
- Create: `05-SESSION-LAYER/03-templates/rbac/least-privilege-role.yaml`
- Create: `05-SESSION-LAYER/03-templates/rbac/read-only-clusterrole.yaml`
- Create: `05-SESSION-LAYER/03-templates/vault/auth-kubernetes.hcl`
- Create: `05-SESSION-LAYER/tools/run-all-audits.sh`
- Replace: playbooks

- [ ] **Step 1: Create directory structure**

```bash
BASE="/home/jimmie/linkops-industries/GP-copilot/GP-PROJECTS/01-instance/slot-3/Anthra-SecLAB/OSI-MODEL-SECURITY/05-SESSION-LAYER"
mkdir -p "$BASE/01-auditors" "$BASE/02-fixers" "$BASE/tools"
mkdir -p "$BASE/03-templates/entra-id" "$BASE/03-templates/keycloak" "$BASE/03-templates/rbac" "$BASE/03-templates/vault"
```

- [ ] **Step 2: Create auditors**

**`audit-rbac-privileges.sh`** — Check K8s RBAC: cluster-admin bindings, wildcard permissions, who-can checks. Uses kubectl. Same checks as GP-CONSULTING but generic.

**`audit-service-accounts.sh`** — SA inventory, automountServiceAccountToken, default SA exposure.

**`audit-session-policy.sh`** — Dual-stack: Entra ID (via az cli / Microsoft Graph API) session timeout + Keycloak REST API session settings. Check idle timeout, max lifetime, brute force protection, cookie flags.

**`audit-mfa-status.sh`** — Dual-stack: Entra ID MFA registration status (az ad user list) + Keycloak TOTP enforcement. Report users without MFA.

- [ ] **Step 3: Create fixers**

**`fix-session-timeout.sh`** — Set session timeouts. Dual-stack: Entra ID Conditional Access policy (via az cli) + Keycloak realm update (via REST API).

**`fix-mfa-enforcement.md`** — "How to enforce MFA" guide. Entra ID: Conditional Access policy requiring MFA for all users. Keycloak: Required action for TOTP. Working examples for both.

**`fix-overprivileged-sa.sh`** — Remove cluster-admin from service accounts, create scoped Roles. Generic K8s.

**`fix-conditional-access-policy.md`** — "How to create a custom Conditional Access policy in Entra ID" — CySA+ focused. Working example: block legacy authentication, require MFA from untrusted locations.

- [ ] **Step 4: Create templates**

Dual-stack templates:
- `entra-id/conditional-access-baseline.json` — Baseline CA policies: require MFA, block legacy auth, sign-in risk policy. WHY comments mapping to AC-2, AC-12, IA-2.
- `entra-id/mfa-enforcement-policy.json` — MFA-specific CA policy.
- `keycloak/realm-export.json` — Mirror GP-CONSULTING's hardened realm template (30min idle, 10hr max, brute force, MFA).
- `keycloak/client-config.json` — OIDC client with PKCE.
- `rbac/` and `vault/` — Mirror GP-CONSULTING templates.

- [ ] **Step 5: Create tools/run-all-audits.sh and replace playbooks**

Playbook cycle: `00-install-validate.md`, `01-assess.md`, `01a-iam-audit.md` (Entra ID focused), `01b-session-policy-audit.md`, `02-fix-AC6-rbac.md`, `02a-fix-AC12-session.md`, `02b-fix-IA2-mfa.md`, `03-validate.md`, `04-triage-alerts.md`.

- [ ] **Step 6: Commit**

```bash
git add OSI-MODEL-SECURITY/05-SESSION-LAYER/
git commit -m "seclab: add L5 session auditors, fixers, dual-stack templates (Entra ID + Keycloak), playbook cycle"
```

---

## Task 6: Layer 6 — Presentation (06-PRESENTATION-LAYER)

**Files:**
- Create: `06-PRESENTATION-LAYER/01-auditors/audit-encryption-at-rest.sh`
- Create: `06-PRESENTATION-LAYER/01-auditors/audit-key-rotation.sh`
- Create: `06-PRESENTATION-LAYER/01-auditors/audit-crypto-standards.sh`
- Create: `06-PRESENTATION-LAYER/01-auditors/audit-secrets-exposure.sh`
- Create: `06-PRESENTATION-LAYER/02-fixers/fix-key-rotation.sh`
- Create: `06-PRESENTATION-LAYER/02-fixers/fix-weak-hashing.md`
- Create: `06-PRESENTATION-LAYER/02-fixers/fix-plaintext-secrets.sh`
- Create: `06-PRESENTATION-LAYER/02-fixers/fix-bitlocker-enforcement.md`
- Create: `06-PRESENTATION-LAYER/03-templates/azure-key-vault/vault-policy.json`
- Create: `06-PRESENTATION-LAYER/03-templates/azure-key-vault/key-rotation-policy.json`
- Create: `06-PRESENTATION-LAYER/03-templates/hashicorp-vault/vault-config.hcl`
- Create: `06-PRESENTATION-LAYER/03-templates/hashicorp-vault/transit-policy.hcl`
- Create: `06-PRESENTATION-LAYER/03-templates/sops/.sops.yaml`
- Create: `06-PRESENTATION-LAYER/03-templates/k8s/encryption-config.yaml`
- Create: `06-PRESENTATION-LAYER/03-templates/openssl/strong-defaults.cnf`
- Create: `06-PRESENTATION-LAYER/tools/run-all-audits.sh`
- Replace: playbooks

- [ ] **Step 1: Create directory structure**

```bash
BASE="/home/jimmie/linkops-industries/GP-copilot/GP-PROJECTS/01-instance/slot-3/Anthra-SecLAB/OSI-MODEL-SECURITY/06-PRESENTATION-LAYER"
mkdir -p "$BASE/01-auditors" "$BASE/02-fixers" "$BASE/tools"
mkdir -p "$BASE/03-templates/azure-key-vault" "$BASE/03-templates/hashicorp-vault" "$BASE/03-templates/sops" "$BASE/03-templates/k8s" "$BASE/03-templates/openssl"
```

- [ ] **Step 2: Create auditors**

**`audit-encryption-at-rest.sh`** — Check: K8s etcd encryption, PostgreSQL SSL, S3/Azure Blob encryption, disk encryption (BitLocker status via PowerShell or LUKS via cryptsetup). Dual-stack.

**`audit-key-rotation.sh`** — Check: Azure Key Vault key age (az keyvault key list), HashiCorp Vault transit key versions, cert-manager cert age, etcd encryption key age.

**`audit-crypto-standards.sh`** — Scan for weak algorithms: MD5, SHA-1, DES, RC4 in configs and code. Check TLS cipher suites across services. Uses grep + openssl.

**`audit-secrets-exposure.sh`** — Check: .env files in git (gitleaks), secrets in K8s ConfigMaps, pre-commit hooks for secret detection. References detect-secrets and gitleaks.

- [ ] **Step 3: Create fixers**

**`fix-key-rotation.sh`** — Dual-stack: Azure Key Vault key rotation (az keyvault key rotate) + HashiCorp Vault transit key rotation (vault write -f transit/keys/*/rotate). Evidence collection.

**`fix-weak-hashing.md`** — "How to migrate from MD5/SHA-1 to modern algorithms" with code examples (Python bcrypt, Go bcrypt, Node.js argon2). Includes detection commands.

**`fix-plaintext-secrets.sh`** — Generic: migrate K8s ConfigMap secrets to Sealed Secrets or External Secrets Operator. Evidence of before/after.

**`fix-bitlocker-enforcement.md`** — CySA+ stack: enable BitLocker via GPO or Intune. PowerShell commands. Azure Disk Encryption alternative.

- [ ] **Step 4: Create templates**

Dual-stack: `azure-key-vault/` (Microsoft) + `hashicorp-vault/` (open-source). Plus `sops/`, `k8s/`, `openssl/` mirroring GP-CONSULTING with WHY comments.

- [ ] **Step 5: Create tools/run-all-audits.sh and replace playbooks**

Playbook cycle: `00-install-validate.md`, `01-assess.md`, `01a-encryption-audit.md`, `01b-crypto-standards-audit.md`, `02-fix-SC28-encryption.md`, `02a-fix-SC13-crypto.md`, `03-validate.md`, `04-triage-alerts.md`.

- [ ] **Step 6: Commit**

```bash
git add OSI-MODEL-SECURITY/06-PRESENTATION-LAYER/
git commit -m "seclab: add L6 presentation auditors, fixers, dual-stack templates (Azure KV + HashiCorp Vault), playbook cycle"
```

---

## Task 7: Layer 7 — Application (07-APPLICATION-LAYER)

The most complex layer. Dual SIEM playbooks (Sentinel + Splunk). Most auditors and fixers.

**Files:**
- Create: `07-APPLICATION-LAYER/01-auditors/audit-siem-ingest.sh`
- Create: `07-APPLICATION-LAYER/01-auditors/audit-edr-agents.sh`
- Create: `07-APPLICATION-LAYER/01-auditors/audit-vuln-scan-coverage.sh`
- Create: `07-APPLICATION-LAYER/01-auditors/audit-alert-rules.sh`
- Create: `07-APPLICATION-LAYER/01-auditors/audit-log-retention.sh`
- Create: `07-APPLICATION-LAYER/02-fixers/fix-sentinel-analytics-rule.md`
- Create: `07-APPLICATION-LAYER/02-fixers/fix-splunk-alert-rules.sh`
- Create: `07-APPLICATION-LAYER/02-fixers/fix-missing-log-source.sh`
- Create: `07-APPLICATION-LAYER/02-fixers/fix-wazuh-fim-paths.sh`
- Create: `07-APPLICATION-LAYER/02-fixers/fix-defender-active-response.md`
- Create: `07-APPLICATION-LAYER/02-fixers/fix-cis-failures.sh`
- Create: `07-APPLICATION-LAYER/02-fixers/fix-missing-headers.sh`
- Create: `07-APPLICATION-LAYER/03-templates/sentinel/analytics-rule-brute-force.json`
- Create: `07-APPLICATION-LAYER/03-templates/sentinel/analytics-rule-priv-escalation.json`
- Create: `07-APPLICATION-LAYER/03-templates/sentinel/workbook-soc-overview.json`
- Create: `07-APPLICATION-LAYER/03-templates/splunk/inputs.conf`
- Create: `07-APPLICATION-LAYER/03-templates/splunk/savedsearches.conf`
- Create: `07-APPLICATION-LAYER/03-templates/splunk/dashboard-soc-overview.xml`
- Create: `07-APPLICATION-LAYER/03-templates/wazuh/ossec.conf`
- Create: `07-APPLICATION-LAYER/03-templates/wazuh/local_rules.xml`
- Create: `07-APPLICATION-LAYER/03-templates/defender/endpoint-policy.json`
- Create: `07-APPLICATION-LAYER/03-templates/kube-bench/job.yaml`
- Create: `07-APPLICATION-LAYER/03-templates/kubescape/framework-nsa.yaml`
- Create: `07-APPLICATION-LAYER/tools/run-all-audits.sh`
- Replace: playbooks (dual SIEM)

- [ ] **Step 1: Create directory structure**

```bash
BASE="/home/jimmie/linkops-industries/GP-copilot/GP-PROJECTS/01-instance/slot-3/Anthra-SecLAB/OSI-MODEL-SECURITY/07-APPLICATION-LAYER"
mkdir -p "$BASE/01-auditors" "$BASE/02-fixers" "$BASE/tools"
mkdir -p "$BASE/03-templates/sentinel" "$BASE/03-templates/splunk" "$BASE/03-templates/wazuh"
mkdir -p "$BASE/03-templates/defender" "$BASE/03-templates/kube-bench" "$BASE/03-templates/kubescape"
```

- [ ] **Step 2: Create auditors**

**`audit-siem-ingest.sh`** — Dual-stack: check Sentinel workspace health (az monitor log-analytics workspace show) + Splunk HEC health (curl localhost:8088). Verify log sources flowing, recent events exist, ingest volume meets threshold.

**`audit-edr-agents.sh`** — Dual-stack: Defender for Endpoint status (MpCmdRun.exe or mdatp health on Linux) + Wazuh agent enrollment and rule activation.

**`audit-vuln-scan-coverage.sh`** — Check: ZAP targets configured, Trivy CI gates present, Grype schedule, Semgrep rules in pipeline. Generic across CI systems.

**`audit-alert-rules.sh`** — Dual-stack: Sentinel analytics rules (az sentinel alert-rule list) + Splunk saved searches (splunk search '| rest /services/saved/searches'). Verify detection coverage.

**`audit-log-retention.sh`** — Check retention policies against compliance requirements (HIPAA 6yr, FedRAMP 3yr, PCI 1yr).

- [ ] **Step 3: Create fixers**

**`fix-sentinel-analytics-rule.md`** — "How to create a custom Sentinel analytics rule" with KQL example. This is the CySA+ core skill. Working example: detect brute force (5+ failed logins in 5 minutes).

```markdown
# Microsoft Sentinel — Custom Analytics Rule

## When You Need This

Sentinel's built-in detection rules cover common threats. When you need to detect:
- Application-specific attack patterns
- Custom log sources not covered by built-in templates
- Organization-specific policy violations

## How to Create an Analytics Rule

### Via Azure Portal
1. Navigate: Sentinel → Analytics → Create → Scheduled query rule
2. Set name, description, severity, MITRE ATT&CK mapping
3. Write the KQL query
4. Set query frequency and lookback period
5. Configure alert threshold
6. Set automated response (optional)

### Working Example: Brute Force Detection

**KQL Query:**
```kql
// Detect brute force: 5+ failed logins from same IP in 5 minutes
// NIST AC-7: Unsuccessful Logon Attempts
// MITRE: T1110 Brute Force

SigninLogs
| where ResultType != "0"  // Non-zero = failure
| where TimeGenerated > ago(5m)
| summarize
    FailedAttempts = count(),
    TargetAccounts = make_set(UserPrincipalName),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by IPAddress, Location = tostring(LocationDetails.city)
| where FailedAttempts >= 5
| extend AccountCount = array_length(TargetAccounts)
| project
    IPAddress,
    Location,
    FailedAttempts,
    AccountCount,
    TargetAccounts,
    Duration = LastAttempt - FirstAttempt
| order by FailedAttempts desc
```

**Rule Configuration:**
| Setting | Value | Why |
|---------|-------|-----|
| Query frequency | Every 5 minutes | Match detection window |
| Lookback | 5 minutes | Same as frequency for no gaps |
| Alert threshold | > 0 results | Any match triggers |
| Severity | High | Brute force = active attack |
| MITRE | T1110 | Brute Force |
| NIST | AC-7 | Unsuccessful Logon Attempts |

### Via ARM Template (Infrastructure as Code)

See `03-templates/sentinel/analytics-rule-brute-force.json` for deployable ARM template.

### Via Azure CLI

```bash
az sentinel alert-rule create \
  --resource-group "REPLACE_RG" \
  --workspace-name "REPLACE_WORKSPACE" \
  --alert-rule-id "brute-force-detection" \
  --scheduled \
  --query "SigninLogs | where ResultType != '0' | ..." \
  --query-frequency "PT5M" \
  --query-period "PT5M" \
  --severity "High" \
  --trigger-operator "GreaterThan" \
  --trigger-threshold 0
```

## More KQL Examples

### Impossible Travel
```kql
SigninLogs
| where ResultType == "0"
| summarize by UserPrincipalName, IPAddress, Location=tostring(LocationDetails.city), TimeGenerated
| sort by UserPrincipalName, TimeGenerated asc
| extend PrevLocation = prev(Location), PrevTime = prev(TimeGenerated), PrevUser = prev(UserPrincipalName)
| where UserPrincipalName == PrevUser
| extend TimeDiff = datetime_diff('minute', TimeGenerated, PrevTime)
| where TimeDiff < 60 and Location != PrevLocation
```

### Privilege Escalation
```kql
AuditLogs
| where OperationName has_any ("Add member to role", "Add eligible member to role")
| where TargetResources[0].modifiedProperties[0].newValue has_any ("Global Administrator", "Privileged Role Administrator")
| project TimeGenerated, InitiatedBy.user.userPrincipalName, TargetResources[0].userPrincipalName, OperationName
```
```

**`fix-splunk-alert-rules.sh`** — Deploy Splunk saved searches from template. Same pattern as GP-CONSULTING's fix-alert-rules.sh but with evidence collection.

**`fix-missing-log-source.sh`** — Generic log source onboarding: identify what's missing, configure forwarding (Filebeat, Fluentd, Splunk UF, Azure Monitor Agent).

**Other fixers:** `fix-wazuh-fim-paths.sh`, `fix-defender-active-response.md`, `fix-cis-failures.sh`, `fix-missing-headers.sh` — all following the same pattern: what's broken, how to fix it, working example.

- [ ] **Step 4: Create templates**

**Sentinel templates:**
- `analytics-rule-brute-force.json` — ARM template for the brute force KQL rule above
- `analytics-rule-priv-escalation.json` — ARM template for privilege escalation detection
- `workbook-soc-overview.json` — Sentinel workbook template for SOC dashboard

**Splunk templates:**
- `inputs.conf` — Mirror GP-CONSULTING's inputs.conf with WHY comments
- `savedsearches.conf` — Mirror GP-CONSULTING's correlation searches
- `dashboard-soc-overview.xml` — Splunk dashboard XML for SOC overview

**Wazuh/Defender/kube-bench/kubescape** — Mirror GP-CONSULTING templates with WHY comments. Defender templates are CySA+ stack addition.

- [ ] **Step 5: Create tools/run-all-audits.sh and replace playbooks**

Playbook cycle with **dual SIEM**:
- `00-install-validate.md` — Install Sentinel workspace (az monitor) OR Splunk. Deploy Wazuh OR Defender. Validate log flow.
- `01-assess.md` — Full L7 assessment checklist (existing content is strong, reformat to GP-CONSULTING header style)
- `01a-sentinel-audit.md` — **NEW: Sentinel-specific SIEM audit.** KQL queries for log source validation, analytics rule health, workbook status, data connector review.
- `01a-splunk-audit.md` — **Splunk-specific SIEM audit.** Mirrors GP-CONSULTING's 01a-splunk-audit.md (now renamed).
- `01b-vuln-scan-audit.md` — ZAP, Trivy, Grype, Semgrep coverage check
- `01c-edr-audit.md` — Defender for Endpoint OR Wazuh agent health
- `02-fix-AU6-alert-rules.md` — Deploy detection rules. References both Sentinel and Splunk fixers.
- `02a-fix-RA5-vuln-scan.md` — Set up scanning pipeline
- `02b-fix-SI7-fim.md` — File integrity monitoring setup
- `03-validate.md` — Re-audit all L7 controls
- `04-triage-alerts.md` — Daily SOC workflow. Dual-stack: Sentinel incidents portal + Splunk notable events. Investigation procedures.

- [ ] **Step 6: Update control-map.md**

Add auditor/fixer/template columns. Add Sentinel alongside existing Splunk entries.

- [ ] **Step 7: Commit**

```bash
git add OSI-MODEL-SECURITY/07-APPLICATION-LAYER/
git commit -m "seclab: add L7 application auditors, fixers, dual SIEM templates (Sentinel + Splunk), playbook cycle"
```

---

## Task 8: Root Files Update

**Files:**
- Modify: `OSI-MODEL-SECURITY/README.md`
- Modify: `OSI-MODEL-SECURITY/control-tools-map.md` (if exists, create if not)

- [ ] **Step 1: Update root README.md**

Update the Layer Index table to reflect new structure. Add a "Directory Structure" section showing the per-layer layout (01-auditors, 02-fixers, etc.). Add a "Dual SIEM" section explaining Sentinel vs Splunk choice. Keep existing methodology and governance framework sections unchanged.

- [ ] **Step 2: Create or update control-tools-map.md**

Cross-layer quick-reference mapping NIST controls to auditor scripts, fixer scripts, and template files. Mirrors GP-CONSULTING's root-level `control-tools-map.md`.

Format:
```markdown
| NIST Control | Layer | Auditor | Fixer | Template |
|-------------|-------|---------|-------|----------|
| SC-7 | L2, L3 | audit-arp-integrity.sh, audit-firewall-rules.sh | fix-arp-monitoring.sh, fix-management-ports.sh | arpwatch.conf, azure-nsg/nsg-baseline.json |
```

- [ ] **Step 3: Commit**

```bash
git add OSI-MODEL-SECURITY/README.md OSI-MODEL-SECURITY/control-tools-map.md
git commit -m "seclab: update root README and add cross-layer control-tools-map"
```

---

## Execution Order

Tasks 1-7 (layers) are **independent** and can be executed in parallel by separate subagents. Task 0 (GP-CONSULTING rename) should go first. Task 8 (root files) should go last after all layers are complete.

```
Task 0 (GP-CONSULTING rename) ──┐
                                 ├── Task 1 (L1 Physical)     ─┐
                                 ├── Task 2 (L2 Data Link)     │
                                 ├── Task 3 (L3 Network)       │
                                 ├── Task 4 (L4 Transport)     ├── Task 8 (Root files)
                                 ├── Task 5 (L5 Session)       │
                                 ├── Task 6 (L6 Presentation)  │
                                 └── Task 7 (L7 Application)  ─┘
```

## Total File Count Estimate

| Category | Per Layer (avg) | Total (7 layers) |
|----------|----------------|-------------------|
| Auditors | 3-5 scripts | ~28 |
| Fixers | 3-5 scripts/docs | ~28 |
| Templates | 4-6 configs | ~35 |
| Playbooks | 7-10 markdown | ~55 |
| Tools | 1 script | 7 |
| **Total new files** | | **~153** |

Plus: 28 old playbook files deleted, 7 control-maps updated, 1 GP-CONSULTING rename, 1 root README update.
