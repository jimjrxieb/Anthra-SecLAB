# Layer 3 Network — Break/Fix Scenarios

## Purpose

Run each scenario's break, detect, fix, validate cycle to demonstrate the control's value and produce evidence for governance reporting.

## How to Run a Scenario

Each scenario is in `scenarios/{CONTROL-ID}-{name}/` and contains 5 files:

| File | Purpose | Format |
|------|---------|--------|
| `break.sh` | Executes the misconfiguration or attack | Shell script |
| `detect.sh` | Detects the vulnerability or exposure | Shell script |
| `fix.sh` | Remediates the finding | Shell script |
| `validate.sh` | Confirms the fix is effective | Shell script |
| `governance.md` | CISO brief with risk, cost, ROI | Governance report |

## Scenario Execution Order

### Scenario 1: SC-7 Firewall Misconfiguration (Scripted)

This scenario is fully scriptable on any Linux host with iptables or Windows host with netsh.

1. **Break:** Run `scenarios/SC-7-firewall-misconfig/break.sh` to open management ports to 0.0.0.0/0
   ```bash
   sudo ./scenarios/SC-7-firewall-misconfig/break.sh eth0
   ```
2. **Detect:** Run `scenarios/SC-7-firewall-misconfig/detect.sh` to confirm exposure via Nmap and rule audit
   ```bash
   sudo ./scenarios/SC-7-firewall-misconfig/detect.sh 10.0.1.50
   ```
3. **Fix:** Run `scenarios/SC-7-firewall-misconfig/fix.sh` to restrict source IP and enable logging
   ```bash
   sudo ./scenarios/SC-7-firewall-misconfig/fix.sh 10.0.100.0/24
   ```
4. **Validate:** Run `scenarios/SC-7-firewall-misconfig/validate.sh` to confirm ports are filtered
   ```bash
   sudo ./scenarios/SC-7-firewall-misconfig/validate.sh 10.0.1.50 10.0.100.0/24
   ```
5. **Governance:** Review `scenarios/SC-7-firewall-misconfig/governance.md` — understand the CISO narrative ($1.46M ALE, $1,200 fix cost, 1,151x ROSI)

### Scenario 2: AC-4 Flat Network (Scripted)

This scenario requires a Linux host acting as a gateway/router between subnets. Use a lab environment with multiple subnets routed through a single host.

1. **Break:** Run `scenarios/AC-4-flat-network/break.sh` to remove all segmentation rules
   ```bash
   sudo ./scenarios/AC-4-flat-network/break.sh
   ```
2. **Detect:** Run `scenarios/AC-4-flat-network/detect.sh` to confirm cross-subnet reachability
   ```bash
   sudo ./scenarios/AC-4-flat-network/detect.sh 10.0.1.0/24 10.0.2.0/24 10.0.3.0/24
   ```
3. **Fix:** Run `scenarios/AC-4-flat-network/fix.sh` to implement zone-based segmentation
   ```bash
   sudo ./scenarios/AC-4-flat-network/fix.sh 10.0.100.0/24 10.0.10.0/24 10.0.20.0/24 10.0.30.0/24
   ```
4. **Validate:** Run `scenarios/AC-4-flat-network/validate.sh` to confirm segmentation is enforced
   ```bash
   sudo ./scenarios/AC-4-flat-network/validate.sh 10.0.100.0/24 10.0.10.0/24 10.0.20.0/24 10.0.30.0/24
   ```
5. **Governance:** Review `scenarios/AC-4-flat-network/governance.md` — understand the CISO narrative ($1.92M ALE, $4,700 fix cost, 387x ROSI)

## Evidence Collection

After each scenario, save evidence to `evidence/YYYY-MM-DD/`:

### SC-7 Firewall Misconfiguration Evidence
- Pre-break iptables/firewall rules snapshot
- Nmap scan showing open management ports (before fix)
- Nmap scan showing filtered management ports (after fix)
- Post-fix iptables rules with admin CIDR restrictions
- Logging configuration verification
- Rate limiting rule verification

### AC-4 Flat Network Evidence
- Pre-break FORWARD chain rules (segmentation rules)
- Nmap sweep showing cross-subnet reachability (before fix)
- Nmap sweep showing blocked cross-subnet traffic (after fix)
- Post-fix FORWARD chain rules with zone-based policy
- Denied traffic log entries (AC4-DENIED prefix)
- Zone map documentation (which CIDRs map to which zones)

## Lab Environment Notes

- SC-7 firewall misconfig works on any Linux host with iptables or any Windows host with netsh
- AC-4 flat network requires a multi-homed Linux host acting as a router (multiple interfaces or VLANs)
- For cloud testing, use AWS Security Groups + VPCs or Azure NSGs + VNets
- All shell scripts require root/sudo privileges
- Evidence directory is gitignored — evidence stays local, not in the repository
- Always save a full iptables backup (`iptables-save > backup.txt`) before running break scenarios
