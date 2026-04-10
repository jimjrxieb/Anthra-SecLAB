# Layer 2 Data Link — Break/Fix Scenarios

## Purpose

Run each scenario's break, detect, fix, validate cycle to demonstrate the control's value and produce evidence for governance reporting.

## How to Run a Scenario

Each scenario is in `scenarios/{CONTROL-ID}-{name}/` and contains 5 files:

| File | Purpose | Format |
|------|---------|--------|
| `break.sh` or `break.md` | Executes or describes the attack | Script or tabletop |
| `detect.sh` or `detect.md` | How to detect the attack | Script or procedures |
| `fix.md` | How to remediate | Implementation steps |
| `validate.sh` or `validate.md` | Confirm the fix works | Script or checklist |
| `governance.md` | CISO brief with risk, cost, ROI | Governance report |

## Scenario Execution Order

### Scenario 1: SC-7 ARP Spoofing (Scripted)

This scenario is fully scriptable in the lab environment.

1. **Break:** Run `scenarios/SC-7-arp-spoofing/break.sh` to perform ARP cache poisoning between two hosts
   ```bash
   sudo ./scenarios/SC-7-arp-spoofing/break.sh eth0 192.168.1.1 192.168.1.100
   ```
2. **Detect:** Run `scenarios/SC-7-arp-spoofing/detect.sh` to capture evidence of the spoofing
   ```bash
   sudo ./scenarios/SC-7-arp-spoofing/detect.sh eth0 60
   ```
3. **Fix:** Follow `scenarios/SC-7-arp-spoofing/fix.md` — enable DAI, DHCP snooping, static ARP entries
4. **Validate:** Run `scenarios/SC-7-arp-spoofing/validate.sh` to confirm ARP spoofing is blocked
   ```bash
   sudo ./scenarios/SC-7-arp-spoofing/validate.sh eth0 192.168.1.100 192.168.1.1
   ```
5. **Governance:** Review `scenarios/SC-7-arp-spoofing/governance.md` — understand the CISO narrative ($820K ALE, $1,200 fix cost, 649x ROSI)

### Scenario 2: AC-3 VLAN Hopping (Tabletop)

This scenario is a tabletop exercise because VLAN hopping requires physical switch hardware or a network emulator.

1. **Break:** Read `scenarios/AC-3-vlan-hopping/break.md` — understand double tagging and switch spoofing
2. **Detect:** Follow `scenarios/AC-3-vlan-hopping/detect.md` — review switch configurations and capture 802.1Q traffic
3. **Fix:** Follow `scenarios/AC-3-vlan-hopping/fix.md` — disable DTP, change native VLAN, prune unused VLANs
4. **Validate:** Walk through `scenarios/AC-3-vlan-hopping/validate.md` — verify all 7 configuration checks pass
5. **Governance:** Review `scenarios/AC-3-vlan-hopping/governance.md` — understand the CISO narrative ($1.23M ALE, $2,500 fix cost, 442x ROSI)

## Evidence Collection

After each scenario, save evidence to `evidence/YYYY-MM-DD/`:

### SC-7 ARP Spoofing Evidence
- Pre-attack ARP table snapshot
- Attack execution output (arpspoof/ettercap)
- Detection evidence (arpwatch alerts, tshark captures, duplicate MAC report)
- Post-fix validation report (from validate.sh)
- Switch DAI statistics (`show ip arp inspection statistics`)

### AC-3 VLAN Hopping Evidence
- Switch configuration export (`show running-config`)
- DTP status per port (`show dtp interface`)
- Trunk configuration (`show interface trunk`)
- Native VLAN verification
- VLAN pruning verification
- Tabletop walkthrough notes (attack path before/after fix)

## Lab Environment Notes

- SC-7 ARP spoofing requires at least 2 hosts on the same network segment plus the attacker host
- AC-3 VLAN hopping requires access to switch CLI for configuration review (or GNS3/EVE-NG for full simulation)
- All shell scripts require root/sudo privileges
- Evidence directory is gitignored — evidence stays local, not in the repository
