# Layer 1 Physical — Assess Current State

| Field | Value |
|-------|-------|
| NIST Controls | PE-3, PE-6, PE-13, PE-14, PE-11, PE-15 |
| Tools | audit-physical-access.sh, audit-environmental-controls.sh, pe-assessment-checklist.md |
| Enterprise Equivalent | Rapid7 InsightVM physical module, Qualys Asset Inventory |
| Time Estimate | 2–4 hours on site |
| Rank | D — structured data collection, no interpretation required |

## What This Does

Documents the current physical security posture before implementing or remediating any controls. This assessment establishes the baseline against which improvement is measured. Without it, you cannot know what you are fixing or prove to an auditor that you fixed it.

The assessment covers six NIST PE controls: physical access (PE-3), access monitoring (PE-6), fire protection (PE-13), environmental controls (PE-14), emergency power (PE-11), and water damage protection (PE-15). These controls are required by FedRAMP, HIPAA, and most SOC 2 Type II engagements.

## Why This Matters

Physical security is the layer that all other controls depend on. Encryption, firewalls, and endpoint protection are irrelevant if an attacker can walk into the server room. Regulators know this — physical control failures are audit-blocking findings in FedRAMP and HIPAA. A CISO who cannot answer "who has physical access to our servers?" has a governance gap, not just a technical gap.

---

## Assessment Procedure

### Step 1 — Run Interactive Audit Scripts

```bash
# Run full audit suite (recommended)
./tools/run-all-audits.sh

# Or run individual audits
./01-auditors/audit-physical-access.sh
./01-auditors/audit-environmental-controls.sh
```

Answer each prompt with y (yes/compliant) or n (no/non-compliant). The scripts write evidence to `/tmp/jsa-evidence/` with a timestamp. Review the output file after completion.

### Step 2 — Manual Walkthrough

While on site, physically verify:

1. Walk each controlled entry point — confirm badge readers are functional, doors do not prop open.
2. Check the CCTV dashboard — verify feeds are live, no cameras are offline.
3. Stand in the server room — note temperature displayed on any environmental monitors.
4. Locate UPS equipment — note model, confirm status LEDs show healthy state.
5. Locate fire suppression panel — note system type, last inspection date if posted.
6. Check under raised floor (if accessible) — confirm water sensors are present and labeled.

### Step 3 — Record Findings in Assessment Template

Transfer audit script results to the formal checklist:

```
03-templates/pe-assessment-checklist.md
```

Fill in Status (Pass / Fail / N/A) and Notes for each item. The completed checklist is the primary deliverable for this phase.

---

## Detailed Checklist

### PE-3 Physical Access Control

- [ ] Identify all entry points to the facility
- [ ] For each entry point: what access control exists? (badge, key, none)
- [ ] Are access logs maintained? Where? How long retained?
- [ ] Is there anti-tailgating hardware? (turnstiles, mantraps)
- [ ] Is there a visitor management policy? Is it enforced?
- [ ] Are terminated employees' badges deactivated within 24 hours?
- [ ] When was the last physical penetration test?
- [ ] Is server room access restricted separately from building perimeter?

### PE-6 Monitoring Physical Access

- [ ] Where are CCTV cameras located? Map them.
- [ ] Are there blind spots at controlled entry points?
- [ ] How long is footage retained?
- [ ] Who reviews footage? How often?
- [ ] Are access anomalies (off-hours entry, failed badge attempts) alerted?
- [ ] Are alerts routed to security operations or on-call?

### PE-14 Environmental Controls

- [ ] Is there temperature monitoring in the server room?
- [ ] What are the alert thresholds? (warn: 78°F, critical: 85°F)
- [ ] Who receives alerts?
- [ ] Is there redundant HVAC?
- [ ] When was the HVAC last serviced?
- [ ] Is there a humidity sensor?
- [ ] Is there a water/leak sensor?

### PE-13 Fire Protection

- [ ] What fire suppression system is installed? (FM-200, Novec, sprinkler)
- [ ] When was it last tested?
- [ ] Are smoke detectors installed and tested?
- [ ] Is there a documented evacuation procedure?

### PE-11 Emergency Power

- [ ] Is a UPS installed for all critical systems?
- [ ] What is the UPS load percentage?
- [ ] When was the UPS last load tested?
- [ ] Is there a generator for extended outages?

### PE-15 Water Damage Protection

- [ ] Are water/leak sensors installed under raised floors?
- [ ] Are sensors near HVAC drain pans?
- [ ] Are sensor alerts configured and routed?

---

## Output

Complete the checklist above and produce:

1. Completed `03-templates/pe-assessment-checklist.md` with all statuses filled in
2. Physical security inventory: entry points, cameras, sensors (spreadsheet or table)
3. Gap analysis: which PE controls have findings?
4. Risk ranking of findings using 5x5 matrix

Save all evidence to `/tmp/jsa-evidence/` and copy to `evidence/` in this layer directory.

---

## Implementation Priority (by risk/cost ratio)

| Priority | Control | Finding Type | Risk | Fix Cost | Ratio |
|----------|---------|-------------|------|----------|-------|
| 1 | PE-3 | No badge deactivation SLA | High — credential residue | Low — process change | High |
| 2 | PE-14 | No environmental alerts | High — silent HVAC failure | Low — alert config | High |
| 3 | PE-3 | No access list reviews | High — privilege accumulation | Low — quarterly process | High |
| 4 | PE-6 | No CCTV at entry points | High — no forensic record | Medium — hardware | Medium |
| 5 | PE-13 | Water sprinklers in server room | Critical — destroys equipment | High — system replacement | Medium |
| 6 | PE-11 | No UPS | Critical — data loss on outage | High — hardware | Medium |
| 7 | PE-15 | No water sensors | Medium — delayed flood detection | Low — sensor deployment | Medium |
| 8 | PE-3 | No visitor log | Medium — non-repudiation gap | Low — process/software | Medium |
