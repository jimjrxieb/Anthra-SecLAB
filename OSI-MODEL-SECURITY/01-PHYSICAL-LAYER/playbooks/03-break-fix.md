# Layer 1 Physical — Break/Fix Scenarios

## Purpose

Run each scenario's break → detect → fix → validate cycle to demonstrate the control's value and produce evidence for governance reporting.

## How to Run a Scenario

Each scenario is in `scenarios/{CONTROL-ID}-{name}/` and contains 5 files:

| File | Purpose | Format |
|------|---------|--------|
| `break.md` | Describes how to break or bypass the control | Tabletop exercise |
| `detect.md` | How to detect the misconfiguration or breach | Detection procedures |
| `fix.md` | How to remediate | Implementation steps |
| `validate.md` | How to confirm the fix works | Validation checklist |
| `governance.md` | CISO brief with risk, cost, ROI | Governance report |

## Scenario Execution Order

### Scenario 1: PE-3 Physical Access (Tailgating)

1. Read `scenarios/PE-3-physical-access/break.md` — understand the tailgating scenario
2. Execute the tabletop exercise described in break.md
3. Follow `scenarios/PE-3-physical-access/detect.md` — collect evidence of the bypass
4. Implement controls from `scenarios/PE-3-physical-access/fix.md`
5. Re-test using `scenarios/PE-3-physical-access/validate.md`
6. Review `scenarios/PE-3-physical-access/governance.md` — understand the CISO narrative

### Scenario 2: PE-14 Environmental (HVAC Failure)

1. Read `scenarios/PE-14-environmental/break.md` — understand the HVAC failure scenario
2. Execute the tabletop exercise
3. Follow `scenarios/PE-14-environmental/detect.md` — audit current environmental controls
4. Implement controls from `scenarios/PE-14-environmental/fix.md`
5. Test using `scenarios/PE-14-environmental/validate.md`
6. Review `scenarios/PE-14-environmental/governance.md` — understand the CISO narrative

## Evidence Collection

After each scenario, save evidence to `evidence/YYYY-MM-DD/`:
- Assessment checklists (completed)
- Screenshots of monitoring dashboards
- Alert test results
- Validation test results
- Governance brief (completed with real data)
