# Layer 1 Physical — Triage Alerts (Daily Monitoring)

| Field | Value |
|-------|-------|
| NIST Controls | PE-3, PE-6, PE-14 |
| Tools | Badge system alert console, CCTV dashboard, Environmental monitoring dashboard |
| Enterprise Equivalent | Genetec Security Center alerts, APC NetBotz alert feed, Splunk Physical Security add-on |
| Time Estimate | 15–30 minutes daily |
| Rank | D — structured review against known-good baselines, escalate anomalies |

## What This Does

Defines the daily monitoring workflow for Layer 1 physical security alerts. Covers three alert categories: badge access anomalies (denied events, after-hours access), CCTV anomalies (camera offline, motion in restricted areas), and environmental threshold alerts (temperature, humidity, UPS, water). Establishes the triage decision tree and escalation path.

## Why This Matters

Physical security monitoring is not a quarterly audit activity — it is a daily operational task. A badge denial spike at 2 AM is a security event, not a maintenance ticket. An environmental alert for 84°F is a hardware failure in progress, not a configuration issue to review next week. Triage means deciding what is noise, what is an incident, and what requires immediate escalation. Getting this wrong costs equipment, data, or physical security.

---

## Daily Monitoring Checklist

### PE-3 / PE-6 — Badge and CCTV Review (5 minutes)

Open the badge system admin console and review:

- [ ] Any denied badge events in the last 24 hours
- [ ] Any after-hours access events (outside normal business hours)
- [ ] Any multiple failed attempts on the same credential (3+ = investigate)
- [ ] Any access by accounts that should be inactive (terminated employees)

Open the CCTV dashboard and confirm:

- [ ] All cameras are online (no offline indicators)
- [ ] No alerts flagged by the system

### PE-14 / PE-11 / PE-15 — Environmental Review (5 minutes)

Open the environmental monitoring dashboard:

- [ ] Temperature is in range (64–75°F)
- [ ] Humidity is in range (40–60% RH)
- [ ] UPS shows healthy status, battery charge normal
- [ ] No water sensor alerts
- [ ] No smoke or fire panel alerts

---

## Alert Triage Decision Tree

### Badge Access Denied Events

```
Denied badge event received
│
├─ Single denial, business hours, known employee
│   └─ NOISE — badge reader issue or user error. No action required.
│
├─ Single denial, after hours, known employee
│   └─ INVESTIGATE — confirm with employee whether they attempted access
│       ├─ Yes, they attempted → normal (forgot badge, used wrong card)
│       └─ No, they did not → ESCALATE — potential badge cloning or unauthorized use
│
├─ 3+ denials, same credential, short window
│   └─ INVESTIGATE — brute force attempt or malfunctioning badge
│       ├─ Employee confirms they were trying to enter → hardware issue, ticket to facilities
│       └─ Employee was not on site → ESCALATE — potential unauthorized attempt
│
└─ Access by inactive/terminated credential
    └─ ESCALATE IMMEDIATELY — badge was not deactivated or is being used fraudulently
```

### After-Hours Access Events

```
After-hours access event received (successful entry)
│
├─ Known employee, business context expected (IT maintenance, on-call)
│   └─ VERIFY — check if scheduled maintenance or on-call rotation
│       ├─ Confirmed scheduled → log and close
│       └─ Not scheduled → INVESTIGATE — contact employee for explanation
│
├─ Known employee, no expected business context
│   └─ INVESTIGATE — contact employee, confirm access was intentional
│
└─ Unknown employee or visitor badge
    └─ ESCALATE IMMEDIATELY — physical security incident
```

### Environmental Alerts

```
Temperature alert received
│
├─ WARNING (78–84°F)
│   └─ INVESTIGATE — check HVAC status, confirm alert is real (not sensor fault)
│       ├─ HVAC running normally → sensor calibration issue, ticket to facilities
│       └─ HVAC fault or offline → ESCALATE — hardware at risk within 30–60 minutes
│
└─ CRITICAL (≥85°F)
    └─ ESCALATE IMMEDIATELY — begin emergency cooling procedures
        ├─ Notify data center operations and management
        ├─ Begin graceful shutdown of non-critical systems if temperature continues rising
        └─ Contact HVAC emergency service
```

---

## Escalation Contacts

Fill in before going on shift:

| Situation | Contact | Method | SLA |
|-----------|---------|--------|-----|
| Badge access anomaly — low confidence | SOC analyst on duty | Ticket | 4 hours |
| After-hours access — unconfirmed | Security operations | Phone/Slack | 1 hour |
| Physical security incident | Security operations manager | Phone | Immediate |
| HVAC warning | Data center operations | Ticket | 30 minutes |
| HVAC critical | Data center operations + management | Phone | Immediate |
| Fire / suppression trigger | Fire response team + management | Phone | Immediate |
| Water detection | Facilities emergency | Phone | Immediate |

---

## Investigation Notes Template

When a finding requires investigation, document:

```
Date/Time:
Alert Type:
Alert Details (credential, location, timestamp from system):
Initial Assessment:
Action Taken:
Resolution:
Escalated? Y/N — if yes, to whom and when:
Evidence saved to:
Closed By:
Closed Date/Time:
```

Save completed investigation notes to `evidence/triage-<YYYYMMDD>/` in the layer directory.
