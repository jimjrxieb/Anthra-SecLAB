# Incident Declaration

## What Triggers an Incident Declaration

Not every alert is an incident. Declare an incident when:

- A security event has been confirmed as a true positive
- The scope is unclear and growing investigation is required
- Business operations are affected or at risk
- Regulatory notification may be required (PII involved, HIPAA, PCI)
- An alert has escalated from triage and requires sustained response

## Severity Tiers

| Tier | Name | Criteria | Response SLA | Notifications |
|------|------|----------|-------------|---------------|
| P1 | Critical | Active ransomware, confirmed data exfiltration, complete system compromise | 15 min | CISO, Legal, Executive |
| P2 | High | Probable compromise, privileged account involved, potential data exposure | 1 hr | Security Manager, IT Director |
| P3 | Medium | Confirmed true positive, limited scope, no immediate data risk | 4 hr | Security Manager |
| P4 | Low | True positive with minimal impact, no data risk | 24 hr | Security Team |

## Incident Declaration Template

```
INCIDENT DECLARATION
====================
Declared by:
Date/Time (UTC):
Severity:
Incident Type: [Ransomware / Phishing / Credential Theft / Insider / Other]

Initial Summary (2-3 sentences):

Affected systems:
Affected users:
Affected data (if known):

How discovered:
Alert ID (if applicable):

Incident Commander:
Lead Analyst:

Next update due:
```

## First 15 Minutes

1. Declare the incident and open the ticket
2. Notify required stakeholders per severity tier
3. Assign incident commander (person with authority to make calls)
4. Establish a comms channel (Slack/Teams room, bridge line)
5. Start the incident timeline — log everything with timestamps from this point
