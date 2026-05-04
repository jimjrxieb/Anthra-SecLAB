# Escalation Criteria

## When to Escalate Immediately (do not wait)

- Active ransomware encryption in progress
- Confirmed credential theft with evidence of use
- Data exfiltration in progress (large outbound transfer)
- Privileged account compromise confirmed
- C2 beacon confirmed (outbound to known malicious infrastructure)
- Physical security alert (tailgating, badge cloning)

## When to Escalate After Initial Triage

- True positive with lateral movement evidence
- True positive involving PCI/HIPAA/PII scoped systems
- True positive involving executive or privileged accounts
- Multiple correlated alerts suggesting coordinated attack
- Anomalous behavior with no business justification found

## Escalation Template

When handing off to L2 or IR, include:

```
Alert ID:
Escalating Analyst:
Time of escalation (UTC):

Summary (1-2 sentences):
Affected assets:
Affected accounts:

Evidence collected:
- [list IOCs, log snippets, enrichment results]

What I ruled out:
- [list what you investigated and why it doesn't apply]

Recommended next step:
- [what IR should do first]
```

## Do Not Escalate Without

- At least one corroborating data point beyond the single alert
- Enrichment results on the primary IOC
- A written summary in the case ticket
- The raw log that triggered the alert attached or linked
