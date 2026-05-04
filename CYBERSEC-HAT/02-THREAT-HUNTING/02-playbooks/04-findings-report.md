# Hunt Findings Report

## Purpose

Every hunt ends with a written report — positive or negative. A documented negative is evidence that you looked and found nothing. That is valuable for CA-7 compliance and for calibrating future hunts.

## Report Template

```
HUNT REPORT
===========
Date: 
Analyst:
Hypothesis: [exact hypothesis statement]
ATT&CK Technique: 
Data Sources Used:
Time Spent:

FINDINGS
--------
Result: [Positive / Negative / Inconclusive]

If Positive:
  - What was found:
  - Assets affected:
  - Timeline:
  - Escalated to IR: [yes/no, ticket number]

If Negative:
  - Queries run: [list]
  - Data quality assessment: [were sources complete?]
  - Confidence level: [high/medium/low — why?]

If Inconclusive:
  - What was found but not confirmed:
  - Data gaps that prevented conclusion:
  - Recommended follow-up:

DETECTIONS CREATED
------------------
[If this hunt reveals a detection gap, document the Sigma rule or SIEM alert to create]

NEXT HUNT RECOMMENDATIONS
--------------------------
[What this hunt suggests for the next hypothesis]
```

## Turning Hunts Into Detections

The best hunts produce one of two outcomes:
1. An incident (escalate to IR)
2. A new detection rule (so future attackers get caught by an alert, not a hunt)

If your hunt found something manually, write a Sigma rule for it. The hunt should only need to happen once.
