# PE-3 Physical Access Control — Break

## Scenario: Tailgating

An unauthorized person follows an authorized employee through a badge-controlled door without swiping their own badge. The authorized employee holds the door open out of courtesy.

## What This Simulates

- Social engineering at the physical layer
- Failure of anti-tailgating controls
- Gap between policy ("badge required") and enforcement ("but everyone holds the door")

## Tabletop Setup

1. Identify a badge-controlled entry point to the server room or data center
2. During the exercise, have a team member attempt to follow another through without badging
3. Observe: does the door have anti-tailgating sensors? Does anyone challenge the unbadged person?
4. Document: time of entry, whether challenged, how far into the facility they reached

## What Breaks

- PE-3 (Physical Access Control) — unauthorized access to controlled area
- PE-6 (Monitoring Physical Access) — if CCTV doesn't capture the event
- PE-2 (Physical Access Authorizations) — if visitor log is not updated

## Real-World Examples

- 2019: Capital One breach began with a former employee who still had physical badge access
- Social engineering tests routinely show 60-80% tailgating success rate in corporate environments
- Average cost of unauthorized physical access incident: $1.2M (Ponemon Institute)
