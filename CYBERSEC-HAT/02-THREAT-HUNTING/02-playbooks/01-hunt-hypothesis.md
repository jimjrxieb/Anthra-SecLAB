# Hunt Hypothesis

## Purpose

A hunt without a hypothesis is just random log searching. A good hypothesis is testable, specific, and tied to a real threat relevant to your environment.

## Hypothesis Template

```
IF [threat actor / technique] IS present in our environment,
THEN I expect to see [specific observable indicator]
IN [specific data source / log type].
```

Example:
> IF an attacker has dumped credentials from LSASS, THEN I expect to see a process other than lsass.exe or known security tools accessing /proc/[lsass_pid]/mem or using ptrace on lsass, IN auditd syscall logs or EDR process telemetry.

## How to Pick a Hypothesis

1. **Check your threat model** — what TTPs are relevant to your industry?
2. **Check recent threat intel** — what are active threat actors using right now?
3. **Check your detection gaps** — what ATT&CK techniques have no alert coverage?
4. **Check previous hunt findings** — what did you almost find last time?

## Hypothesis Quality Checklist

- [ ] Tied to a specific ATT&CK technique
- [ ] References a specific data source you actually have
- [ ] Defines what a positive finding looks like
- [ ] Defines what a negative finding looks like (also acceptable outcome)
- [ ] Time-bounded: will complete in one hunt session (hours, not days)

## Document Before Hunting

Write this down before you touch any data:
- Hypothesis statement
- ATT&CK technique ID
- Data sources to query
- Expected positive indicators
- Expected negative indicators
- Start time / planned end time
