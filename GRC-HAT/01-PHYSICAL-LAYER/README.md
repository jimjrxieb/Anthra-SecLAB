# Layer 1 — Physical

## What This Layer Covers

Physical access to facilities, environmental controls, hardware security, media protection. This is the foundation — if someone can physically access your servers, every other layer's controls are bypassable.

## Why It Matters

A server accidentally unplugged costs downtime. An unauthorized person in a data center costs everything. Physical security is the control that every auditor checks first and most organizations assume is "someone else's problem."

## NIST 800-53 Controls

| Control ID | Control Name | What It Requires |
|-----------|-------------|-----------------|
| PE-1 | Physical and Environmental Protection Policy | Documented policy for physical security |
| PE-2 | Physical Access Authorizations | Maintain list of authorized personnel |
| PE-3 | Physical Access Control | Badge readers, locks, mantraps, visitor logs |
| PE-6 | Monitoring Physical Access | CCTV, access logs, intrusion detection |
| PE-13 | Fire Protection | Fire suppression, detection, evacuation procedures |
| PE-14 | Environmental Controls | HVAC, humidity, temperature monitoring and alerting |

## Tools

| Tool | Type | Cost | Purpose |
|------|------|------|---------|
| Badge access / RFID | Physical | Varies | Access control enforcement |
| CCTV / NVR | Physical | Varies | Visual monitoring and evidence |
| Environmental sensors | Physical | Varies | Temperature, humidity, water detection |
| Snipe-IT | Open source | Free | Asset inventory and tracking |

## Scenarios

| Scenario | Control | Format |
|----------|---------|--------|
| [PE-3 Physical Access](scenarios/PE-3-physical-access/) | PE-3 | Tabletop (.md) |
| [PE-14 Environmental](scenarios/PE-14-environmental/) | PE-14 | Tabletop (.md) |
