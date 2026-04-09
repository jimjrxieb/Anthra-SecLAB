# PE-14 Environmental Controls — Break

## Scenario: HVAC Failure

The primary HVAC system serving the server room fails. Without cooling, server room temperature rises from the recommended 64-75°F (18-24°C) to over 95°F (35°C) within 30 minutes. Servers begin thermal throttling, then shutting down.

## What This Simulates

- Single point of failure in environmental controls
- Lack of temperature monitoring and alerting
- No automated response to environmental threshold breach
- No redundant cooling system

## Tabletop Setup

1. Identify the server room HVAC system and its monitoring (if any)
2. Ask: what happens if the primary unit fails at 2 AM on a Saturday?
3. Walk through: who gets alerted? How? What is the response time? Is there a backup unit?
4. Check: are temperature sensors installed? Do they send alerts? To whom? At what threshold?

## What Breaks

- PE-14 (Environmental Controls) — no redundant cooling, no monitoring, no automated response
- CP-2 (Contingency Planning) — if there is no documented response procedure
- SI-4 (Monitoring) — if there is no environmental alerting

## Real-World Examples

- 2023: British Airways — data center cooling failure caused 3-day outage, $150M in losses
- 2022: Twitter — data center temperature excursion forced emergency server shutdowns
- Average cost of unplanned data center downtime: $9,000/minute (Uptime Institute 2023)
