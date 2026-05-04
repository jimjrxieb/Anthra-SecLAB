# PE-14 Environmental Controls — Fix

## Remediation Steps

### Immediate (0-30 days)

1. **Temperature sensors** — install sensors in server room if missing (minimum: 2 per room at different locations)
2. **Alert configuration** — set thresholds: warning at 80°F (27°C), critical at 85°F (29°C), emergency at 90°F (32°C)
3. **Alert routing** — route to NOC, facilities team, and on-call engineer via SMS + email + PagerDuty
4. **Emergency procedure** — document: who to call, what to shut down first, where the backup cooling is

### Short-term (30-90 days)

1. **Redundant HVAC** — install backup cooling unit with automatic failover
2. **Hot aisle/cold aisle** — implement containment to maximize cooling efficiency
3. **UPS integration** — ensure HVAC is on UPS power for graceful transition during power events

### Long-term (90+ days)

1. **DCIM integration** — integrate environmental monitoring into data center infrastructure management platform
2. **Predictive maintenance** — IoT sensors on HVAC compressor, fan, refrigerant levels for early failure warning
3. **Annual capacity review** — verify cooling capacity matches current and projected heat load

## Implementation Cost Estimate

| Control | One-time Cost | Annual Cost | Notes |
|---------|-------------|-------------|-------|
| Temperature sensors (2) | $200-$500 | $0 | Wireless IP sensors |
| Alert configuration | $0 | $0 | Configuration of existing monitoring |
| Emergency procedure doc | $500 | $200/yr | Staff time to write and review annually |
| Redundant HVAC unit | $15,000-$50,000 | $3,000/yr | Depends on server room size |
| Hot/cold aisle containment | $5,000-$20,000 | $0 | One-time installation |
