# T1110 Brute Force / Lockout — Investigation

**ATT&CK:** T1110 — Brute Force
**Triage time target:** 15 minutes to initial verdict

## Triage Checklist

### Volume Analysis

- [ ] How many failed attempts? Over what time window?
- [ ] Attempts per minute — is this automated (>10/min) or manual (slow)?
- [ ] Single source IP or distributed (password spray from many IPs)?
- [ ] Single target user or multiple users (spray pattern)?

### Source Analysis

- [ ] Is the source IP a known scanner, Tor exit, or VPN datacenter? (Check AbuseIPDB)
- [ ] Has this IP appeared before in your logs?
- [ ] Is the IP external or internal? Internal brute force is higher severity.
- [ ] Geographic origin — expected or anomalous?

### Target Analysis

- [ ] Which accounts are being targeted?
- [ ] Are targeted accounts real (valid usernames) or garbage (enumeration)?
- [ ] Are privileged accounts (admin, root, service accounts) in the target list?
- [ ] Did any account get successfully authenticated after failures? (Critical finding)

### Success-After-Failure Check

This is the most important check. A success after many failures = possible account compromise.
- [ ] Run detect.sh and check the `success-after-fail-ips.txt` output
- [ ] If any IPs had both failures and successes: pull the full session log for that IP
- [ ] Determine if the successful login was legitimate (user traveling?) or unauthorized

## Key Questions to Answer

1. Was any account successfully authenticated during or after the brute force?
2. Is this ongoing or did it stop?
3. Is the source IP already blocked?
4. Are any privileged accounts being targeted?

## Escalate If

- Any account successfully authenticated from the attacking IP
- Privileged accounts are in the target list
- Attack is internal (source IP is inside the network)
- Attack is ongoing and lockout is not stopping it
