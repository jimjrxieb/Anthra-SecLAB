# Containment

## Purpose

Stop the bleeding. Prevent the attacker from doing more damage. Do NOT remediate yet — preserve evidence.

## Containment vs. Remediation

| Containment | Remediation |
|------------|-------------|
| Stop ongoing harm | Fix the root cause |
| Preserve evidence | Clean up artifacts |
| Done immediately | Done after investigation |
| Reversible | Permanent |

## Containment Options (in order of escalation)

### 1. Network Isolation (host level)
```bash
# Disable network interface
sudo ip link set <interface> down
# Or via firewall — block all traffic except to/from forensics workstation
sudo iptables -I INPUT -j DROP
sudo iptables -I OUTPUT -j DROP
sudo iptables -I INPUT -s <forensics_workstation_ip> -j ACCEPT
sudo iptables -I OUTPUT -d <forensics_workstation_ip> -j ACCEPT
```

### 2. VLAN Quarantine (network level)
Move the host to a quarantine VLAN (requires network team). Preserves the host state while blocking lateral movement.

### 3. Account Lockout
```bash
sudo usermod -L <compromised_username>   # lock account
# Force log out active sessions:
pkill -u <compromised_username> -KILL
```

### 4. Service Shutdown (targeted)
If a specific service is compromised (web server, database):
```bash
sudo systemctl stop <service>
```

## What NOT to Do

- **Do NOT reboot** — destroys volatile memory (running processes, network connections, encryption keys)
- **Do NOT run antivirus on the live system** — can alter or delete evidence
- **Do NOT delete suspicious files** — preserve for forensics
- **Do NOT reset passwords before scoping** — attacker may notice and escalate

## Document Every Action

Every containment action goes in the incident timeline with:
- Timestamp (UTC)
- Analyst who took the action
- Exact command run
- Observed effect
