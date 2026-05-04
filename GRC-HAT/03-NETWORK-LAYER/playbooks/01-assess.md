# Layer 3 Network — Assess Current State

| Field | Value |
|-------|-------|
| NIST Controls | SC-7, AC-4, SI-3, SI-4 |
| Tools | audit-firewall-rules.sh, audit-suricata-config.sh, audit-zeek-config.sh, audit-network-segmentation.sh |
| Time Estimate | 1–2 hours |
| Rank | D |

---

## Objective

Document the current network layer security posture before implementing any controls. Run the automated auditors, then complete the manual checklists. Layer 3 controls fail silently — a firewall with default ACCEPT looks like a firewall until you check the policy. A Suricata instance with 0 rules still shows as running.

Run auditors first:

```bash
bash tools/run-all-audits.sh
# Review: /tmp/jsa-evidence/l3-full-audit-*/l3-audit-report.txt
```

---

## SC-7 — Boundary Protection Checklist (10 items)

- [ ] What firewall technology is in use? (iptables, nftables, Windows Firewall, pfSense, Azure NSG, AWS SG)
- [ ] What is the default INPUT/inbound policy? (Must be DROP/DENY/Block — not ACCEPT/Allow)
- [ ] What is the default FORWARD policy? (Must be DROP/DENY on any routing host or gateway)
- [ ] Are management ports (SSH 22, RDP 3389) restricted to admin CIDR only — not 0.0.0.0/0 or `*`?
- [ ] Is connection logging enabled on management ports? (LOG target on Linux, LogAllowed/LogBlocked on Windows)
- [ ] Is rate limiting configured on SSH/RDP? (5 new connections/min per source minimum)
- [ ] Are there any rules with source 0.0.0.0/0 and action ACCEPT? List every rule.
- [ ] When was the last external port scan? (Nmap, Shodan, Censys, Azure Security Center)
- [ ] Are cloud security groups (Azure NSG, AWS SG) aligned with host-level firewall rules?
- [ ] Is the firewall configuration under version control or backed up to a documented location?

**SC-7 scoring:** 8–10 PASS = satisfactory. Below 6 = remediate before next review.

---

## AC-4 — Network Segmentation Checklist (10 items)

- [ ] How many network zones exist? Map each (name, purpose, CIDR, interface)
- [ ] Are zones enforced by firewall rules, or only by routing (routing alone is insufficient)?
- [ ] What cross-zone traffic flows are explicitly allowed? Document source, destination, port, justification.
- [ ] Is there a default deny for cross-zone traffic (FORWARD chain or NSG inter-subnet rules)?
- [ ] Can user workstations directly reach database servers? (Should be NO — AC-4 violation)
- [ ] Can user workstations directly reach management interfaces (iDRAC, IPMI, KVM)? (Should be NO)
- [ ] Is denied cross-zone traffic logged?
- [ ] Is the network flat — single /8 or /16 with no internal segmentation?
- [ ] Are VLANs mapped to security zones with documented firewall rules between them?
- [ ] Does Kubernetes NetworkPolicy exist? (If K8s is deployed — default-deny required)

---

## SI-3 — IDS/IPS Checklist (6 items)

- [ ] Is an IDS/IPS deployed? (Suricata, Snort, AWS GuardDuty, Azure Defender for Endpoint)
- [ ] What traffic is the IDS/IPS inspecting? (North-south only? East-west? Both?)
- [ ] Are signatures current? Run: `find /var/lib/suricata/rules -name "*.rules" -newer $(date -d '7 days ago' +%Y%m%d%H%M%S) | wc -l`
- [ ] Is the IDS/IPS in detection-only mode or blocking (IPS) mode?
- [ ] Are IDS/IPS alerts forwarded to a SIEM or SOC queue?
- [ ] What is the current total rule count? (30K+ ET Open is the healthy baseline)

---

## SI-4 — Flow Logging Checklist (6 items)

- [ ] Are flow logs or EVE JSON logs enabled?
- [ ] What traffic is captured — all interfaces, or only perimeter?
- [ ] Where are flow logs stored? What is the retention period?
- [ ] Are flow logs integrated with a SIEM or queued for daily SOC review?
- [ ] Can you reconstruct a host's traffic patterns for the last 30 days?
- [ ] Are DNS query logs captured? (Zeek dns.log, Windows DNS Audit, Azure DNS analytics)

---

## Routing Security Checklist (5 items)

- [ ] Are static routes documented and reviewed? (No undocumented routes)
- [ ] If dynamic routing is in use (OSPF, BGP), is route authentication enabled?
- [ ] Are there any asymmetric routing paths that could bypass firewall inspection?
- [ ] Is IP forwarding disabled on hosts that are not designated gateways? (`sysctl net.ipv4.ip_forward`)
- [ ] Is unicast reverse path forwarding (uRPF / BCP38) enabled on edge interfaces?

---

## Assessment Output

Complete the checklists above and produce:

1. **Network zone map** — zones, CIDRs, allowed flows, denied flows, owner
2. **Firewall rule audit** — overpermissive rules (0.0.0.0/0 ACCEPT), missing deny defaults, logging gaps
3. **Management port exposure report** — which ports are accessible from which source ranges
4. **IDS/IPS posture** — tool, rule count, freshness, detection mode, SIEM integration status
5. **Gap analysis** — which SC-7, AC-4, SI-3, SI-4 controls have findings
6. **Risk ranking** — each finding ranked on 5x5 matrix (likelihood × impact)

---

## Implementation Priority

| Priority | Finding | Fix | NIST |
|----------|---------|-----|------|
| Critical | Default INPUT policy = ACCEPT | fix-default-deny.sh | SC-7 |
| Critical | SSH/RDP open to 0.0.0.0/0 | fix-management-ports.sh | SC-7, AC-17 |
| High | No IDS/IPS deployed | 00-install-validate.md | SI-3 |
| High | Flat network, no segmentation | fix-default-deny.sh + VLAN work | AC-4 |
| High | Suricata rules >30 days old | fix-suricata-rule-update.sh | SI-3 |
| Medium | No EVE JSON output | Edit suricata.yaml template | SI-4 |
| Medium | No flow logs (Azure NSG) | nsg-baseline.json flow log section | AU-2 |
| Medium | No K8s NetworkPolicy | default-deny.yaml | AC-4 |
| Low | No Zeek deployed | 00-install-validate.md | SI-4 |
| Low | SSH rate limiting absent | fix-management-ports.sh | SC-7 |
