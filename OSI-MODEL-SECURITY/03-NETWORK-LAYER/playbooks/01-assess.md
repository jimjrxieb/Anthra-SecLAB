# Layer 3 Network — Assess Current State

## Purpose

Document the current network layer security posture before implementing any controls. This assessment establishes the baseline for measuring improvement. Layer 3 is where routing, firewalling, and segmentation live — if these controls are missing, every security zone is a fiction and every ACL is theater.

## Assessment Checklist

### SC-7 Firewall and Boundary Protection

- [ ] What firewall technology is in use? (iptables, nftables, Windows Firewall, pfSense, Azure NSG, AWS SG)
- [ ] What is the default INPUT policy? (Should be DROP/DENY)
- [ ] What is the default FORWARD policy? (Should be DROP/DENY on routers/gateways)
- [ ] Are management ports (SSH 22, RDP 3389) restricted to admin CIDR only?
- [ ] Are management ports exposed to 0.0.0.0/0 or ::/0 on any interface?
- [ ] Is connection logging enabled for management port access?
- [ ] Is rate limiting configured on management ports? (brute force protection)
- [ ] Are there any rules with source 0.0.0.0/0 and action ACCEPT? List them.
- [ ] When was the last external port scan (Nmap, Shodan, Censys check)?
- [ ] Are cloud security groups (AWS SG, Azure NSG) aligned with host-level firewall rules?

### AC-4 Network Segmentation and Information Flow

- [ ] How many network zones exist? Map them (name, purpose, CIDR, interfaces)
- [ ] Are zones enforced by firewall rules or only by routing?
- [ ] What cross-zone traffic flows are explicitly allowed?
- [ ] What cross-zone traffic flows are explicitly denied?
- [ ] Is there a default deny for cross-zone traffic?
- [ ] Can user workstations directly reach database servers? (Should be NO)
- [ ] Can user workstations directly reach management interfaces? (Should be NO)
- [ ] Is denied cross-zone traffic logged?
- [ ] Is the network flat (single subnet, no segmentation)?
- [ ] Are there VLAN-to-firewall-zone mappings documented?

### IDS/IPS and Traffic Inspection

- [ ] Is an IDS/IPS deployed? (Suricata, Snort, AWS GuardDuty, Azure Defender)
- [ ] What traffic is the IDS/IPS inspecting? (North-south? East-west? Both?)
- [ ] Are IDS/IPS rules current? When were signatures last updated?
- [ ] Is the IDS/IPS in detection mode or prevention mode?
- [ ] Are IDS/IPS alerts forwarded to a SIEM?
- [ ] What is the false positive rate? Is tuning documented?

### Flow Logging and Visibility

- [ ] Are flow logs enabled? (VPC Flow Logs, NetFlow, sFlow, IPFIX)
- [ ] What traffic is captured? (All, sampled, specific interfaces only?)
- [ ] Where are flow logs stored? Retention period?
- [ ] Are flow logs integrated with a SIEM or analysis tool?
- [ ] Can you reconstruct traffic patterns for a given host over the last 30 days?
- [ ] Are DNS query logs captured?

### Routing Security

- [ ] Are static routes documented and reviewed?
- [ ] If dynamic routing is used (OSPF, BGP), is authentication enabled?
- [ ] Are there any asymmetric routing paths that bypass firewall inspection?
- [ ] Is source IP validation enabled? (BCP38/BCP84, uRPF)
- [ ] Are IP forwarding and routing only enabled on designated gateway hosts?

## Output

Complete the checklist above and produce:
1. Network zone map (zones, CIDRs, allowed flows, denied flows)
2. Firewall rule audit (overpermissive rules, missing deny defaults, logging gaps)
3. Management port exposure report (which ports are accessible from where)
4. Gap analysis: which SC-7, AC-4, and SI-4 controls have findings?
5. Risk ranking of findings using 5x5 matrix
