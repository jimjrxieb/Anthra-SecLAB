# Layer 3 Network — Implement Controls

## Purpose

Implement network layer security controls based on assessment findings. Start with highest-risk gaps from the 01-assess output. Network layer controls range from zero-cost firewall configuration to moderate-cost IDS/IPS deployment.

## Implementation Order

Priority by risk and cost-efficiency:

### Priority 1: Firewall Hardening Baseline (Week 1, ~$800 staff time)

These are configuration changes on existing firewalls that eliminate the most critical exposure.

1. **Restrict management ports to admin CIDR**
   - Linux (iptables):
     ```bash
     # Allow SSH from admin subnet only
     iptables -A INPUT -p tcp --dport 22 -s 10.0.100.0/24 -j ACCEPT
     iptables -A INPUT -p tcp --dport 22 -j DROP
     ```
   - Windows Firewall (netsh):
     ```powershell
     netsh advfirewall firewall add rule name="SSH Admin Only" dir=in action=allow protocol=tcp localport=22 remoteip=10.0.100.0/24
     netsh advfirewall firewall add rule name="SSH Block All" dir=in action=block protocol=tcp localport=22
     ```
   - pfSense: Firewall > Rules > WAN > add block rule for ports 22,3389 from any source except admin alias
   - Azure NSG:
     ```bash
     az network nsg rule create --name AllowSSHAdmin --nsg-name MyNSG \
       --priority 100 --source-address-prefixes 10.0.100.0/24 \
       --destination-port-ranges 22 --access Allow --protocol Tcp
     az network nsg rule create --name DenySSHAll --nsg-name MyNSG \
       --priority 200 --destination-port-ranges 22 --access Deny --protocol Tcp
     ```

2. **Set default INPUT/FORWARD policy to DROP**
   ```bash
   # Ensure established connections are allowed first
   iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
   iptables -P INPUT DROP
   iptables -P FORWARD DROP
   ```

3. **Enable connection logging for management ports**
   ```bash
   iptables -A INPUT -p tcp --dport 22 -j LOG --log-prefix "SSH-ACCESS: "
   iptables -A INPUT -p tcp --dport 3389 -j LOG --log-prefix "RDP-ACCESS: "
   ```

4. **Add rate limiting on management ports**
   ```bash
   iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW \
     -m hashlimit --hashlimit-above 5/min --hashlimit-burst 5 \
     --hashlimit-mode srcip --hashlimit-name ssh-limit -j DROP
   ```

### Priority 2: Network Segmentation (Week 1-2, ~$3,500 staff time)

1. **Define network zones**
   - MGMT: Admin/management subnet (bastion, jump boxes)
   - APP: Application servers (web, API, middleware)
   - DATA: Database and storage (MySQL, PostgreSQL, S3)
   - USER: End-user workstations

2. **Implement zone-based firewall rules**
   - Allow only approved cross-zone flows (see fix.sh for full example)
   - MGMT -> ALL (admin access on management ports)
   - APP -> DATA (database ports only)
   - USER -> APP (HTTP/HTTPS only)
   - Default deny everything else

3. **Enable denied traffic logging**
   ```bash
   iptables -A FORWARD -j LOG --log-prefix "ZONE-DENIED: " --log-level 4
   iptables -A FORWARD -j DROP
   ```

4. **Cloud segmentation (if applicable)**
   - AWS: Security Groups per zone + NACLs as backup
   - Azure: NSGs per subnet + Azure Firewall for zone-crossing
   - Use infrastructure-as-code (Terraform) to enforce and audit

### Priority 3: IDS/IPS Deployment (Week 2-4, ~$2,000-$5,000)

1. **Deploy Suricata in IDS mode on zone boundaries**
   ```bash
   # Install Suricata
   apt-get install suricata
   # Configure to monitor inter-zone interface
   suricata -c /etc/suricata/suricata.yaml -i eth0
   ```
   - Cost: $0 (open source) + $2,000 staff time for deployment and tuning
   - Alternative: pfSense with Suricata package (GUI-based)

2. **Enable rule updates (ET Open or ET Pro)**
   ```bash
   suricata-update
   suricata-update enable-source et/open
   ```
   - ET Open: free, community rules
   - ET Pro: $900/sensor/year, commercial rules with faster updates

3. **Integrate with SIEM (Splunk, Elastic, Wazuh)**
   - Forward EVE JSON logs to SIEM
   - Create dashboards for alert triage
   - Tune false positives (expect 2-4 weeks of tuning)

### Priority 4: Flow Logging and Visibility (Week 3-4, ~$500-$2,000)

1. **Enable VPC Flow Logs (AWS) or NSG Flow Logs (Azure)**
   ```bash
   # AWS VPC Flow Logs
   aws ec2 create-flow-logs --resource-type VPC --resource-ids vpc-xxx \
     --traffic-type ALL --log-destination-type s3 --log-destination arn:aws:s3:::flow-logs
   ```
   - Cost: $0.50/GB ingested (AWS), storage costs for retention

2. **Deploy NetFlow/sFlow collector on-prem**
   - ntopng (open source): $0 community, $800/year pro
   - SiLK (open source, CERT/CC): $0
   - Configure routers/switches to export flow data

3. **Enable DNS query logging**
   ```bash
   # BIND DNS logging
   logging { channel query_log { file "/var/log/dns-queries.log"; }; };
   ```
   - DNS logs are critical for C2 detection and data exfiltration detection

### Priority 5: Advanced Controls (Month 2-6, ~$5,000-$20,000)

1. Deploy Suricata in IPS mode (inline, not just monitoring)
2. Implement micro-segmentation (per-host firewall rules, Calico for K8s)
3. Deploy network detection and response (NDR) — Zeek, Darktrace, ExtraHop
4. Enable BGP/OSPF authentication for routing protocol security
5. Deploy source IP validation (uRPF) on all router interfaces

## Change Management Notes

- **Firewall rule changes require a maintenance window.** Incorrect rules can block legitimate traffic. Test on a non-production host first.
- **Default DROP policy changes are high-risk.** Ensure you have ACCEPT rules for established connections and your current SSH session before changing the policy.
- **IDS/IPS in IPS mode can block legitimate traffic.** Always deploy in IDS (detection-only) mode first. Move to IPS after 2-4 weeks of tuning.
- **Document every rule change.** Save `iptables-save` before and after. Use comments on every rule for audit trail.

## Verification After Each Implementation

After each control is implemented, run the corresponding scenario's `validate.sh` to confirm it works. Do not proceed to the next priority without validation.
