# Layer 3 Network — Install and Validate

| Field | Value |
|-------|-------|
| NIST Controls | SC-7, SI-3, SI-4, AU-2 |
| Tools | Suricata, Zeek, iptables/nftables, Azure NSG, Windows Firewall |
| Enterprise Equivalent | Palo Alto NGFW, Cisco Stealthwatch, Darktrace, Vectra AI |
| Time Estimate | 2–4 hours (full stack) |
| Rank | D |

---

## Objective

Install and validate the Layer 3 monitoring and enforcement stack before running assessments. Every tool must prove it is capturing traffic before proceeding to 01-assess. An unvalidated install produces silent blind spots — the lab reports clean when it is actually blind.

---

## Option A: Security Onion (Covers Suricata + Zeek)

Security Onion bundles Suricata, Zeek, and the supporting infrastructure in a single install. Preferred for lab environments.

```bash
# Add Security Onion repo
curl -fsSL https://repo.securityonion.net/so-setup/install-so.sh | sudo bash

# Or download ISO from https://securityonion.net/
# Minimum: 4 CPU, 8GB RAM, 200GB storage
```

**Validate Security Onion:**

```bash
sudo so-status          # All services should show: running
sudo so-rule-update     # Pull latest rules (requires internet access)

# Verify Suricata
sudo cat /var/log/suricata/stats.log | tail -20 | grep "capture.kernel_packets"

# Verify Zeek
ls /nsm/zeek/logs/current/
```

---

## Option B: Standalone Suricata

### Install (Debian/Ubuntu)

```bash
# Add official Suricata PPA (newer versions than distro packages)
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt-get update
sudo apt-get install -y suricata suricata-update

# RHEL/CentOS/Rocky
sudo dnf install -y epel-release
sudo dnf install -y suricata
```

### Configure

```bash
# Deploy gold-standard config from template
sudo cp 03-templates/suricata/suricata.yaml /etc/suricata/suricata.yaml

# Edit HOME_NET to match your actual network
sudo nano /etc/suricata/suricata.yaml
# Change: HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
# To:     HOME_NET: "[your-actual-cidr]"

# Deploy custom local rules
sudo cp 03-templates/suricata/local.rules /etc/suricata/rules/local.rules
```

### Pull Rules

```bash
# Enable ET Open (Emerging Threats — free, 30K+ rules)
sudo suricata-update enable-source et/open
sudo suricata-update

# Verify rule count
sudo find /var/lib/suricata/rules -name "*.rules" \
  -exec grep -c "^alert" {} \; | awk '{sum+=$1} END {print "Total rules:", sum}'
# Healthy: 30,000+
```

### Start and Enable

```bash
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata
```

### Validate Suricata

```bash
# Check build info
suricata --build-info

# Test config syntax
sudo suricata -T -c /etc/suricata/suricata.yaml
# Expected: "Configuration provided was successfully loaded."

# VALIDATION TEST: Trigger ET OPEN rule 2100498
curl http://testmynids.org/uid/index.html
sleep 2

# Check for detection in eve.json
tail -50 /var/log/suricata/eve.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('event_type') == 'alert':
            print('ALERT:', e['alert']['signature'])
    except: pass
"
# Expected: ALERT: ET POLICY curl User-Agent (or similar rule firing)
```

---

## Option C: Standalone Zeek

### Install (Debian/Ubuntu)

```bash
# Add Zeek repo
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
  | sudo tee /etc/apt/sources.list.d/security:zeek.list

curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
  | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

sudo apt-get update
sudo apt-get install -y zeek

# Add Zeek to PATH
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

### Configure

```bash
# Deploy baseline config from template
sudo cp 03-templates/zeek/local.zeek /opt/zeek/share/zeek/site/local.zeek

# Set the monitored interface in node.cfg
sudo nano /opt/zeek/etc/node.cfg
# Change: interface=eth0  →  your monitoring interface

# Configure networks.cfg (equivalent to HOME_NET)
echo "10.0.0.0/8        Private" | sudo tee /opt/zeek/etc/networks.cfg
```

### Start Zeek

```bash
sudo zeekctl deploy    # Initial deploy
sudo zeekctl status    # Verify running
sudo zeekctl start     # Start if stopped
```

### Validate Zeek

```bash
zeek --version

# Check log generation
ls -lh /opt/zeek/logs/current/
# Expected: conn.log, dns.log, http.log, ssl.log, notice.log

# Verify conn.log is being written
wc -l /opt/zeek/logs/current/conn.log
# Should increase every few seconds with network activity

# VALIDATION TEST: Generate a DNS query and check dns.log
dig google.com
sleep 2
grep "google.com" /opt/zeek/logs/current/dns.log | tail -3
```

---

## Azure NSG Setup

### Deploy Baseline NSG

```bash
# Requires: az cli authenticated, target resource group exists
az login  # or az login --use-device-code

# Deploy NSG from template (replace values)
az deployment group create \
  --resource-group YOUR-RG \
  --template-file 03-templates/azure-nsg/nsg-baseline.json \
  --parameters adminCidr="10.10.0.0/16" \
  --parameters storageAccountId="/subscriptions/SUB-ID/resourceGroups/RG/providers/Microsoft.Storage/storageAccounts/STORAGE-ACCT"

# Verify NSG created
az network nsg show --name jsa-baseline-nsg --resource-group YOUR-RG --output table
```

### Enable NSG Flow Logs

```bash
# Enable flow logs via az cli
az network watcher flow-log create \
  --location eastus \
  --name jsa-baseline-nsg-flowlog \
  --nsg jsa-baseline-nsg \
  --resource-group YOUR-RG \
  --storage-account YOUR-STORAGE-ACCOUNT \
  --enabled true \
  --retention 90

# Verify
az network watcher flow-log show \
  --location eastus \
  --name jsa-baseline-nsg-flowlog \
  --query "enabled"
```

---

## Windows Firewall Setup

```powershell
# Run as Administrator
# Apply hardened baseline (reference 03-templates/windows-firewall/hardened-gpo.md)

# Set default inbound BLOCK
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block

# Enable logging
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 32767

# Restrict SSH/RDP to admin CIDR (replace with your CIDR)
$adminCidr = "10.10.0.0/16"
New-NetFirewallRule -DisplayName "JSA-RDP-Admin" -Direction Inbound `
    -Protocol TCP -LocalPort 3389 -RemoteAddress $adminCidr -Action Allow

# Validate
Get-NetFirewallProfile | Select-Object Name, DefaultInboundAction, LogAllowed
```

---

## Stack Validation Summary

Run after all tools are installed:

```bash
# Run the automated auditors
cd /path/to/03-NETWORK-LAYER
bash tools/run-all-audits.sh
```

All auditors should return no FAIL items before moving to 01-assess.

| Tool | Validation Command | Expected Result |
|------|-------------------|----------------|
| Suricata | `curl testmynids.org/uid/index.html && tail eve.json` | Alert fires for test signature |
| Zeek | `dig google.com && grep google dns.log` | DNS query logged |
| iptables | `iptables -L INPUT -n \| head -1` | Policy: DROP |
| Azure NSG | `az network nsg show -n jsa-baseline-nsg` | Rules present, flow logs enabled |
| Windows Firewall | `Get-NetFirewallProfile \| Select DefaultInboundAction` | Block on all profiles |
