# Layer 3 Network — Fix SC-7: Full Firewall Hardening

| Field | Value |
|-------|-------|
| NIST Controls | SC-7 (Boundary Protection), AC-17 (Remote Access), AC-4 (Information Flow), AU-2 (Event Logging) |
| Tools | fix-default-deny.sh, fix-management-ports.sh, Windows Firewall, Azure NSG template |
| Time Estimate | 1–2 hours |
| Rank | D (execution) / C (policy decisions on allowed traffic) |

---

## Objective

Harden firewall configuration to satisfy NIST SC-7 boundary protection requirements. Covers Linux iptables/nftables, Windows Firewall via PowerShell/GPO, and Azure NSG. Sequence matters: apply default-deny first, then open only what is required.

**Warning:** These scripts modify active firewall rules. Run from a console session or ensure your source IP is within the admin CIDR before executing.

---

## Phase 1: Default-Deny Policy

### Linux

```bash
# Detect your SSH source IP before running
echo "My SSH source: $SSH_CLIENT" | awk '{print $1}'
# OR
echo "My SSH source: $SSH_CONNECTION" | awk '{print $1}'

# Run default-deny fixer
sudo bash 02-fixers/fix-default-deny.sh
```

What it does:
- Preserves `ESTABLISHED,RELATED` rules (prevents current session drop)
- Whitelists current SSH source IP (lockout protection)
- Sets `iptables -P INPUT DROP`
- Sets `iptables -P FORWARD DROP`
- Saves evidence before and after

**Verify:**

```bash
iptables -L INPUT -n | head -1
# Expected: Chain INPUT (policy DROP)

iptables -L FORWARD -n | head -1
# Expected: Chain FORWARD (policy DROP)
```

### Windows

```powershell
# Run as Administrator
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block

# Verify
Get-NetFirewallProfile | Select-Object Name, DefaultInboundAction
```

### Azure NSG

```bash
# Set default deny inbound via ARM template
az deployment group create \
  --resource-group YOUR-RG \
  --template-file 03-templates/azure-nsg/nsg-baseline.json \
  --parameters adminCidr="YOUR-ADMIN-CIDR"

# Verify rule 4096 (Deny-All-Inbound) exists
az network nsg rule list --nsg-name jsa-baseline-nsg -g YOUR-RG \
  --query "[?priority==4096]" --output table
```

---

## Phase 2: Management Port Restriction

### Linux

```bash
# Set admin CIDR before running
export ADMIN_CIDR="10.10.0.0/16"  # Replace with your actual admin network

# Run the fixer
sudo -E bash 02-fixers/fix-management-ports.sh
```

What it does:
- Removes any existing open-to-all SSH/RDP rules
- Adds SSH ACCEPT rule from ADMIN_CIDR only
- Adds SSH LOG rule (AU-2 requirement)
- Adds rate limiting (5 new connections per source per 60s)
- Adds RDP ACCEPT rule from ADMIN_CIDR only
- Adds explicit DROP + LOG for both ports from all other sources

**Verify:**

```bash
# Confirm SSH is restricted
iptables -L INPUT -n | grep "dpt:22"
# Expected: Lines showing ADMIN_CIDR source, LOG, DROP from any other source

# Confirm logging is working
tail -f /var/log/kern.log | grep "JSA-SSH"
# Then try: ssh <this-host> from outside admin CIDR (should appear as JSA-SSH-DENY)
```

### Windows

```powershell
# Set admin CIDR
$adminCidr = "10.10.0.0/16"

# Remove any unrestricted SSH/RDP rules
Get-NetFirewallRule | Where-Object {
    $_.DisplayName -match "SSH|Remote Desktop"
} | ForEach-Object {
    $filter = $_ | Get-NetFirewallAddressFilter
    if ($filter.RemoteAddress -contains 'Any') {
        Write-Host "Removing: $($_.DisplayName)"
        Remove-NetFirewallRule -InputObject $_
    }
}

# Add restricted SSH rule
New-NetFirewallRule -DisplayName "JSA-SSH-Admin" -Direction Inbound `
    -Protocol TCP -LocalPort 22 -RemoteAddress $adminCidr -Action Allow

# Add restricted RDP rule
New-NetFirewallRule -DisplayName "JSA-RDP-Admin" -Direction Inbound `
    -Protocol TCP -LocalPort 3389 -RemoteAddress $adminCidr -Action Allow

# Enable logging
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 32767

# Verify
Get-NetFirewallRule | Where-Object { $_.LocalPort -match "22|3389" } |
    Select-Object DisplayName, Enabled, Action
```

Reference: `03-templates/windows-firewall/hardened-gpo.md` for GPO deployment steps.

### Azure NSG

The `nsg-baseline.json` template restricts SSH (100) and RDP (110) to adminCidr parameter. Verify:

```bash
az network nsg rule list --nsg-name jsa-baseline-nsg -g YOUR-RG \
  --query "[?priority<=200]" --output table
# Rules 100 and 110 should show ADMIN_CIDR as sourceAddressPrefix, not '*'
```

---

## Phase 3: Enable Firewall Logging

### Linux iptables

```bash
# LOG before DROP on INPUT chain (if not already done by fix-management-ports.sh)
# Log all dropped INPUT packets with a prefix for grep
iptables -I INPUT $(iptables -L INPUT --line-numbers -n | tail -1 | awk '{print $1}') \
  -j LOG --log-prefix "JSA-INPUT-DROP: " --log-level 4

# Verify logs are flowing
tail -f /var/log/kern.log | grep "JSA-INPUT-DROP"
```

### Windows

```powershell
# Verify logging is enabled
Get-NetFirewallProfile | Select-Object Name, LogAllowed, LogBlocked, LogFileName

# Read recent firewall log
Get-Content "$env:SYSTEMROOT\system32\logfiles\firewall\pfirewall.log" -Tail 20 -Wait
```

---

## Phase 4: Kubernetes NetworkPolicy

If Kubernetes is present, apply default-deny:

```bash
# Apply to each namespace (repeat for all non-system namespaces)
kubectl apply -f 03-templates/network-policies/default-deny.yaml -n default
kubectl apply -f 03-templates/network-policies/default-deny.yaml -n production
kubectl apply -f 03-templates/network-policies/default-deny.yaml -n staging

# Verify
kubectl get networkpolicy --all-namespaces

# Test (should fail after applying default-deny)
kubectl run test-pod --image=busybox --restart=Never --rm -it -- \
  wget -q --timeout=5 http://kubernetes.default.svc/ || echo "Connection blocked (expected)"
```

---

## Validation

Re-run the firewall auditor to confirm all FAIL items are resolved:

```bash
sudo bash 01-auditors/audit-firewall-rules.sh
# Expected: 0 FAIL items
```

Evidence checklist for SC-7 compliance:
- [ ] iptables-before.txt and iptables-after.txt captured
- [ ] SSH restricted to ADMIN_CIDR (confirmed in audit output)
- [ ] Rate limiting active on SSH
- [ ] Logging enabled and generating events
- [ ] Evidence copied to `evidence/` directory

```bash
cp -r /tmp/jsa-evidence/default-deny-* evidence/
cp -r /tmp/jsa-evidence/mgmt-ports-* evidence/
```
