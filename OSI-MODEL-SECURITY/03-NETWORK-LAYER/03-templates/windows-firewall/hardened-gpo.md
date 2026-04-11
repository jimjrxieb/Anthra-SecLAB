# Windows Firewall Hardening — GPO and PowerShell

| Field | Value |
|-------|-------|
| NIST Controls | SC-7 (Boundary Protection), AC-17 (Remote Access), AU-2 (Event Logging) |
| Tools | Windows Firewall with Advanced Security, Group Policy, PowerShell |
| Enterprise Equivalent | Palo Alto NGFW, Cisco ASA, Azure Firewall |
| Applies To | Windows Server 2016+, Windows 10/11 |
| Time Estimate | 30–60 minutes |

---

## Objective

Apply a hardened Windows Firewall configuration that satisfies NIST SC-7 (boundary protection) and AU-2 (event logging). This covers both standalone host hardening and domain-wide deployment via Group Policy.

---

## Step 1: Set Default Inbound Policy to Block

**Why:** NIST SC-7 requires explicit allowlisting at network boundaries. Windows Firewall default "Allow" means new services automatically become accessible — a violation of least privilege.

### Via PowerShell (immediate, single host)

```powershell
# Block all inbound on all profiles (Domain, Private, Public)
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block

# Allow outbound (change to Block if egress filtering is required)
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

# Verify
Get-NetFirewallProfile | Select-Object Name, DefaultInboundAction, DefaultOutboundAction, Enabled
```

Expected output:
```
Name    DefaultInboundAction  DefaultOutboundAction  Enabled
----    --------------------  ---------------------  -------
Domain  Block                 Allow                  True
Private Block                 Allow                  True
Public  Block                 Allow                  True
```

### Via netsh (legacy, runs as admin without PS)

```cmd
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
netsh advfirewall show allprofiles
```

### Via Group Policy

```
Computer Configuration → Windows Settings → Security Settings →
Windows Firewall with Advanced Security → Windows Firewall with Advanced Security
→ [Right-click] Properties
→ Domain Profile → Inbound connections: Block
→ Private Profile → Inbound connections: Block
→ Public Profile → Inbound connections: Block
```

---

## Step 2: Restrict Management Ports to Admin CIDR

**Why:** NIST AC-17 requires remote access to be controlled and limited to authorized users/systems. SSH/RDP open to 0.0.0.0/0 violates SC-7 (boundary protection) and enables brute force attacks.

### SSH — Allow from Admin CIDR Only

```powershell
# Remove any existing unrestricted SSH rule
Get-NetFirewallRule -DisplayName "SSH*" | Where-Object {
    (Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_).RemoteAddress -contains 'Any'
} | Remove-NetFirewallRule

# Create restricted SSH rule (replace 10.10.0.0/16 with your admin CIDR)
New-NetFirewallRule `
    -DisplayName "JSA-SSH-Admin-Allow" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 22 `
    -RemoteAddress "10.10.0.0/16" `
    -Action Allow `
    -Profile Any `
    -Description "SC-7: SSH restricted to admin network. NIST AC-17. $(Get-Date -Format 'yyyy-MM-dd')"

# Verify
Get-NetFirewallRule -DisplayName "JSA-SSH-Admin-Allow" | Get-NetFirewallAddressFilter
```

### RDP — Allow from Admin CIDR Only

```powershell
# Disable built-in RDP rule (allows from Any by default)
Disable-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)"
Disable-NetFirewallRule -DisplayName "Remote Desktop - User Mode (UDP-In)"

# Create restricted RDP rule
New-NetFirewallRule `
    -DisplayName "JSA-RDP-Admin-Allow" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 3389 `
    -RemoteAddress "10.10.0.0/16" `
    -Action Allow `
    -Profile Any `
    -Description "SC-7: RDP restricted to admin network. NIST AC-17. $(Get-Date -Format 'yyyy-MM-dd')"

# Verify
Get-NetFirewallRule -DisplayName "JSA-RDP*" | Format-Table Name, Enabled, Action
```

### Via Group Policy

```
Computer Configuration → Windows Settings → Security Settings →
Windows Firewall with Advanced Security → Inbound Rules
→ New Rule → Port → TCP → Specific local ports: 3389
→ Allow the connection → Select profiles
→ Under "Scope" tab: Remote IP Address → "These IP addresses" → Add admin CIDR
→ Name: JSA-RDP-Admin-Allow
```

---

## Step 3: Enable Logging

**Why:** NIST AU-2 requires logging security-relevant events. Windows Firewall logging records both allowed and blocked connections, which is required for SC-7 compliance (boundary event logging).

### Via PowerShell

```powershell
# Enable logging on all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -LogAllowed True `
    -LogBlocked True `
    -LogMaxSizeKilobytes 32767    # 32 MB per profile

# Set log file location (default: %systemroot%\system32\logfiles\firewall\)
Set-NetFirewallProfile -Profile Domain `
    -LogFileName "%systemroot%\system32\logfiles\firewall\pfirewall-domain.log"
Set-NetFirewallProfile -Profile Private `
    -LogFileName "%systemroot%\system32\logfiles\firewall\pfirewall-private.log"
Set-NetFirewallProfile -Profile Public `
    -LogFileName "%systemroot%\system32\logfiles\firewall\pfirewall-public.log"

# Verify logging configuration
Get-NetFirewallProfile | Select-Object Name, LogAllowed, LogBlocked, LogMaxSizeKilobytes, LogFileName
```

### Forward Logs to SIEM

Configure Windows Event Forwarding (WEF) or a SIEM agent to collect:
- **Event ID 5031**: Windows Firewall blocked application
- **Event ID 5152**: Packet blocked by Windows Filtering Platform
- **Event ID 5154**: Process opened listening port
- **Event ID 5156**: Network connection permitted
- **Event ID 5157**: Network connection blocked

```powershell
# View recent firewall events in Event Log
Get-WinEvent -LogName "Security" | Where-Object {
    $_.Id -in @(5031, 5152, 5154, 5156, 5157)
} | Select-Object TimeCreated, Id, Message | Format-List | head -50
```

---

## Step 4: Egress Filtering for Sensitive Zones

**Why:** Default outbound ALLOW is often acceptable for workstations but not for servers. A compromised server should not be able to reach arbitrary external endpoints.

```powershell
# Change server default outbound to Block
Set-NetFirewallProfile -Profile Domain -DefaultOutboundAction Block

# Allow necessary egress: DNS
New-NetFirewallRule `
    -DisplayName "JSA-Allow-DNS-Egress" `
    -Direction Outbound `
    -Protocol UDP `
    -RemotePort 53 `
    -Action Allow

# Allow HTTPS to trusted subnets or external
New-NetFirewallRule `
    -DisplayName "JSA-Allow-HTTPS-Egress" `
    -Direction Outbound `
    -Protocol TCP `
    -RemotePort 443 `
    -Action Allow

# Allow NTP (time sync)
New-NetFirewallRule `
    -DisplayName "JSA-Allow-NTP-Egress" `
    -Direction Outbound `
    -Protocol UDP `
    -RemotePort 123 `
    -Action Allow
```

---

## Step 5: GPO Deployment Steps

For domain-wide deployment:

1. Open **Group Policy Management Console** (gpmc.msc)
2. Create a new GPO: **JSA-Firewall-Hardened-Baseline**
3. Link to appropriate OU (Server OU, Workstation OU)
4. Configure settings as described in Steps 1–4 above
5. Run `gpupdate /force` on a test machine to validate
6. Check **Event Log > Security** for firewall events (IDs 5031, 5152+)

```powershell
# Force GPO refresh and verify
gpupdate /force
Get-NetFirewallProfile | Select-Object Name, DefaultInboundAction, LogAllowed, LogBlocked
```

---

## Validation Commands

```powershell
# Full firewall status
netsh advfirewall show allprofiles

# List all inbound allow rules
Get-NetFirewallRule -Direction Inbound -Action Allow | 
    Select-Object DisplayName, Enabled, Profile | 
    Format-Table

# Check management port rules
Get-NetFirewallRule | Where-Object {
    $_.LocalPort -match "22|3389"
} | Select-Object DisplayName, Enabled, Action, Direction | Format-Table

# Verify logging
Get-NetFirewallProfile | Select-Object Name, LogAllowed, LogBlocked, LogFileName

# Test a blocked connection (should appear in firewall log)
Test-NetConnection -ComputerName 8.8.8.8 -Port 80
```

---

## NIST Control Mapping

| Directive | NIST Control | Rationale |
|-----------|-------------|-----------|
| Default inbound Block | SC-7 | Deny by default, permit by exception |
| SSH/RDP source restriction | AC-17, SC-7 | Remote access limited to authorized users/systems |
| Logging enabled (allow+block) | AU-2, AU-3 | Log all network boundary events with sufficient detail |
| Log size / retention | AU-9 | Protect audit logs from loss |
| Egress filtering | AC-4, SC-7 | Control information flows in both directions |
