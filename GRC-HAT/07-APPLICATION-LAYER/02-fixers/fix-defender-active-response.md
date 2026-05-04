# fix-defender-active-response.md — Configure Defender for Endpoint Automated Response

**NIST:** SI-3 (malicious code protection), SI-4 (monitoring), IR-4 (incident handling)
**Tool:** Microsoft Defender for Endpoint (MDE) via Microsoft 365 Defender portal
**Time:** 30–60 minutes
**Rank:** C (configuration decisions require human judgment)

---

## What This Fixes

Defender for Endpoint installed but automated response not configured — alerts fire but no automated containment occurs. This guide enables:
- Attack Surface Reduction (ASR) rules
- Automated Investigation and Remediation (AIR)
- Custom detection rules with KQL
- Auto-isolate on critical alerts

---

## Step 1: Attack Surface Reduction Rules

**Portal path:** security.microsoft.com > Settings > Endpoints > Attack surface reduction

### Recommended ASR Rules (Block Mode)

Enable these in **Block** mode (not Audit) once you've tested for false positives:

| Rule | GUID | Why |
|---|---|---|
| Block credential stealing from LSASS | 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0 | Prevents Mimikatz-style attacks |
| Block Office apps from creating child processes | d4f940ab-401b-4efc-aadc-ad5f3c50688a | Macros spawning cmd.exe |
| Block execution of potentially obfuscated scripts | 5beb7efe-fd9a-4556-801d-275e5ffc04cc | PowerShell obfuscation |
| Block untrusted/unsigned processes from USB | b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 | Removable media attack vector |
| Block JavaScript/VBScript from launching executables | d3e037e1-3eb8-44c8-a917-57927947596d | Script-based initial access |

### PowerShell Deployment

```powershell
# Enable ASR rules in Block mode
# Run on endpoints or deploy via Intune/Group Policy

$ASRRules = @{
    # Block credential stealing from LSASS
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0" = "1"   # 1=Block, 2=Audit, 0=Disabled
    # Block Office from creating child processes
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "1"
    # Block obfuscated scripts
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "1"
    # Block untrusted USB processes
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "1"
    # Block JS/VBS launching executables
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "1"
}

Set-MpPreference -AttackSurfaceReductionRules_Ids ($ASRRules.Keys) `
                 -AttackSurfaceReductionRules_Actions ($ASRRules.Values)

# Verify
Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions
```

---

## Step 2: Automated Investigation Settings

**Portal path:** security.microsoft.com > Settings > Endpoints > Advanced features

Enable these settings:
- **Automated Investigation**: ON
- **Automatically resolve alerts**: ON (for low-confidence alerts)
- **Allow or block file**: ON (enables file quarantine actions)
- **Live Response**: ON (allows analyst remote shell access)

### Set Automation Level per Device Group

```
security.microsoft.com > Settings > Endpoints > Device groups > Edit group > Automation level
```

Recommended levels:
| Device Group | Automation Level | Rationale |
|---|---|---|
| Servers (Production) | Semi — require approval for all | Manual approval for prod changes |
| Workstations | Full — remediate threats automatically | High confidence, low blast radius |
| Domain Controllers | Semi — require approval for all | Critical systems, never auto-remediate |

---

## Step 3: Custom Detection Rules with KQL

**Portal path:** security.microsoft.com > Hunting > Custom detections > Create rule

Custom detections run Advanced Hunting KQL queries on a schedule and trigger alerts (with optional automated response actions).

### Example 1: Auto-Isolate on LSASS Dump Attempt

```kql
// KQL: Detect LSASS memory access — credential dump attempt
// Trigger: Alert + Isolate machine action
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ ("procdump.exe", "mimikatz.exe", "pypykatz.exe", "lsassy.py")
    or (ProcessCommandLine has "lsass" and ProcessCommandLine has_any ("dump", "minidump", "full"))
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName,
          ProcessCommandLine, AccountName, AccountDomain
```

**Custom detection settings:**
| Field | Value |
|---|---|
| Rule name | CRED-DUMP-LSASS-Access |
| Frequency | Every 1 hour |
| Alert title | Potential LSASS credential dump |
| Severity | High |
| Category | CredentialAccess |
| MITRE technique | T1003.001 |
| Response actions | **Isolate device** |

### Example 2: Detect PowerShell Download Cradle

```kql
// KQL: PowerShell downloading from internet — common C2 or dropper technique
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "IEX", "Invoke-Expression",
    "DownloadString", "DownloadFile",
    "WebClient", "Net.WebClient",
    "bitsadmin", "certutil -decode"
  )
| where ProcessCommandLine !has "WindowsUpdate"    // exclude legitimate WU traffic
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

**Response action:** Collect investigation package (for forensics, no auto-isolation)

### Example 3: Suspicious Scheduled Task Creation

```kql
// KQL: New scheduled task with suspicious command — persistence indicator
DeviceEvents
| where Timestamp > ago(1h)
| where ActionType == "ScheduledTaskCreated"
| extend TaskDetails = parse_json(AdditionalFields)
| extend
    TaskName = tostring(TaskDetails.TaskName),
    Command  = tostring(TaskDetails.TaskContent)
| where Command has_any (
    "powershell", "cmd.exe", "wscript", "cscript",
    "mshta", "regsvr32", "rundll32", "certutil"
  )
| project Timestamp, DeviceName, AccountName, TaskName, Command
```

---

## Step 4: Verify Automated Response

After configuring, test with a simulated alert:

```powershell
# Simulate a detection event (safe test — no actual malware)
# This creates a test alert in Defender
Invoke-WebRequest -Uri "https://defender.microsoft.com/testmalware" -UseBasicParsing
# OR use the built-in test:
$url = "https://aka.ms/ioavtest"
(New-Object System.Net.WebClient).DownloadString($url)
```

**Verify in portal:**
1. security.microsoft.com > Incidents & alerts > Alerts
2. Find the test alert — confirm it was triggered
3. Check Automated investigations — confirm AIR ran
4. Check Device actions — confirm isolation (if configured)

---

## Validation Evidence

```powershell
# Capture current state as evidence
$evidence = @{
    RealTimeProtection  = (Get-MpComputerStatus).RealTimeProtectionEnabled
    ASRRulesEnabled     = (Get-MpPreference).AttackSurfaceReductionRules_Actions
    CloudProtection     = (Get-MpComputerStatus).AMRunningMode
    LastQuickScan       = (Get-MpComputerStatus).QuickScanEndTime
    SignatureVersion    = (Get-MpComputerStatus).AntivirusSignatureVersion
    SignatureAge        = (Get-MpComputerStatus).AntivirusSignatureAge
}
$evidence | ConvertTo-Json | Tee-Object -FilePath "defender-evidence-$(Get-Date -Format 'yyyyMMdd').json"
```

Save output to `evidence/` directory for compliance documentation.
