# Splunk Queries — SOC Triage

Reference library for common triage searches. Adapt index/sourcetype to your environment.

## Phishing / Email (T1566.001)

```spl
index=email sourcetype=exchange OR sourcetype=o365
| search subject="*invoice*" OR subject="*urgent*" OR subject="*verify*"
| stats count by sender, recipient, subject
| sort -count
```

```spl
index=endpoint sourcetype=sysmon EventCode=1
| where ParentImage LIKE "%OUTLOOK%"
| table _time, ComputerName, User, ParentImage, Image, CommandLine
```

## Account Abuse / Valid Accounts (T1078)

```spl
index=auth sourcetype=WinEventLog:Security EventCode=4624
| eval hour=strftime(_time, "%H")
| where (hour < 6 OR hour > 22)
| stats count by Account_Name, src_ip, hour
| sort -count
```

```spl
index=auth sourcetype=linux_secure "Accepted"
| iplocation src_ip
| stats dc(Country) as countries, values(Country) as country_list by user
| where countries > 1
```

## Brute Force (T1110)

```spl
index=auth sourcetype=linux_secure "Failed password"
| bin _time span=5m
| stats count by _time, src_ip
| where count > 20
| sort -count
```

```spl
index=auth sourcetype=WinEventLog:Security EventCode=4625
| stats count by src_ip, TargetUserName
| where count > 10
| sort -count
```

## Malicious PowerShell (T1059.001)

```spl
index=endpoint sourcetype=WinEventLog:Security EventCode=4104
| search ScriptBlockText="*-EncodedCommand*" OR ScriptBlockText="*FromBase64String*" OR ScriptBlockText="*IEX*" OR ScriptBlockText="*Invoke-Expression*"
| table _time, ComputerName, UserID, ScriptBlockText
```

```spl
index=endpoint sourcetype=sysmon EventCode=1
| where (Image LIKE "%powershell.exe%" OR Image LIKE "%pwsh.exe%")
| where CommandLine LIKE "%-enc%" OR CommandLine LIKE "%-e %"
| table _time, ComputerName, User, CommandLine
```
