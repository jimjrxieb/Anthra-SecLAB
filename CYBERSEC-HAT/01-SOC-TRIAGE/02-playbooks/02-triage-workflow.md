# Triage Workflow

## Purpose

Investigate an alert from intake to decision (close / escalate / open incident).

## Decision Framework

Every alert ends in one of three outcomes:
- **Close (False Positive):** Document why it is not a real threat
- **Escalate (Needs IR):** Enough evidence to open an incident
- **Monitor (Inconclusive):** Not enough evidence to act, set a watch

## Investigation Steps

### 1. Enrich the IOCs

For every indicator in the alert (IP, domain, hash, user, host):
- IP: Check VirusTotal, AbuseIPDB, Shodan
- Domain: Check VirusTotal, urlscan.io, WHOIS age
- Hash: Check VirusTotal, MalwareBazaar
- User: Check AD/IAM for account status, group memberships, recent changes
- Host: Check asset inventory for owner, criticality, patch status

### 2. Expand the Timeline

Pull logs ±30 minutes around the alert timestamp for the affected host and user:
- Authentication events (login, logoff, failed)
- Process execution events
- Network connections
- File system changes

Look for: what happened before (setup), what happened after (follow-through).

### 3. Answer the 5 Ws

- **Who:** Which account, from which IP/location?
- **What:** What action was taken? What tool/technique?
- **When:** What time? During business hours? Weekends?
- **Where:** Which host? Which network segment?
- **Why:** Is there a business reason for this activity?

### 4. Make the Call

True positive indicators:
- IOC matches known malicious threat intel
- Activity is impossible for the account (impossible travel, impossible hours)
- Known attack pattern (encoded command, LOLBIN abuse, lateral movement)
- Multiple indicators correlating to the same actor/campaign

False positive indicators:
- Activity matches a known maintenance window or change ticket
- Source IP is a known scanner, proxy, or internal tool
- User is known to have this behavior pattern
- Alert rule has a documented FP pattern

### 5. Document and Act

Write your conclusion: what you found, what evidence supports it, what you decided.

If escalating: write a clear handoff note — what happened, what you already ruled out, what needs to happen next.
