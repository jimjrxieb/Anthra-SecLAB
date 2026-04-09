# Layer 5 Session — Break/Fix Scenarios

## Purpose

Run each scenario's break, detect, fix, validate cycle to demonstrate the control's value and produce evidence for governance reporting.

## How to Run a Scenario

Each scenario is in `scenarios/{CONTROL-ID}-{name}/` and contains a mix of .sh scripts and .md documentation:

### AC-12 No Session Timeout

| File | Purpose | Format |
|------|---------|--------|
| `break.sh` | Modifies app config to disable session timeouts, generates token with no expiry | Script |
| `detect.sh` | Analyzes response headers, JWT claims, and config for missing timeouts | Script |
| `fix.sh` | Sets 15-min idle timeout, 8-hr max lifetime, token rotation, secure cookies | Script |
| `fix.md` | Microsoft Entra ID Conditional Access session policy configuration (UI steps) | Documentation |
| `validate.sh` | Verifies timeout config, JWT claims, cookie attributes, session behavior | Script |
| `governance.md` | CISO brief with AC-12 risk, AiTM attack data, Gordon-Loeb, ROSI | Documentation |

### SC-23 Session Fixation

| File | Purpose | Format |
|------|---------|--------|
| `break.md` | Describes session fixation vulnerability pattern and attack flow | Documentation |
| `detect.sh` | Captures session cookie before/after login, checks if ID changes | Script |
| `fix.sh` | Generates session regeneration patches for Flask, Express, Java, PHP | Script |
| `validate.sh` | Verifies session ID changes on login, old ID invalid, strict mode | Script |
| `governance.md` | CISO brief with SC-23 risk, session hijacking data, Gordon-Loeb, ROSI | Documentation |

## Scenario Execution Order

### Scenario 1: AC-12 No Session Timeout

1. Read the scenario overview in `scenarios/AC-12-no-session-timeout/governance.md` — understand the business risk
2. Run `scenarios/AC-12-no-session-timeout/break.sh` — create vulnerable session config
   ```bash
   ./scenarios/AC-12-no-session-timeout/break.sh http://localhost:8080
   ```
3. Run `scenarios/AC-12-no-session-timeout/detect.sh` — confirm the vulnerability
   ```bash
   ./scenarios/AC-12-no-session-timeout/detect.sh http://localhost:8080
   ```
4. Run `scenarios/AC-12-no-session-timeout/fix.sh` — apply session timeout controls
   ```bash
   ./scenarios/AC-12-no-session-timeout/fix.sh
   ```
5. Follow `scenarios/AC-12-no-session-timeout/fix.md` — configure Entra ID Conditional Access policies
6. Run `scenarios/AC-12-no-session-timeout/validate.sh` — confirm the fix
   ```bash
   ./scenarios/AC-12-no-session-timeout/validate.sh http://localhost:8080
   ```
7. Review `scenarios/AC-12-no-session-timeout/governance.md` — understand the CISO narrative

### Scenario 2: SC-23 Session Fixation

1. Read `scenarios/SC-23-session-fixation/break.md` — understand the session fixation attack pattern
2. Run the tabletop exercise described in break.md using browser DevTools
3. Run `scenarios/SC-23-session-fixation/detect.sh` — test for session fixation
   ```bash
   ./scenarios/SC-23-session-fixation/detect.sh http://localhost:8080 /login testuser testpass
   ```
4. Run `scenarios/SC-23-session-fixation/fix.sh` — generate session regeneration patches
   ```bash
   ./scenarios/SC-23-session-fixation/fix.sh /tmp/sc23-session-lab flask
   ```
5. Apply the framework-specific patch from the evidence directory
6. Run `scenarios/SC-23-session-fixation/validate.sh` — verify the fix
   ```bash
   ./scenarios/SC-23-session-fixation/validate.sh http://localhost:8080 /login testuser testpass
   ```
7. Review `scenarios/SC-23-session-fixation/governance.md` — understand the CISO narrative

## Tools Required

| Tool | Install | Purpose |
|------|---------|---------|
| curl | Pre-installed on most systems | HTTP requests, cookie capture, header analysis |
| python3 | Pre-installed on most systems | JWT decoding, config analysis |
| Burp Suite CE | https://portswigger.net/burp/communitydownload | Manual session analysis, cookie inspection |
| OWASP ZAP | https://www.zaproxy.org/download/ | Automated session fixation scanning |
| Browser DevTools | Built into Chrome/Firefox | Cookie inspection, token analysis |

## Evidence Collection

After each scenario, save evidence to `evidence/YYYY-MM-DD/`:
- Session configuration files (before and after)
- JWT token analysis output
- Response header captures
- Cookie attribute analysis
- Validation test results
- Governance brief (completed with real data from the environment)
