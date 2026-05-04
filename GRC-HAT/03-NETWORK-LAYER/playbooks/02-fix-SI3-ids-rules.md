# Layer 3 Network — Fix SI-3: Update IDS Rules and Deploy Custom Signatures

| Field | Value |
|-------|-------|
| NIST Controls | SI-3 (Malicious Code Protection), SI-5 (Security Alerts and Advisories) |
| Tools | fix-suricata-rule-update.sh, suricata-update, local.rules |
| Time Estimate | 30–45 minutes |
| Rank | D |

---

## Objective

Update Suricata to current rule signatures and deploy site-specific custom rules. SI-3 requires mechanisms to receive and deploy current malicious code signatures. Rules that are stale or absent cannot detect threats from the last 7 days.

---

## When to Run This Playbook

- Suricata rules are more than 7 days old (SI-3 finding)
- Rule count is below 30,000 (under-deployed)
- Custom local.rules do not exist or are empty
- After a new threat intelligence report with IOCs to operationalize
- After a detection gap is identified (an attack that should have fired didn't)

---

## Step 1: Run the Automated Fixer

```bash
sudo bash 02-fixers/fix-suricata-rule-update.sh
```

The script handles:
1. Records pre-update rule count (evidence)
2. Runs `suricata-update` or `so-rule-update` (Security Onion)
3. Deploys custom local.rules from template
4. Reloads Suricata (kill -USR2, zero downtime)
5. Verifies post-update rule count increased
6. Runs live detection test (testmynids.org)
7. Evidence package in `/tmp/jsa-evidence/suricata-rule-update-*/`

---

## Step 2: Verify Update Applied

```bash
# Confirm rule count increased
grep "rules loaded\|rules\|post_count\|pre_count" /tmp/jsa-evidence/suricata-rule-update-*/rule-counts.txt

# Verify Suricata is still running after reload
sudo systemctl status suricata
sudo pgrep suricata && echo "Running" || echo "STOPPED"

# Check stats log for the reload event
grep "reload\|Rules\|loaded" /var/log/suricata/suricata.log | tail -10
```

---

## Step 3: Create Custom Signatures (If Required)

Reference: `02-fixers/fix-suricata-custom-signature.md`

The template `03-templates/suricata/local.rules` includes 7 rule sections covering:
- Authentication attacks (SSH/RDP brute force, cleartext passwords)
- DNS evasion (DoH bypass, suspicious TLDs, long queries)
- Lateral movement (SMB sweeps, SMBv1)
- Database exposure (MySQL, PostgreSQL, Redis, MongoDB from external)
- Cleartext protocols (FTP, Telnet, HTTP Basic Auth)
- C2 indicators (commented — enable after tuning)

To add a new custom rule:

```bash
# 1. Edit local.rules
sudo nano /etc/suricata/rules/local.rules

# 2. Use next available SID in 1000000-1099999 range
grep -oE "sid:[0-9]+" /etc/suricata/rules/local.rules | sort -t: -k2 -n | tail -5

# 3. Validate syntax
sudo suricata -T -c /etc/suricata/suricata.yaml
# Must return: "Configuration provided was successfully loaded."

# 4. Reload
sudo kill -USR2 $(pgrep suricata)

# 5. Verify rule loaded
sudo suricatasc -c ruleset-stats 2>/dev/null | grep "rules"
```

---

## Step 4: Test Custom Rules

```bash
# Test SSH brute force detection (SID 1000001)
# Requires hping3 or nmap
sudo hping3 -S -p 22 -c 10 --fast $(hostname -I | awk '{print $1}')
# OR
nmap -sS -p 22 --max-rate 10 127.0.0.1

# Check for SID 1000001
tail -50 /var/log/suricata/eve.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        a = e.get('alert', {})
        if a.get('signature_id') == 1000001:
            print('PASS:', a.get('signature'))
    except: pass
"
```

---

## Step 5: Schedule Regular Updates

SI-3 compliance requires regular signature updates. Automate with cron:

```bash
# Daily update at 2 AM
echo "0 2 * * * root /usr/bin/suricata-update && kill -USR2 \$(pgrep suricata)" \
  | sudo tee /etc/cron.d/suricata-update

# Verify cron entry
cat /etc/cron.d/suricata-update

# Test cron job manually
sudo /usr/bin/suricata-update && sudo kill -USR2 $(pgrep suricata)
echo "Manual run: $?"
```

---

## Evidence

After running the fixer, evidence is at:

```
/tmp/jsa-evidence/suricata-rule-update-TIMESTAMP/
  ├── update.log              # Full fixer execution log
  ├── rule-counts.txt         # pre_count, post_count, delta
  ├── suricata-update.log     # suricata-update output
  ├── local.rules.pre-update  # Backup of previous local.rules
  └── eve-post-test.txt       # Live detection test results
```

Copy to `evidence/` directory for audit trail:

```bash
cp -r /tmp/jsa-evidence/suricata-rule-update-* evidence/
```
