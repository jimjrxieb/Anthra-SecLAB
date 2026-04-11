# How to Create a Custom Suricata Signature

| Field | Value |
|-------|-------|
| NIST Controls | SI-3 (Malicious Code Protection), SI-4 (System Monitoring) |
| MITRE Coverage | Multiple — see per-rule metadata |
| Applies To | Suricata 6.x / 7.x |
| SID Range | 1000000–1099999 (local/custom rules) |
| Time Estimate | 15–30 minutes per rule |

---

## Objective

Write, deploy, and validate a custom Suricata detection rule. This covers situations where ET Open or other public rule sets do not detect your specific environment threats. Custom signatures are required for:

- Site-specific application traffic (internal APIs, custom protocols)
- Threat intel IOCs (malicious domains, attacker infrastructure)
- Compliance-driven monitoring (detect cleartext auth, prohibited protocols)
- Lateral movement patterns unique to your network architecture

---

## Rule Anatomy

```
action proto src_ip src_port direction dst_ip dst_port (options)
```

| Field | Values | Notes |
|-------|--------|-------|
| `action` | `alert`, `drop`, `pass`, `reject` | Use `alert` in detection mode, `drop` in IPS mode |
| `proto` | `tcp`, `udp`, `icmp`, `dns`, `http`, `tls`, `smtp` | Application-layer protos need app-layer keywords |
| `src_ip` | `$HOME_NET`, `$EXTERNAL_NET`, `any`, `192.168.0.0/16` | Use Suricata variables where possible |
| `src_port` | `any`, `$HTTP_PORTS`, `[80,8080]`, `!443` | Port or port group |
| `direction` | `->` (one-way), `<>` (both) | Almost always `->` |
| `dst_ip` / `dst_port` | Same as src | |

### Key Options

| Option | Purpose |
|--------|---------|
| `msg:"..."` | Alert message — shown in SIEM, logs, dashboards |
| `flow:established,to_server` | Match only established TCP flows going to server |
| `content:"..."` | Literal byte match in payload |
| `nocase` | Case-insensitive content match |
| `http_method` | Match HTTP verb (GET, POST, PUT) |
| `http_client_body` | Match in HTTP request body |
| `http_header` | Match in HTTP headers |
| `dns_query` | Match DNS query name |
| `tls_sni` | Match TLS Server Name Indication |
| `pcre:"/pattern/flags"` | Perl-Compatible Regex match |
| `threshold:type limit,track by_src,count 5,seconds 60` | Rate limiting |
| `classtype:...` | Alert classification (affects priority) |
| `sid:XXXXXXX` | Unique rule ID — use 1000000–1099999 for local rules |
| `rev:1` | Rule revision — increment when you change a rule |
| `metadata:` | Structured metadata for SIEM enrichment |

---

## Working Example 1: Cleartext Password Over HTTP

**Threat:** MITRE T1552.001 — Credentials in Files / cleartext auth over unencrypted channel

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (
    msg:"ANTHRA-LOCAL Cleartext Password Submission over HTTP";
    flow:established,to_server;
    http_method;
    content:"POST";
    http_client_body;
    content:"password=";
    nocase;
    classtype:credential-theft;
    sid:1000001;
    rev:1;
    metadata:
        nist SI-4,
        mitre_technique T1552.001,
        deployment perimeter-egress,
        created_date 2026-04-10,
        reviewed_by SOC;
)
```

**What it catches:** Any POST request from your internal network with `password=` in the body sent over plain HTTP. Catches web forms, old applications, and developer test endpoints transmitting credentials in cleartext.

**Tuning note:** Will fire on internal staging environments with HTTP basic auth. Add `threshold:type limit,track by_src,count 3,seconds 60` to reduce noise, or add `!` exclusions for known-safe internal hosts.

---

## Working Example 2: DNS Query to Suspicious TLD

**Threat:** MITRE T1568 — Dynamic Resolution / C2 infrastructure on high-abuse TLDs

```suricata
alert dns any any -> any any (
    msg:"ANTHRA-LOCAL DNS Query to High-Risk TLD (.top .xyz .click)";
    dns_query;
    pcre:"/\.(top|xyz|click|tk|pw|cc|su)$/i";
    classtype:bad-unknown;
    sid:1000002;
    rev:1;
    metadata:
        nist SI-4,
        mitre_technique T1568,
        deployment internal-dns-monitoring,
        created_date 2026-04-10,
        reviewed_by SOC;
)
```

**What it catches:** DNS lookups to top-level domains with documented high abuse rates (.top, .xyz, .click, .tk, .pw, .cc, .su). These are not blocked — they are flagged for SOC review.

**Tuning note:** Expect false positives from browser telemetry and ad networks. Add `threshold:type limit,track by_src,count 1,seconds 300` to cap noise per source.

---

## Working Example 3: SSH Brute Force Detection

**Threat:** MITRE T1110 — Brute Force / credential stuffing against SSH

```suricata
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
    msg:"ANTHRA-LOCAL SSH Brute Force Attempt (5 in 60s)";
    flow:to_server;
    flags:S;
    threshold:type both,track by_src,count 5,seconds 60;
    classtype:attempted-admin;
    sid:1000003;
    rev:1;
    metadata:
        nist AC-7,
        nist SI-4,
        mitre_technique T1110.001,
        deployment perimeter,
        created_date 2026-04-10,
        reviewed_by SOC;
)
```

**What it catches:** Source IPs that send 5+ SYN packets to port 22 within 60 seconds. The `type both` threshold suppresses alerts until the threshold is met, then fires once per interval per source.

**Tuning note:** Adjust count and seconds for your environment. Aggressive scanners hit 20+ per second — a count of 5/60s may still generate noise. Consider `type limit,track by_src,count 1,seconds 60` for alert-once-per-minute behavior.

---

## Deploy Your Signature

### Step 1: Add to local.rules

```bash
sudo nano /etc/suricata/rules/local.rules
# Paste your rule, save
```

### Step 2: Validate syntax

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
# Should output: Configuration provided was successfully loaded.
# Any syntax errors will be shown with line numbers
```

### Step 3: Reload rules (no restart needed)

```bash
# Live reload via signal (preferred — zero downtime)
sudo kill -USR2 $(pgrep suricata)

# Or full restart
sudo systemctl restart suricata
```

### Step 4: Verify rule is loaded

```bash
# Count loaded rules
sudo suricatasc -c ruleset-stats 2>/dev/null
# OR check stats log
grep "rules loaded" /var/log/suricata/stats.log | tail -5
```

---

## Test Your Signature

Generate traffic that should match the rule, then check eve.json.

### Test Example 1 (cleartext password):

```bash
# Generate matching traffic (HTTP POST with password= in body)
curl -X POST http://httpbin.org/post \
  -d "username=test&password=hunter2" \
  -H "Content-Type: application/x-www-form-urlencoded"

# Check eve.json for the alert
tail -100 /var/log/suricata/eve.json | \
  python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('event_type') == 'alert':
            print(json.dumps(e.get('alert'), indent=2))
    except: pass
"
```

### Test Example 2 (DNS to suspicious TLD):

```bash
# Trigger a DNS query to .top TLD
dig @8.8.8.8 example.top

# Check dns.log or eve.json
tail -50 /var/log/suricata/eve.json | grep -i "suspicious\|top\|xyz"
```

### Test Example 3 (SSH brute force simulation):

```bash
# Using hping3 (send SYN packets to port 22)
# WARNING: Only do this against hosts you own/control
sudo hping3 -S -p 22 -c 10 <target-ip>

# Or use nmap SYN scan
nmap -sS -p 22 <target-ip>
```

---

## SID Range Policy

| Range | Owner | Purpose |
|-------|-------|---------|
| 1–999999 | Emerging Threats / community | ET Open, community rules |
| 1000000–1099999 | **Your organization** | Local custom rules |
| 1100000–1999999 | Reserved | Future community use |
| 2000000–2999999 | ET Pro | Commercial ET Pro rules |
| 3000000–3999999 | Reserved | Other commercial sources |

Always increment `rev:` when modifying a rule. SID must be unique — duplicates cause loading errors.

---

## Classtype Reference

| Classtype | Priority | Use Case |
|-----------|----------|---------|
| `attempted-admin` | High | Brute force, privilege escalation attempts |
| `credential-theft` | High | Password capture, credential exposure |
| `command-and-control` | Critical | C2 beaconing, RAT callbacks |
| `bad-unknown` | Medium | Suspicious but unconfirmed |
| `policy-violation` | Low | Cleartext protocols, prohibited services |
| `network-scan` | Low | Port/host scanning activity |

---

## Common Mistakes

1. **Forgetting `nocase`** — `content:"password="` misses `PASSWORD=`, `Password=`
2. **Wrong flow direction** — `flow:to_client` on a rule intended to catch requests
3. **Missing `rev:`** — Suricata requires both `sid:` and `rev:`
4. **Using payload keywords on UDP DNS** — `content:` on DNS needs `dns_query` instead
5. **SID conflict** — Check existing local.rules before assigning a new SID
6. **Too-broad pcre** — Test regex at regex101.com with real traffic samples first
