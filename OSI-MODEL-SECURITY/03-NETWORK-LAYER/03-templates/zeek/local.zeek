# Zeek Local Configuration — Baseline Protocol Monitoring
# NIST Controls: AU-2 (Event Logging), SI-4 (System Monitoring), SI-7 (File Integrity)
#
# WHY: NIST AU-2 requires organizations to identify events that must be logged.
# Zeek provides protocol-level metadata that packet captures cannot at scale —
# conn.log records every network connection with metadata, dns.log records every
# query, http.log records every HTTP transaction. This creates an audit trail
# that satisfies AU-2 without capturing full packet content.
#
# Deploy: Copy to /opt/zeek/share/zeek/site/local.zeek (or platform equivalent)
# Apply:  zeekctl deploy (or kill -HUP $(pgrep zeek) for live reload)

# ─── Core Protocol Analyzers ─────────────────────────────────────────────────

# WHY: conn.log is the foundation of all Zeek analysis.
# Every connection gets an entry with src/dst, bytes, duration, state.
# Without this, you cannot detect beaconing, lateral movement, or exfiltration.
@load base/protocols/conn

# WHY: dns.log captures every DNS query and response.
# DNS is the primary C2 channel (T1071.004). Without DNS logging, an attacker
# can use DNS tunneling for months without detection. Satisfies AU-2 for DNS events.
@load base/protocols/dns

# WHY: http.log captures URL, method, response code, user-agent, and host.
# Enables detection of webshells, malicious downloads, and C2 over HTTP (T1071.001).
@load base/protocols/http

# WHY: ssl.log captures TLS certificate details, JA3/JA3S hashes, SNI.
# JA3 fingerprinting identifies malware by its TLS client hello pattern,
# even when the payload is encrypted.
@load base/protocols/ssl

# WHY: ftp.log captures FTP commands and file transfers in cleartext.
# SC-8 compliance: any FTP use is a policy violation that must be logged.
@load base/protocols/ftp

# WHY: smtp.log captures email metadata — to/from, subject, attachment names.
# Phishing (T1566) and BEC attacks are visible in SMTP metadata without
# decrypting message content.
@load base/protocols/smtp

# WHY: ssh.log captures SSH connection metadata including hassh fingerprint.
# Hassh identifies the SSH client software — useful for detecting SSH scanners
# and malware with distinctive SSH client implementations.
@load base/protocols/ssh

# WHY: rdp.log captures RDP connection attempts and encryption negotiation.
# Required for detecting RDP brute force (T1110) and BlueKeep exploitation.
@load base/protocols/rdp

# WHY: smb.log captures SMB file access, share enumeration, and admin shares.
# SMB lateral movement (T1021.002, T1210) generates distinctive log patterns.
@load base/protocols/smb

# WHY: krb.log captures Kerberos ticket requests and errors.
# Kerberoasting (T1558.003) and Golden Ticket attacks generate Kerberos anomalies.
@load base/protocols/krb

# ─── File Analysis ────────────────────────────────────────────────────────────

# WHY: NIST SI-7 (Software, Firmware, and Information Integrity) requires
# mechanisms to detect unauthorized file modifications.
# hash-all-files computes MD5/SHA1/SHA256 for every file seen in network traffic.
# This enables retroactive IOC matching — if a malicious file was transferred
# before the IOC was known, you can search logs after the fact.
@load frameworks/files/hash-all-files

# WHY: extract-all-files stores copies of transferred files for forensic analysis.
# WARNING: Generates significant disk usage. Enable only for forensic investigations
# or on high-value segments with limited traffic volume.
# @load frameworks/files/extract-all-files

# ─── Detection Policies ──────────────────────────────────────────────────────

# WHY: known-hosts.log tracks the first time each host is seen.
# New hosts appearing in the network (T1078 - Valid Accounts on new systems)
# are immediately visible in known-hosts.log with their first-seen timestamp.
@load policy/protocols/conn/known-hosts

# WHY: known-services.log tracks services (port/protocol combos) per host.
# A server that suddenly starts listening on a new port is a lateral movement
# or malware deployment indicator.
@load policy/protocols/conn/known-services

# WHY: detect-external-names alerts when an internal host resolves to an
# external IP that previously had a different address (potential DNS hijacking
# or fast-flux C2 infrastructure).
@load policy/protocols/dns/detect-external-names

# WHY: capture-loss.log records when Zeek misses packets due to overload.
# AU-9 (Protection of Audit Information) requires detecting monitoring gaps.
# If capture-loss is >5%, the sensor needs more resources or a different deployment.
@load policy/misc/capture-loss

# WHY: Detect scans by tracking connection failure patterns.
# Port scanners (T1046) generate many failed connections in short time windows.
@load policy/misc/scan

# WHY: Track software versions seen in the environment.
# software.log records HTTP server software, SSH versions, FTP banners.
# Critical for vulnerability management — when a CVE drops, you can immediately
# identify which hosts are running the affected software version.
@load policy/frameworks/software/vulnerable

# ─── Logging Configuration ────────────────────────────────────────────────────

# WHY: UTC timestamps prevent timezone confusion in incident response.
# An alert at "2:00 AM" means different things depending on the analyst's timezone.
# UTC eliminates ambiguity for cross-timezone SOC teams.
redef Log::default_rotation_interval = 1 hr;
redef Log::default_rotation_postprocessor_cmd = "";

# WHY: JSON output enables direct SIEM ingestion without parsing.
# TSV (default) requires field-by-field parsers that break on content with tabs.
# Note: Uncomment if your Zeek version supports JSON writer.
# @load tuning/json-logs

# ─── Alert Thresholds ─────────────────────────────────────────────────────────

# WHY: SSH brute force detection via scan framework.
# The scan policy generates notices for hosts doing rapid connection attempts.
# Adjust thresholds to match your environment's normal behavior.
redef Scan::scan_threshold = 25;        # Connections to unique hosts before scan notice
redef Scan::scan_timeout = 15 min;      # Time window for scan counting

# ─── Selective Protocol Disabling ────────────────────────────────────────────
# If specific protocols generate excessive noise in your environment,
# comment their @load line above rather than disabling here.
# Disabling without documenting creates silent blind spots.

# ─── Local Additions ──────────────────────────────────────────────────────────
# Add site-specific @load directives below this line.
# Document the WHY for each addition — future engineers will maintain this.
