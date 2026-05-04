# Scan and Inventory

## Purpose

Know what you have before you can know what is vulnerable. Scanning against an incomplete inventory means you have blind spots.

## Asset Inventory First

Before scanning, build or verify the asset list:
```bash
# Discover live hosts on your network
nmap -sn 192.168.1.0/24 -oG - | awk '/Up$/{print $2}' > /tmp/live-hosts.txt
cat /tmp/live-hosts.txt

# For each live host, identify OS and open services
nmap -sV -O -iL /tmp/live-hosts.txt -oN /tmp/nmap-inventory.txt
```

## Running Vulnerability Scans

### Lynis (Linux host audit)
```bash
sudo lynis audit system
# Results: /var/log/lynis.log
# Report: /var/log/lynis-report.dat
```

### Trivy (filesystem / container)
```bash
# Filesystem scan
trivy fs / --severity HIGH,CRITICAL --format table

# Docker image scan
trivy image ubuntu:22.04 --severity HIGH,CRITICAL
```

### Nuclei (network services)
```bash
# Scan a target for known CVEs
nuclei -target http://localhost -severity high,critical -t cves/

# Scan for exposed management interfaces
nuclei -target 192.168.1.0/24 -t network/ -severity high,critical
```

### OpenVAS / Greenbone (comprehensive network scan)
```bash
# Via CLI (gvm-cli)
gvm-cli --protocol GMP socket --xml "<get_tasks/>"
# Or use the web interface at https://localhost:9392
```

## Scan Cadence (NIST RA-5 Requirement)

| Environment | Minimum Frequency | Recommended |
|-------------|------------------|-------------|
| Internet-facing systems | Monthly | Weekly |
| Internal servers | Quarterly | Monthly |
| Workstations | Quarterly | Monthly |
| After any significant change | Immediately | Immediately |
