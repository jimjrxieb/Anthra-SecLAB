# Verify and Close

## Purpose

A finding is not closed until re-scan confirms it is gone. Self-attestation ("we patched it") is not verification. Evidence is a second scan result.

## Verification Steps

### 1. Re-run the original detection
```bash
# If detected by Lynis: re-run lynis and check the specific finding is gone
sudo lynis audit system 2>/dev/null | grep "<finding_id>"

# If detected by Trivy: re-scan the target
trivy fs / --severity HIGH,CRITICAL | grep "<CVE_ID>"

# If detected by Nmap: re-scan the port/service
nmap -sV -p <port> <target_ip>

# If detected by Nuclei: re-run the specific template
nuclei -target <target> -t <template_path>
```

### 2. Verify the patch version
```bash
# Confirm patched version is installed
dpkg -l <package_name>
# or
rpm -qi <package_name>

# Confirm the vulnerable version string is gone
<application> --version
```

### 3. Functional test
After patching, verify the system still works:
- Application health check
- Service status: `systemctl status <service>`
- Log review: no errors in the first 10 minutes post-patch

## Closing a Finding

Document in your vulnerability tracker:
- Re-scan date
- Re-scan result (clean)
- Patch version installed
- Analyst who verified
- Date closed

## False Closure Prevention

Before marking closed, answer:
- [ ] Did I re-scan with the same tool that found it?
- [ ] Did the re-scan explicitly show this CVE/finding is gone?
- [ ] Is the patch actually applied to the right system? (Not a different host)
- [ ] Is the patched service running the new version? (Not still running the old binary)

A reboot may be required for the patch to take effect.
