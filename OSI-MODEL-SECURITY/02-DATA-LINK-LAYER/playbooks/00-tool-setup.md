# Layer 2 — Tool Setup Playbook

## Purpose

Install and verify the L2 detection and attack tools required for SC-7 ARP spoofing and AC-3 VLAN hopping scenarios. These tools run on the **WSL host**, not inside the k3s cluster — because ARP operates below Kubernetes on the Docker bridge network.

## Why These Tools Are Not Pre-Installed

The SOC stack (Falco, Fluent Bit, Splunk, Prometheus) covers Layers 3-7. Layer 2 detection requires host-level packet capture tools that have no reason to run outside of this scenario. Install before the scenario, tear down after. Clean lab, clean host.

## Prerequisites

- WSL2 with sudo access
- k3d cluster running (`k3d cluster list` shows `seclab`)
- Docker running (k3d nodes are Docker containers on a shared bridge)

## Tool Inventory

| Tool | Package | Purpose in Scenario |
|------|---------|-------------------|
| `arpspoof` | dsniff | ARP cache poisoning — the attack tool (break.sh) |
| `arpwatch` | arpwatch | ARP change monitoring — detection (detect.sh) |
| `tshark` | tshark | Packet capture and ARP analysis — detection (detect.sh) |
| `arping` | arping | ARP ping — validation and testing (validate.sh) |
| `arp` | net-tools | ARP table inspection — all scenarios |
| `tcpdump` | tcpdump | Low-level packet capture — backup detection method |

## Setup

```bash
cd OSI-MODEL-SECURITY/02-DATA-LINK-LAYER/tools/
sudo ./setup-l2-tools.sh
```

The script will:
1. Check which packages are already installed
2. Install only what's missing
3. Verify every tool is in PATH
4. Show available network interfaces
5. Show the k3d Docker bridge network with container IPs

## Identify Your Attack Surface

After setup, note the k3d bridge network. Your targets are:

```
k3d-seclab-server-0   172.19.0.3   (control plane)
k3d-seclab-agent-1    172.19.0.4   (worker — runs anthra-api)
k3d-seclab-agent-0    172.19.0.5   (worker — runs anthra-ui)
```

The interface to use is the Docker bridge — typically `br-*` or `docker0`. Find it with:

```bash
ip route | grep 172.19.0.0
```

## Run the Scenario

```bash
# Terminal 1 — Start detection first (so you have evidence of the attack)
cd ../scenarios/SC-7-arp-spoofing/
sudo ./detect.sh <interface> 120

# Terminal 2 — Run the attack while detection is watching
sudo ./break.sh <interface> 172.19.0.3 172.19.0.5

# After fixing — validate the fix holds
sudo ./validate.sh <interface> 172.19.0.5 172.19.0.3
```

## Teardown

When done with all L2 scenarios:

```bash
cd ../tools/
sudo ./teardown-l2-tools.sh
```

The teardown script will:
1. Kill any running arpwatch, arpspoof, tshark, tcpdump processes
2. Disable IP forwarding if it was left enabled
3. Flush the ARP cache to remove poisoned entries
4. Remove all installed packages (keeps net-tools)
5. Clean up arpwatch state files
6. Clean up `/tmp/sc7-*` evidence directories
7. Verify clean state

To keep evidence files for documentation:

```bash
sudo ./teardown-l2-tools.sh --keep-evidence
```

## Evidence Collection

Both `detect.sh` and `validate.sh` write evidence to timestamped directories under `/tmp/sc7-*`. Before teardown, copy anything you need to the evidence directory:

```bash
cp -r /tmp/sc7-arp-evidence-* ../evidence/
cp -r /tmp/sc7-validate-* ../evidence/
```
