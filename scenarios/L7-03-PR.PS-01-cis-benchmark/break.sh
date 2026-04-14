#!/usr/bin/env bash
#
# CSF: PROTECT / PR.PS-01 — Configuration management practices applied to IT assets
# CIS v8: 4.1 — Establish and Maintain a Secure Configuration Process
# NIST 800-53: CM-6 — Configuration Settings, CM-7 — Least Functionality
#
# L7-03 PR.PS-01 — Break: NO-OP
#
# This script intentionally does nothing.
#
# CIS benchmark failures are the DEFAULT state of most Kubernetes clusters.
# The vulnerability is not that someone broke something after deployment.
# The vulnerability is that nobody ran the benchmark after deployment.
#
# This is the most common real-world CIS finding pattern:
#   - Cluster deployed, application deployed, team moved on
#   - No benchmark run, no audit scheduled, no evidence collected
#   - Assessor or audit triggers the first real scan months later
#   - 30-50 FAIL findings discovered that have existed since day one
#
# Usage: bash break.sh
# Expected: Informational output only. No changes made.

set -euo pipefail

echo "=== L7-03 Break: No action required ==="
echo ""
echo "CIS benchmark failures are the DEFAULT state of most Kubernetes clusters."
echo "The vulnerability is not that someone broke something --"
echo "it is that nobody checked after deployment."
echo ""
echo "This is a no-op. The cluster ships with benchmark gaps by default."
echo "That IS the finding."
echo ""
echo "What most teams skip:"
echo "  - No scheduled kube-bench run post-deployment"
echo "  - No kubescape scan in the CI/CD pipeline"
echo "  - No CM-6 baseline documented before the first assessment"
echo "  - No POA&M entries for known configuration gaps"
echo ""
echo "Real-world data (from Aqua Security 2023 survey):"
echo "  - 60% of production clusters have never had a CIS benchmark run"
echo "  - Average: 38 FAIL findings on first audit"
echo "  - Most common: missing securityContext, no NetworkPolicy, no PSS labels"
echo ""
echo "Run baseline.sh to see the current failures in this cluster."
echo ""
echo "=== Break complete (no changes made) ==="
