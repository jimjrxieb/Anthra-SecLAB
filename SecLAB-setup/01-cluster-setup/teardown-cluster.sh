#!/usr/bin/env bash
# SecLAB Cluster Teardown
# Destroys the k3d cluster completely. All data lost.
# The gp-splunk container on the host is NOT affected.

set -euo pipefail

CLUSTER_NAME="seclab"

echo "============================================"
echo "SecLAB Cluster Teardown"
echo "============================================"

if k3d cluster list | grep -q "${CLUSTER_NAME}"; then
    echo "Deleting cluster '${CLUSTER_NAME}'..."
    k3d cluster delete "${CLUSTER_NAME}"
    echo "Cluster deleted."
else
    echo "Cluster '${CLUSTER_NAME}' does not exist — nothing to do."
fi

echo ""
echo "Note: gp-splunk container was NOT affected."
echo "Note: Docker images were NOT removed. Run 'docker image prune' to clean up."
echo "============================================"
