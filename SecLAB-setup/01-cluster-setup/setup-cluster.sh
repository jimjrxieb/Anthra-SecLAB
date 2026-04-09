#!/usr/bin/env bash
# SecLAB Cluster Setup
# Creates k3d cluster, builds app images, deploys target application.
# Idempotent — safe to run multiple times.
#
# Prerequisites: docker, k3d, kubectl, helm
# Splunk must be running: docker ps | grep gp-splunk

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "${SCRIPT_DIR}")")"
APP_DIR="${PROJECT_DIR}/target-application"
CLUSTER_NAME="seclab"
NAMESPACE="anthra"

echo "============================================"
echo "SecLAB Cluster Setup"
echo "============================================"
echo ""

# --- Prerequisites ---
echo "--- Checking prerequisites ---"
for cmd in docker k3d kubectl helm; do
    if ! command -v "${cmd}" &>/dev/null; then
        echo "ERROR: ${cmd} is not installed"
        exit 1
    fi
    echo "  ${cmd}: $(command -v ${cmd})"
done

# Check Splunk is running
if ! docker ps --format '{{.Names}}' | grep -q gp-splunk; then
    echo ""
    echo "WARNING: gp-splunk container is not running."
    echo "  Log shipping (Fluent Bit) and alert forwarding (Falcosidekick)"
    echo "  will not work until Splunk is started."
    echo "  Start it with: docker start gp-splunk"
    echo ""
fi

echo ""

# --- Cluster ---
echo "--- Creating k3d cluster ---"
if k3d cluster list | grep -q "${CLUSTER_NAME}"; then
    echo "  Cluster '${CLUSTER_NAME}' already exists — skipping creation"
else
    k3d cluster create --config "${SCRIPT_DIR}/k3d-config.yaml"
    echo "  Cluster '${CLUSTER_NAME}' created"
fi

# Wait for nodes ready
echo "  Waiting for nodes..."
kubectl wait --for=condition=Ready nodes --all --timeout=120s
echo "  All nodes ready"
echo ""

# --- Build images ---
echo "--- Building application images ---"

echo "  Building anthra-api:seclab..."
docker build -t anthra-api:seclab -f "${APP_DIR}/api/Dockerfile" "${APP_DIR}/api/" -q

echo "  Building anthra-log-ingest:seclab..."
docker build -t anthra-log-ingest:seclab -f "${APP_DIR}/services/Dockerfile" "${APP_DIR}/services/" -q

# UI: use GHCR image (Portfolio-Prod UI) — already pulled
if docker images --format '{{.Repository}}:{{.Tag}}' | grep -q 'ghcr.io/jimjrxieb/portfolio-ui:latest'; then
    echo "  anthra-ui: using ghcr.io/jimjrxieb/portfolio-ui:latest (already pulled)"
else
    echo "  Pulling ghcr.io/jimjrxieb/portfolio-ui:latest..."
    docker pull ghcr.io/jimjrxieb/portfolio-ui:latest
fi

echo ""

# --- Import images into k3d ---
echo "--- Importing images into k3d ---"
k3d image import \
    anthra-api:seclab \
    anthra-log-ingest:seclab \
    ghcr.io/jimjrxieb/portfolio-ui:latest \
    -c "${CLUSTER_NAME}"
echo "  Images imported"
echo ""

# --- Deploy application ---
echo "--- Deploying target application ---"
kubectl apply -k "${APP_DIR}/infrastructure/kustomize/overlays/local/"

echo "  Waiting for pods..."
kubectl wait --for=condition=Ready pods --all -n "${NAMESPACE}" --timeout=180s
echo "  All pods ready"
echo ""

# --- Verify ---
echo "--- Verification ---"
echo ""
kubectl get pods -n "${NAMESPACE}" -o wide
echo ""

# Health checks
echo "  UI (localhost:30000):"
if curl -sf -o /dev/null http://localhost:30000 2>/dev/null; then
    echo "    PASS"
else
    echo "    FAIL (may need a few seconds to start)"
fi

echo "  API (localhost:30080):"
if curl -sf -o /dev/null http://localhost:30080/api/health 2>/dev/null; then
    echo "    PASS"
else
    echo "    FAIL (may need a few seconds to start)"
fi

echo ""
echo "============================================"
echo "SecLAB cluster ready"
echo ""
echo "  UI:  http://localhost:30000"
echo "  API: http://localhost:30080"
echo "  Log: http://localhost:30090"
echo ""
echo "Next: deploy SOC stack with:"
echo "  bash SecLAB-setup/02-soc-stack/deploy-stack.sh"
echo "============================================"
