#!/usr/bin/env bash
# SC-7 Boundary Protection — Fix
# NIST 800-53: SC-7 | Layer: L3 Network | Package: 02-CLUSTER-HARDEN
# Type: Preventive + Detective
#
# Restores default-deny NetworkPolicy and per-service ingress rules
# in the anthra namespace. Idempotent — safe to run multiple times.

set -euo pipefail

NAMESPACE="anthra"

echo "=== SC-7 Fix: Restoring boundary protection ==="

# Default-deny all ingress
cat <<'POLICY' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: anthra
  labels:
    seclab-scenario: SC-7
spec:
  podSelector: {}
  policyTypes:
    - Ingress
POLICY

# Allow ingress to anthra-ui from any (NodePort traffic)
cat <<'POLICY' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ui-ingress
  namespace: anthra
  labels:
    seclab-scenario: SC-7
spec:
  podSelector:
    matchLabels:
      app: anthra-ui
  policyTypes:
    - Ingress
  ingress:
    - ports:
        - protocol: TCP
          port: 80
POLICY

# Allow ingress to anthra-api from anthra-ui only
cat <<'POLICY' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-from-ui
  namespace: anthra
  labels:
    seclab-scenario: SC-7
spec:
  podSelector:
    matchLabels:
      app: anthra-api
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: anthra-ui
      ports:
        - protocol: TCP
          port: 8080
POLICY

# Allow ingress to anthra-db from anthra-api only
cat <<'POLICY' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-db-from-api
  namespace: anthra
  labels:
    seclab-scenario: SC-7
spec:
  podSelector:
    matchLabels:
      app: anthra-db
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: anthra-api
      ports:
        - protocol: TCP
          port: 5432
POLICY

# Allow ingress to anthra-log-ingest from anthra-api only
cat <<'POLICY' | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-log-ingest-from-api
  namespace: anthra
  labels:
    seclab-scenario: SC-7
spec:
  podSelector:
    matchLabels:
      app: anthra-log-ingest
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: anthra-api
      ports:
        - protocol: TCP
          port: 9090
POLICY

echo "=== SC-7 Fix complete ==="
kubectl get networkpolicy -n "${NAMESPACE}" -o wide
