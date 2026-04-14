#!/usr/bin/env bash
# =============================================================================
# L7-05 — DE.AE-02: Alert Fatigue (No Custom Falco Tuning)
# Phase: FIX — Deploy custom Falco rules; suppress known FPs; add Portfolio rules
#
# CSF:       DETECT / DE.AE-02 (Potentially adverse events analyzed)
# CIS v8:    8.11 — Tune Security Event Alert Thresholds
# NIST:      AU-6 — Audit Record Review, Analysis, and Reporting
# Cluster:   k3d-seclab
# Namespace: falco
#
# WHAT THIS DOES:
#   1. Creates a ConfigMap in the falco namespace with:
#      a. Exceptions for known-good Portfolio processes (suppresses FP flood)
#      b. Custom rules for Portfolio-specific threat patterns (adds signal)
#   2. Labels the ConfigMap so Falco picks it up via the rules.files Helm value
#   3. Restarts Falco to reload the rule set
#
# ARGOCD NOTE: Falco is deployed via Helm through ArgoCD. The ConfigMap created
#   here is NOT managed by ArgoCD (no app.kubernetes.io/instance label matching
#   the ArgoCD app). It is an additive resource. Check before applying:
#   kubectl get cm -n falco -l app.kubernetes.io/instance
#   If falco-custom-rules shows an ArgoCD instance, put this in the Helm chart.
# =============================================================================
set -euo pipefail

FALCO_NS="falco"
CM_NAME="falco-custom-portfolio-rules"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "============================================================"
echo "L7-05 FIX — Deploy Custom Falco Rules for Portfolio"
echo "Timestamp: ${TIMESTAMP}"
echo "Namespace: ${FALCO_NS}"
echo "ConfigMap: ${CM_NAME}"
echo "============================================================"
echo ""

# --- Pre-flight: confirm Falco is running ---
echo "[PRE] Verifying Falco is running..."
FALCO_PODS=$(kubectl get pods -n "${FALCO_NS}" \
  -l app.kubernetes.io/name=falco \
  --no-headers 2>/dev/null | grep -c Running || true)

if (( FALCO_PODS == 0 )); then
  echo "ERROR: No running Falco pods found in namespace ${FALCO_NS}."
  echo "       Resolve the Falco deployment issue first (see L7-04)."
  exit 1
fi
echo "  Falco pods running: ${FALCO_PODS}"
echo ""

# --- Apply the custom rules ConfigMap ---
echo "[1/3] Creating custom rules ConfigMap..."

kubectl apply -f - <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-custom-portfolio-rules
  namespace: falco
  labels:
    app.kubernetes.io/component: custom-rules
    app.kubernetes.io/part-of: falco
    seclab.scenario: L7-05-DE.AE-02
  annotations:
    seclab.tuning-date: "2026-04-12"
    seclab.tuned-by: "L7-05 fix.sh"
    seclab.au6-justification: "Suppress known-good Portfolio health check processes; add application-specific threat rules"
data:
  portfolio_rules.yaml: |
    # ==========================================================================
    # Portfolio Custom Falco Rules
    # AU-6 justification: Suppress false positives from known Portfolio processes.
    # Each exception documents the process, container, and business justification.
    # Reviewed: 2026-04-12 | Next review: 2026-07-12
    # ==========================================================================

    # --- EXCEPTION: Package manager in init containers ---
    # Justification: Portfolio init containers run pip install at startup.
    # This is expected, pinned-version, build-time behavior — not runtime threat.
    # Risk accepted: Low. Process is pip/pip3 only, in init containers only.
    - rule: Launch Package Management Process in Container
      condition: >
        container.name in (init, dependency-installer, pip-setup)
        and proc.name in (pip, pip3)
      override:
        condition: append
        desc: "AU-6 exception: pip in Portfolio init containers is expected. Reviewed 2026-04-12."

    # --- EXCEPTION: Health probe reads of /proc and /etc/hostname ---
    # Justification: Kubernetes liveness and readiness probes read /proc/self/status
    # and /etc/hostname on every check interval (every 10 seconds). These are
    # initiated by the kubelet, not the application. Not a threat indicator.
    # Risk accepted: Low. Scope is /proc/self/* and /etc/hostname only.
    - rule: Read sensitive file untrusted
      condition: >
        container.name in (api, ui, chroma)
        and proc.name in (curl, python3, python)
        and (fd.name startswith "/proc/self"
          or fd.name = "/etc/hostname"
          or fd.name = "/etc/os-release"
          or fd.name = "/etc/resolv.conf")
      override:
        condition: append
        desc: "AU-6 exception: health probe reads in Portfolio containers. Reviewed 2026-04-12."

    # ==========================================================================
    # CUSTOM RULES — Portfolio-Specific Threat Detection
    # These rules detect threats specific to the Portfolio application stack.
    # They are the signal that was missing before tuning.
    # ==========================================================================

    # --- CUSTOM RULE 1: Shell exec inside the API container ---
    # The Portfolio API is a FastAPI application. It should never spawn an
    # interactive shell. A shell exec in the api container is a strong indicator
    # of command injection, container breakout, or a compromised application.
    # Severity: CRITICAL — always investigate immediately.
    - rule: Portfolio API Shell Spawn
      desc: >
        Shell process spawned inside the Portfolio API container. The API is a
        Python FastAPI app and has no legitimate reason to spawn sh or bash.
        This is a strong indicator of command injection or container compromise.
      condition: >
        spawned_process
        and container.name = "api"
        and proc.name in (sh, bash, dash, zsh, ksh)
        and not proc.pname in (python, python3, uvicorn, gunicorn)
      output: >
        PORTFOLIO THREAT: Shell spawned in API container
        (user=%user.name cmd=%proc.cmdline container=%container.name
        image=%container.image.repository pid=%proc.pid ppid=%proc.ppid)
      priority: CRITICAL
      tags: [portfolio, shell, container_compromise, DE.AE-02]

    # --- CUSTOM RULE 2: /etc/passwd or /etc/shadow read in API container ---
    # The Portfolio API reads application config files, not system credential files.
    # Reading /etc/passwd or /etc/shadow inside the API container indicates either
    # a vulnerability exploit attempting privilege escalation or credential dumping.
    # Severity: ERROR — escalate to L2.
    - rule: Portfolio API Credential File Read
      desc: >
        Sensitive credential file read inside the Portfolio API container.
        The API has no business reason to read /etc/passwd or /etc/shadow.
        Possible indicators: privilege escalation attempt, credential dumping.
      condition: >
        open_read
        and container.name = "api"
        and fd.name in (/etc/passwd, /etc/shadow, /etc/gshadow, /etc/master.passwd)
      output: >
        PORTFOLIO THREAT: Credential file read in API container
        (user=%user.name file=%fd.name proc=%proc.name container=%container.name
        image=%container.image.repository)
      priority: ERROR
      tags: [portfolio, credential_access, DE.AE-02, AU-6]

    # --- CUSTOM RULE 3: Outbound connection from API pod to non-cluster IP ---
    # The Portfolio API communicates with ChromaDB and PostgreSQL — both internal
    # cluster services (10.x.x.x or 172.x.x.x). An outbound TCP connection to
    # a routable non-RFC1918 address from the API container is anomalous.
    # Possible indicators: data exfiltration, C2 callback, supply chain compromise.
    # Severity: WARNING — investigate but may be legitimate external API call.
    - rule: Portfolio API Unexpected Outbound Connection
      desc: >
        Outbound TCP connection from Portfolio API container to a non-cluster address.
        The API is expected to communicate only with internal services. External
        connections may indicate data exfiltration or C2 callback behavior.
      condition: >
        outbound
        and container.name = "api"
        and not fd.sip startswith "10."
        and not fd.sip startswith "172."
        and not fd.sip startswith "192.168."
        and not fd.sip = "127.0.0.1"
        and fd.sport != 53
      output: >
        PORTFOLIO THREAT: Unexpected outbound connection from API
        (user=%user.name dest=%fd.rip:%fd.rport proc=%proc.name container=%container.name
        image=%container.image.repository)
      priority: WARNING
      tags: [portfolio, exfiltration, c2, DE.AE-02]
YAML

echo "  ConfigMap ${CM_NAME} applied."
echo ""

# --- Verify the ConfigMap was created ---
echo "[2/3] Verifying ConfigMap content..."
kubectl get configmap "${CM_NAME}" -n "${FALCO_NS}" -o yaml \
  | grep -A2 "labels:" \
  | head -8
echo ""

# --- Restart Falco to pick up the new rules ---
echo "[3/3] Restarting Falco DaemonSet to reload rules..."
echo "  NOTE: This causes a brief (~30s) monitoring gap during pod restart."
echo "  Document this window if required for your AU-6 evidence."
echo ""
kubectl rollout restart daemonset/falco -n "${FALCO_NS}"
echo ""
echo "  Waiting for Falco rollout to complete (timeout: 120s)..."
kubectl rollout status daemonset/falco -n "${FALCO_NS}" --timeout=120s
echo ""

# --- Confirm Falco picked up the custom rules ---
echo "Confirming Falco loaded the custom rules..."
sleep 5
kubectl logs -n "${FALCO_NS}" \
  -l app.kubernetes.io/name=falco \
  --tail=30 \
  --prefix=false \
  2>/dev/null \
  | grep -iE "(portfolio|custom|rules loaded|exception)" \
  | head -10 \
  || echo "  No rule-load confirmation found in logs yet. Wait 30s and check manually."

echo ""
echo "============================================================"
echo "FIX COMPLETE"
echo ""
echo "Applied:"
echo "  - Exceptions: pip in init containers, health probe file reads"
echo "  - Custom rule 1: Portfolio API Shell Spawn (CRITICAL)"
echo "  - Custom rule 2: Portfolio API Credential File Read (ERROR)"
echo "  - Custom rule 3: Portfolio API Unexpected Outbound Connection (WARNING)"
echo ""
echo "AU-6 documentation: See ConfigMap annotation 'seclab.au6-justification'"
echo "Next step: Proceed to remediate.md, then run verify.sh"
echo "============================================================"
