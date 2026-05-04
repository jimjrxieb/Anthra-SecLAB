#!/usr/bin/env bash
# fix-missing-log-source.sh — Onboard missing log sources to Sentinel or Splunk
# NIST: AU-2 (event logging), AU-12 (audit generation), SI-4 (monitoring)
# Usage: ./fix-missing-log-source.sh [--sentinel | --splunk] [--source <source-name>]
#
# CSF 2.0: DE.AE-07 (Threat intel integrated)
# CIS v8: 8.2 (Collect Audit Logs)
# NIST: AU-2 (Audit Events)
#
set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS() { echo -e "${GREEN}[PASS]${NC} $*"; }
WARN() { echo -e "${YELLOW}[WARN]${NC} $*"; }
FAIL() { echo -e "${RED}[FAIL]${NC} $*"; }
INFO() { echo -e "       $*"; }
SECTION() { echo -e "\n${BLUE}═══ $* ═══${NC}"; }

SIEM="${1:-list}"
SOURCE="${3:-all}"

# Supported sources
EXPECTED_SOURCES=(
    "WindowsSecurityEvents"
    "LinuxSyslog"
    "AzureActiveDirectory"
    "AzureActivity"
    "Office365"
    "KubernetesAudit"
    "ContainerInsights"
)

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
EVIDENCE_DIR="/tmp/jsa-evidence/missing-log-source-${TIMESTAMP}"
mkdir -p "$EVIDENCE_DIR"

echo "======================================================"
echo " Missing Log Source Onboarding — AU-2 / AU-12 / SI-4"
echo " SIEM: ${SIEM}"
echo " Source: ${SOURCE}"
echo " Evidence: ${EVIDENCE_DIR}"
echo " $(date)"
echo "======================================================"
echo ""

if [[ "$SIEM" == "list" ]]; then
    echo "Usage: $0 [--sentinel | --splunk] [--source <name>]"
    echo ""
    echo "Available sources:"
    for SRC in "${EXPECTED_SOURCES[@]}"; do
        echo "  $SRC"
    done
    echo ""
    echo "Examples:"
    echo "  $0 --sentinel --source WindowsSecurityEvents"
    echo "  $0 --sentinel --source KubernetesAudit"
    echo "  $0 --splunk --source WindowsSecurityEvents"
    exit 0
fi

FINDINGS=0

# ─── Identify Missing Sources ─────────────────────────────────────────────────
SECTION "Identifying Missing Log Sources"

WORKSPACE_NAME="${SENTINEL_WORKSPACE:-}"
RESOURCE_GROUP="${SENTINEL_RG:-}"
SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:-}"

if [[ "$SIEM" == "--sentinel" ]]; then
    if ! command -v az &>/dev/null; then
        FAIL "az CLI required for Sentinel source onboarding"
        exit 1
    fi

    if [[ -z "$WORKSPACE_NAME" || -z "$RESOURCE_GROUP" ]]; then
        FAIL "Set SENTINEL_WORKSPACE and SENTINEL_RG environment variables"
        exit 1
    fi

    # List current data connectors
    az rest \
        --method GET \
        --url "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/${WORKSPACE_NAME}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2022-11-01" \
        --output json > "$EVIDENCE_DIR/current-connectors.json" 2>/dev/null || true

    CONNECTED=$(jq -r '.value[].kind // empty' "$EVIDENCE_DIR/current-connectors.json" 2>/dev/null | sort | uniq)
    echo "Currently connected sources:"
    echo "$CONNECTED" | sed 's/^/  /'

    # Compare against expected
    for SRC in "${EXPECTED_SOURCES[@]}"; do
        if echo "$CONNECTED" | grep -qi "$SRC"; then
            PASS "Connected: $SRC"
        else
            WARN "Missing: $SRC"
            FINDINGS=$((FINDINGS + 1))
        fi
    done
fi

# ─── Windows Security Events (Sentinel) ───────────────────────────────────────
if [[ "$SIEM" == "--sentinel" && ("$SOURCE" == "WindowsSecurityEvents" || "$SOURCE" == "all") ]]; then
    SECTION "Onboarding: Windows Security Events → Sentinel"

    INFO "Method: Azure Monitor Agent (AMA) — recommended over MMA for new deployments"
    INFO "Requires: Azure Arc or Azure VM agent, Data Collection Rule"

    # Create DCR for Windows Security Events
    DCR_TEMPLATE=$(cat <<'EOF'
{
  "location": "${LOCATION}",
  "properties": {
    "dataSources": {
      "windowsEventLogs": [
        {
          "streams": ["Microsoft-SecurityEvent"],
          "xPathQueries": [
            "Security!*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672 or EventID=4698 or EventID=4728 or EventID=4732)]]"
          ],
          "name": "SecurityEvents-WindowsSecurity"
        }
      ]
    },
    "destinations": {
      "logAnalytics": [
        {
          "workspaceResourceId": "/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.OperationalInsights/workspaces/${WORKSPACE_NAME}",
          "name": "la-dest"
        }
      ]
    },
    "dataFlows": [
      {
        "streams": ["Microsoft-SecurityEvent"],
        "destinations": ["la-dest"]
      }
    ]
  }
}
EOF
    )
    echo "$DCR_TEMPLATE" > "$EVIDENCE_DIR/windows-dcr-template.json"

    INFO "DCR template saved to $EVIDENCE_DIR/windows-dcr-template.json"
    INFO "Deploy with:"
    INFO "  az monitor data-collection rule create \\"
    INFO "    --name 'WindowsSecurityEvents-DCR' \\"
    INFO "    --resource-group '$RESOURCE_GROUP' \\"
    INFO "    --location 'eastus' \\"
    INFO "    --rule-file '$EVIDENCE_DIR/windows-dcr-template.json'"
fi

# ─── Linux Syslog (Sentinel) ──────────────────────────────────────────────────
if [[ "$SIEM" == "--sentinel" && ("$SOURCE" == "LinuxSyslog" || "$SOURCE" == "all") ]]; then
    SECTION "Onboarding: Linux Syslog → Sentinel"

    INFO "Install Syslog connector via Sentinel portal:"
    INFO "  Sentinel > Data connectors > Syslog > Open connector page"
    INFO ""
    INFO "Or install AMA on Linux host:"
    cat << 'EOF'
# Install Azure Monitor Agent on Linux (requires Arc enrollment)
wget https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/DataConnectors/CEF-Log-Analytics-Agent/cef_installer.py
python3 cef_installer.py <workspace-id> <primary-key>
EOF
    echo ""
    INFO "Verify after install:"
    INFO "  az monitor log-analytics query --workspace-name $WORKSPACE_NAME -g $RESOURCE_GROUP \\"
    INFO "    --analytics-query 'Syslog | take 5'"
fi

# ─── Kubernetes Audit Logs (Sentinel) ─────────────────────────────────────────
if [[ "$SIEM" == "--sentinel" && ("$SOURCE" == "KubernetesAudit" || "$SOURCE" == "all") ]]; then
    SECTION "Onboarding: Kubernetes Audit Logs → Sentinel"

    INFO "Method: Container Insights + Diagnostic Settings"
    INFO ""
    INFO "Step 1: Enable Container Insights on AKS cluster"
    cat << 'EOF'
az aks enable-addons \
  --resource-group "$AKS_RG" \
  --name "$AKS_CLUSTER" \
  --addons monitoring \
  --workspace-resource-id "/subscriptions/${SUBSCRIPTION_ID}/resourcegroups/${RESOURCE_GROUP}/providers/microsoft.operationalinsights/workspaces/${WORKSPACE_NAME}"
EOF
    echo ""
    INFO "Step 2: Enable diagnostic settings for kube-audit"
    cat << 'EOF'
az monitor diagnostic-settings create \
  --name "k8s-audit-to-sentinel" \
  --resource "/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${AKS_RG}/providers/Microsoft.ContainerService/managedClusters/${AKS_CLUSTER}" \
  --workspace "/subscriptions/${SUBSCRIPTION_ID}/resourcegroups/${RESOURCE_GROUP}/providers/microsoft.operationalinsights/workspaces/${WORKSPACE_NAME}" \
  --logs '[{"category":"kube-audit","enabled":true},{"category":"kube-audit-admin","enabled":true}]'
EOF
fi

# ─── Splunk: Forwarder Configuration ─────────────────────────────────────────
if [[ "$SIEM" == "--splunk" ]]; then
    SECTION "Onboarding Log Sources → Splunk"

    SPLUNK_HOST="${SPLUNK_HOST:-localhost}"
    SPLUNK_PORT="${SPLUNK_HEC_PORT:-8088}"
    HEC_TOKEN="${SPLUNK_HEC_TOKEN:-}"

    if [[ -z "$HEC_TOKEN" ]]; then
        WARN "Set SPLUNK_HEC_TOKEN for HEC-based onboarding"
        INFO "Create token: Splunk Settings > Data Inputs > HTTP Event Collector > New Token"
    fi

    if [[ "$SOURCE" == "WindowsSecurityEvents" || "$SOURCE" == "all" ]]; then
        SECTION "Splunk: Windows Security Events via Universal Forwarder"
        INFO "Install Splunk Universal Forwarder on Windows host:"
        cat << 'EOF'
# On Windows host — PowerShell
$installer = "splunkforwarder-9.0.0-6818ac46f2ec-x64-release.msi"
Start-Process msiexec -ArgumentList "/i $installer AGREETOLICENSE=yes SPLUNKUSERNAME=admin SPLUNKPASSWORD=changeme /quiet" -Wait

# Configure to forward to Splunk
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" add forward-server splunk-server:9997
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" add monitor "C:\Windows\System32\winevt\Logs\Security.evtx" -index main -sourcetype WinEventLog:Security
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" restart
EOF
    fi

    if [[ "$SOURCE" == "LinuxSyslog" || "$SOURCE" == "all" ]]; then
        SECTION "Splunk: Linux Syslog via rsyslog"
        cat << 'EOF'
# On Linux host — configure rsyslog to forward to Splunk HEC
cat > /etc/rsyslog.d/50-splunk.conf << 'RSYSLOG'
# Forward all auth logs to Splunk via TCP
$ModLoad omfwd
auth,authpriv.*   @splunk-server:514
RSYSLOG

systemctl restart rsyslog
EOF
    fi

    if [[ "$SOURCE" == "KubernetesAudit" || "$SOURCE" == "all" ]]; then
        SECTION "Splunk: Kubernetes Audit Logs via Fluent Bit"
        INFO "See 03-templates/splunk/inputs.conf for HEC configuration"
        INFO "Deploy Fluent Bit with Splunk output:"
        cat << 'EOF'
# values.yaml for Fluent Bit Helm chart
config:
  outputs: |
    [OUTPUT]
        Name        splunk
        Match       kube.audit.*
        Host        splunk-server
        Port        8088
        Splunk_Token ${HEC_TOKEN}
        TLS         On
        TLS.Verify  Off

helm upgrade --install fluent-bit fluent/fluent-bit \
  --namespace logging \
  --values values.yaml
EOF
    fi
fi

# ─── Verify Onboarding ────────────────────────────────────────────────────────
SECTION "Verification Commands"

echo ""
echo "After onboarding, verify data is flowing:"
echo ""

if [[ "$SIEM" == "--sentinel" ]]; then
    cat << 'EOF'
# Sentinel: Check for new data (run 15 minutes after onboarding)
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "SecurityEvent | where TimeGenerated > ago(1h) | take 5"

# Check Windows events
az monitor log-analytics query \
  --workspace-name "$SENTINEL_WORKSPACE" \
  --resource-group "$SENTINEL_RG" \
  --analytics-query "SecurityEvent | where TimeGenerated > ago(1h) | summarize count() by EventID"
EOF
elif [[ "$SIEM" == "--splunk" ]]; then
    cat << 'EOF'
# Splunk: Check for new events
curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "https://localhost:8089/services/search/jobs" \
  --data-urlencode "search=search index=main earliest=-1h | stats count by sourcetype" \
  -d "exec_mode=oneshot&output_mode=json"
EOF
fi

echo ""
echo "======================================================"
echo " Log Source Onboarding Complete"
echo " Evidence: ${EVIDENCE_DIR}"
echo " Findings before fix: ${FINDINGS}"
echo "======================================================"

{
    echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "action: fix-missing-log-source"
    echo "siem: $SIEM"
    echo "source: $SOURCE"
    echo "findings_identified: $FINDINGS"
    echo "evidence_dir: $EVIDENCE_DIR"
} > "$EVIDENCE_DIR/fix-summary.txt"
