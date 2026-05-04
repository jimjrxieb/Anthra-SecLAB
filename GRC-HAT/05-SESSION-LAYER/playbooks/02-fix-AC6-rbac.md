# 02-fix-AC6-rbac.md — RBAC Remediation (AC-6 Least Privilege)

| Field | Value |
|---|---|
| **NIST Controls** | AC-6 (Least Privilege), AC-2 (Account Management) |
| **Tools** | kubectl, fix-overprivileged-sa.sh |
| **Enterprise Equiv** | Prisma Cloud CIEM ($200K+/yr), Styra DAS ($100K+/yr) |
| **Time** | 45 minutes |
| **Rank** | D (scripted, low decision complexity for clear overprivilege) |

---

## Purpose

Remove overprivileged RBAC bindings, create scoped roles, and disable default service account token mounting. Run `audit-rbac-privileges.sh` and `audit-service-accounts.sh` first — this playbook remediates the findings from those audits.

---

## Before You Start

```bash
# Verify findings exist before remediating
./01-auditors/audit-rbac-privileges.sh default
./01-auditors/audit-service-accounts.sh default

# If no findings, STOP — nothing to remediate
```

---

## Step 1: Review What You're Removing

Before removing any ClusterRoleBinding, confirm the workload it serves.

```bash
# Who is bound to cluster-admin?
kubectl get clusterrolebindings -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for item in data.get('items', []):
    if item.get('roleRef', {}).get('name') == 'cluster-admin':
        name = item['metadata']['name']
        subjects = item.get('subjects', [])
        for s in subjects:
            print(f'CRB: {name}')
            print(f'  Subject: {s.get(\"kind\")} / {s.get(\"name\")} (ns: {s.get(\"namespace\", \"cluster\")})')
"

# What does a given SA actually do? (check pod logs + events)
SA_NAMESPACE="default"
SA_NAME="my-sa"
kubectl get pods -n "${SA_NAMESPACE}" \
  -o json | python3 -c "
import json, sys
d = json.load(sys.stdin)
for p in d.get('items', []):
    spec = p.get('spec', {})
    if spec.get('serviceAccountName') == '${SA_NAME}':
        print(f'Pod using SA: {p[\"metadata\"][\"name\"]}')
"
```

---

## Step 2: Run the Fixer (Dry-Run First)

```bash
# Dry-run: see what would happen without applying changes
./02-fixers/fix-overprivileged-sa.sh default --dry-run

# Review the output — verify the Role being created covers what the workload needs
# Then apply:
./02-fixers/fix-overprivileged-sa.sh default
```

---

## Step 3: Manual RBAC Remediation (If Needed)

For custom workloads that need different permissions than the template role:

```bash
NAMESPACE="my-app"

# 1. Remove cluster-admin CRB
CLUSTER_ADMIN_CRB="my-app-cluster-admin"
kubectl delete clusterrolebinding "${CLUSTER_ADMIN_CRB}"

# 2. Create scoped Role — customize verbs and resources for your workload
cat <<'EOF' | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: my-app-role
  namespace: my-app
  annotations:
    nist-control: "AC-6 — Least Privilege"
rules:
  - apiGroups: [""]
    resources: ["configmaps", "secrets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
EOF

# 3. Create RoleBinding
cat <<'EOF' | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: my-app-rolebinding
  namespace: my-app
subjects:
  - kind: ServiceAccount
    name: my-app-sa
    namespace: my-app
roleRef:
  kind: Role
  name: my-app-role
  apiGroup: rbac.authorization.k8s.io
EOF

# 4. Disable automount on default SA
kubectl patch serviceaccount default \
  -n "${NAMESPACE}" \
  -p '{"automountServiceAccountToken": false}'

# 5. Create dedicated SA for workloads that need K8s API access
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app-sa
  namespace: my-app
  annotations:
    nist-control: "AC-2 — Account Management"
automountServiceAccountToken: false
EOF
```

---

## Step 4: Verify with kubectl auth can-i

```bash
NAMESPACE="default"
SA_NAME="default"

echo "Testing permissions for SA: system:serviceaccount:${NAMESPACE}:${SA_NAME}"
echo ""

# These should all return "no" after remediation
for OP in "create deployments" "delete pods" "get secrets" "create clusterrolebindings" "exec pods" "*"; do
    VERB="${OP%% *}"
    RESOURCE="${OP##* }"
    RESULT=$(kubectl auth can-i "${VERB}" "${RESOURCE}" \
        --namespace "${NAMESPACE}" \
        --as "system:serviceaccount:${NAMESPACE}:${SA_NAME}" \
        2>/dev/null || echo "no")
    STATUS="[PASS]"
    [[ "$RESULT" == "yes" ]] && STATUS="[FAIL]"
    echo "${STATUS} can-i ${OP}: ${RESULT}"
done

echo ""
# These should return "yes" (minimum access)
for OP in "get configmaps" "list pods" "get services"; do
    VERB="${OP%% *}"
    RESOURCE="${OP##* }"
    RESULT=$(kubectl auth can-i "${VERB}" "${RESOURCE}" \
        --namespace "${NAMESPACE}" \
        --as "system:serviceaccount:${NAMESPACE}:${SA_NAME}" \
        2>/dev/null || echo "no")
    STATUS="[PASS]"
    [[ "$RESULT" == "no" ]] && STATUS="[WARN] (expected yes)"
    echo "${STATUS} can-i ${OP}: ${RESULT}"
done
```

---

## Templates

See `03-templates/rbac/` for ready-to-apply manifests:
- `least-privilege-role.yaml` — application workload Role + RoleBinding + ServiceAccount
- `read-only-clusterrole.yaml` — security auditor ClusterRole (no Secrets, no exec)

---

## Evidence

```bash
EVIDENCE_DIR="/tmp/jsa-evidence/rbac-fix-$(date +%Y%m%d)"
mkdir -p "${EVIDENCE_DIR}"

# After state
kubectl get clusterrolebindings -o yaml > "${EVIDENCE_DIR}/after-clusterrolebindings.yaml"
kubectl get roles --all-namespaces -o yaml > "${EVIDENCE_DIR}/after-roles.yaml"
kubectl get rolebindings --all-namespaces -o yaml > "${EVIDENCE_DIR}/after-rolebindings.yaml"
kubectl get serviceaccounts --all-namespaces -o yaml > "${EVIDENCE_DIR}/after-serviceaccounts.yaml"

echo "Evidence: ${EVIDENCE_DIR}"
```
