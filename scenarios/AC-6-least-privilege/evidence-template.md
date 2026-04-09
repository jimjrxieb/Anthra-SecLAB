# AC-6 Least Privilege — Evidence

**NIST Control:** AC-6 Least Privilege
**OSI Layer:** L3 Cluster
**5 C's Package:** 02-CLUSTER-HARDEN
**Control Type:** Preventive

## Break

**Action:** Bound default service account to cluster-admin ClusterRole.

**Command:** `bash scenarios/AC-6-least-privilege/break.sh`

**Before state (secure):**
<!-- Paste: kubectl auth can-i output showing denied -->
```
```

## Detection

**Tools:** kubectl auth can-i, kubescape (C-0035, C-0188)

**auth can-i results:**
<!-- Paste: privilege check output -->
```
```

**kubescape results:**
<!-- Paste: RBAC control findings from ac6-kubescape.json -->
```
```

**ClusterRoleBinding state:**
<!-- Paste: ac6-crb-state.json contents -->
```
```

## Fix

**Action:** Removed cluster-admin binding. Created namespace-scoped read-only Role.

**Command:** `bash scenarios/AC-6-least-privilege/fix.sh`

**After state (remediated):**
<!-- Paste: kubectl auth can-i output showing denied -->
```
```

## Evidence Files

| File | Description | SHA256 |
|------|-------------|--------|
| `ac6-crb-state.json` | ClusterRoleBinding dump | |
| `ac6-kubescape.json` | kubescape RBAC scan | |
