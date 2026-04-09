# CM-7 Least Functionality — Evidence

**NIST Control:** CM-7 Least Functionality
**OSI Layer:** L3 Network
**5 C's Package:** 02-CLUSTER-HARDEN
**Control Type:** Preventive

## Break

**Action:** Added wildcard ingress rule allowing all pod-to-pod traffic.

**Command:** `bash scenarios/CM-7-least-functionality/break.sh`

**Before state (secure — SC-7 policies in place):**
<!-- Paste: kubectl get netpol -n anthra -o wide -->
```
```

**After break (wildcard added):**
<!-- Paste: kubectl get netpol -n anthra -o wide -->
```
```

## Detection

**Tools:** kubescape (full scan), polaris (audit)

**Wildcard check:**
<!-- Paste: output from kubectl wildcard check -->
```
```

**kubescape results:**
<!-- Paste: key findings from cm7-kubescape.json -->
```
```

**polaris results:**
<!-- Paste: key findings from cm7-polaris.json -->
```
```

## Fix

**Action:** Removed wildcard ingress rule, leaving per-service rules intact.

**Command:** `bash scenarios/CM-7-least-functionality/fix.sh`

**After state (remediated):**
<!-- Paste: kubectl get netpol -n anthra -o wide -->
```
```

## Evidence Files

| File | Description | SHA256 |
|------|-------------|--------|
| `cm7-netpol-state.json` | kubectl netpol dump | |
| `cm7-kubescape.json` | kubescape full scan | |
| `cm7-polaris.json` | polaris audit | |
