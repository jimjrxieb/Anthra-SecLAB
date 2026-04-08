# SC-7 Boundary Protection — Evidence

**NIST Control:** SC-7 Boundary Protection
**OSI Layer:** L3 Network
**5 C's Package:** 02-CLUSTER-HARDEN
**Control Type:** Preventive + Detective

## Break

**Action:** Deleted all NetworkPolicies in `anthra` namespace.

**Command:** `bash scenarios/SC-7-boundary-protection/break.sh`

**Before state (secure):**
<!-- Paste: kubectl get netpol -n anthra -o wide -->
```
```

## Detection

**Tools:** kube-hunter, kubescape (control C-0260)

**kube-hunter results:**
<!-- Paste: vulnerability count and key findings from sc7-kube-hunter.json -->
```
```

**kubescape results:**
<!-- Paste: failed controls from sc7-kubescape.json -->
```
```

## Fix

**Action:** Restored default-deny + per-service NetworkPolicy rules.

**Command:** `bash scenarios/SC-7-boundary-protection/fix.sh`

**After state (remediated):**
<!-- Paste: kubectl get netpol -n anthra -o wide -->
```
```

## Evidence Files

| File | Description | SHA256 |
|------|-------------|--------|
| `sc7-netpol-state.json` | kubectl netpol dump (before) | |
| `sc7-kube-hunter.json` | kube-hunter probe results | |
| `sc7-kubescape.json` | kubescape network control scan | |
| `sc7-netpol-state.json` | kubectl netpol dump (after) | |
