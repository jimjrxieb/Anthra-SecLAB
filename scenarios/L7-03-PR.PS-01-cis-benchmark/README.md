# L7-03 — PR.PS-01: CIS Benchmark Failures Unremediated

## Scenario Summary

The k3d-seclab cluster was deployed and configured for the Portfolio application
without running a formal CIS Kubernetes Benchmark audit. kube-bench and kubescape
report FAIL and WARN findings across worker node configuration, Pod Security
Standards, network policy posture, and workload security context settings.

This is the most realistic scenario in the lab. Nobody broke anything. Nobody
introduced a vulnerability after the fact. The cluster simply shipped in its
default state, the benchmark was never run, and the findings have been sitting
undetected ever since.

The break.sh script is a no-op. The failures already exist. This scenario teaches
what a CIS audit looks like in practice, how to interpret the output, and how to
move from a list of FAIL findings to a prioritized remediation plan with auditable
evidence.

---

## Control Mapping

| Field             | Value                                                                  |
|-------------------|------------------------------------------------------------------------|
| CSF Function      | PROTECT                                                                |
| CSF Category      | PR.PS — Platform Security                                              |
| CSF Subcategory   | PR.PS-01 — Configuration management practices applied to IT assets    |
| CIS v8 Control    | 4.1 — Establish and Maintain a Secure Configuration Process            |
| NIST 800-53       | CM-6 — Configuration Settings, CM-7 — Least Functionality             |
| OSI Layer         | Layer 7 — Application (cluster configuration layer)                   |
| Severity          | Medium to High (depends on which findings are present)                 |
| Rank              | C — Analyst proposes, human approves (configuration changes)           |
| Difficulty        | Level 1                                                                |

---

## Why This Scenario Exists

Enterprise Kubernetes clusters routinely fail CIS benchmarks. Not because
engineers are careless, but because:

1. The benchmark has not been run since initial deployment
2. The team responsible for operations is not the team that owns security
3. kube-bench output is long and intimidating — nobody prioritized reading it
4. Some findings look like noise until an auditor flags them as gaps

In a FedRAMP Moderate engagement, CM-6 requires that configuration settings
for information technology products be established and documented. CM-7 requires
that the system be configured to provide only essential capabilities. Unremediated
benchmark failures are direct gaps in both controls.

This scenario gives a Level 1 analyst the tools to run the audit, interpret the
output, and produce evidence that an assessor can use.

---

## What break.sh Does

Nothing. The vulnerability is the default state.

Running kube-bench against a standard k3s deployment will surface real findings.
Running kubescape will produce a compliance score below 100%. These findings
are the scenario. There is no artificial injection needed.

---

## Affected Assets

- **Cluster:** k3d-seclab (k3s v1.31)
- **Namespace:** anthra
- **Deployments:** portfolio-anthra-portfolio-app-api, portfolio-anthra-portfolio-app-ui,
  portfolio-anthra-portfolio-app-chroma
- **Tools:** kube-bench at `/usr/local/bin/kube-bench`, kubescape at `/home/jimmie/bin/kubescape`

---

## Scenario Lifecycle

| Phase       | File                 | What Happens                                             |
|-------------|----------------------|----------------------------------------------------------|
| Baseline    | `baseline.sh`        | Run kube-bench and kubescape, save PASS/FAIL/WARN counts |
| Break       | `break.sh`           | No-op — failures already exist in the default cluster    |
| Detect      | `detect.md`          | L1 analyst runs audit tools and reads the output         |
| Investigate | `investigate.md`     | Prioritize findings, check compensating controls         |
| Fix         | `fix.sh`             | Remediate the top 5 fixable findings                     |
| Remediate   | `remediate.md`       | Full CIS benchmark structure, POA&M guidance             |
| Verify      | `verify.sh`          | Re-run scans, compare FAIL count before vs after         |
| Report      | `report-template.md` | Auditor-ready evidence template                          |

---

## References

- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes
- NIST 800-53 Rev 5: CM-6 Configuration Settings
- NIST 800-53 Rev 5: CM-7 Least Functionality
- NIST CSF 2.0: PR.PS-01
- kube-bench: https://github.com/aquasecurity/kube-bench
- kubescape: https://github.com/kubescape/kubescape
