# 02a-fix-RA5-vuln-scan.md — Set Up Vulnerability Scanning Pipeline

| Field | Value |
|---|---|
| **NIST Controls** | RA-5 (vulnerability scanning), SA-11 (developer security testing) |
| **Tools** | OWASP ZAP / Trivy / Semgrep / kube-bench CronJob |
| **Fixes** | Missing DAST in CI, no SAST gates, no container scanning, no K8s benchmark schedule |
| **Time** | 1 hour |
| **Rank** | D (add CI steps — no infrastructure changes) |

---

## Purpose

`audit-vuln-scan-coverage.sh` found scanning gaps. This playbook wires scanning tools into CI/CD pipelines so vulnerabilities are caught before production. Each fix is a CI pipeline change — low risk, high value.

---

## 1. ZAP Baseline Scan in CI

### GitHub Actions

```yaml
# .github/workflows/security-scan.yml
# Add this job to your existing workflow
# NIST RA-5: automated vulnerability scanning in CI pipeline

name: Security Scans

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    # Run weekly against staging
    - cron: '0 2 * * 1'

jobs:
  zap-dast-scan:
    name: ZAP Baseline DAST Scan
    runs-on: ubuntu-latest
    # Run only if the app is deployed to staging
    # Remove this condition if you have a dedicated test environment
    if: github.ref == 'refs/heads/main'

    steps:
      - uses: actions/checkout@v4

      - name: ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.10.0
        with:
          target: '${{ secrets.STAGING_URL }}'  # Set in repo secrets
          rules_file_name: '.zap/rules.tsv'      # Custom rule config (optional)
          cmd_options: '-a'                       # -a = include alpha passive rules
          fail_action: true                       # Fail PR on High findings

      - name: Upload ZAP Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: zap-baseline-report
          path: report_html.html
```

### GitLab CI

```yaml
# .gitlab-ci.yml additions
# NIST RA-5: DAST scan stage

dast-zap-scan:
  stage: security
  image: ghcr.io/zaproxy/zaproxy:stable
  variables:
    TARGET_URL: $STAGING_URL
  script:
    - mkdir -p /tmp/zap-reports
    - zap-baseline.py
        -t "$TARGET_URL"
        -r /tmp/zap-reports/zap-report.html
        -J /tmp/zap-reports/zap-report.json
        -x /tmp/zap-reports/zap-report.xml
        -a
        --autooff
  artifacts:
    when: always
    paths:
      - /tmp/zap-reports/
    expire_in: 30 days
  only:
    - main
    - merge_requests
```

---

## 2. Trivy Image Scan Gate

### GitHub Actions

```yaml
# Add to .github/workflows/security-scan.yml
  trivy-container-scan:
    name: Trivy Container Vulnerability Scan
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Build container image
        run: docker build -t app:${{ github.sha }} .

      - name: Trivy image scan — fail on HIGH/CRITICAL
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'app:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'HIGH,CRITICAL'
          exit-code: '1'          # NIST RA-5: fail build on unacceptable findings
          ignore-unfixed: true    # Don't fail on vulnerabilities without fixes

      - name: Upload Trivy SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'

  trivy-fs-scan:
    name: Trivy Filesystem Scan (dependencies)
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Trivy filesystem scan — dependencies + configs
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'table'
          severity: 'HIGH,CRITICAL'
          exit-code: '1'
```

---

## 3. Semgrep Pre-Commit and CI Gate

### Pre-Commit Hook

```bash
# Install pre-commit
pip install pre-commit

# Add Semgrep to .pre-commit-config.yaml
cat >> .pre-commit-config.yaml << 'EOF'
# NIST SA-11: SAST in developer workflow — catches issues before commit
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: 'v1.45.0'
    hooks:
      - id: semgrep
        args:
          - '--config'
          - 'p/security-audit'
          - '--error'          # Fail on findings
          - '--strict'         # Strict mode
        language: python
        types: [python, javascript, typescript, go, java]
EOF

# Install hooks
pre-commit install

# Test on all files
pre-commit run --all-files semgrep
```

### GitHub Actions CI Gate

```yaml
# Add to .github/workflows/security-scan.yml
  semgrep-sast:
    name: Semgrep SAST Scan
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/owasp-top-ten
            p/secrets
          # NIST SA-11: developer security testing gate
          # Fail on ERROR level findings only
          generateSarif: "1"

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: semgrep.sarif
```

---

## 4. kube-bench CronJob

Run CIS benchmark on a schedule so regressions are caught:

```bash
# Deploy the kube-bench Job template
kubectl apply -f ../03-templates/kube-bench/job.yaml

# To run on a schedule, use a CronJob
cat << 'EOF' | kubectl apply -f -
apiVersion: batch/v1
kind: CronJob
metadata:
  name: kube-bench-weekly
  namespace: kube-bench
  annotations:
    description: "Weekly CIS Kubernetes Benchmark — NIST CM-6"
spec:
  # Every Monday at 2:00 AM
  schedule: "0 2 * * 1"
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 1
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          hostPID: true
          hostNetwork: true
          securityContext:
            runAsUser: 0
          containers:
            - name: kube-bench
              image: aquasec/kube-bench:v0.7.1
              command: ["kube-bench", "--json"]
              resources:
                requests:
                  cpu: "100m"
                  memory: "128Mi"
              volumeMounts:
                - name: etc-kubernetes
                  mountPath: /etc/kubernetes
                  readOnly: true
                - name: var-lib-kubelet
                  mountPath: /var/lib/kubelet
                  readOnly: true
          volumes:
            - name: etc-kubernetes
              hostPath: {path: "/etc/kubernetes"}
            - name: var-lib-kubelet
              hostPath: {path: "/var/lib/kubelet"}
EOF

# Verify CronJob created
kubectl get cronjob -n kube-bench
```

---

## Verification

After implementing all fixes:

```bash
# Re-run vulnerability scan audit
./01-auditors/audit-vuln-scan-coverage.sh

# Expected improvements:
# - Trivy: found in CI pipeline
# - Semgrep: pre-commit hook installed, CI gate present
# - ZAP: found in CI pipeline (or Docker image present)
# - kube-bench: CronJob scheduled
```

**Next step:** `03-validate.md`
