"""
Anthra Center — Centralized Security Monitoring & Compliance Platform
Multi-tenant FedRAMP Moderate SaaS for federal agencies

Built for speed-to-market by a development team focused on features.
Now needs FedRAMP Moderate hardening to enter federal market.

NIST 800-53 Control Mapping:
- IA-5(1): Password-Based Authentication (bcrypt)
- SC-7(5): Denial of Service (CORS restriction)
- SC-13: Cryptographic Protection (bcrypt)
- SI-11: Error Handling (Minimal error exposure)
- AC-6: Least Privilege (Credential management)
"""

import json
import os
import random
import sqlite3
from datetime import datetime
from typing import Optional

import bcrypt
import psycopg2
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# =============================================================================
# Configuration - Credentials from environment variables (NIST AC-6)
# =============================================================================
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "anthra")
DB_USER = os.getenv("DB_USER", "anthra")
DB_PASSWORD = os.getenv("DB_PASSWORD")

app = FastAPI(
    title="Anthra Center",
    version="2.0.0",
    description="Centralized security monitoring and FedRAMP compliance platform",
)

TRUSTED_ORIGINS = os.getenv("CORS_ORIGINS", "https://anthra.cloud,https://api.anthra.cloud").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=TRUSTED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    print(f"ERROR: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"error": "An internal server error occurred. Please contact support."},
    )


# =============================================================================
# Database
# =============================================================================
def get_db():
    try:
        if not DB_PASSWORD:
            raise Exception("DB_PASSWORD not set")
        return psycopg2.connect(
            host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD,
        )
    except Exception:
        conn = sqlite3.connect("/tmp/anthra.db")
        _init_sqlite(conn)
        return conn


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# =============================================================================
# SSP Control Data — NIST 800-53 Rev 5, FedRAMP Moderate Baseline
# =============================================================================
SSP_CONTROLS = [
    # AC - Access Control
    {"control_id": "AC-1",  "family": "AC", "title": "Policy and Procedures", "status": "Implemented", "description": "Access control policy documented in SSP Section 9. Updated annually."},
    {"control_id": "AC-2",  "family": "AC", "title": "Account Management", "status": "Implemented", "description": "RBAC audit complete. ServiceAccounts dedicated per service. automountServiceAccountToken: false on app pods. Evidence: rbac_audit, kube_bench."},
    {"control_id": "AC-3",  "family": "AC", "title": "Access Enforcement", "status": "Partially Implemented", "description": "Kyverno enforces non-root, drop ALL caps. PSS restricted on anthra namespace. Missing: application-level RBAC middleware. Evidence: kyverno_nonroot, polaris."},
    {"control_id": "AC-6",  "family": "AC", "title": "Least Privilege", "status": "Partially Implemented", "description": "K8s pods run as non-root (UID 10001). Capabilities dropped. PSS restricted enforced. Missing: fine-grained RBAC roles. Evidence: kyverno_drop_caps, rbac_audit."},
    {"control_id": "AC-7",  "family": "AC", "title": "Unsuccessful Logon Attempts", "status": "Not Implemented", "description": "No account lockout after failed attempts. No rate limiting on /api/auth/login."},
    {"control_id": "AC-8",  "family": "AC", "title": "System Use Notification", "status": "Not Implemented", "description": "No login banner or acceptable use notice displayed before authentication."},
    {"control_id": "AC-14", "family": "AC", "title": "Permitted Actions Without Identification", "status": "Not Implemented", "description": "All API endpoints accessible without authentication. No session management."},
    {"control_id": "AC-17", "family": "AC", "title": "Remote Access", "status": "Partially Implemented", "description": "NetworkPolicy default-deny enforced on all namespaces. Service-aware allow rules. Missing: VPN/mTLS between services. Evidence: network_policy_check, conftest."},
    # AU - Audit and Accountability
    {"control_id": "AU-2",  "family": "AU", "title": "Event Logging", "status": "Partially Implemented", "description": "Falco DaemonSet on all nodes captures syscalls + K8s audit. 10 watchers run (apparmor, drift, events, network, pss, seccomp, secrets, supply-chain). Missing: application-level audit events. Evidence: falco, k8s_audit_logs."},
    {"control_id": "AU-3",  "family": "AU", "title": "Content of Audit Records", "status": "Not Implemented", "description": "Falco captures who/what/when for syscalls. Missing: structured audit records with user identity, outcome, originating IP for application events. Evidence: none — gap."},
    {"control_id": "AU-6",  "family": "AU", "title": "Audit Record Review", "status": "Implemented", "description": "Anthra Center dashboard provides real-time log review. Findings feed sorted by severity. NIST control mapping on each finding."},
    {"control_id": "AU-8",  "family": "AU", "title": "Time Stamps", "status": "Implemented", "description": "All events use UTC timestamps via Python datetime.utcnow() and PostgreSQL NOW()."},
    {"control_id": "AU-9",  "family": "AU", "title": "Protection of Audit Information", "status": "Implemented", "description": "RBAC restricts audit log access. Kube-bench validates API server audit settings. Evidence: rbac_audit, kube_bench."},
    {"control_id": "AU-11", "family": "AU", "title": "Audit Record Retention", "status": "Not Implemented", "description": "No log retention policy. Logs lost on pod restart (ephemeral SQLite). FedRAMP requires 1-year online, 3-year archive."},
    {"control_id": "AU-12", "family": "AU", "title": "Audit Record Generation", "status": "Not Implemented", "description": "Falco generates runtime audit events. Missing: application-level audit generation (CRUD operations, auth events). No centralized audit pipeline. Evidence: none — gap."},
    # CA - Security Assessment
    {"control_id": "CA-2",  "family": "CA", "title": "Control Assessments", "status": "Implemented", "description": "Automated scanning via Trivy, Kubescape, Checkov, Semgrep. Results mapped to NIST controls and displayed in Anthra Center."},
    {"control_id": "CA-7",  "family": "CA", "title": "Continuous Monitoring", "status": "Partially Implemented", "description": "CI/CD pipeline runs security scans on push. Missing: scheduled production rescans, drift detection."},
    # CM - Configuration Management
    {"control_id": "CM-2",  "family": "CM", "title": "Baseline Configuration", "status": "Implemented", "description": "Kustomize base/overlays for all services. Images pinned to semver. ArgoCD syncs from git. Checkov: 785 passed, 70 failed. Evidence: kube_bench, checkov, polaris."},
    {"control_id": "CM-3",  "family": "CM", "title": "Configuration Change Control", "status": "Implemented", "description": "ArgoCD GitOps — all changes via git PR. promote-image.sh tracks dev→staging→prod. Git history = audit trail. Evidence: argocd, git log."},
    {"control_id": "CM-6",  "family": "CM", "title": "Configuration Settings", "status": "Partially Implemented", "description": "PSS restricted on app namespaces. Kyverno enforces resource limits, seccomp, non-root. Polaris 81/100. Missing: OS-level CIS hardening. Evidence: kube_bench, kyverno."},
    {"control_id": "CM-7",  "family": "CM", "title": "Least Functionality", "status": "Partially Implemented", "description": "Capabilities dropped, read-only rootfs, non-root. Debug endpoint removed. Missing: 70 Checkov failures (image digest, imagePullPolicy). Evidence: checkov, conftest."},
    {"control_id": "CM-8",  "family": "CM", "title": "System Component Inventory", "status": "Partially Implemented", "description": "Container SBOM generated by Trivy. 4 services tracked. Missing: full asset inventory with owners, classifications. Evidence: trivy_sbom."},
    # CP - Contingency Planning
    {"control_id": "CP-9",  "family": "CP", "title": "System Backup", "status": "Not Implemented", "description": "No automated database backups. No backup verification testing. PostgreSQL data on ephemeral volume."},
    {"control_id": "CP-10", "family": "CP", "title": "System Recovery and Reconstitution", "status": "Partially Implemented", "description": "K8s deployments auto-restart on failure. No documented RTO/RPO. No disaster recovery runbook."},
    # IA - Identification and Authentication
    {"control_id": "IA-2",  "family": "IA", "title": "Identification and Authentication (Org Users)", "status": "Partially Implemented", "description": "Username/password login exists. Missing: MFA (IA-2(1)), network access (IA-2(2))."},
    {"control_id": "IA-4",  "family": "IA", "title": "Identifier Management", "status": "Implemented", "description": "Unique user IDs assigned via auto-increment. Tenant isolation by tenant_id."},
    {"control_id": "IA-5",  "family": "IA", "title": "Authenticator Management", "status": "Partially Implemented", "description": "Passwords hashed with bcrypt (cost 12). Missing: password complexity enforcement, credential rotation policy, MFA tokens."},
    {"control_id": "IA-6",  "family": "IA", "title": "Authentication Feedback", "status": "Implemented", "description": "Generic 'Invalid username or password' message on failed login. No credential exposure in error responses."},
    {"control_id": "IA-8",  "family": "IA", "title": "Identification and Authentication (Non-Org Users)", "status": "Not Implemented", "description": "No federated identity. No PIV/CAC support. Required for federal user access."},
    # IR - Incident Response
    {"control_id": "IR-1",  "family": "IR", "title": "Policy and Procedures", "status": "Not Implemented", "description": "No incident response plan documented. No defined roles, communication channels, or escalation paths."},
    {"control_id": "IR-4",  "family": "IR", "title": "Incident Handling", "status": "Not Implemented", "description": "Falco detects runtime threats. Missing: automated containment, forensic capture, post-incident review, documented IRP. Evidence: none — gap."},
    {"control_id": "IR-5",  "family": "IR", "title": "Incident Monitoring", "status": "Partially Implemented", "description": "Falco on all nodes. 10 watchers report drift, secrets, network, events. Anthra Center aggregates alerts. Missing: 24/7 automated response. Evidence: falco, jsa_infrasec."},
    {"control_id": "IR-6",  "family": "IR", "title": "Incident Reporting", "status": "Not Implemented", "description": "No US-CERT/CISA incident reporting capability. FedRAMP requires reporting within 1 hour for significant incidents."},
    # MP - Media Protection
    {"control_id": "MP-2",  "family": "MP", "title": "Media Access", "status": "Not Implemented", "description": "No media access controls. S3 bucket encryption not enforced (finding: SC-28)."},
    # PE - Physical (inherited from AWS)
    {"control_id": "PE-1",  "family": "PE", "title": "Policy and Procedures", "status": "Inherited", "description": "Physical security controls inherited from AWS GovCloud. AWS FedRAMP High ATO covers PE family."},
    # PL - Planning
    {"control_id": "PL-2",  "family": "PL", "title": "System Security and Privacy Plans", "status": "Partially Implemented", "description": "SSP in progress. Appendix A findings documented. Missing: full SSP narrative, security architecture diagrams."},
    # RA - Risk Assessment
    {"control_id": "RA-3",  "family": "RA", "title": "Risk Assessment", "status": "Implemented", "description": "Automated risk assessment via multi-scanner pipeline. Findings ranked E through S. CVSS scores from NVD."},
    {"control_id": "RA-5",  "family": "RA", "title": "Vulnerability Monitoring and Scanning", "status": "Implemented", "description": "Trivy (CVEs), Semgrep (SAST), Gitleaks (secrets), Kubescape (K8s), Checkov (IaC). CI/CD and on-demand scanning."},
    # SA - System and Services Acquisition
    {"control_id": "SA-3",  "family": "SA", "title": "System Development Life Cycle", "status": "Partially Implemented", "description": "Secure SDLC with pre-commit hooks and CI/CD gates. Missing: formal security requirements in design phase."},
    {"control_id": "SA-4",  "family": "SA", "title": "Acquisition Process", "status": "Partially Implemented", "description": "Open-source dependencies scanned by Trivy/Grype. Missing: vendor security assessment for 3rd-party services."},
    {"control_id": "SA-11", "family": "SA", "title": "Developer Testing and Evaluation", "status": "Implemented", "description": "14 custom Semgrep rules for FedRAMP. 8 pre-commit validators. Security pipeline with 9 jobs runs on every PR."},
    # SC - System and Communications Protection
    {"control_id": "SC-5",  "family": "SC", "title": "Denial of Service Protection", "status": "Implemented", "description": "K8s resource limits + LimitRange + ResourceQuota on all namespaces. Kyverno enforces resource limits on admission. Evidence: kyverno_resource_limits, polaris."},
    {"control_id": "SC-7",  "family": "SC", "title": "Boundary Protection", "status": "Partially Implemented", "description": "NetworkPolicy default-deny on all namespaces. Service-aware allow rules (envoy→ui, envoy→api, api→db, api→ingest). 38 policies total. Missing: WAF, egress filtering. Evidence: network_policy_check."},
    {"control_id": "SC-8",  "family": "SC", "title": "Transmission Confidentiality and Integrity", "status": "Partially Implemented", "description": "Envoy Gateway handles TLS termination. PostgreSQL sslmode=require. Missing: mTLS between services, cert-manager production certs. Evidence: checkov, conftest."},
    {"control_id": "SC-12", "family": "SC", "title": "Cryptographic Key Establishment and Management", "status": "Not Implemented", "description": "No key management system. TLS certificates not yet provisioned. No HSM integration."},
    {"control_id": "SC-13", "family": "SC", "title": "Cryptographic Protection", "status": "Implemented", "description": "bcrypt for passwords (cost 12). PostgreSQL SSL for data in transit. Missing: data at rest encryption for application data."},
    {"control_id": "SC-28", "family": "SC", "title": "Protection of Information at Rest", "status": "Partially Implemented", "description": "K8s secrets base64 encoded (not encrypted). S3 bucket encryption not enforced. EBS encryption not verified."},
    # SI - System and Information Integrity
    {"control_id": "SI-2",  "family": "SI", "title": "Flaw Remediation", "status": "Implemented", "description": "CVE scanning via Trivy on every build. CI/CD blocks on CRITICAL/HIGH. Dependency updates tracked in findings."},
    {"control_id": "SI-3",  "family": "SI", "title": "Malicious Code Protection", "status": "Partially Implemented", "description": "Falcon EDR on cluster nodes. Container image scanning. Missing: runtime file integrity monitoring."},
    {"control_id": "SI-4",  "family": "SI", "title": "System Monitoring", "status": "Implemented", "description": "CrowdStrike Falcon for runtime threat detection. MITRE ATT&CK mapped. Alerts surfaced in Anthra Center dashboard."},
    {"control_id": "SI-5",  "family": "SI", "title": "Security Alerts, Advisories, and Directives", "status": "Partially Implemented", "description": "NVD CVE data consumed via Trivy. Missing: US-CERT advisory integration, BOD compliance tracking."},
    {"control_id": "SI-10", "family": "SI", "title": "Information Input Validation", "status": "Not Implemented", "description": "XSS vulnerability in search (dangerouslySetInnerHTML). No server-side input sanitization on log messages."},
    {"control_id": "SI-11", "family": "SI", "title": "Error Handling", "status": "Implemented", "description": "Global exception handler returns generic errors. Stack traces logged internally only."},
]

POAM_ITEMS = [
    # CRITICAL (3)
    {"id": 1,  "control": "AC-14", "weakness": "All API endpoints accessible without authentication", "severity": "CRITICAL", "scheduled": "2026-03-25", "status": "In Progress", "milestone": "Deploy JWT middleware with RBAC enforcement"},
    {"id": 2,  "control": "IA-5",  "weakness": "14 exposed API keys in findings JSON and secret.yaml (B-rank, human review)", "severity": "CRITICAL", "scheduled": "2026-03-20", "status": "Open", "milestone": "Rotate all exposed keys, migrate to AWS Secrets Manager via ExternalSecrets"},
    {"id": 3,  "control": "IA-2",  "weakness": "No multi-factor authentication for federal users", "severity": "CRITICAL", "scheduled": "2026-03-30", "status": "In Progress", "milestone": "Integrate TOTP/WebAuthn for privileged users, Login.gov for federal SSO"},
    # HIGH (14) — from real gap analysis
    {"id": 4,  "control": "AC-3",  "weakness": "Application-level RBAC middleware not implemented", "severity": "HIGH", "scheduled": "2026-04-01", "status": "Planned", "milestone": "JWT + role-based route guards on all API endpoints"},
    {"id": 5,  "control": "AC-6",  "weakness": "Fine-grained K8s RBAC roles not scoped per service", "severity": "HIGH", "scheduled": "2026-04-01", "status": "In Progress", "milestone": "Dedicated ClusterRoles per agent, remove wildcard permissions"},
    {"id": 6,  "control": "AU-3",  "weakness": "No structured audit records (who/what/when/where/outcome)", "severity": "HIGH", "scheduled": "2026-04-15", "status": "Planned", "milestone": "Implement structured audit logging with user identity, IP, outcome fields"},
    {"id": 7,  "control": "AU-12", "weakness": "No application-level audit record generation", "severity": "HIGH", "scheduled": "2026-04-15", "status": "Planned", "milestone": "Emit audit events for CRUD operations, auth events, privilege changes"},
    {"id": 8,  "control": "CM-6",  "weakness": "70 Checkov failures (image digest, imagePullPolicy, secrets-as-files)", "severity": "HIGH", "scheduled": "2026-04-01", "status": "In Progress", "milestone": "Pin images to digest, set imagePullPolicy:Always, mount secrets as files"},
    {"id": 9,  "control": "CM-7",  "weakness": "70 Checkov IaC failures: image digest pinning (8), SA token mounts (4)", "severity": "HIGH", "scheduled": "2026-04-01", "status": "In Progress", "milestone": "Apply Checkov remediation templates from GP-Copilot fixer-scripts"},
    {"id": 10, "control": "IR-4",  "weakness": "No incident handling capability — no IRP, no containment, no forensics", "severity": "HIGH", "scheduled": "2026-04-15", "status": "Planned", "milestone": "Document IRP with CISA reporting, deploy 03-DEPLOY-RUNTIME responders"},
    {"id": 11, "control": "RA-5",  "weakness": "Trivy image scan not run on production images", "severity": "HIGH", "scheduled": "2026-03-25", "status": "Open", "milestone": "Run Trivy image scan on all 4 Anthra container images, add to CI gate"},
    {"id": 12, "control": "SA-10", "weakness": "No formal security requirements in design phase", "severity": "HIGH", "scheduled": "2026-04-15", "status": "Planned", "milestone": "Add threat modeling to SDLC, document in SSP Section 13"},
    {"id": 13, "control": "SA-11", "weakness": "14 custom Semgrep rules deployed but coverage gaps remain", "severity": "HIGH", "scheduled": "2026-04-01", "status": "In Progress", "milestone": "Expand Semgrep rules to cover Go and React, add to pre-commit hooks"},
    {"id": 14, "control": "SC-7",  "weakness": "No WAF or egress filtering beyond NetworkPolicy", "severity": "HIGH", "scheduled": "2026-04-15", "status": "Planned", "milestone": "Deploy AWS WAF on ALB, add egress NetworkPolicy for external APIs only"},
    {"id": 15, "control": "SC-8",  "weakness": "No mTLS between services, production TLS via cert-manager pending", "severity": "HIGH", "scheduled": "2026-04-01", "status": "In Progress", "milestone": "Deploy cert-manager, enforce TLS 1.2+, evaluate Istio mTLS"},
    {"id": 16, "control": "SC-28", "weakness": "K8s secrets base64 only, S3/EBS encryption not verified", "severity": "HIGH", "scheduled": "2026-04-01", "status": "Planned", "milestone": "Enable EBS encryption, S3 SSE-KMS, ExternalSecrets for K8s"},
    {"id": 17, "control": "SI-2",  "weakness": "CVE scanning CI gate exists but Trivy image scan empty", "severity": "HIGH", "scheduled": "2026-03-25", "status": "Open", "milestone": "Run Trivy image scan, fix CRITICAL/HIGH CVEs, block in CI"},
    # MEDIUM (4)
    {"id": 18, "control": "AC-17", "weakness": "No VPN or mTLS required for API access", "severity": "MEDIUM", "scheduled": "2026-05-01", "status": "Planned", "milestone": "Evaluate VPN gateway or Cloudflare Access for API protection"},
    {"id": 19, "control": "CM-8",  "weakness": "Container SBOM exists but no full asset inventory with owners", "severity": "MEDIUM", "scheduled": "2026-05-01", "status": "Planned", "milestone": "Complete asset inventory in Backstage catalog with ownership and classification"},
    {"id": 20, "control": "IR-5",  "weakness": "Falco monitoring active but no 24/7 automated response", "severity": "MEDIUM", "scheduled": "2026-04-15", "status": "In Progress", "milestone": "Enable jsa-infrasec autonomous agent for E/D rank auto-remediation"},
    {"id": 21, "control": "SI-10", "weakness": "XSS vulnerability in search component (dangerouslySetInnerHTML)", "severity": "MEDIUM", "scheduled": "2026-03-20", "status": "Open", "milestone": "Replace dangerouslySetInnerHTML with DOMPurify sanitized rendering"},
]

# Simulated scan results per vendor type
VENDOR_SCAN_TEMPLATES = {
    "falcon": [
        ("RUNTIME_DETECTION", "HIGH", "Suspicious outbound DNS query", "Container {asset} made DNS query to known malicious domain via DoH.", "container", "Execution", "T1071.004", "Block egress to DoH providers, investigate container", "SI-4", "C"),
        ("RUNTIME_DETECTION", "MEDIUM", "Unusual process execution", "Process /bin/sh spawned by web server in {asset}. Potential webshell.", "container", "Execution", "T1059.004", "Review web server logs, check for uploaded files", "SI-4", "D"),
        ("RUNTIME_DETECTION", "HIGH", "Container escape attempt", "seccomp violation detected in {asset}. Attempted syscall: unshare.", "container", "Privilege Escalation", "T1611", "Verify seccomp profile, patch container runtime", "SI-4", "B"),
    ],
    "trivy": [
        ("VULNERABILITY", "CRITICAL", "CVE-2024-38816: Spring Framework path traversal", "Path traversal via crafted URL in Spring Framework < 6.1.12. CVSS 9.8.", "package", None, None, "Upgrade spring-framework to >= 6.1.12", "SI-2", "D"),
        ("VULNERABILITY", "HIGH", "CVE-2024-45337: golang.org/x/crypto SSH auth bypass", "Authentication bypass in SSH server implementations. CVSS 8.1.", "package", None, None, "Upgrade golang.org/x/crypto to latest", "SI-2", "D"),
        ("VULNERABILITY", "MEDIUM", "CVE-2024-7264: libcurl ASN1 date parser overflow", "Buffer overflow parsing ASN.1 dates. DoS risk. CVSS 6.5.", "package", None, None, "Upgrade curl/libcurl to >= 8.9.0", "SI-2", "E"),
    ],
    "kubescape": [
        ("MISCONFIGURATION", "HIGH", "Container allows privilege escalation", "Container {asset} has allowPrivilegeEscalation not explicitly set to false.", "pod", None, None, "Set securityContext.allowPrivilegeEscalation: false", "AC-6", "D"),
        ("MISCONFIGURATION", "MEDIUM", "Missing pod disruption budget", "Deployment {asset} has no PodDisruptionBudget. Availability risk during node maintenance.", "deployment", None, None, "Create PDB with minAvailable or maxUnavailable", "CP-10", "E"),
        ("MISCONFIGURATION", "HIGH", "Writable root filesystem", "Container {asset} has readOnlyRootFilesystem not set. Attackers can modify binaries.", "pod", None, None, "Set securityContext.readOnlyRootFilesystem: true", "SC-28", "D"),
    ],
    "checkov": [
        ("MISCONFIGURATION", "HIGH", "S3 bucket versioning disabled", "Bucket {asset} has no versioning. Cannot recover from accidental deletion.", "bucket", None, None, "Enable S3 versioning for data protection", "CP-9", "C"),
        ("MISCONFIGURATION", "MEDIUM", "Security group allows unrestricted SSH", "SG {asset} allows 0.0.0.0/0 on port 22. Brute force risk.", "security_group", None, None, "Restrict SSH to bastion host CIDR only", "SC-7", "C"),
        ("MISCONFIGURATION", "HIGH", "IAM policy allows wildcard actions", "IAM policy on {asset} uses Action: '*'. Violates least privilege.", "iam_policy", None, None, "Scope IAM actions to specific required permissions", "AC-6", "C"),
    ],
    "gitleaks": [
        ("SECRET_EXPOSURE", "CRITICAL", "Database password in configuration file", "Plaintext database credential found in {asset}.", "file", None, None, "Remove from source, rotate credential, use Secrets Manager", "IA-5", "B"),
        ("SECRET_EXPOSURE", "HIGH", "Private key committed to repository", "RSA private key detected in {asset}. Key may be compromised.", "file", None, None, "Revoke key, generate new keypair, add to .gitignore", "IA-5", "B"),
    ],
    "semgrep": [
        ("VULNERABILITY", "HIGH", "SQL injection via string formatting", "User input concatenated into SQL query in {asset}. Use parameterized queries.", "file", None, None, "Replace f-string SQL with parameterized query (?)", "SI-10", "D"),
        ("VULNERABILITY", "MEDIUM", "Insecure deserialization", "pickle.loads() called on untrusted data in {asset}.", "file", None, None, "Use json.loads() or validate input before deserialization", "SI-10", "D"),
    ],
}


def _init_sqlite(conn):
    """Initialize SQLite schema for demo mode."""
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vendors'")
    if cur.fetchone():
        return  # Already initialized

    conn.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT, level TEXT, message TEXT, source TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT, severity TEXT, title TEXT, description TEXT,
            source TEXT, nist_control TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT, source TEXT, finding_type TEXT, severity TEXT,
            title TEXT, description TEXT, asset_type TEXT, asset_id TEXT,
            namespace TEXT, cve_id TEXT, mitre_tactic TEXT, mitre_technique TEXT,
            remediation TEXT, nist_control TEXT, rank TEXT,
            status TEXT DEFAULT 'open',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE, password_hash TEXT, email TEXT,
            role TEXT DEFAULT 'viewer', tenant_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # INTENTIONAL SECURITY GAP: Vendor API keys stored in plaintext (IA-5 violation)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vendors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT,
            name TEXT,
            vendor_type TEXT,
            api_endpoint TEXT,
            api_key TEXT,
            status TEXT DEFAULT 'disconnected',
            last_scan TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Seed all demo data
    try:
        admin_pass = hash_password("admin123")
        conn.execute(
            "INSERT INTO users (username, password_hash, email, role, tenant_id) VALUES (?, ?, ?, ?, ?)",
            ("admin", admin_pass, "admin@anthra.io", "admin", "tenant-1"),
        )

        demo_logs = [
            ("tenant-1", "INFO",  "Falcon sensor connected: worker-node-1", "falcon"),
            ("tenant-1", "INFO",  "Falcon sensor connected: worker-node-2", "falcon"),
            ("tenant-1", "WARN",  "Trivy scan: 3 HIGH CVEs found in api:latest", "trivy"),
            ("tenant-1", "ERROR", "Falcon detection: Suspicious process elevation on worker-node-1", "falcon"),
            ("tenant-1", "INFO",  "Kubescape scan completed: 7 controls failed", "kubescape"),
            ("tenant-1", "WARN",  "Checkov: S3 bucket missing encryption", "checkov"),
            ("tenant-1", "INFO",  "Log ingestion pipeline healthy: 1,247 events/min", "ingest"),
            ("tenant-1", "ERROR", "Failed authentication attempt: admin from 203.0.113.5", "auth"),
            ("tenant-1", "WARN",  "Polaris: Pod default/api-server missing resource limits", "polaris"),
            ("tenant-1", "INFO",  "Compliance scan: AC-2 FAIL, AU-2 PASS, SC-7 FAIL", "compliance"),
            ("tenant-2", "INFO",  "Falcon sensor connected: prod-node-1", "falcon"),
            ("tenant-2", "WARN",  "Trivy scan: 1 CRITICAL CVE in postgres:15", "trivy"),
            ("tenant-2", "INFO",  "Kubescape scan completed: 3 controls failed", "kubescape"),
            ("tenant-2", "ERROR", "Falcon detection: Reverse shell attempt on prod-node-1", "falcon"),
            ("tenant-2", "INFO",  "Log ingestion pipeline healthy: 832 events/min", "ingest"),
            ("tenant-3", "INFO",  "Falcon sensor connected: staging-node-1", "falcon"),
            ("tenant-3", "INFO",  "Trivy scan: 0 CRITICAL, 2 MEDIUM CVEs", "trivy"),
            ("tenant-3", "INFO",  "All compliance controls passing", "compliance"),
        ]
        conn.executemany(
            "INSERT INTO logs (tenant_id, level, message, source) VALUES (?, ?, ?, ?)",
            demo_logs,
        )

        demo_findings = [
            ("tenant-1", "falcon",    "RUNTIME_DETECTION",  "CRITICAL", "Suspicious process elevation",           "Process attempted kernel access without authorization on worker-node-1. Behavioral indicator of privilege escalation exploit.", "node", "worker-node-1", None, None, "Privilege Escalation", "T1068", "Isolate node, investigate process tree, patch kernel", "SI-4", "B", "open"),
            ("tenant-1", "falcon",    "RUNTIME_DETECTION",  "HIGH",     "Cryptominer detected",                   "Known cryptomining binary executed in container anthra-api. CPU usage spike to 98%.", "container", "anthra-api", "default", None, "Execution", "T1496", "Kill process, rebuild container from clean image", "SI-4", "C", "open"),
            ("tenant-1", "trivy",     "VULNERABILITY",      "CRITICAL", "CVE-2024-24762: python-multipart RCE",   "Remote code execution via crafted multipart request in python-multipart < 0.0.18. CVSS 9.8.", "package", "python-multipart:0.0.16", "default", "CVE-2024-24762", None, None, "Upgrade python-multipart to >= 0.0.18", "SI-2", "D", "open"),
            ("tenant-1", "trivy",     "VULNERABILITY",      "HIGH",     "CVE-2024-6345: setuptools arbitrary code", "Code execution via malicious package metadata in setuptools < 70.0. CVSS 8.1.", "package", "setuptools:69.0.2", "default", "CVE-2024-6345", None, None, "Upgrade setuptools to >= 70.0.0", "SI-2", "D", "open"),
            ("tenant-1", "trivy",     "VULNERABILITY",      "HIGH",     "CVE-2023-4863: libwebp heap overflow",   "Heap buffer overflow in libwebp via crafted WebP image. CVSS 8.8.", "package", "libwebp:1.2.4", "default", "CVE-2023-4863", None, None, "Upgrade base image with patched libwebp", "SI-2", "D", "open"),
            ("tenant-1", "trivy",     "VULNERABILITY",      "MEDIUM",   "CVE-2024-2511: OpenSSL memory growth",   "Unbounded memory growth processing TLSv1.3 sessions. DoS risk.", "package", "openssl:3.0.1", "default", "CVE-2024-2511", None, None, "Upgrade openssl to >= 3.0.14", "SI-2", "E", "open"),
            ("tenant-1", "kubescape", "MISCONFIGURATION",   "HIGH",     "Pod running as root",                    "Pod default/anthra-api runs as root (UID 0). Violates CIS K8s 5.2.6 and Pod Security Standards restricted profile.", "pod", "anthra-api", "default", None, None, None, "Add runAsNonRoot: true and runAsUser: 10001 to securityContext", "AC-6", "D", "open"),
            ("tenant-1", "kubescape", "MISCONFIGURATION",   "HIGH",     "Container missing resource limits",      "Container anthra-api has no CPU/memory limits. Risk of resource exhaustion affecting co-located workloads.", "pod", "anthra-api", "default", None, None, None, "Set resources.limits.cpu and resources.limits.memory", "SC-5", "D", "open"),
            ("tenant-1", "kubescape", "MISCONFIGURATION",   "HIGH",     "No NetworkPolicy defined",               "Namespace default has no NetworkPolicy. All pod-to-pod traffic unrestricted.", "namespace", "default", "default", None, None, None, "Apply deny-all default NetworkPolicy, allow only required traffic", "SC-7", "C", "open"),
            ("tenant-1", "kubescape", "MISCONFIGURATION",   "MEDIUM",   "Service exposed via NodePort",           "Service anthra-api uses NodePort type, exposing port 30080 on all cluster nodes.", "service", "anthra-api-svc", "default", None, None, None, "Migrate to ClusterIP + Ingress with TLS termination", "SC-7", "C", "open"),
            ("tenant-1", "checkov",   "MISCONFIGURATION",   "HIGH",     "S3 bucket missing server-side encryption", "Bucket anthra-logs-prod has no default encryption. Data at rest is unprotected.", "bucket", "anthra-logs-prod", None, None, None, None, "Enable AES-256 or AWS KMS encryption on bucket", "SC-28", "C", "open"),
            ("tenant-1", "checkov",   "MISCONFIGURATION",   "MEDIUM",   "CloudTrail not logging data events",     "CloudTrail trail anthra-prod only logs management events. S3 data access not audited.", "trail", "anthra-prod", None, None, None, None, "Enable S3 data event logging in CloudTrail", "AU-2", "C", "open"),
            ("tenant-1", "falcon",    "VULNERABILITY",      "HIGH",     "CVE-2024-21626: runc container escape",  "Container escape via leaked file descriptors in runc < 1.1.12. Host filesystem access possible.", "package", "runc:1.1.10", None, "CVE-2024-21626", None, None, "Upgrade runc to >= 1.1.12 on all nodes", "SI-2", "B", "open"),
            ("tenant-1", "gitleaks",  "SECRET_EXPOSURE",    "CRITICAL", "AWS access key in source code",          "AWS Access Key ID AKIA*** found in api/config.py line 14. Key is active.", "file", "api/config.py:14", None, None, None, None, "Rotate key immediately, move to AWS Secrets Manager", "IA-5", "B", "open"),
            ("tenant-1", "semgrep",   "VULNERABILITY",      "HIGH",     "XSS via dangerouslySetInnerHTML",        "User-controlled input rendered via dangerouslySetInnerHTML in ui/src/App.jsx:72. Enables stored XSS.", "file", "ui/src/App.jsx:72", None, None, None, None, "Sanitize input with DOMPurify or use React text rendering", "SI-10", "D", "open"),
            ("tenant-2", "falcon",    "RUNTIME_DETECTION",  "CRITICAL", "Reverse shell connection attempt",       "Outbound connection to 198.51.100.23:4444 from container va-api. Matches known C2 pattern.", "container", "va-api", "va-prod", None, "Command and Control", "T1071", "Isolate pod, block egress IP, forensic analysis", "SI-4", "S", "open"),
            ("tenant-2", "trivy",     "VULNERABILITY",      "CRITICAL", "CVE-2024-32002: git RCE via clone",     "Remote code execution when cloning specially crafted git repositories. CVSS 9.1.", "package", "git:2.39.2", "va-prod", "CVE-2024-32002", None, None, "Upgrade git to >= 2.39.4", "SI-2", "D", "open"),
            ("tenant-2", "kubescape", "MISCONFIGURATION",   "MEDIUM",   "Automount service account token",        "Pod va-api automounts K8s API token. Unnecessary API access if compromised.", "pod", "va-api", "va-prod", None, None, None, "Set automountServiceAccountToken: false", "AC-6", "D", "open"),
            ("tenant-2", "checkov",   "MISCONFIGURATION",   "MEDIUM",   "RDS instance publicly accessible",       "RDS instance va-db has PubliclyAccessible=true. Database exposed to internet.", "rds", "va-db", None, None, None, None, "Set PubliclyAccessible=false, use VPC private subnets", "SC-7", "C", "open"),
            ("tenant-3", "trivy",     "VULNERABILITY",      "MEDIUM",   "CVE-2024-0727: OpenSSL NULL dereference", "NULL pointer dereference processing PKCS12 files. DoS only.", "package", "openssl:3.1.4", "gsa-prod", "CVE-2024-0727", None, None, "Upgrade openssl to >= 3.1.5", "SI-2", "E", "open"),
            ("tenant-3", "kubescape", "MISCONFIGURATION",   "LOW",      "Image using mutable tag",                "Container gsa-api uses tag :v2.1 instead of SHA digest. Image content not guaranteed.", "container", "gsa-api", "gsa-prod", None, None, None, "Pin image to SHA256 digest", "CM-2", "E", "open"),
        ]
        conn.executemany(
            "INSERT INTO findings (tenant_id, source, finding_type, severity, title, description, asset_type, asset_id, namespace, cve_id, mitre_tactic, mitre_technique, remediation, nist_control, rank, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            demo_findings,
        )

        demo_alerts = [
            ("tenant-1", "CRITICAL", "Active privilege escalation detected",    "Falcon detected T1068 on worker-node-1. Immediate investigation required.", "falcon", "SI-4"),
            ("tenant-1", "HIGH",     "14 unpatched CVEs in production",        "Trivy scan found 2 CRITICAL + 3 HIGH + 9 MEDIUM CVEs across production images.", "trivy", "SI-2"),
            ("tenant-1", "HIGH",     "No NetworkPolicy in default namespace",  "All pods can communicate without restriction. Lateral movement risk.", "kubescape", "SC-7"),
            ("tenant-1", "CRITICAL", "AWS access key exposed in source code",  "Active AWS key found in api/config.py. Key rotation required.", "gitleaks", "IA-5"),
            ("tenant-2", "CRITICAL", "Reverse shell attempt blocked",          "Outbound C2 connection from va-api to 198.51.100.23:4444. Pod isolated.", "falcon", "SI-4"),
            ("tenant-2", "HIGH",     "RDS publicly accessible",                "Database va-db exposed to internet. Sensitive data at risk.", "checkov", "SC-7"),
            ("tenant-3", "LOW",      "Minor CVEs in staging",                  "2 MEDIUM CVEs found. No action required for staging environment.", "trivy", "SI-2"),
        ]
        conn.executemany(
            "INSERT INTO alerts (tenant_id, severity, title, description, source, nist_control) VALUES (?, ?, ?, ?, ?, ?)",
            demo_alerts,
        )

        # Pre-configured vendor integrations (credentials in plaintext — INTENTIONAL GAP)
        demo_vendors = [
            ("tenant-1", "CrowdStrike Falcon", "falcon", "https://api.crowdstrike.com", "cs-api-key-7f3a9b2c4d1e8f5a6b0c", "connected", "2026-03-10T14:30:00"),
            ("tenant-1", "Aqua Trivy",         "trivy",  "https://trivy.anthra.internal:8443", "trivy-token-a1b2c3d4e5f6", "connected", "2026-03-10T14:30:00"),
            ("tenant-1", "Kubescape",          "kubescape", "https://kubescape.anthra.internal:8443", "ks-sa-token-x9y8z7", "connected", "2026-03-10T14:30:00"),
            ("tenant-1", "Checkov",            "checkov", "https://checkov.anthra.internal:8443", "checkov-api-key-m4n5o6", "connected", "2026-03-10T14:00:00"),
            ("tenant-1", "Gitleaks",           "gitleaks", "https://github.com/api/v3", "ghp_R3aLt0k3nH3r3N0tF4k3AtA11", "connected", "2026-03-10T13:00:00"),
            ("tenant-1", "Semgrep",            "semgrep", "https://semgrep.anthra.internal:8443", "sg-app-token-q1w2e3r4", "connected", "2026-03-10T13:00:00"),
            ("tenant-2", "CrowdStrike Falcon", "falcon", "https://api.crowdstrike.com", "cs-va-key-8d2f1a9c3b7e", "connected", "2026-03-10T12:00:00"),
            ("tenant-2", "Aqua Trivy",         "trivy",  "https://trivy.va-prod.internal:8443", "trivy-va-tok-j5k6l7", "connected", "2026-03-10T12:00:00"),
        ]
        conn.executemany(
            "INSERT INTO vendors (tenant_id, name, vendor_type, api_endpoint, api_key, status, last_scan) VALUES (?, ?, ?, ?, ?, ?, ?)",
            demo_vendors,
        )

        conn.commit()
    except Exception:
        pass


# =============================================================================
# Models
# =============================================================================
class LoginRequest(BaseModel):
    username: str
    password: str


class AlertRequest(BaseModel):
    tenant_id: str
    severity: str
    title: str
    description: str


class LogRequest(BaseModel):
    tenant_id: str
    level: str
    message: str
    source: str


class VendorRequest(BaseModel):
    tenant_id: str
    name: str
    vendor_type: str
    api_endpoint: str
    api_key: str


# =============================================================================
# Health
# =============================================================================
@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "anthra-center",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat(),
    }


# =============================================================================
# Auth (NIST IA-2)
# =============================================================================
@app.post("/api/auth/login")
async def login(request: LoginRequest):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, email, role, tenant_id, password_hash FROM users WHERE username = ?",
        (request.username,),
    )
    user_row = cur.fetchone()
    conn.close()

    if user_row:
        user_id, username, email, role, tenant_id, stored_hash = user_row
        if verify_password(request.password, stored_hash):
            return {"status": "authenticated", "user_id": user_id, "username": username,
                    "email": email, "role": role, "tenant_id": tenant_id}

    return JSONResponse(status_code=401, content={"error": "Invalid username or password"})


@app.post("/api/auth/register")
async def register(request: Request):
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")
    email = body.get("email", "")
    tenant_id = body.get("tenant_id", "tenant-1")

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, email, tenant_id) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), email, tenant_id),
        )
        conn.commit()
        return {"status": "registered", "username": username}
    except Exception:
        raise HTTPException(status_code=400, detail="Registration failed. Username may already exist.")
    finally:
        conn.close()


# =============================================================================
# Logs (NIST AU-2)
# =============================================================================
@app.get("/api/logs")
async def get_logs(tenant_id: Optional[str] = None, limit: int = 100):
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id is required")
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM logs WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?",
        (tenant_id, min(limit, 1000)),
    )
    rows = cur.fetchall()
    conn.close()
    return {"logs": [{"id": r[0], "tenant_id": r[1], "level": r[2], "message": r[3],
                      "source": r[4], "timestamp": r[5]} for r in rows],
            "count": len(rows)}


@app.post("/api/logs")
async def create_log(log: LogRequest):
    conn = get_db()
    conn.execute(
        "INSERT INTO logs (tenant_id, level, message, source) VALUES (?, ?, ?, ?)",
        (log.tenant_id, log.level, log.message, log.source),
    )
    conn.commit()
    conn.close()
    return {"status": "created", "tenant_id": log.tenant_id}


# =============================================================================
# Alerts
# =============================================================================
@app.get("/api/alerts")
async def get_alerts(tenant_id: Optional[str] = None):
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id is required")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM alerts WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,))
    rows = cur.fetchall()
    conn.close()
    return {"alerts": [{"id": r[0], "tenant_id": r[1], "severity": r[2], "title": r[3],
                        "description": r[4], "source": r[5], "nist_control": r[6],
                        "created_at": r[7]} for r in rows],
            "count": len(rows)}


@app.post("/api/alerts")
async def create_alert(alert: AlertRequest):
    conn = get_db()
    conn.execute(
        "INSERT INTO alerts (tenant_id, severity, title, description) VALUES (?, ?, ?, ?)",
        (alert.tenant_id, alert.severity, alert.title, alert.description),
    )
    conn.commit()
    conn.close()
    return {"status": "created"}


# =============================================================================
# Findings (NIST SI-2, SI-4)
# =============================================================================
@app.get("/api/findings")
async def get_findings(tenant_id: Optional[str] = None, severity: Optional[str] = None,
                       source: Optional[str] = None, nist_control: Optional[str] = None):
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id is required")
    conn = get_db()
    cur = conn.cursor()
    query = "SELECT * FROM findings WHERE tenant_id = ?"
    params = [tenant_id]
    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())
    if source:
        query += " AND source = ?"
        params.append(source)
    if nist_control:
        query += " AND nist_control = ?"
        params.append(nist_control)
    query += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, created_at DESC"
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return {"findings": [{"id": r[0], "tenant_id": r[1], "source": r[2], "finding_type": r[3],
                          "severity": r[4], "title": r[5], "description": r[6], "asset_type": r[7],
                          "asset_id": r[8], "namespace": r[9], "cve_id": r[10], "mitre_tactic": r[11],
                          "mitre_technique": r[12], "remediation": r[13], "nist_control": r[14],
                          "rank": r[15], "status": r[16], "created_at": r[17]} for r in rows],
            "count": len(rows)}


# =============================================================================
# Vendor Integrations — INTENTIONAL SECURITY GAP: plaintext API keys (IA-5)
# =============================================================================
@app.get("/api/vendors")
async def get_vendors(tenant_id: Optional[str] = None):
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id is required")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM vendors WHERE tenant_id = ? ORDER BY created_at DESC", (tenant_id,))
    rows = cur.fetchall()
    conn.close()
    # INTENTIONAL: API keys returned in plaintext — no masking
    return {"vendors": [{"id": r[0], "tenant_id": r[1], "name": r[2], "vendor_type": r[3],
                         "api_endpoint": r[4], "api_key": r[5], "status": r[6],
                         "last_scan": r[7], "created_at": r[8]} for r in rows],
            "count": len(rows)}


@app.post("/api/vendors")
async def add_vendor(vendor: VendorRequest):
    conn = get_db()
    # INTENTIONAL: Stores API key in plaintext (IA-5 violation)
    conn.execute(
        "INSERT INTO vendors (tenant_id, name, vendor_type, api_endpoint, api_key, status) VALUES (?, ?, ?, ?, ?, ?)",
        (vendor.tenant_id, vendor.name, vendor.vendor_type, vendor.api_endpoint, vendor.api_key, "disconnected"),
    )
    conn.commit()
    conn.close()
    return {"status": "created", "name": vendor.name}


@app.post("/api/vendors/{vendor_id}/connect")
async def connect_vendor(vendor_id: int):
    conn = get_db()
    conn.execute("UPDATE vendors SET status = 'connected' WHERE id = ?", (vendor_id,))
    conn.commit()
    conn.close()
    return {"status": "connected", "vendor_id": vendor_id}


@app.post("/api/vendors/{vendor_id}/scan")
async def trigger_vendor_scan(vendor_id: int):
    """Simulate a vendor scan — generates realistic findings."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT tenant_id, name, vendor_type FROM vendors WHERE id = ?", (vendor_id,))
    vendor = cur.fetchone()
    if not vendor:
        conn.close()
        raise HTTPException(status_code=404, detail="Vendor not found")

    tenant_id, vendor_name, vendor_type = vendor
    templates = VENDOR_SCAN_TEMPLATES.get(vendor_type, [])
    if not templates:
        conn.close()
        return {"status": "no_templates", "message": f"No scan templates for {vendor_type}"}

    # Pick 1-3 random findings from templates
    selected = random.sample(templates, min(len(templates), random.randint(1, 3)))
    generated = []
    assets = ["anthra-api", "anthra-worker", "anthra-ingest", "va-api", "gsa-api",
              "prod-node-1", "staging-node-1", "anthra-logs-prod", "sg-0a1b2c3d"]

    for tmpl in selected:
        finding_type, severity, title, desc, asset_type, tactic, technique, remediation, nist, rank = tmpl
        asset = random.choice(assets)
        cve_id = None
        if "CVE-" in title:
            cve_id = title.split(":")[0]

        conn.execute(
            "INSERT INTO findings (tenant_id, source, finding_type, severity, title, description, asset_type, asset_id, namespace, cve_id, mitre_tactic, mitre_technique, remediation, nist_control, rank, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (tenant_id, vendor_type, finding_type, severity, title,
             desc.replace("{asset}", asset), asset_type, asset, "default",
             cve_id, tactic, technique, remediation, nist, rank, "open"),
        )
        generated.append({"severity": severity, "title": title})

        # Also create a log entry for the scan
        conn.execute(
            "INSERT INTO logs (tenant_id, level, message, source) VALUES (?, ?, ?, ?)",
            (tenant_id, "WARN" if severity in ("CRITICAL", "HIGH") else "INFO",
             f"{vendor_name} scan: {title}", vendor_type),
        )

    # Update last_scan timestamp
    conn.execute(
        "UPDATE vendors SET last_scan = ?, status = 'connected' WHERE id = ?",
        (datetime.utcnow().isoformat(), vendor_id),
    )
    conn.commit()
    conn.close()

    return {"status": "scan_complete", "vendor": vendor_name, "findings_generated": len(generated),
            "findings": generated}


@app.delete("/api/vendors/{vendor_id}")
async def delete_vendor(vendor_id: int):
    conn = get_db()
    conn.execute("DELETE FROM vendors WHERE id = ?", (vendor_id,))
    conn.commit()
    conn.close()
    return {"status": "deleted", "vendor_id": vendor_id}


# =============================================================================
# SSP & Compliance (NIST CA-2, PL-2)
# =============================================================================
@app.get("/api/ssp")
async def get_ssp():
    """Return System Security Plan overview and control implementation details."""
    return {
        "system_name": "Anthra Security Platform (NovaSec Cloud)",
        "csp": "Anthra Security Inc.",
        "authorization_level": "FedRAMP Moderate",
        "nist_revision": "NIST 800-53 Rev 5",
        "total_controls": len(SSP_CONTROLS),
        "authorization_boundary": "AWS GovCloud (us-gov-west-1) — EKS cluster, RDS PostgreSQL, S3, CloudWatch",
        "last_updated": "2026-03-16",
        "assessor": "Ghost Protocol (LinkOps Industries)",
        "3pao": "Pending Selection",
        "ato_status": "In Progress — Pre-Assessment",
        "controls": SSP_CONTROLS,
    }


@app.get("/api/ssp/families")
async def get_control_families(tenant_id: Optional[str] = None):
    """Control family summary with findings cross-reference."""
    # Build family summaries from SSP data
    families = {}
    for ctrl in SSP_CONTROLS:
        fam = ctrl["family"]
        if fam not in families:
            families[fam] = {"family": fam, "controls": [], "implemented": 0, "partial": 0,
                             "not_implemented": 0, "inherited": 0, "findings": 0}
        families[fam]["controls"].append(ctrl)
        if ctrl["status"] == "Implemented":
            families[fam]["implemented"] += 1
        elif ctrl["status"] == "Partially Implemented":
            families[fam]["partial"] += 1
        elif ctrl["status"] == "Inherited":
            families[fam]["inherited"] += 1
        else:
            families[fam]["not_implemented"] += 1

    # Cross-reference with live findings
    if tenant_id:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT nist_control, COUNT(*) FROM findings WHERE tenant_id = ? AND status = 'open' GROUP BY nist_control",
            (tenant_id,),
        )
        finding_counts = dict(cur.fetchall())
        conn.close()

        for fam_data in families.values():
            for ctrl in fam_data["controls"]:
                ctrl_findings = finding_counts.get(ctrl["control_id"], 0)
                # Also match family prefix (e.g., findings tagged "SI-2" match SI family)
                ctrl["open_findings"] = ctrl_findings
                fam_data["findings"] += ctrl_findings

    FAMILY_NAMES = {
        "AC": "Access Control", "AU": "Audit and Accountability", "AT": "Awareness and Training",
        "CA": "Security Assessment and Authorization", "CM": "Configuration Management",
        "CP": "Contingency Planning", "IA": "Identification and Authentication",
        "IR": "Incident Response", "MA": "Maintenance", "MP": "Media Protection",
        "PE": "Physical and Environmental Protection", "PL": "Planning",
        "PM": "Program Management", "PS": "Personnel Security", "RA": "Risk Assessment",
        "SA": "System and Services Acquisition", "SC": "System and Communications Protection",
        "SI": "System and Information Integrity",
    }

    result = []
    for fam_id, fam_data in sorted(families.items()):
        total = len(fam_data["controls"])
        result.append({
            "family": fam_id,
            "name": FAMILY_NAMES.get(fam_id, fam_id),
            "total_controls": total,
            "implemented": fam_data["implemented"],
            "partial": fam_data["partial"],
            "not_implemented": fam_data["not_implemented"],
            "inherited": fam_data["inherited"],
            "open_findings": fam_data["findings"],
            "compliance_pct": round(((fam_data["implemented"] + fam_data["inherited"]) / total * 100) if total else 0),
            "controls": fam_data["controls"],
        })

    return {"families": result, "total_families": len(result)}


@app.get("/api/ssp/poam")
async def get_poam():
    """Plan of Action & Milestones — required FedRAMP artifact."""
    return {
        "title": "POA&M — Anthra Security Platform",
        "system": "Anthra Center",
        "last_updated": "2026-03-10",
        "items": POAM_ITEMS,
        "summary": {
            "total": len(POAM_ITEMS),
            "open": sum(1 for i in POAM_ITEMS if i["status"] == "Open"),
            "in_progress": sum(1 for i in POAM_ITEMS if i["status"] == "In Progress"),
            "planned": sum(1 for i in POAM_ITEMS if i["status"] == "Planned"),
            "critical": sum(1 for i in POAM_ITEMS if i["severity"] == "CRITICAL"),
            "high": sum(1 for i in POAM_ITEMS if i["severity"] == "HIGH"),
        },
    }


# =============================================================================
# Search (INTENTIONAL XSS)
# =============================================================================
@app.get("/api/search")
async def search_logs(q: str = "", tenant_id: Optional[str] = None):
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id is required")
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM logs WHERE tenant_id = ? AND message LIKE ? LIMIT 100",
        (tenant_id, f"%{q}%"),
    )
    rows = cur.fetchall()
    conn.close()
    return {"results": [{"id": r[0], "tenant_id": r[1], "level": r[2], "message": r[3],
                         "source": r[4], "timestamp": r[5]} for r in rows],
            "query": q, "count": len(rows)}


# =============================================================================
# Stats
# =============================================================================
@app.get("/api/stats")
async def get_stats(tenant_id: Optional[str] = None):
    conn = get_db()
    cur = conn.cursor()

    def count_query(table, extra=""):
        q = f"SELECT COUNT(*) FROM {table}"
        if tenant_id:
            q += f" WHERE tenant_id = ?"
            if extra:
                q += f" AND {extra}"
            cur.execute(q, (tenant_id,))
        else:
            if extra:
                q += f" WHERE {extra}"
            cur.execute(q)
        return cur.fetchone()[0]

    log_count = count_query("logs")
    alert_count = count_query("alerts")
    open_findings = count_query("findings", "status = 'open'")

    cur.execute("SELECT COUNT(DISTINCT tenant_id) FROM logs")
    tenant_count = cur.fetchone()[0]

    sev_q = "SELECT severity, COUNT(*) FROM findings"
    src_q = "SELECT source, COUNT(*) FROM findings"
    if tenant_id:
        cur.execute(sev_q + " WHERE tenant_id = ? GROUP BY severity", (tenant_id,))
    else:
        cur.execute(sev_q + " GROUP BY severity")
    severity_counts = dict(cur.fetchall())

    if tenant_id:
        cur.execute(src_q + " WHERE tenant_id = ? GROUP BY source", (tenant_id,))
    else:
        cur.execute(src_q + " GROUP BY source")
    source_counts = dict(cur.fetchall())

    # Vendor count
    if tenant_id:
        cur.execute("SELECT COUNT(*) FROM vendors WHERE tenant_id = ? AND status = 'connected'", (tenant_id,))
    else:
        cur.execute("SELECT COUNT(*) FROM vendors WHERE status = 'connected'")
    vendor_count = cur.fetchone()[0]

    conn.close()

    # SSP compliance summary
    implemented = sum(1 for c in SSP_CONTROLS if c["status"] == "Implemented")
    partial = sum(1 for c in SSP_CONTROLS if c["status"] == "Partially Implemented")
    not_impl = sum(1 for c in SSP_CONTROLS if c["status"] == "Not Implemented")
    inherited = sum(1 for c in SSP_CONTROLS if c["status"] == "Inherited")

    return {
        "total_logs": log_count,
        "total_alerts": alert_count,
        "active_tenants": tenant_count,
        "open_findings": open_findings,
        "connected_vendors": vendor_count,
        "findings_by_severity": {
            "CRITICAL": severity_counts.get("CRITICAL", 0),
            "HIGH": severity_counts.get("HIGH", 0),
            "MEDIUM": severity_counts.get("MEDIUM", 0),
            "LOW": severity_counts.get("LOW", 0),
        },
        "findings_by_source": source_counts,
        "compliance": {
            "total_controls": len(SSP_CONTROLS),
            "implemented": implemented,
            "partial": partial,
            "not_implemented": not_impl,
            "inherited": inherited,
            "compliance_pct": round((implemented + inherited) / len(SSP_CONTROLS) * 100),
        },
        "poam_summary": {
            "total": len(POAM_ITEMS),
            "open": sum(1 for i in POAM_ITEMS if i["status"] == "Open"),
            "in_progress": sum(1 for i in POAM_ITEMS if i["status"] == "In Progress"),
        },
    }
