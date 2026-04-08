-- Anthra Center database schema
-- Multi-tenant security monitoring and log aggregation

CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    tenant_id TEXT,
    level TEXT,
    message TEXT,
    source TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    tenant_id TEXT,
    severity TEXT,
    title TEXT,
    description TEXT,
    source TEXT,
    nist_control TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    tenant_id TEXT,
    source TEXT,
    finding_type TEXT,
    severity TEXT,
    title TEXT,
    description TEXT,
    asset_type TEXT,
    asset_id TEXT,
    namespace TEXT,
    cve_id TEXT,
    mitre_tactic TEXT,
    mitre_technique TEXT,
    remediation TEXT,
    nist_control TEXT,
    rank TEXT,
    status TEXT DEFAULT 'open',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT DEFAULT 'viewer'
);

-- Seed users (MD5 password - intentional security gap for demo)
INSERT INTO users (username, password_hash, role)
VALUES ('admin', md5('admin123'), 'admin')
ON CONFLICT (username) DO NOTHING;

-- Seed logs (realistic multi-source operational logs)
INSERT INTO logs (tenant_id, level, message, source, created_at) VALUES
    ('tenant-1', 'INFO',  'Falcon sensor connected: worker-node-1',              'falcon',     NOW() - INTERVAL '4 hours'),
    ('tenant-1', 'INFO',  'Falcon sensor connected: worker-node-2',              'falcon',     NOW() - INTERVAL '4 hours'),
    ('tenant-1', 'WARN',  'Trivy scan: 3 HIGH CVEs found in api:latest',         'trivy',      NOW() - INTERVAL '3 hours'),
    ('tenant-1', 'ERROR', 'Falcon detection: Suspicious process elevation on worker-node-1', 'falcon', NOW() - INTERVAL '2 hours'),
    ('tenant-1', 'INFO',  'Kubescape scan completed: 7 controls failed',         'kubescape',  NOW() - INTERVAL '2 hours'),
    ('tenant-1', 'WARN',  'Checkov: S3 bucket missing encryption',               'checkov',    NOW() - INTERVAL '90 minutes'),
    ('tenant-1', 'INFO',  'Log ingestion pipeline healthy: 1,247 events/min',    'ingest',     NOW() - INTERVAL '1 hour'),
    ('tenant-1', 'ERROR', 'Failed authentication attempt: admin from 203.0.113.5', 'auth',     NOW() - INTERVAL '45 minutes'),
    ('tenant-1', 'WARN',  'Polaris: Pod default/api-server missing resource limits', 'polaris', NOW() - INTERVAL '30 minutes'),
    ('tenant-1', 'INFO',  'Compliance scan: AC-2 FAIL, AU-2 PASS, SC-7 FAIL',   'compliance', NOW() - INTERVAL '15 minutes'),
    ('tenant-2', 'INFO',  'Falcon sensor connected: prod-node-1',                'falcon',     NOW() - INTERVAL '3 hours'),
    ('tenant-2', 'WARN',  'Trivy scan: 1 CRITICAL CVE in postgres:15',           'trivy',      NOW() - INTERVAL '2 hours'),
    ('tenant-2', 'INFO',  'Kubescape scan completed: 3 controls failed',         'kubescape',  NOW() - INTERVAL '1 hour'),
    ('tenant-2', 'ERROR', 'Falcon detection: Reverse shell attempt on prod-node-1', 'falcon',  NOW() - INTERVAL '30 minutes'),
    ('tenant-2', 'INFO',  'Log ingestion pipeline healthy: 832 events/min',      'ingest',     NOW() - INTERVAL '10 minutes'),
    ('tenant-3', 'INFO',  'Falcon sensor connected: staging-node-1',             'falcon',     NOW() - INTERVAL '5 hours'),
    ('tenant-3', 'INFO',  'Trivy scan: 0 CRITICAL, 2 MEDIUM CVEs',              'trivy',      NOW() - INTERVAL '4 hours'),
    ('tenant-3', 'INFO',  'All compliance controls passing',                     'compliance', NOW() - INTERVAL '1 hour');

-- Seed findings (normalized GPFinding format from vendor integrations)
-- tenant-1: DHS - active threats + CVEs + misconfigs
INSERT INTO findings (tenant_id, source, finding_type, severity, title, description, asset_type, asset_id, namespace, cve_id, mitre_tactic, mitre_technique, remediation, nist_control, rank, status) VALUES
    ('tenant-1', 'falcon',    'RUNTIME_DETECTION',  'CRITICAL', 'Suspicious process elevation',           'Process attempted kernel access without authorization on worker-node-1. Behavioral indicator of privilege escalation exploit.', 'node', 'worker-node-1', NULL, NULL, 'Privilege Escalation', 'T1068', 'Isolate node, investigate process tree, patch kernel', 'SI-4', 'B', 'open'),
    ('tenant-1', 'falcon',    'RUNTIME_DETECTION',  'HIGH',     'Cryptominer detected',                   'Known cryptomining binary executed in container anthra-api. CPU usage spike to 98%.', 'container', 'anthra-api', 'default', NULL, 'Execution', 'T1496', 'Kill process, rebuild container from clean image', 'SI-4', 'C', 'open'),
    ('tenant-1', 'trivy',     'VULNERABILITY',      'CRITICAL', 'CVE-2024-24762: python-multipart RCE',   'Remote code execution via crafted multipart request in python-multipart < 0.0.18. CVSS 9.8.', 'package', 'python-multipart:0.0.16', 'default', 'CVE-2024-24762', NULL, NULL, 'Upgrade python-multipart to >= 0.0.18', 'SI-2', 'D', 'open'),
    ('tenant-1', 'trivy',     'VULNERABILITY',      'HIGH',     'CVE-2024-6345: setuptools arbitrary code', 'Code execution via malicious package metadata in setuptools < 70.0. CVSS 8.1.', 'package', 'setuptools:69.0.2', 'default', 'CVE-2024-6345', NULL, NULL, 'Upgrade setuptools to >= 70.0.0', 'SI-2', 'D', 'open'),
    ('tenant-1', 'trivy',     'VULNERABILITY',      'HIGH',     'CVE-2023-4863: libwebp heap overflow',   'Heap buffer overflow in libwebp via crafted WebP image. CVSS 8.8.', 'package', 'libwebp:1.2.4', 'default', 'CVE-2023-4863', NULL, NULL, 'Upgrade base image with patched libwebp', 'SI-2', 'D', 'open'),
    ('tenant-1', 'trivy',     'VULNERABILITY',      'MEDIUM',   'CVE-2024-2511: OpenSSL memory growth',   'Unbounded memory growth processing TLSv1.3 sessions. DoS risk.', 'package', 'openssl:3.0.1', 'default', 'CVE-2024-2511', NULL, NULL, 'Upgrade openssl to >= 3.0.14', 'SI-2', 'E', 'open'),
    ('tenant-1', 'kubescape', 'MISCONFIGURATION',   'HIGH',     'Pod running as root',                    'Pod default/anthra-api runs as root (UID 0). Violates CIS K8s 5.2.6 and Pod Security Standards restricted profile.', 'pod', 'anthra-api', 'default', NULL, NULL, NULL, 'Add runAsNonRoot: true and runAsUser: 10001 to securityContext', 'AC-6', 'D', 'open'),
    ('tenant-1', 'kubescape', 'MISCONFIGURATION',   'HIGH',     'Container missing resource limits',      'Container anthra-api has no CPU/memory limits. Risk of resource exhaustion affecting co-located workloads.', 'pod', 'anthra-api', 'default', NULL, NULL, NULL, 'Set resources.limits.cpu and resources.limits.memory', 'SC-5', 'D', 'open'),
    ('tenant-1', 'kubescape', 'MISCONFIGURATION',   'HIGH',     'No NetworkPolicy defined',               'Namespace default has no NetworkPolicy. All pod-to-pod traffic unrestricted.', 'namespace', 'default', 'default', NULL, NULL, NULL, 'Apply deny-all default NetworkPolicy, allow only required traffic', 'SC-7', 'C', 'open'),
    ('tenant-1', 'kubescape', 'MISCONFIGURATION',   'MEDIUM',   'Service exposed via NodePort',           'Service anthra-api uses NodePort type, exposing port 30080 on all cluster nodes.', 'service', 'anthra-api-svc', 'default', NULL, NULL, NULL, 'Migrate to ClusterIP + Ingress with TLS termination', 'SC-7', 'C', 'open'),
    ('tenant-1', 'checkov',   'MISCONFIGURATION',   'HIGH',     'S3 bucket missing server-side encryption', 'Bucket anthra-logs-prod has no default encryption. Data at rest is unprotected.', 'bucket', 'anthra-logs-prod', NULL, NULL, NULL, NULL, 'Enable AES-256 or AWS KMS encryption on bucket', 'SC-28', 'C', 'open'),
    ('tenant-1', 'checkov',   'MISCONFIGURATION',   'MEDIUM',   'CloudTrail not logging data events',     'CloudTrail trail anthra-prod only logs management events. S3 data access not audited.', 'trail', 'anthra-prod', NULL, NULL, NULL, NULL, 'Enable S3 data event logging in CloudTrail', 'AU-2', 'C', 'open'),
    ('tenant-1', 'falcon',    'VULNERABILITY',      'HIGH',     'CVE-2024-21626: runc container escape',  'Container escape via leaked file descriptors in runc < 1.1.12. Host filesystem access possible.', 'package', 'runc:1.1.10', NULL, 'CVE-2024-21626', NULL, NULL, 'Upgrade runc to >= 1.1.12 on all nodes', 'SI-2', 'B', 'open'),
    ('tenant-1', 'gitleaks',  'SECRET_EXPOSURE',    'CRITICAL', 'AWS access key in source code',          'AWS Access Key ID AKIA*** found in api/config.py line 14. Key is active.', 'file', 'api/config.py:14', NULL, NULL, NULL, NULL, 'Rotate key immediately, move to AWS Secrets Manager', 'IA-5', 'B', 'open'),
    ('tenant-1', 'semgrep',   'VULNERABILITY',      'HIGH',     'XSS via dangerouslySetInnerHTML',        'User-controlled input rendered via dangerouslySetInnerHTML in ui/src/App.jsx. Enables stored XSS.', 'file', 'ui/src/App.jsx:72', NULL, NULL, NULL, NULL, 'Sanitize input with DOMPurify or use React text rendering', 'SI-10', 'D', 'open'),

-- tenant-2: VA - fewer issues, mostly CVEs
    ('tenant-2', 'falcon',    'RUNTIME_DETECTION',  'CRITICAL', 'Reverse shell connection attempt',       'Outbound connection to 198.51.100.23:4444 from container va-api. Matches known C2 pattern.', 'container', 'va-api', 'va-prod', NULL, 'Command and Control', 'T1071', 'Isolate pod, block egress IP, forensic analysis', 'SI-4', 'S', 'open'),
    ('tenant-2', 'trivy',     'VULNERABILITY',      'CRITICAL', 'CVE-2024-32002: git RCE via clone',     'Remote code execution when cloning specially crafted git repositories. CVSS 9.1.', 'package', 'git:2.39.2', 'va-prod', 'CVE-2024-32002', NULL, NULL, 'Upgrade git to >= 2.39.4', 'SI-2', 'D', 'open'),
    ('tenant-2', 'kubescape', 'MISCONFIGURATION',   'MEDIUM',   'Automount service account token',        'Pod va-api automounts K8s API token. Unnecessary API access if compromised.', 'pod', 'va-api', 'va-prod', NULL, NULL, NULL, 'Set automountServiceAccountToken: false', 'AC-6', 'D', 'open'),
    ('tenant-2', 'checkov',   'MISCONFIGURATION',   'MEDIUM',   'RDS instance publicly accessible',       'RDS instance va-db has PubliclyAccessible=true. Database exposed to internet.', 'rds', 'va-db', NULL, NULL, NULL, NULL, 'Set PubliclyAccessible=false, use VPC private subnets', 'SC-7', 'C', 'open'),

-- tenant-3: GSA - mostly clean, low severity
    ('tenant-3', 'trivy',     'VULNERABILITY',      'MEDIUM',   'CVE-2024-0727: OpenSSL NULL dereference', 'NULL pointer dereference processing PKCS12 files. DoS only.', 'package', 'openssl:3.1.4', 'gsa-prod', 'CVE-2024-0727', NULL, NULL, 'Upgrade openssl to >= 3.1.5', 'SI-2', 'E', 'open'),
    ('tenant-3', 'kubescape', 'MISCONFIGURATION',   'LOW',      'Image using mutable tag',                'Container gsa-api uses tag :v2.1 instead of SHA digest. Image content not guaranteed.', 'container', 'gsa-api', 'gsa-prod', NULL, NULL, NULL, 'Pin image to SHA256 digest', 'CM-2', 'E', 'open');

-- Seed alerts (compliance-relevant alerts)
INSERT INTO alerts (tenant_id, severity, title, description, source, nist_control, created_at) VALUES
    ('tenant-1', 'CRITICAL', 'Active privilege escalation detected',    'Falcon detected T1068 on worker-node-1. Immediate investigation required.',                    'falcon',     'SI-4',  NOW() - INTERVAL '2 hours'),
    ('tenant-1', 'HIGH',     '14 unpatched CVEs in production',        'Trivy scan found 2 CRITICAL + 3 HIGH + 9 MEDIUM CVEs across production images.',               'trivy',      'SI-2',  NOW() - INTERVAL '3 hours'),
    ('tenant-1', 'HIGH',     'No NetworkPolicy in default namespace',  'All pods can communicate without restriction. Lateral movement risk.',                          'kubescape',  'SC-7',  NOW() - INTERVAL '2 hours'),
    ('tenant-1', 'CRITICAL', 'AWS access key exposed in source code',  'Active AWS key found in api/config.py. Key rotation required.',                                 'gitleaks',   'IA-5',  NOW() - INTERVAL '1 hour'),
    ('tenant-2', 'CRITICAL', 'Reverse shell attempt blocked',          'Outbound C2 connection from va-api to 198.51.100.23:4444. Pod isolated.',                       'falcon',     'SI-4',  NOW() - INTERVAL '30 minutes'),
    ('tenant-2', 'HIGH',     'RDS publicly accessible',                'Database va-db exposed to internet. Sensitive data at risk.',                                   'checkov',    'SC-7',  NOW() - INTERVAL '1 hour'),
    ('tenant-3', 'LOW',      'Minor CVEs in staging',                  '2 MEDIUM CVEs found. No action required for staging environment.',                              'trivy',      'SI-2',  NOW() - INTERVAL '4 hours');
