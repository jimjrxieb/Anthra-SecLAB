import ChatPanel from './ChatPanel';

const REPO_BASE = 'https://github.com/jimjrxieb/Portfolio';

interface SkillItem {
  name: string;
  description: string;
  path: string;
  isFile?: boolean;
  lineNumber?: number;
}

interface SkillSection {
  id: string;
  icon: string;
  title: string;
  items: SkillItem[];
}

const skillSections: SkillSection[] = [
  {
    id: 'ai_ml',
    icon: '🤖',
    title: 'AI/ML Security',
    items: [
      { name: 'RAG Pipeline', description: '137 vectors, semantic search', path: 'data/README.md', isFile: true },
      { name: 'Prompt Injection', description: 'Regex pattern detection', path: 'api/security/llm_security.py', isFile: true, lineNumber: 42 },
      { name: 'Input Sanitization', description: 'XSS/delimiter filtering', path: 'api/security/llm_security.py', isFile: true, lineNumber: 117 },
      { name: 'Rate Limiting', description: '10 req/min per IP', path: 'api/security/llm_security.py', isFile: true, lineNumber: 196 },
      { name: 'Audit Logging', description: 'Hashed IP, query tracking', path: 'api/security/llm_security.py', isFile: true, lineNumber: 249 },
      { name: 'Hardened Prompt', description: 'Role boundaries', path: 'api/security/prompts.py', isFile: true },
    ],
  },
  {
    id: 'security_scanning',
    icon: '🔍',
    title: 'Security Scanning',
    items: [
      { name: 'Trivy', description: 'Container vulnerabilities', path: '.github/workflows/main.yml', isFile: true, lineNumber: 386 },
      { name: 'Semgrep', description: 'SAST analysis', path: '.github/workflows/main.yml', isFile: true, lineNumber: 60 },
      { name: 'detect-secrets', description: 'Secret detection', path: '.github/workflows/main.yml', isFile: true, lineNumber: 131 },
      { name: 'Bandit', description: 'Python security', path: '.github/workflows/main.yml', isFile: true, lineNumber: 104 },
      { name: 'Checkov', description: 'IaC security scanning', path: '.github/workflows/main.yml', isFile: true, lineNumber: 162 },
    ],
  },
  {
    id: 'policy_as_code',
    icon: '📜',
    title: 'Policy-as-Code (OPA/Rego)',
    items: [
      { name: 'Container Security', description: '13 deny rules: runAsNonRoot, capabilities, resource limits', path: 'GP-copilot/conftest-policies/container-security.rego', isFile: true },
      { name: 'Image Security', description: 'Trusted registries, tag validation, imagePullPolicy', path: 'GP-copilot/conftest-policies/image-security.rego', isFile: true },
      { name: 'Block Privileged', description: 'Deny across Deployment/StatefulSet/DaemonSet/Pod', path: 'GP-copilot/conftest-policies/block-privileged.rego', isFile: true },
      { name: 'Gatekeeper PSS', description: 'hostNetwork/hostPID/hostIPC + seccompProfile', path: 'GP-copilot/gatekeeper-temps/pod-security-standards.yaml', isFile: true },
      { name: 'Resource Limits', description: 'ConstraintTemplate for CPU/memory enforcement', path: 'GP-copilot/gatekeeper-temps/resource-limits.yaml', isFile: true },
      { name: 'Policy Unit Tests', description: '9 Rego tests: deny/allow scenarios', path: 'GP-copilot/conftest-policies/tests/container_test.rego', isFile: true },
      { name: 'CI Policy Gate', description: 'conftest verify + test on manifests', path: '.github/workflows/main.yml', isFile: true, lineNumber: 445 },
    ],
  },
  {
    id: 'deployment',
    icon: '🚀',
    title: 'Deployment Methods',
    items: [
      { name: 'kubectl Manifests', description: 'Simple deployments', path: 'infrastructure/method1-simple-kubectl' },
      { name: 'Terraform', description: 'Infrastructure as Code', path: 'infrastructure/method2-terraform-localstack' },
      { name: 'Helm Charts', description: 'Production packaging', path: 'infrastructure/method3-helm-argocd/helm-chart' },
      { name: 'ArgoCD GitOps', description: 'Continuous delivery', path: 'infrastructure/method3-helm-argocd/argocd' },
    ],
  },
  {
    id: 'cicd',
    icon: '⚙️',
    title: 'CI/CD Pipeline',
    items: [
      { name: 'GitHub Actions', description: 'Full workflow', path: '.github/workflows/main.yml', isFile: true },
      { name: 'Parallel Scans', description: '7 tools in parallel', path: '.github/workflows/main.yml', isFile: true, lineNumber: 46 },
      { name: 'Multi-env Deploy', description: 'Dev → Staging → Prod', path: '.github/workflows/main.yml', isFile: true, lineNumber: 487 },
    ],
  },
  {
    id: 'hardening',
    icon: '🛡️',
    title: 'Hardening',
    items: [
      { name: 'NetworkPolicies', description: 'Default-deny + explicit allow', path: 'infrastructure/shared-security/kubernetes/network-policies/default-deny-all.yaml', isFile: true },
      { name: 'RBAC', description: 'Scoped roles, no cluster-admin', path: 'infrastructure/shared-security/kubernetes/rbac/roles.yaml', isFile: true },
      { name: 'Security Headers', description: 'CSP, HSTS, X-Frame-Options + 4 more', path: 'ui/Dockerfile', isFile: true, lineNumber: 28 },
      { name: 'Non-root Containers', description: 'runAsUser: 10001, readOnlyRootFilesystem', path: 'infrastructure/method1-simple-kubectl/01-portfolio-api.yaml', isFile: true },
    ],
  },
  {
    id: 'infrastructure',
    icon: '🏗️',
    title: 'Infrastructure',
    items: [
      { name: 'Kubernetes', description: 'Full cluster config', path: 'infrastructure' },
      { name: 'FastAPI Backend', description: 'Async API', path: 'api/main.py', isFile: true },
      { name: 'React/Vite Frontend', description: 'Modern UI', path: 'ui/src' },
      { name: 'Docker Multi-stage', description: 'Optimized builds', path: 'api/Dockerfile', isFile: true },
    ],
  },
];

function buildGitHubUrl(item: SkillItem): string {
  const baseType = item.isFile ? 'blob' : 'tree';
  const lineAnchor = item.lineNumber ? `#L${item.lineNumber}` : '';
  return `${REPO_BASE}/${baseType}/main/${item.path}${lineAnchor}`;
}

export default function PortfolioBuild() {
  return (
    <div className="bg-snow/5 backdrop-blur-sm rounded-2xl border border-white/10 p-6">
      {/* Column Header */}
      <div className="flex items-center gap-3 mb-6 pb-4 border-b border-white/10">
        <span className="text-2xl">🤖</span>
        <h2 className="text-xl font-bold text-white">AI & Automation</h2>
      </div>

      {/* Chat Section - Sheyla */}
      <div className="mb-8 pb-6 border-b border-white/10">
        <div className="flex items-center gap-3 mb-4">
          <span className="text-2xl">💬</span>
          <div>
            <h3 className="text-white font-semibold text-lg">Talk to Sheyla</h3>
            <p className="text-crystal-400 text-sm">Ask about my experience</p>
          </div>
        </div>
        <ChatPanel />
      </div>

      {/* Skills Section */}
      <h3 className="text-lg font-bold text-white mb-4">
        This Portfolio is Built With
      </h3>
      <p className="text-text-secondary text-sm mb-6">
        Every skill links to actual code in the repo as proof.
      </p>

      <div className="space-y-6">
        {skillSections.map((section) => (
          <div key={section.id}>
            <h3 className="flex items-center gap-2 text-white font-semibold mb-3">
              <span>{section.icon}</span>
              <span>{section.title}</span>
            </h3>
            <ul className="space-y-2 pl-1">
              {section.items.map((item) => (
                <li key={item.name} className="flex items-start gap-2 text-sm">
                  <span className="text-crystal-400 mt-0.5">•</span>
                  <div className="flex-1">
                    <a
                      href={buildGitHubUrl(item)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-crystal-400 hover:text-crystal-300 transition-colors font-medium inline-flex items-center gap-1"
                    >
                      {item.name}
                      <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                      </svg>
                    </a>
                    <span className="text-text-secondary ml-1">— {item.description}</span>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}
