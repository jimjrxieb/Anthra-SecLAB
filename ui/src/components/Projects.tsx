import React, { useState, useMemo } from 'react';

// Types
interface Project {
  title: string;
  description: string;
  status: string;
  icon: string;
  highlights: string[];
  repoUrl?: string;
  screenshots?: { src: string; alt: string }[];
}

interface Tool {
  name: string;
  description: string;
  link?: string;
}

interface ToolCategory {
  title: string;
  icon: string;
  tools: Tool[];
}

type ProjectKey = 'gpcopilot' | 'anthra' | 'interview' | 'jade';
type CategoryKey = 'languages' | 'aiml' | 'cloud' | 'security' | 'devops';

// Constants
const FEATURED_PROJECTS: Record<ProjectKey, Project> = {
  gpcopilot: {
    title: 'GP-Copilot - DevSecOps Automation Platform',
    description: '70% auto-fix rate on security findings—runs 24/7 in production Kubernetes',
    status: 'Production',
    icon: '🔒',
    repoUrl: 'https://github.com/jimjrxieb/Portfolio/tree/main/GP-copilot',
    highlights: [
      '🎯 Impact: 70% vulnerability auto-remediation, saving hours of manual triage daily',
      'JADE v0.9: Custom fine-tuned LLM (Qwen2.5-7B) trained on 300k+ security examples',
      '14 scanner NPCs: Trivy, Semgrep, Gitleaks, Bandit, Checkov, Kubescape, and more',
      'RAG-enhanced: 29,000+ security vectors for context-aware fix recommendations',
      'Real clients: Deployed for ZRS Management property portfolio (4,000+ units)',
      'Policy-as-Code: OPA/Gatekeeper with automated policy generation',
      'Zero cloud dependency: 100% local inference, HIPAA/SOC2 ready',
    ],
  },
  anthra: {
    title: 'Anthra-SecLAB — Security Compliance Platform',
    description: 'FedRAMP Moderate authorization engagement — 323 NIST 800-53 controls, real scan data, GitOps deployment',
    status: 'Production',
    icon: '🏛️',
    repoUrl: 'https://github.com/jimjrxieb/Anthra-SecLAB',
    screenshots: [
      { src: '/projects/anthra-compliance.jpeg', alt: 'FedRAMP Compliance Dashboard — 14 NIST control families with real scan data' },
      { src: '/projects/anthra-findings.jpeg', alt: 'Security Findings — industry standard vs GP-Copilot scanners' },
      { src: '/projects/anthra-ssp.jpeg', alt: 'System Security Plan — SSP best practices and 3PAO guidance' },
      { src: '/projects/anthra-poam.jpeg', alt: 'POA&M — 21 tracked items with severity and milestones' },
    ],
    highlights: [
      '🎯 Impact: FedRAMP Moderate readiness for federal agency sales (DHS, VA, GSA)',
      'NIST 800-53: 53 controls tracked, 36% compliance with automated evidence collection',
      'Real scan data: Checkov (785 pass/70 fail), Polaris (81/100), 14 NIST-mapped findings',
      'GitOps: Kustomize base/overlays + ArgoCD — dev/staging/prod promotion pipeline',
      'Golden path: create-app-deployment.sh stamps hardened K8s manifests in 30 seconds',
      'Platform engineering: Kyverno admission (13 policies), PSS restricted, NetworkPolicy default-deny',
      '11 FedRAMP playbooks: Access Control through Continuous Compliance (CA-7)',
      'GP-Copilot value-add: auto-fix E/D rank, JADE approves C rank, human decides B/S rank',
    ],
  },
  interview: {
    title: 'AI-Powered Interview Platform',
    description: 'Enterprise-grade cloud architecture demonstrating AWS security best practices',
    status: 'Deployed',
    icon: '🚀',
    repoUrl: 'https://github.com/jimjrxieb/ai-powered-project',
    highlights: [
      '🎯 Impact: Full SDLC security pipeline catching vulnerabilities before production',
      'GitHub Actions: 6-tool parallel security scanning (secrets, SAST, SCA, containers)',
      'AWS Security: S3+KMS encryption, DynamoDB, IAM least-privilege, Secrets Manager',
      'GitOps: ArgoCD with branch-based environments (dev/staging/prod)',
      'Cost optimization: LocalStack for AWS service testing ($0 dev costs)',
      'Stack: Next.js + TypeScript + Drizzle ORM + AWS SDK',
    ],
  },
  jade: {
    title: 'Sheyla - Secure AI Chatbot',
    description: 'Production RAG with defense-in-depth LLM security—try it below',
    status: 'Live',
    icon: '🤖',
    repoUrl: 'https://github.com/jimjrxieb/Portfolio',
    highlights: [
      '🛡️ LLM Security: Prompt injection detection, input/output sanitization',
      'Rate Limiting: 10 req/min per IP prevents abuse and cost attacks',
      'Audit Logging: Hashed IPs, query tracking for compliance',
      'Vector DB: ChromaDB with 118 embeddings, sub-100ms semantic search',
      'Hardened Prompt: Role boundaries prevent persona hijacking',
      'Defense-in-Depth: 5 layers from Cloudflare WAF to LLM output filtering',
    ],
  },
} as const;

const TOOL_CATEGORIES: Record<CategoryKey, ToolCategory> = {
  cloud: {
    title: 'Cloud & Infrastructure (IaC)',
    icon: '☁️',
    tools: [
      { name: 'Kubernetes (CKA Certified)', description: '3 deployment methods: kubectl → Terraform → Helm+ArgoCD', link: 'https://github.com/jimjrxieb/Portfolio/tree/main/infrastructure/method1-simple-kubectl' },
      { name: 'Terraform + LocalStack', description: 'IaC with AWS service simulation (cost-conscious)', link: 'https://github.com/jimjrxieb/Portfolio/tree/main/infrastructure/method2-terraform-localstack' },
      { name: 'Terraform Projects', description: 'Modular, multi-environment infrastructure provisioning', link: 'https://github.com/jimjrxieb/Terraform_project' },
      { name: 'Docker Multi-Stage Builds', description: 'Non-root containers, security contexts, optimization', link: 'https://github.com/jimjrxieb/Portfolio/tree/main/api' },
      { name: 'Helm Charts', description: 'Kubernetes package manager for production deployments', link: 'https://github.com/jimjrxieb/Portfolio/tree/main/infrastructure/method3-helm-argocd' },
      { name: 'AWS (S3/KMS/Secrets Manager)', description: 'Cloud services, encryption, secrets management', link: 'https://github.com/jimjrxieb/ai-powered-project' },
    ],
  },
  devops: {
    title: 'CI/CD & Automation',
    icon: '⚙️',
    tools: [
      { name: 'GitHub Actions', description: '6-tool parallel security scanning pipeline', link: 'https://github.com/jimjrxieb/Portfolio/blob/main/.github/workflows/main.yml' },
      { name: 'ArgoCD GitOps', description: 'Automated pull-based deployments with sync policies', link: 'https://github.com/jimjrxieb/Portfolio/tree/main/infrastructure/method3-helm-argocd' },
      { name: 'Python Automation', description: 'FastAPI, async/await, RAG pipelines, CLI tools', link: 'https://github.com/jimjrxieb/Portfolio/tree/main/api' },
      { name: 'Bash/Shell Scripting', description: 'Infrastructure automation and provisioning scripts', link: 'https://github.com/jimjrxieb/Portfolio/tree/main/infrastructure/method1-simple-kubectl' },
      { name: 'Pre-commit Hooks', description: 'Local secrets detection and security validation', link: 'https://github.com/jimjrxieb/Portfolio/blob/main/.pre-commit-config.yaml' },
    ],
  },
  security: {
    title: 'Security & Compliance (DevSecOps)',
    icon: '🛡️',
    tools: [
      { name: 'OPA/Conftest Policies', description: '13 policies, 11 automated tests in CI pipeline', link: 'https://github.com/jimjrxieb/Portfolio/tree/main/GP-copilot/conftest-policies' },
      { name: 'Gatekeeper Admission Control', description: 'Runtime Kubernetes policy enforcement', link: 'https://github.com/jimjrxieb/Portfolio/tree/main/infrastructure' },
      { name: 'CompTIA Security+ Certified', description: 'Security hardening, compliance, vulnerability mgmt' },
      { name: '6-Tool Security Pipeline', description: 'detect-secrets, Semgrep, Trivy, Bandit, Safety, npm', link: 'https://github.com/jimjrxieb/Portfolio/blob/main/.github/workflows/main.yml' },
      { name: 'Network Policies + RBAC', description: 'Zero-trust networking, least-privilege access', link: 'https://github.com/jimjrxieb/Portfolio/tree/main/infrastructure/method1-simple-kubectl' },
      { name: 'Secrets Management', description: 'Never commit credentials, Kubernetes secrets automation', link: 'https://github.com/jimjrxieb/Portfolio/blob/main/infrastructure/method1-simple-kubectl/create-secrets-from-env.sh' },
    ],
  },
  aiml: {
    title: 'AI/ML Security',
    icon: '🧠',
    tools: [
      { name: 'Secure RAG Pipeline', description: '118 vectors with semantic search', link: 'https://github.com/jimjrxieb/Portfolio/blob/main/data/README.md' },
      { name: 'Prompt Injection Defense', description: 'Regex patterns block override attempts', link: 'https://github.com/jimjrxieb/Portfolio/blob/main/api/security/llm_security.py#L42' },
      { name: 'Input/Output Sanitization', description: 'XSS filtering, delimiter stripping', link: 'https://github.com/jimjrxieb/Portfolio/blob/main/api/security/llm_security.py#L117' },
      { name: 'LLM Rate Limiting', description: '10 req/min per IP to prevent abuse', link: 'https://github.com/jimjrxieb/Portfolio/blob/main/api/security/llm_security.py#L196' },
      { name: 'Audit Logging', description: 'Hashed IPs, query tracking, compliance', link: 'https://github.com/jimjrxieb/Portfolio/blob/main/api/security/llm_security.py#L249' },
      { name: 'Hardened System Prompt', description: 'Role boundaries, fail-safe responses', link: 'https://github.com/jimjrxieb/Portfolio/blob/main/api/security/prompts.py' },
    ],
  },
  languages: {
    title: 'Languages & Scripting',
    icon: '💻',
    tools: [
      { name: 'Python', description: 'FastAPI, async, automation, AI/ML pipelines', link: 'https://github.com/jimjrxieb/Portfolio/tree/main/api' },
      { name: 'TypeScript', description: 'React, type-safe production frontends', link: 'https://github.com/jimjrxieb/Portfolio/tree/main/ui' },
      { name: 'Rego (OPA)', description: 'Policy-as-Code for compliance automation', link: 'https://github.com/jimjrxieb/Portfolio/tree/main/GP-copilot/conftest-policies' },
      { name: 'Bash/Shell', description: 'Infrastructure automation and provisioning', link: 'https://github.com/jimjrxieb/Portfolio/tree/main/scripts' },
      { name: 'YAML/JSON', description: 'Configuration, IaC, Kubernetes manifests', link: 'https://github.com/jimjrxieb/Portfolio/tree/main/infrastructure' },
    ],
  },
} as const;

// Components
const ProjectCard: React.FC<{
  project: Project;
  projectKey: string;
  isSelected: boolean;
  onToggle: () => void;
}> = ({ project, isSelected, onToggle }) => (
  <button
    onClick={onToggle}
    className={`w-full text-left p-3 rounded-lg border transition-colors ${
      isSelected
        ? 'bg-crystal-500/20 border-crystal-500/30'
        : 'bg-snow/5 border-white/10 hover:bg-snow/10'
    }`}
  >
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-3">
        <span className="text-xl">{project.icon}</span>
        <div>
          <div className="text-white font-medium text-sm">
            {project.title}
          </div>
          <div className="text-text-secondary text-xs">
            {project.description}
          </div>
        </div>
      </div>
      <div className="text-right">
        <div className="text-xs text-crystal-400 font-medium">
          {project.status}
        </div>
        <div className="text-text-secondary text-xs">
          {isSelected ? '▼' : '▶'}
        </div>
      </div>
    </div>

    {isSelected && (
      <div className="mt-3 pt-3 border-t border-white/10">
        <div className="grid grid-cols-1 gap-2">
          {project.highlights.map((highlight, index) => (
            <div key={index} className="flex items-start gap-2">
              <span className="text-crystal-400 mt-1">•</span>
              <span className="text-text-secondary text-xs">{highlight}</span>
            </div>
          ))}
        </div>
        {project.screenshots && project.screenshots.length > 0 && (
          <div className="mt-3 pt-3 border-t border-white/10">
            <div className="grid grid-cols-2 gap-2">
              {project.screenshots.map((ss, i) => (
                <a key={i} href={ss.src} target="_blank" rel="noopener noreferrer">
                  <img
                    src={ss.src}
                    alt={ss.alt}
                    className="rounded border border-white/10 hover:border-crystal-500/50 transition-colors w-full"
                    loading="lazy"
                  />
                  <span className="text-text-secondary text-[10px] mt-0.5 block">{ss.alt}</span>
                </a>
              ))}
            </div>
          </div>
        )}
        {project.repoUrl && (
          <div className="mt-3 pt-3 border-t border-white/10">
            <a
              href={project.repoUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 text-crystal-400 hover:text-crystal-300 text-xs underline"
            >
              <span>📂</span> View Repository on GitHub
            </a>
          </div>
        )}
      </div>
    )}
  </button>
);

const ToolItem: React.FC<{ tool: Tool }> = ({ tool }) => {
  return (
    <div className="py-2 border-b border-white/5 last:border-b-0">
      <div>
        {tool.link ? (
          <a
            href={tool.link}
            target="_blank"
            rel="noopener noreferrer"
            className="text-white hover:text-crystal-400 font-medium text-sm underline decoration-dotted underline-offset-2"
          >
            {tool.name} →
          </a>
        ) : (
          <div className="text-white font-medium text-sm">{tool.name}</div>
        )}
        <div className="text-text-secondary text-xs">{tool.description}</div>
      </div>
    </div>
  );
};

const CategorySection: React.FC<{
  category: ToolCategory;
  categoryKey: string;
  isSelected: boolean;
  onToggle: () => void;
}> = ({ category, isSelected, onToggle }) => (
  <div>
    <button
      onClick={onToggle}
      className="w-full text-left bg-snow/10 hover:bg-snow/20 border border-white/10 rounded-lg p-4 transition-colors"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-2xl">{category.icon}</span>
          <div>
            <h3 className="text-white font-semibold">
              {category.title}
            </h3>
            <p className="text-text-secondary text-sm">
              {category.tools.length} tools • Click to expand
            </p>
          </div>
        </div>
        <div className="text-text-secondary">{isSelected ? '▼' : '▶'}</div>
      </div>
    </button>

    {isSelected && (
      <div className="mt-3 bg-snow/5 border border-white/10 rounded-lg p-4">
        <div className="grid grid-cols-1 gap-3">
          {category.tools.map(tool => (
            <ToolItem key={tool.name} tool={tool} />
          ))}
        </div>
      </div>
    )}
  </div>
);

// Main Component
export default function Projects() {
  const [selectedCategory, setSelectedCategory] = useState<CategoryKey | null>(
    null
  );
  const [selectedProject, setSelectedProject] = useState<ProjectKey | null>(
    'gpcopilot'
  );

  const toggleCategory = (key: CategoryKey) => {
    setSelectedCategory(prev => (prev === key ? null : key));
  };

  const toggleProject = (key: ProjectKey) => {
    setSelectedProject(prev => (prev === key ? null : key));
  };

  return (
    <div className="space-y-4" data-dev="projects">
      {/* Certifications Banner */}
      <div className="bg-gradient-to-r from-crystal-500/10 to-gold-500/10 border border-crystal-500/20 rounded-lg p-4">
        <h4 className="text-white font-semibold mb-2 flex items-center gap-2">
          <span>🎓</span> Certifications
        </h4>
        <div className="text-sm space-y-1">
          <div className="text-white">✅ CKA (Certified Kubernetes Administrator)</div>
          <div className="text-white">✅ CompTIA Security+</div>
          <div className="text-white">✅ AWS Certified Solutions Architect – Associate</div>
          <div className="text-crystal-400">🔄 Certified Cloud Native Platform Engineering Associate – CNPA (In Progress)</div>
        </div>
      </div>

      {/* Project Selector */}
      <div className="bg-snow/10 border border-white/10 rounded-lg p-4">
        <h4 className="text-white font-semibold mb-3">
          Featured Projects
        </h4>
        <div className="space-y-2">
          {(Object.entries(FEATURED_PROJECTS) as [ProjectKey, Project][]).map(
            ([key, project]) => (
              <ProjectCard
                key={key}
                project={project}
                projectKey={key}
                isSelected={selectedProject === key}
                onToggle={() => toggleProject(key)}
              />
            )
          )}
        </div>
      </div>

      {/* Tool Categories */}
      <div className="grid grid-cols-1 gap-3">
        {(Object.entries(TOOL_CATEGORIES) as [CategoryKey, ToolCategory][]).map(
          ([key, category]) => (
            <CategorySection
              key={key}
              category={category}
              categoryKey={key}
              isSelected={selectedCategory === key}
              onToggle={() => toggleCategory(key)}
            />
          )
        )}
      </div>

    </div>
  );
}
