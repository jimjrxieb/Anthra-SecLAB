import React, { useState } from 'react';

const GP_COPILOT_URL = 'https://github.com/jimjrxieb/Portfolio/tree/main/GP-copilot';
const PORTFOLIO_URL = 'https://github.com/jimjrxieb/Portfolio';
const ANTHRA_URL = 'https://github.com/jimjrxieb/Anthra-SecLAB';


export default function CurrentVenture() {
  const [fedrampExpanded, setFedrampExpanded] = useState(false);

  return (
    <div className="space-y-6">
      {/* Column Header */}
      <div className="bg-snow/5 backdrop-blur-sm rounded-2xl border border-white/10 p-6">
        <div className="flex items-center gap-3">
          <span className="text-2xl">🏗️</span>
          <h2 className="text-xl font-bold text-white">Platform Engineering</h2>
        </div>
      </div>

      {/* GP-Copilot Featured Card */}
      <div className="bg-gradient-to-br from-crystal-500/10 to-jade-500/10 backdrop-blur-sm rounded-2xl border border-crystal-500/30 p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold text-white">Featured Project</h2>
          <span className="px-2 py-1 bg-jade-500/20 text-jade-400 text-xs rounded-full border border-jade-500/30">
            Active Development
          </span>
        </div>

        <div className="mb-4">
          <h3 className="text-2xl font-bold text-crystal-400 mb-1">GP-COPILOT</h3>
          <p className="text-text-secondary text-sm">Reduces attack surface and cloud spend in the same engagement</p>
        </div>

        <p className="text-text-secondary text-sm mb-6 leading-relaxed">
          A platform that gives platform engineers{' '}
          <span className="text-jade-400 font-medium">end-to-end security coverage</span> using
          playbooks and engagement guides. AI agents read the playbooks and execute autonomously —
          you provide oversight for the hard decisions.
        </p>

        {/* Consulting Packages */}
        <div className="mb-6">
          <h4 className="text-sm font-semibold text-white mb-4 uppercase tracking-wide">
            Engagement Packages
          </h4>

          {/* Phase 1: Secure */}
          <div className="mb-3">
            <div className="flex items-center gap-2 mb-2">
              <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
              <span className="text-red-400 text-[10px] font-semibold uppercase tracking-wider">Secure</span>
            </div>
            <div className="space-y-2 ml-3 border-l border-red-400/20 pl-3">
              <div className="bg-snow/5 rounded-lg p-2.5 border border-white/5">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-crystal-400 text-xs">01</span>
                  <strong className="text-white text-xs">APP-SEC</strong>
                </div>
                <p className="text-text-secondary text-xs leading-relaxed">
                  16 parallel scanners. Auto-triage by severity rank. Fixer scripts for every finding. Issues caught here cost nothing.
                </p>
              </div>
              <div className="bg-snow/5 rounded-lg p-2.5 border border-white/5">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-crystal-400 text-xs">02</span>
                  <strong className="text-white text-xs">CLUSTER-HARDENING</strong>
                </div>
                <p className="text-text-secondary text-xs leading-relaxed">
                  50+ policies across CI, admission, and runtime. Kyverno/OPA/Gatekeeper. Audit first, enforce after validation. Portfolio: 34% → 71.5%.
                </p>
              </div>
              <div className="bg-snow/5 rounded-lg p-2.5 border border-white/5">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-crystal-400 text-xs">03</span>
                  <strong className="text-white text-xs">DEPLOY-RUNTIME</strong>
                </div>
                <p className="text-text-secondary text-xs leading-relaxed">
                  Falco + 20 watchers + 15 responders. 21-second MTTR. Cryptomining, privilege escalation, and drift detected and killed autonomously.
                </p>
              </div>
            </div>
          </div>

          {/* Phase 2: Understand */}
          <div className="mb-3">
            <div className="flex items-center gap-2 mb-2">
              <span className="w-1.5 h-1.5 rounded-full bg-gold-400" />
              <span className="text-gold-400 text-[10px] font-semibold uppercase tracking-wider">Understand</span>
            </div>
            <div className="space-y-2 ml-3 border-l border-gold-400/20 pl-3">
              <div className="bg-snow/5 rounded-lg p-2.5 border border-white/5">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-crystal-400 text-xs">04</span>
                  <strong className="text-white text-xs">KUBESTER</strong>
                </div>
                <p className="text-text-secondary text-xs leading-relaxed">
                  13-playbook specialist pass. Perfects what 01-03 built — RBAC, seccomp, mTLS, CIS benchmarks. Takes compliance from 71% to 95%+.
                </p>
              </div>
              <div className="bg-snow/5 rounded-lg p-2.5 border border-white/5">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-crystal-400 text-xs">05</span>
                  <strong className="text-white text-xs">JSA-AUTONOMOUS</strong>
                </div>
                <p className="text-text-secondary text-xs leading-relaxed">
                  4 agents running 24/7. E/D rank findings fixed without humans. Every runtime finding generates prevention rules that flow back to CI — issues never recur.
                </p>
              </div>
            </div>
          </div>

          {/* Phase 3: Optimize */}
          <div className="mb-3">
            <div className="flex items-center gap-2 mb-2">
              <span className="w-1.5 h-1.5 rounded-full bg-jade-400" />
              <span className="text-jade-400 text-[10px] font-semibold uppercase tracking-wider">Optimize</span>
            </div>
            <div className="space-y-2 ml-3 border-l border-jade-400/20 pl-3">
              <div className="bg-snow/5 rounded-lg p-2.5 border border-white/5">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-crystal-400 text-xs">06</span>
                  <strong className="text-white text-xs">CLOUD-SECURITY</strong>
                </div>
                <p className="text-text-secondary text-xs leading-relaxed">
                  Secure AWS migration with Terraform. VPC isolation, IAM hardening, Karpenter right-sizing. 45% infrastructure cost reduction.
                </p>
              </div>
              <div className="bg-snow/5 rounded-lg p-2.5 border border-white/5">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-crystal-400 text-xs">07</span>
                  <strong className="text-white text-xs">FEDRAMP-READY</strong>
                </div>
                <p className="text-text-secondary text-xs leading-relaxed">
                  NIST 800-53 compliance in weeks, not months. Automated gap analysis, machine-verifiable evidence, SSP generation. Unlocks federal revenue.
                </p>
              </div>
              <div className="bg-snow/5 rounded-lg p-2.5 border border-white/5">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-crystal-400 text-xs">08</span>
                  <strong className="text-white text-xs">VENDOR-INTEGRATION</strong>
                </div>
                <p className="text-text-secondary text-xs leading-relaxed">
                  CrowdStrike, Wiz, Prisma findings normalized, deduplicated, and auto-remediated. Makes $200K vendor spend actually pay for itself.
                </p>
              </div>
            </div>
          </div>

          <div className="mt-3 pt-3 border-t border-white/5">
            <div className="flex items-center justify-between">
              <p className="text-text-secondary/60 text-xs font-mono">
                secure → understand → optimize → outcome
              </p>
              <span className="text-jade-400/60 text-[10px]">28k+ lines</span>
            </div>
          </div>
        </div>

        {/* CTA */}
        <a
          href={GP_COPILOT_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 text-crystal-400 hover:text-crystal-300 transition-colors text-sm font-medium"
        >
          View GP-Copilot
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 8l4 4m0 0l-4 4m4-4H3" />
          </svg>
        </a>
      </div>

      {/* Projects */}
      <div className="bg-snow/5 backdrop-blur-sm rounded-2xl border border-white/10 p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <span>🚀</span>
          <span>Projects</span>
        </h2>

        <div className="space-y-3">
          {/* Portfolio */}
          <div className="bg-snow/5 rounded-lg p-4 border border-white/5">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-white font-medium">Portfolio</h3>
              <span className="px-2 py-0.5 bg-jade-500/20 text-jade-400 text-xs rounded-full">
                Live
              </span>
            </div>
            <p className="text-text-secondary text-xs mb-2">
              This platform. Full-stack React + FastAPI with RAG-powered AI assistant, 8-scanner CI pipeline, ArgoCD GitOps on k3s.
            </p>
            <a
              href={PORTFOLIO_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="text-crystal-400 hover:text-crystal-300 transition-colors text-xs inline-flex items-center gap-1"
            >
              View Source
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
              </svg>
            </a>
          </div>

          {/* Anthra-Cloud */}
          <div className="bg-snow/5 rounded-lg p-4 border border-white/5">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-white font-medium">Anthra-Cloud</h3>
              <span className="px-2 py-0.5 bg-crystal-500/20 text-crystal-400 text-xs rounded-full">
                Active
              </span>
            </div>
            <p className="text-text-secondary text-xs">
              Multi-tenant SaaS security monitoring platform. EKS, Terraform, OPA policies, and full CI/CD hardening pipeline.
            </p>
          </div>

          {/* Anthra-SecLAB (expandable) */}
          <div className="bg-snow/5 rounded-lg border border-white/5 overflow-hidden">
            <button
              onClick={() => setFedrampExpanded(!fedrampExpanded)}
              className="w-full text-left p-4 hover:bg-snow/10 transition-colors"
            >
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-white font-medium">Anthra-SecLAB</h3>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 bg-gold-500/20 text-gold-400 text-xs rounded-full">
                    In Progress
                  </span>
                  <span className="text-text-secondary text-xs">{fedrampExpanded ? '▼' : '▶'}</span>
                </div>
              </div>
              <p className="text-text-secondary text-xs">
                FedRAMP Moderate compliance project. 323 NIST 800-53 controls mapped to infrastructure evidence with automated gap analysis.
              </p>
            </button>

            {fedrampExpanded && (
              <div className="border-t border-white/5 p-4 space-y-4">
                {/* Screenshots */}
                <div className="grid grid-cols-2 gap-2">
                  {[
                    { src: '/projects/anthra-compliance.jpeg', alt: 'Compliance Dashboard' },
                    { src: '/projects/anthra-findings.jpeg', alt: 'Security Findings' },
                    { src: '/projects/anthra-ssp.jpeg', alt: 'System Security Plan' },
                    { src: '/projects/anthra-poam.jpeg', alt: 'POA&M Tracking' },
                  ].map((img, i) => (
                    <a key={i} href={img.src} target="_blank" rel="noopener noreferrer">
                      <img src={img.src} alt={img.alt} className="rounded border border-white/10 hover:border-crystal-500/50 transition-colors w-full" loading="lazy" />
                      <span className="text-text-secondary text-[10px] mt-0.5 block">{img.alt}</span>
                    </a>
                  ))}
                </div>

                {/* Industry Standard vs GP-Copilot */}
                <div className="space-y-3">
                  <div className="bg-snow/5 rounded-lg p-3 border border-white/5">
                    <h4 className="text-xs font-semibold text-white mb-2">Industry Standard (best practice)</h4>
                    <div className="space-y-1 text-xs text-text-secondary">
                      <div className="flex items-center gap-2"><span className="w-1.5 h-1.5 rounded-full bg-jade-500 shrink-0" /><span>Checkov, Trivy, Kubescape — IaC + CVE + K8s scanning</span></div>
                      <div className="flex items-center gap-2"><span className="w-1.5 h-1.5 rounded-full bg-jade-500 shrink-0" /><span>NIST 800-53 control mapping (manual spreadsheets)</span></div>
                      <div className="flex items-center gap-2"><span className="w-1.5 h-1.5 rounded-full bg-jade-500 shrink-0" /><span>SSP written in Word, POA&M in Excel</span></div>
                      <div className="flex items-center gap-2"><span className="w-1.5 h-1.5 rounded-full bg-jade-500 shrink-0" /><span>Evidence screenshots collected by hand</span></div>
                    </div>
                  </div>

                  <div className="bg-crystal-500/5 rounded-lg p-3 border border-crystal-500/20">
                    <h4 className="text-xs font-semibold text-crystal-400 mb-2">GP-Copilot Value-Add (what I built)</h4>
                    <div className="space-y-1 text-xs text-text-secondary">
                      <div className="flex items-center gap-2"><span className="w-1.5 h-1.5 rounded-full bg-crystal-500 shrink-0" /><span><span className="text-white">scan-and-map.py</span> — auto-maps findings to NIST control IDs</span></div>
                      <div className="flex items-center gap-2"><span className="w-1.5 h-1.5 rounded-full bg-crystal-500 shrink-0" /><span><span className="text-white">gap-analysis.py</span> — generates control matrix + POA&M + remediation plan in one run</span></div>
                      <div className="flex items-center gap-2"><span className="w-1.5 h-1.5 rounded-full bg-crystal-500 shrink-0" /><span><span className="text-white">Golden path</span> — stamps hardened Kustomize deployments with ArgoCD GitOps (dev/staging/prod)</span></div>
                      <div className="flex items-center gap-2"><span className="w-1.5 h-1.5 rounded-full bg-crystal-500 shrink-0" /><span><span className="text-white">11 FedRAMP playbooks</span> — Access Control through Continuous Compliance (CA-7)</span></div>
                      <div className="flex items-center gap-2"><span className="w-1.5 h-1.5 rounded-full bg-crystal-500 shrink-0" /><span><span className="text-white">Rank engine</span> — E/D auto-fix, C needs JADE approval, B/S needs human</span></div>
                      <div className="flex items-center gap-2"><span className="w-1.5 h-1.5 rounded-full bg-crystal-500 shrink-0" /><span><span className="text-white">Evidence as code</span> — JSON scans with timestamps, not Word docs and screenshots</span></div>
                    </div>
                  </div>
                </div>

                {/* Scan Results */}
                <div className="grid grid-cols-4 gap-2 text-center">
                  <div className="bg-snow/5 rounded-lg p-2">
                    <div className="text-lg font-bold text-crystal-400">53</div>
                    <div className="text-text-secondary text-[10px]">Controls Tracked</div>
                  </div>
                  <div className="bg-snow/5 rounded-lg p-2">
                    <div className="text-lg font-bold text-gold-400">36%</div>
                    <div className="text-text-secondary text-[10px]">Compliance</div>
                  </div>
                  <div className="bg-snow/5 rounded-lg p-2">
                    <div className="text-lg font-bold text-jade-400">785</div>
                    <div className="text-text-secondary text-[10px]">Checkov Pass</div>
                  </div>
                  <div className="bg-snow/5 rounded-lg p-2">
                    <div className="text-lg font-bold text-red-400">21</div>
                    <div className="text-text-secondary text-[10px]">POA&M Items</div>
                  </div>
                </div>

                {/* CTA */}
                <a
                  href={ANTHRA_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 text-crystal-400 hover:text-crystal-300 transition-colors text-xs font-medium"
                >
                  View Repository on GitHub
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                  </svg>
                </a>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Platform Metrics */}
      <div className="bg-snow/5 backdrop-blur-sm rounded-2xl border border-white/10 p-6">
        <h3 className="text-white font-semibold mb-4">Platform Metrics</h3>
        <div className="grid grid-cols-2 gap-3">
          <div className="text-center p-3 bg-snow/5 rounded-lg">
            <div className="text-2xl font-bold text-crystal-400">2min</div>
            <div className="text-text-secondary text-xs">Content Deploy</div>
          </div>
          <div className="text-center p-3 bg-snow/5 rounded-lg">
            <div className="text-2xl font-bold text-gold-400">10min</div>
            <div className="text-text-secondary text-xs">Full CI/CD</div>
          </div>
          <div className="text-center p-3 bg-snow/5 rounded-lg">
            <div className="text-2xl font-bold text-jade-400">&lt;100ms</div>
            <div className="text-text-secondary text-xs">RAG Search</div>
          </div>
          <div className="text-center p-3 bg-snow/5 rounded-lg">
            <div className="text-2xl font-bold text-crystal-300">2,656+</div>
            <div className="text-text-secondary text-xs">RAG Vectors</div>
          </div>
        </div>
      </div>
    </div>
  );
}
