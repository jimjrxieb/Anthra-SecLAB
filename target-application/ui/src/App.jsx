import { useState, useEffect, useCallback } from "react";

const API = "/api";

const SEV = {
  CRITICAL: { bg: "bg-red-900/50", border: "border-red-500", text: "text-red-400", badge: "bg-red-600" },
  HIGH:     { bg: "bg-orange-900/30", border: "border-orange-500", text: "text-orange-400", badge: "bg-orange-600" },
  MEDIUM:   { bg: "bg-yellow-900/30", border: "border-yellow-500", text: "text-yellow-400", badge: "bg-yellow-600" },
  LOW:      { bg: "bg-blue-900/30", border: "border-blue-500", text: "text-blue-400", badge: "bg-blue-600" },
};

const LOG_COLORS = { ERROR: "text-red-400", WARN: "text-yellow-400", INFO: "text-green-400" };

const RANK_LABELS = { S: "Human Only", B: "Human + JADE", C: "JADE Approval", D: "Auto + Log", E: "Full Auto" };

function Badge({ severity }) {
  const c = SEV[severity] || SEV.LOW;
  return <span className={`${c.badge} text-white text-xs font-bold px-2 py-0.5 rounded`}>{severity}</span>;
}

export default function App() {
  const [tenantId, setTenantId] = useState("tenant-1");
  const [page, setPage] = useState("compliance");
  const [stats, setStats] = useState(null);
  const [findings, setFindings] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [logs, setLogs] = useState([]);
  const [families, setFamilies] = useState([]);
  const [poam, setPoam] = useState(null);
  const [ssp, setSsp] = useState(null);
  const [vendors, setVendors] = useState([]);
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [search, setSearch] = useState("");
  const [searchHtml, setSearchHtml] = useState("");
  const [expandedFamily, setExpandedFamily] = useState(null);

  // Vendor form
  const [vForm, setVForm] = useState({ name: "", vendor_type: "falcon", api_endpoint: "", api_key: "" });

  const tenants = [
    { id: "tenant-1", label: "DHS" },
    { id: "tenant-2", label: "VA" },
    { id: "tenant-3", label: "GSA" },
  ];

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [sR, fR, aR, lR, famR, pR, sspR, vR] = await Promise.all([
        fetch(`${API}/stats?tenant_id=${tenantId}`),
        fetch(`${API}/findings?tenant_id=${tenantId}`),
        fetch(`${API}/alerts?tenant_id=${tenantId}`),
        fetch(`${API}/logs?tenant_id=${tenantId}`),
        fetch(`${API}/ssp/families?tenant_id=${tenantId}`),
        fetch(`${API}/ssp/poam`),
        fetch(`${API}/ssp`),
        fetch(`${API}/vendors?tenant_id=${tenantId}`),
      ]);
      setStats(await sR.json());
      setFindings((await fR.json()).findings || []);
      setAlerts((await aR.json()).alerts || []);
      setLogs((await lR.json()).logs || []);
      setFamilies((await famR.json()).families || []);
      setPoam(await pR.json());
      setSsp(await sspR.json());
      setVendors((await vR.json()).vendors || []);
    } catch (e) { console.error(e); }
    setLoading(false);
  }, [tenantId]);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  async function runScan(vendorId) {
    setScanResult(null);
    const res = await fetch(`${API}/vendors/${vendorId}/scan`, { method: "POST" });
    const data = await res.json();
    setScanResult(data);
    fetchAll();
  }

  async function addVendor(e) {
    e.preventDefault();
    await fetch(`${API}/vendors`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...vForm, tenant_id: tenantId }),
    });
    setVForm({ name: "", vendor_type: "falcon", api_endpoint: "", api_key: "" });
    fetchAll();
  }

  async function connectVendor(id) {
    await fetch(`${API}/vendors/${id}/connect`, { method: "POST" });
    fetchAll();
  }

  async function doSearch() {
    const res = await fetch(`${API}/search?q=${encodeURIComponent(search)}&tenant_id=${tenantId}`);
    const html = await res.text();
    setSearchHtml(html);
  }

  const sevCounts = stats?.findings_by_severity || {};
  const comp = stats?.compliance || {};
  const navItems = [
    { key: "compliance", label: "Compliance" },
    { key: "findings", label: "Findings" },
    { key: "vendors", label: "Vendors" },
    { key: "ssp", label: "SSP" },
    { key: "poam", label: "POA&M" },
    { key: "alerts", label: "Alerts" },
    { key: "logs", label: "Logs" },
    { key: "search", label: "Search" },
  ];

  return (
    <div className="min-h-screen flex flex-col">
      {/* BEFORE STATE Banner */}
      <div className="bg-amber-900/60 border-b border-amber-600 px-4 py-1.5 text-amber-200 text-xs flex items-center gap-2">
        <span className="font-bold uppercase tracking-wide">BEFORE STATE</span>
        <span className="text-amber-500">|</span>
        <span>No auth. No RBAC. XSS in search. API keys in plaintext. No audit trail. See README.</span>
      </div>

      {/* Header */}
      <header className="bg-anthra-800 border-b border-anthra-600 px-6 py-3">
        <div className="max-w-[1400px] mx-auto flex items-center justify-between">
          <div className="flex items-center gap-6">
            <div>
              <h1 className="text-xl font-bold text-white tracking-tight">
                Anthra <span className="text-indigo-400">Center</span>
              </h1>
              <p className="text-xs text-gray-500">FedRAMP Moderate | NIST 800-53 Rev 5</p>
            </div>
            <nav className="flex gap-1 ml-4">
              {navItems.map((n) => (
                <button key={n.key} onClick={() => setPage(n.key)}
                  className={`px-3 py-1.5 text-xs font-medium rounded transition-colors ${
                    page === n.key ? "bg-indigo-600 text-white" : "text-gray-400 hover:text-white hover:bg-anthra-700"
                  }`}>
                  {n.label}
                </button>
              ))}
            </nav>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex bg-anthra-700 rounded overflow-hidden border border-anthra-500">
              {tenants.map((t) => (
                <button key={t.id} onClick={() => setTenantId(t.id)}
                  className={`px-3 py-1 text-xs font-medium transition-colors ${
                    tenantId === t.id ? "bg-indigo-600 text-white" : "text-gray-400 hover:text-white"
                  }`}>
                  {t.label}
                </button>
              ))}
            </div>
            <button onClick={fetchAll} disabled={loading}
              className="bg-anthra-700 hover:bg-anthra-600 text-gray-300 text-xs px-3 py-1.5 rounded border border-anthra-500 disabled:opacity-50">
              {loading ? "..." : "Refresh"}
            </button>
            <span className="text-xs text-red-400 border border-red-800 rounded px-2 py-1">No Auth</span>
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-[1400px] w-full mx-auto px-6 py-5">

        {/* ===================== COMPLIANCE DASHBOARD ===================== */}
        {page === "compliance" && (
          <div>
            {/* FedRAMP Overview */}
            <div className="bg-anthra-800 border border-indigo-700/50 rounded-lg p-4 mb-6">
              <div className="flex items-start gap-6">
                <div className="flex-1">
                  <h2 className="text-lg font-bold text-white mb-2">FedRAMP Moderate Authorization</h2>
                  <p className="text-xs text-gray-400 leading-relaxed mb-3">
                    The <span className="text-indigo-400">Federal Risk and Authorization Management Program</span> is the US government's
                    standard for authorizing cloud services used by federal agencies. FedRAMP Moderate covers
                    323 NIST 800-53 Rev 5 controls protecting Controlled Unclassified Information (CUI) — the level
                    required to sell SaaS to DHS, VA, GSA, and most civilian agencies.
                  </p>
                  <div className="grid grid-cols-3 gap-3 text-xs">
                    <div className="bg-anthra-900/50 rounded p-2">
                      <div className="text-indigo-400 font-semibold mb-1">What a 3PAO Looks For</div>
                      <ul className="text-gray-500 space-y-0.5">
                        <li><span className="text-gray-400">SSP</span> — System Security Plan (how each control is implemented)</li>
                        <li><span className="text-gray-400">POA&M</span> — Plan of Action & Milestones (open gaps with dates)</li>
                        <li><span className="text-gray-400">SAR</span> — Security Assessment Report (3PAO's independent findings)</li>
                        <li><span className="text-gray-400">Evidence</span> — Scanner JSON, policy YAML, git history with timestamps</li>
                        <li><span className="text-gray-400">CA-7</span> — Continuous monitoring (monthly scans, annual re-assessment)</li>
                      </ul>
                    </div>
                    <div className="bg-anthra-900/50 rounded p-2">
                      <div className="text-indigo-400 font-semibold mb-1">FedRAMP Playbooks (07-FEDRAMP-READY)</div>
                      <ul className="text-gray-500 space-y-0.5">
                        <li><span className="text-gray-400">00</span> FedRAMP Quickstart</li>
                        <li><span className="text-gray-400">01</span> Access Control Hardening (AC)</li>
                        <li><span className="text-gray-400">02</span> Audit Logging (AU)</li>
                        <li><span className="text-gray-400">03</span> Configuration Management (CM)</li>
                        <li><span className="text-gray-400">04</span> System & Communications (SC)</li>
                        <li><span className="text-gray-400">05</span> System Integrity (SI)</li>
                        <li><span className="text-gray-400">06</span> Identity & Authentication (IA)</li>
                        <li><span className="text-gray-400">07</span> Incident Response (IR)</li>
                        <li><span className="text-gray-400">08</span> Documentation Package (SSP, POA&M)</li>
                        <li><span className="text-gray-400">09</span> 3PAO Preparation</li>
                        <li><span className="text-gray-400">10</span> Continuous Compliance (CA-7)</li>
                      </ul>
                    </div>
                    <div className="bg-anthra-900/50 rounded p-2">
                      <div className="text-indigo-400 font-semibold mb-1">Automated Evidence Output</div>
                      <ul className="text-gray-500 space-y-0.5">
                        <li><span className="text-gray-400">Checkov JSON</span> — IaC compliance (785 passed, 70 failed)</li>
                        <li><span className="text-gray-400">NIST mapping</span> — 14 findings auto-mapped to control IDs</li>
                        <li><span className="text-gray-400">Polaris</span> — K8s security score: 81/100</li>
                        <li><span className="text-gray-400">ArgoCD git log</span> — Change control audit trail (CM-3)</li>
                        <li><span className="text-gray-400">Kyverno reports</span> — Admission enforcement proof (CM-6)</li>
                      </ul>
                    </div>
                  </div>
                </div>
                <div className="shrink-0 text-right">
                  <div className="text-xs text-gray-600 mb-1">Engagement</div>
                  <div className="text-xs text-gray-500">NovaSec Cloud</div>
                  <div className="text-xs text-gray-500">FedRAMP Moderate</div>
                  <div className="text-xs text-gray-500">323 controls</div>
                  <div className="text-xs text-gray-600 mt-2 mb-1">Scanned</div>
                  <div className="text-xs text-gray-500">Feb 26, 2026</div>
                  <div className="text-xs text-gray-600 mt-2 mb-1">Consultant</div>
                  <div className="text-xs text-indigo-400">Ghost Protocol</div>
                </div>
              </div>
            </div>

            {/* Top metrics */}
            <div className="grid grid-cols-6 gap-3 mb-6">
              <div className="bg-anthra-800 border border-anthra-600 rounded-lg p-3 col-span-2">
                <div className="text-xs text-gray-500 mb-1">Overall Compliance</div>
                <div className="flex items-end gap-2">
                  <span className="text-3xl font-bold text-indigo-400">{comp.compliance_pct || 0}%</span>
                  <span className="text-xs text-gray-500 mb-1">{comp.implemented || 0} + {comp.inherited || 0} of {comp.total_controls || 0} controls</span>
                </div>
                <div className="mt-2 h-2 bg-anthra-700 rounded-full overflow-hidden">
                  <div className="h-full bg-indigo-500 rounded-full" style={{ width: `${comp.compliance_pct || 0}%` }} />
                </div>
              </div>
              {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
                <div key={s} className={`${SEV[s].bg} border ${SEV[s].border} rounded-lg p-3`}>
                  <div className={`text-2xl font-bold ${SEV[s].text}`}>{sevCounts[s] || 0}</div>
                  <div className="text-xs text-gray-500">{s} Findings</div>
                </div>
              ))}
            </div>

            {/* Control Families Grid */}
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">NIST 800-53 Control Families</h2>
            <div className="grid grid-cols-3 gap-3 mb-6">
              {families.map((f) => {
                const total = f.total_controls;
                const pct = f.compliance_pct;
                const isExpanded = expandedFamily === f.family;
                return (
                  <div key={f.family} className={`bg-anthra-800 border rounded-lg overflow-hidden cursor-pointer transition-colors ${
                    f.open_findings > 0 ? "border-orange-700 hover:border-orange-500" : "border-anthra-600 hover:border-indigo-600"
                  }`} onClick={() => setExpandedFamily(isExpanded ? null : f.family)}>
                    <div className="p-3">
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-2">
                          <span className="text-indigo-400 font-mono font-bold text-sm">{f.family}</span>
                          <span className="text-gray-400 text-xs">{f.name}</span>
                        </div>
                        <span className={`text-xs font-bold ${pct >= 80 ? "text-green-400" : pct >= 50 ? "text-yellow-400" : "text-red-400"}`}>
                          {pct}%
                        </span>
                      </div>
                      <div className="h-1.5 bg-anthra-700 rounded-full overflow-hidden mb-2">
                        <div className={`h-full rounded-full ${pct >= 80 ? "bg-green-500" : pct >= 50 ? "bg-yellow-500" : "bg-red-500"}`}
                          style={{ width: `${pct}%` }} />
                      </div>
                      <div className="flex gap-3 text-xs text-gray-500">
                        <span className="text-green-400">{f.implemented} done</span>
                        <span className="text-yellow-400">{f.partial} partial</span>
                        <span className="text-red-400">{f.not_implemented} missing</span>
                        {f.inherited > 0 && <span className="text-blue-400">{f.inherited} inherited</span>}
                        {f.open_findings > 0 && <span className="text-orange-400 font-medium ml-auto">{f.open_findings} findings</span>}
                      </div>
                    </div>
                    {isExpanded && (
                      <div className="border-t border-anthra-700 bg-anthra-900/50 p-3 space-y-1.5">
                        {f.controls.map((ctrl) => (
                          <div key={ctrl.control_id} className="flex items-start gap-2 text-xs">
                            <span className="font-mono text-indigo-300 w-12 shrink-0">{ctrl.control_id}</span>
                            <span className={`w-2 h-2 rounded-full mt-1 shrink-0 ${
                              ctrl.status === "Implemented" ? "bg-green-500" :
                              ctrl.status === "Partially Implemented" ? "bg-yellow-500" :
                              ctrl.status === "Inherited" ? "bg-blue-500" : "bg-red-500"
                            }`} />
                            <div className="flex-1">
                              <span className="text-gray-300">{ctrl.title}</span>
                              <p className="text-gray-600 mt-0.5">{ctrl.description}</p>
                              {ctrl.open_findings > 0 && (
                                <span className="text-orange-400 text-xs">({ctrl.open_findings} open finding{ctrl.open_findings > 1 ? "s" : ""})</span>
                              )}
                            </div>
                            <span className={`shrink-0 text-xs px-1.5 py-0.5 rounded ${
                              ctrl.status === "Implemented" ? "bg-green-900/50 text-green-400" :
                              ctrl.status === "Partially Implemented" ? "bg-yellow-900/50 text-yellow-400" :
                              ctrl.status === "Inherited" ? "bg-blue-900/50 text-blue-400" : "bg-red-900/50 text-red-400"
                            }`}>
                              {ctrl.status === "Partially Implemented" ? "Partial" : ctrl.status === "Not Implemented" ? "Missing" : ctrl.status}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Quick POA&M + Stats footer */}
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-anthra-800 border border-anthra-600 rounded-lg p-3">
                <h3 className="text-xs font-semibold text-gray-400 uppercase mb-2">POA&M Summary</h3>
                <div className="flex gap-4 text-sm">
                  <span className="text-red-400">{stats?.poam_summary?.open || 0} Open</span>
                  <span className="text-yellow-400">{stats?.poam_summary?.in_progress || 0} In Progress</span>
                  <span className="text-gray-400">{poam?.summary?.planned || 0} Planned</span>
                  <span className="text-gray-500 ml-auto">{poam?.summary?.total || 0} total items</span>
                </div>
              </div>
              <div className="bg-anthra-800 border border-anthra-600 rounded-lg p-3">
                <h3 className="text-xs font-semibold text-gray-400 uppercase mb-2">Platform Status</h3>
                <div className="flex gap-4 text-sm">
                  <span className="text-white">{stats?.connected_vendors || 0} Vendors</span>
                  <span className="text-white">{stats?.open_findings || 0} Open Findings</span>
                  <span className="text-white">{stats?.total_alerts || 0} Alerts</span>
                  <span className="text-white">{stats?.total_logs || 0} Log Events</span>
                  <span className="text-gray-500 ml-auto">{stats?.active_tenants || 0} Tenants</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ===================== FINDINGS ===================== */}
        {page === "findings" && (
          <div className="space-y-2">
            {/* Scanner Overview */}
            <div className="bg-anthra-800 border border-indigo-700/50 rounded-lg p-4 mb-4">
              <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Security Scanners</h2>
              <div className="grid grid-cols-2 gap-4 text-xs">
                <div>
                  <div className="text-indigo-400 font-semibold mb-2">Industry Standard (best practice)</div>
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-green-500 shrink-0" />
                      <span className="text-gray-300 w-20">Trivy</span>
                      <span className="text-gray-500">Container image CVEs + filesystem dependencies</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-green-500 shrink-0" />
                      <span className="text-gray-300 w-20">Semgrep</span>
                      <span className="text-gray-500">SAST — code patterns (SQL injection, XSS, hardcoded secrets)</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-green-500 shrink-0" />
                      <span className="text-gray-300 w-20">Gitleaks</span>
                      <span className="text-gray-500">Secret detection in git history and source files</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-green-500 shrink-0" />
                      <span className="text-gray-300 w-20">Checkov</span>
                      <span className="text-gray-500">IaC misconfiguration (Terraform, K8s YAML, Dockerfile)</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-green-500 shrink-0" />
                      <span className="text-gray-300 w-20">Kubescape</span>
                      <span className="text-gray-500">K8s CIS benchmarks + NSA hardening guide</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-green-500 shrink-0" />
                      <span className="text-gray-300 w-20">Bandit</span>
                      <span className="text-gray-500">Python-specific SAST (eval, exec, shell injection)</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-green-500 shrink-0" />
                      <span className="text-gray-300 w-20">Hadolint</span>
                      <span className="text-gray-500">Dockerfile linting (non-root, pinned versions, HEALTHCHECK)</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-green-500 shrink-0" />
                      <span className="text-gray-300 w-20">Grype</span>
                      <span className="text-gray-500">Dependency vulnerability scanning (SCA)</span>
                    </div>
                  </div>
                </div>
                <div>
                  <div className="text-indigo-400 font-semibold mb-2">GP-Copilot Value-Add (what we bring)</div>
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-indigo-500 shrink-0" />
                      <span className="text-gray-300 w-20">Falcon</span>
                      <span className="text-gray-500">Runtime threat detection — process elevation, crypto mining, container escape</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-indigo-500 shrink-0" />
                      <span className="text-gray-300 w-20">Falco</span>
                      <span className="text-gray-500">Syscall monitoring — shell spawns, sensitive file access, network anomalies</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-indigo-500 shrink-0" />
                      <span className="text-gray-300 w-20">Polaris</span>
                      <span className="text-gray-500">K8s security scoring (81/100) — security contexts, probes, resource limits</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-indigo-500 shrink-0" />
                      <span className="text-gray-300 w-20">Conftest</span>
                      <span className="text-gray-500">Custom OPA/Rego policies written for this client's architecture</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-indigo-500 shrink-0" />
                      <span className="text-gray-300 w-20">Kyverno</span>
                      <span className="text-gray-500">Admission control — 13 policies enforcing security at deploy time</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-indigo-500 shrink-0" />
                      <span className="text-gray-300 w-20">10 Watchers</span>
                      <span className="text-gray-500">Drift, secrets, PSS, seccomp, apparmor, network, supply-chain audits</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-indigo-500 shrink-0" />
                      <span className="text-gray-300 w-20">scan-and-map</span>
                      <span className="text-gray-500">Auto-maps every finding to NIST 800-53 control IDs</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-indigo-500 shrink-0" />
                      <span className="text-gray-300 w-20">Rank Engine</span>
                      <span className="text-gray-500">E→S classification — auto-fix E/D, JADE approves C, human decides B/S</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2 mb-3">
              <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide">Security Findings</h2>
              <span className="text-xs text-gray-600">({findings.length})</span>
            </div>
            {findings.map((f) => {
              const c = SEV[f.severity] || SEV.LOW;
              return (
                <div key={f.id} className={`${c.bg} border ${c.border} rounded-lg p-3`}>
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <Badge severity={f.severity} />
                        <span className="text-xs text-gray-500 bg-anthra-700 px-1.5 py-0.5 rounded">{f.source}</span>
                        <span className="text-xs text-gray-600">{f.finding_type}</span>
                        {f.cve_id && <span className="text-xs text-cyan-400 font-mono">{f.cve_id}</span>}
                      </div>
                      <h3 className="text-white text-sm font-medium">{f.title}</h3>
                      <p className="text-xs text-gray-400 mt-0.5">{f.description}</p>
                      {f.remediation && (
                        <p className="text-xs text-green-400/80 mt-1"><span className="text-green-600">Fix:</span> {f.remediation}</p>
                      )}
                    </div>
                    <div className="text-right shrink-0 space-y-1">
                      {f.nist_control && (
                        <div className="text-xs font-mono bg-indigo-900/50 text-indigo-300 px-2 py-0.5 rounded border border-indigo-700">
                          {f.nist_control}
                        </div>
                      )}
                      {f.rank && <div className="text-xs text-gray-500">{f.rank}-rank <span className="text-gray-600">({RANK_LABELS[f.rank]})</span></div>}
                      {f.mitre_technique && <div className="text-xs text-gray-600">MITRE {f.mitre_technique}</div>}
                      <div className="text-xs text-gray-700">{f.asset_type}: {f.asset_id}</div>
                    </div>
                  </div>
                </div>
              );
            })}
            {findings.length === 0 && <p className="text-gray-600 text-sm py-8 text-center">No findings for this tenant.</p>}
          </div>
        )}

        {/* ===================== VENDORS ===================== */}
        {page === "vendors" && (
          <div>
            <div className="bg-red-900/20 border border-red-800 rounded-lg p-3 mb-4 text-xs text-red-300">
              <span className="font-bold">SECURITY GAP (IA-5):</span> Vendor API keys are stored and displayed in plaintext. No encryption, no masking, no vault integration.
            </div>

            {/* Existing Vendors */}
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Connected Vendors</h2>
            <div className="grid grid-cols-2 gap-3 mb-6">
              {vendors.map((v) => (
                <div key={v.id} className="bg-anthra-800 border border-anthra-600 rounded-lg p-3">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${v.status === "connected" ? "bg-green-500" : "bg-gray-600"}`} />
                      <span className="text-white text-sm font-medium">{v.name}</span>
                      <span className="text-xs text-gray-500 bg-anthra-700 px-1.5 py-0.5 rounded">{v.vendor_type}</span>
                    </div>
                    <div className="flex gap-1.5">
                      {v.status !== "connected" && (
                        <button onClick={() => connectVendor(v.id)}
                          className="text-xs bg-green-700 hover:bg-green-600 text-white px-2 py-1 rounded">
                          Connect
                        </button>
                      )}
                      <button onClick={() => runScan(v.id)}
                        className="text-xs bg-indigo-600 hover:bg-indigo-500 text-white px-2 py-1 rounded">
                        Run Scan
                      </button>
                    </div>
                  </div>
                  <div className="text-xs space-y-0.5">
                    <div className="text-gray-500">Endpoint: <span className="text-gray-400 font-mono">{v.api_endpoint}</span></div>
                    <div className="text-red-400">API Key: <span className="font-mono text-red-300">{v.api_key}</span></div>
                    {v.last_scan && <div className="text-gray-600">Last scan: {v.last_scan}</div>}
                  </div>
                </div>
              ))}
              {vendors.length === 0 && <p className="text-gray-600 text-sm col-span-2 text-center py-4">No vendors configured.</p>}
            </div>

            {/* Scan result toast */}
            {scanResult && (
              <div className="bg-green-900/30 border border-green-700 rounded-lg p-3 mb-4">
                <div className="text-green-400 text-sm font-medium">
                  Scan Complete: {scanResult.vendor} — {scanResult.findings_generated} new finding(s)
                </div>
                {scanResult.findings?.map((f, i) => (
                  <div key={i} className="text-xs text-gray-400 mt-1">
                    <Badge severity={f.severity} /> <span className="ml-1">{f.title}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Add Vendor Form */}
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Add Vendor Integration</h2>
            <form onSubmit={addVendor} className="bg-anthra-800 border border-anthra-600 rounded-lg p-4 space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-gray-500 block mb-1">Vendor Name</label>
                  <input value={vForm.name} onChange={(e) => setVForm({ ...vForm, name: e.target.value })}
                    placeholder="e.g. CrowdStrike Falcon" required
                    className="w-full bg-anthra-700 border border-anthra-500 text-gray-200 text-sm rounded px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-indigo-500" />
                </div>
                <div>
                  <label className="text-xs text-gray-500 block mb-1">Type</label>
                  <select value={vForm.vendor_type} onChange={(e) => setVForm({ ...vForm, vendor_type: e.target.value })}
                    className="w-full bg-anthra-700 border border-anthra-500 text-gray-200 text-sm rounded px-3 py-1.5">
                    <option value="falcon">EDR (Falcon)</option>
                    <option value="trivy">Scanner (Trivy)</option>
                    <option value="kubescape">K8s (Kubescape)</option>
                    <option value="checkov">IaC (Checkov)</option>
                    <option value="gitleaks">Secrets (Gitleaks)</option>
                    <option value="semgrep">SAST (Semgrep)</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="text-xs text-gray-500 block mb-1">API Endpoint</label>
                <input value={vForm.api_endpoint} onChange={(e) => setVForm({ ...vForm, api_endpoint: e.target.value })}
                  placeholder="https://api.vendor.com" required
                  className="w-full bg-anthra-700 border border-anthra-500 text-gray-200 text-sm rounded px-3 py-1.5 font-mono focus:outline-none focus:ring-1 focus:ring-indigo-500" />
              </div>
              <div>
                <label className="text-xs text-red-400 block mb-1">API Key (stored in plaintext — IA-5 violation)</label>
                <input value={vForm.api_key} onChange={(e) => setVForm({ ...vForm, api_key: e.target.value })}
                  placeholder="Enter API key (will NOT be encrypted)" required type="text"
                  className="w-full bg-anthra-700 border border-red-800 text-red-300 text-sm rounded px-3 py-1.5 font-mono focus:outline-none focus:ring-1 focus:ring-red-500" />
              </div>
              <button type="submit" className="bg-indigo-600 hover:bg-indigo-700 text-white text-sm px-4 py-2 rounded">
                Add Vendor
              </button>
            </form>
          </div>
        )}

        {/* ===================== SSP ===================== */}
        {page === "ssp" && ssp && (
          <div>
            {/* SSP Explainer */}
            <div className="bg-anthra-800 border border-indigo-700/50 rounded-lg p-4 mb-4">
              <h2 className="text-lg font-bold text-white mb-2">What is a System Security Plan (SSP)?</h2>
              <p className="text-xs text-gray-400 leading-relaxed mb-3">
                The SSP is the <span className="text-indigo-400">single most important document in a FedRAMP authorization</span>. It describes
                every security control in your system — how it's implemented, who's responsible, and what evidence proves it works.
                A typical FedRAMP Moderate SSP is 300+ pages. The 3PAO reads this document line by line and tests each claim independently.
              </p>
              <div className="grid grid-cols-3 gap-3 text-xs mb-3">
                <div className="bg-anthra-900/50 rounded p-2">
                  <div className="text-indigo-400 font-semibold mb-1">SSP Best Practices</div>
                  <ul className="text-gray-500 space-y-0.5">
                    <li>Every control must say <span className="text-gray-300">Implemented</span>, <span className="text-yellow-400">Partially Implemented</span>, <span className="text-blue-400">Inherited</span>, or <span className="text-red-400">Planned</span></li>
                    <li>Each statement needs <span className="text-gray-300">who, what, when, how</span> — not just "we do this"</li>
                    <li>Reference specific tools, configs, and evidence artifacts</li>
                    <li>Inherited controls (PE, PS from AWS) must cite the CSP's ATO</li>
                    <li>Update the SSP every time you change your architecture</li>
                  </ul>
                </div>
                <div className="bg-anthra-900/50 rounded p-2">
                  <div className="text-indigo-400 font-semibold mb-1">What 3PAOs Reject</div>
                  <ul className="text-gray-500 space-y-0.5">
                    <li><span className="text-red-400">Vague statements</span> — "We use encryption" (which algorithm? what key size?)</li>
                    <li><span className="text-red-400">No evidence</span> — Claims without scanner output, config files, or screenshots</li>
                    <li><span className="text-red-400">Stale dates</span> — SSP says "last scanned Jan 2025" but it's March 2026</li>
                    <li><span className="text-red-400">Missing POA&M</span> — Partial controls without a remediation plan and target date</li>
                    <li><span className="text-red-400">Manual-only processes</span> — "We review logs weekly" (prove it with automation)</li>
                  </ul>
                </div>
                <div className="bg-anthra-900/50 rounded p-2">
                  <div className="text-indigo-400 font-semibold mb-1">How GP-Copilot Helps</div>
                  <ul className="text-gray-500 space-y-0.5">
                    <li><span className="text-green-400">Auto-generated evidence</span> — Checkov JSON, Trivy scans, Polaris scores with timestamps</li>
                    <li><span className="text-green-400">Control-mapped policies</span> — Every Kyverno rule tagged with its NIST control ID</li>
                    <li><span className="text-green-400">Git history = CM-3</span> — ArgoCD promotion trail proves change control</li>
                    <li><span className="text-green-400">Playbook 08</span> — Documentation Package generator (SSP narrative + appendices)</li>
                    <li><span className="text-green-400">Playbook 10</span> — Continuous Compliance (CA-7 monthly scans automated)</li>
                  </ul>
                </div>
              </div>
            </div>

            {/* SSP Metadata */}
            <div className="bg-anthra-800 border border-indigo-700 rounded-lg p-4 mb-4">
              <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-2">System Information</h2>
              <div className="grid grid-cols-2 gap-x-8 gap-y-1 text-sm">
                <div><span className="text-gray-500">System Name:</span> <span className="text-white">{ssp.system_name}</span></div>
                <div><span className="text-gray-500">CSP:</span> <span className="text-white">{ssp.csp}</span></div>
                <div><span className="text-gray-500">Authorization Level:</span> <span className="text-indigo-400 font-medium">{ssp.authorization_level}</span></div>
                <div><span className="text-gray-500">Framework:</span> <span className="text-white">{ssp.nist_revision}</span></div>
                <div><span className="text-gray-500">Authorization Boundary:</span> <span className="text-white">{ssp.authorization_boundary}</span></div>
                <div><span className="text-gray-500">Assessor:</span> <span className="text-white">{ssp.assessor}</span></div>
                <div><span className="text-gray-500">3PAO:</span> <span className="text-yellow-400">{ssp["3pao"]}</span></div>
                <div><span className="text-gray-500">ATO Status:</span> <span className="text-yellow-400">{ssp.ato_status}</span></div>
                <div><span className="text-gray-500">Total Controls:</span> <span className="text-white">{ssp.total_controls}</span></div>
                <div><span className="text-gray-500">Last Updated:</span> <span className="text-white">{ssp.last_updated}</span></div>
              </div>
            </div>

            <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Control Implementation Statements</h3>
            <div className="space-y-2">
              {ssp.controls?.map((ctrl) => (
                <div key={ctrl.control_id} className="bg-anthra-800 border border-anthra-600 rounded-lg p-3 flex items-start gap-3">
                  <span className="font-mono text-indigo-400 text-sm w-12 shrink-0">{ctrl.control_id}</span>
                  <span className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${
                    ctrl.status === "Implemented" ? "bg-green-500" :
                    ctrl.status === "Partially Implemented" ? "bg-yellow-500" :
                    ctrl.status === "Inherited" ? "bg-blue-500" : "bg-red-500"
                  }`} />
                  <div className="flex-1">
                    <div className="text-sm text-white font-medium">{ctrl.title}</div>
                    <p className="text-xs text-gray-400 mt-0.5">{ctrl.description}</p>
                  </div>
                  <span className={`text-xs px-2 py-0.5 rounded shrink-0 ${
                    ctrl.status === "Implemented" ? "bg-green-900/50 text-green-400 border border-green-800" :
                    ctrl.status === "Partially Implemented" ? "bg-yellow-900/50 text-yellow-400 border border-yellow-800" :
                    ctrl.status === "Inherited" ? "bg-blue-900/50 text-blue-400 border border-blue-800" :
                    "bg-red-900/50 text-red-400 border border-red-800"
                  }`}>
                    {ctrl.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ===================== POA&M ===================== */}
        {page === "poam" && poam && (
          <div>
            <div className="bg-anthra-800 border border-anthra-600 rounded-lg p-4 mb-4">
              <h2 className="text-lg font-bold text-white mb-1">Plan of Action & Milestones (POA&M)</h2>
              <p className="text-xs text-gray-500">{poam.system} | Last Updated: {poam.last_updated}</p>
              <div className="flex gap-4 mt-2 text-sm">
                <span className="text-red-400">{poam.summary.open} Open</span>
                <span className="text-yellow-400">{poam.summary.in_progress} In Progress</span>
                <span className="text-gray-400">{poam.summary.planned} Planned</span>
                <span className="text-gray-500 ml-auto">{poam.summary.critical} Critical | {poam.summary.high} High</span>
              </div>
            </div>
            <div className="space-y-2">
              {poam.items?.map((item) => {
                const c = SEV[item.severity] || SEV.MEDIUM;
                return (
                  <div key={item.id} className={`${c.bg} border ${c.border} rounded-lg p-3`}>
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-xs font-mono text-indigo-400 bg-indigo-900/50 px-1.5 py-0.5 rounded">{item.control}</span>
                          <Badge severity={item.severity} />
                          <span className={`text-xs px-1.5 py-0.5 rounded ${
                            item.status === "Open" ? "bg-red-900/50 text-red-400" :
                            item.status === "In Progress" ? "bg-yellow-900/50 text-yellow-400" :
                            "bg-gray-800 text-gray-400"
                          }`}>{item.status}</span>
                        </div>
                        <p className="text-sm text-white">{item.weakness}</p>
                        <p className="text-xs text-gray-400 mt-1">Milestone: {item.milestone}</p>
                      </div>
                      <div className="text-xs text-gray-500 shrink-0">Due: {item.scheduled}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ===================== ALERTS ===================== */}
        {page === "alerts" && (
          <div className="space-y-2">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">Security Alerts ({alerts.length})</h2>
            {alerts.map((a) => {
              const c = SEV[a.severity] || SEV.LOW;
              return (
                <div key={a.id} className={`${c.bg} border-l-4 ${c.border} rounded-r-lg p-3 flex items-center gap-3`}>
                  <Badge severity={a.severity} />
                  <div className="flex-1">
                    <span className="text-white text-sm font-medium">{a.title}</span>
                    <span className="text-gray-500 text-xs ml-2">{a.description}</span>
                  </div>
                  {a.nist_control && <span className="text-xs font-mono text-indigo-400">{a.nist_control}</span>}
                  <span className="text-xs text-gray-600">{a.source}</span>
                </div>
              );
            })}
            {alerts.length === 0 && <p className="text-gray-600 text-sm py-8 text-center">No alerts.</p>}
          </div>
        )}

        {/* ===================== LOGS ===================== */}
        {page === "logs" && (
          <div className="bg-anthra-800 border border-anthra-600 rounded-lg overflow-hidden">
            <div className="px-3 py-2 border-b border-anthra-600 text-xs text-gray-500 uppercase tracking-wide">
              Raw Vendor Logs ({logs.length})
            </div>
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-anthra-700 text-gray-600">
                  <th className="text-left px-3 py-1.5 w-14">Level</th>
                  <th className="text-left px-3 py-1.5 w-20">Source</th>
                  <th className="text-left px-3 py-1.5">Message</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((l, i) => (
                  <tr key={i} className="border-b border-anthra-700/30 hover:bg-anthra-700/20">
                    <td className={`px-3 py-1 font-mono font-bold ${LOG_COLORS[l.level] || "text-gray-400"}`}>{l.level}</td>
                    <td className="px-3 py-1 text-gray-500">{l.source}</td>
                    <td className="px-3 py-1 text-gray-300 font-mono">{l.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* ===================== SEARCH (XSS) ===================== */}
        {page === "search" && (
          <div>
            <div className="bg-red-900/20 border border-red-800 rounded-lg p-3 mb-4 text-xs text-red-300">
              <span className="font-bold">SECURITY GAP (SI-10):</span> Search renders raw HTML via{" "}
              <code className="bg-red-900/50 px-1 rounded">dangerouslySetInnerHTML</code>. Stored XSS payloads execute here.
            </div>
            <div className="flex gap-2 mb-4">
              <input value={search} onChange={(e) => setSearch(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && doSearch()} placeholder="Search logs..."
                className="flex-1 bg-anthra-700 border border-anthra-500 text-gray-200 text-sm rounded px-3 py-2 font-mono focus:outline-none focus:ring-1 focus:ring-indigo-500" />
              <button onClick={doSearch} className="bg-indigo-600 hover:bg-indigo-700 text-white text-sm px-4 py-2 rounded">Search</button>
            </div>
            <div className="bg-anthra-800 border border-anthra-600 rounded-lg p-4 font-mono text-sm text-gray-300 min-h-[100px]"
              dangerouslySetInnerHTML={{ __html: searchHtml }} />
          </div>
        )}
      </main>

      <footer className="border-t border-anthra-700 py-3 text-center text-xs text-gray-600">
        Anthra Center v2.0.0 | FedRAMP Moderate (Pre-Hardening) | NIST 800-53 Rev 5 | Ghost Protocol Assessment
      </footer>
    </div>
  );
}
