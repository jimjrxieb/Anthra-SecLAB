# Portfolio Redesign Discovery

**Date**: 2026-01-05
**GitHub Repo**: https://github.com/jimjrxieb/Portfolio

## Project Structure

```
Portfolio/
├── ui/                          # Frontend (React + Vite + Tailwind)
│   ├── src/
│   │   ├── App.jsx              # Entry point
│   │   ├── pages/Landing.jsx    # Main page (TO BE REFACTORED)
│   │   ├── components/
│   │   │   ├── ChatPanel.tsx    # Chat wrapper
│   │   │   ├── ChatBoxFixed.tsx # Sheyla chatbot
│   │   │   └── Projects.tsx     # Projects list
│   │   └── lib/api.ts           # API utilities
│   ├── tailwind.config.js       # Theme colors defined
│   └── public/                  # Static assets
├── api/                         # Backend (FastAPI)
│   └── main.py                  # API endpoints
├── backend/                     # Additional backend
│   └── engines/                 # LLM engines
├── rag-pipeline/                # RAG system
│   ├── 00-new-rag-data/
│   ├── 03-ingest-rag-data/      # ChromaDB ingestion
│   └── run_pipeline.py
├── infrastructure/
│   ├── method1-simple-kubectl/  # K8s manifests
│   │   └── k8s-security/
│   │       ├── network-policies/
│   │       ├── rbac/
│   │       └── pod-security/
│   ├── method2-terraform-localstack/
│   └── method3-helm-argocd/
│       ├── argocd/
│       └── helm-chart/
├── GP-copilot/                  # Security automation
│   ├── conftest-policies/       # OPA policies
│   └── gatekeeper-temps/        # Gatekeeper templates
└── .github/workflows/main.yml   # CI/CD pipeline
```

## Existing Links (From Current Code)

- **LinkedIn**: https://www.linkedin.com/in/jimmie-coleman-jr-564a8a199/
- **GitHub**: https://github.com/jimjrxieb
- **Repo**: https://github.com/jimjrxieb/Portfolio

## Styling System

- **Framework**: Tailwind CSS
- **Theme Colors** (from tailwind.config.js):
  - `jade-*`: Green accent (#00A86B)
  - `crystal-*`: Blue accent (#0ea5e9)
  - `gold-*`: Gold accent (#f59e0b)
  - `ink`: Background (#0A0A0A)
  - `snow`: White (#FAFAFA)
  - `text-primary`: White (#FFFFFF)
  - `text-secondary`: Muted gray (#8b949e)

## GitHub Links for Skills

### AI/ML Architecture
| Skill | Path | GitHub URL |
|-------|------|------------|
| RAG Pipeline | `rag-pipeline/` | https://github.com/jimjrxieb/Portfolio/tree/main/rag-pipeline |
| ChromaDB Vectors | `rag-pipeline/03-ingest-rag-data/` | https://github.com/jimjrxieb/Portfolio/tree/main/rag-pipeline/03-ingest-rag-data |
| Ollama Embeddings | `rag-pipeline/` | https://github.com/jimjrxieb/Portfolio/tree/main/rag-pipeline |
| Claude API | `api/main.py` | https://github.com/jimjrxieb/Portfolio/blob/main/api/main.py |
| Sheyla AI | `ui/src/components/ChatBoxFixed.tsx` | https://github.com/jimjrxieb/Portfolio/blob/main/ui/src/components/ChatBoxFixed.tsx |

### Security Scanning
| Skill | Path | GitHub URL |
|-------|------|------------|
| Trivy | `.github/workflows/main.yml#L310` | https://github.com/jimjrxieb/Portfolio/blob/main/.github/workflows/main.yml#L310 |
| Semgrep | `.github/workflows/main.yml#L60` | https://github.com/jimjrxieb/Portfolio/blob/main/.github/workflows/main.yml#L60 |
| detect-secrets | `.github/workflows/main.yml#L131` | https://github.com/jimjrxieb/Portfolio/blob/main/.github/workflows/main.yml#L131 |
| Bandit | `.github/workflows/main.yml#L104` | https://github.com/jimjrxieb/Portfolio/blob/main/.github/workflows/main.yml#L104 |
| Safety | `.github/workflows/main.yml#L110` | https://github.com/jimjrxieb/Portfolio/blob/main/.github/workflows/main.yml#L110 |

### Policy-as-Code
| Skill | Path | GitHub URL |
|-------|------|------------|
| OPA/Conftest | `GP-copilot/02-package/conftest-policies/` | https://github.com/jimjrxieb/Portfolio/tree/main/GP-copilot/02-package/conftest-policies |
| Gatekeeper | `GP-copilot/02-package/gatekeeper-constraints/` | https://github.com/jimjrxieb/Portfolio/tree/main/GP-copilot/02-package/gatekeeper-constraints |
| Policy Tests | `.github/workflows/main.yml#L369` | https://github.com/jimjrxieb/Portfolio/blob/main/.github/workflows/main.yml#L369 |

### Deployment Methods
| Skill | Path | GitHub URL |
|-------|------|------------|
| kubectl Manifests | `infrastructure/method1-simple-kubectl/` | https://github.com/jimjrxieb/Portfolio/tree/main/infrastructure/method1-simple-kubectl |
| Terraform | `infrastructure/method2-terraform-localstack/` | https://github.com/jimjrxieb/Portfolio/tree/main/infrastructure/method2-terraform-localstack |
| Helm Charts | `infrastructure/method3-helm-argocd/helm-chart/` | https://github.com/jimjrxieb/Portfolio/tree/main/infrastructure/method3-helm-argocd/helm-chart |
| ArgoCD GitOps | `infrastructure/method3-helm-argocd/argocd/` | https://github.com/jimjrxieb/Portfolio/tree/main/infrastructure/method3-helm-argocd/argocd |

### CI/CD Pipeline
| Skill | Path | GitHub URL |
|-------|------|------------|
| GitHub Actions | `.github/workflows/main.yml` | https://github.com/jimjrxieb/Portfolio/blob/main/.github/workflows/main.yml |
| Parallel Security Scans | `.github/workflows/main.yml#L46` | https://github.com/jimjrxieb/Portfolio/blob/main/.github/workflows/main.yml#L46 |
| Multi-env Deploy | `.github/workflows/main.yml#L411` | https://github.com/jimjrxieb/Portfolio/blob/main/.github/workflows/main.yml#L411 |

### Hardening
| Skill | Path | GitHub URL |
|-------|------|------------|
| NetworkPolicies | `infrastructure/method1-simple-kubectl/k8s-security/network-policies/` | https://github.com/jimjrxieb/Portfolio/tree/main/infrastructure/method1-simple-kubectl/k8s-security/network-policies |
| RBAC | `infrastructure/method1-simple-kubectl/k8s-security/rbac/` | https://github.com/jimjrxieb/Portfolio/tree/main/infrastructure/method1-simple-kubectl/k8s-security/rbac |
| Pod Security | `infrastructure/method1-simple-kubectl/k8s-security/pod-security/` | https://github.com/jimjrxieb/Portfolio/tree/main/infrastructure/method1-simple-kubectl/k8s-security/pod-security |
| Non-root Containers | `ui/Dockerfile` | https://github.com/jimjrxieb/Portfolio/blob/main/ui/Dockerfile |

### Infrastructure
| Skill | Path | GitHub URL |
|-------|------|------------|
| Kubernetes | `infrastructure/` | https://github.com/jimjrxieb/Portfolio/tree/main/infrastructure |
| FastAPI Backend | `api/main.py` | https://github.com/jimjrxieb/Portfolio/blob/main/api/main.py |
| React/Vite Frontend | `ui/src/` | https://github.com/jimjrxieb/Portfolio/tree/main/ui/src |

## Certifications

- **CKA** (Certified Kubernetes Administrator): Complete
- **Security+** (CompTIA Security+): Complete
- **AWS Certified Solutions Architect – Associate**: Complete
- **CNPA** (Certified Cloud Native Platform Engineering Associate): In Progress

## Resume

- **Status**: No resume.pdf found in public/
- **Action**: User should add resume to `ui/public/resume.pdf`

## Sheyla Chat Trigger

- Current: Embedded in ChatPanel component
- Location: `ui/src/components/ChatBoxFixed.tsx`
- Trigger: Component is always visible in left panel

## Components to Create

1. `Hero.tsx` - Full-width hero with name, title, links, certs, quote
2. `PortfolioBuild.tsx` - Left column with skill categories + GitHub links
3. `CurrentVenture.tsx` - Right column with GP-Copilot + other projects
4. Update `Landing.jsx` to use new layout
