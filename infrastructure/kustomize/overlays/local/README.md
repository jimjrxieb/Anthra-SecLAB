# Local Overlay — Quick Dev on Docker Desktop K8s

Fast local deploy for UI development. Same Kustomize manifests that run on staging (EC2/k3s) and EKS — just with NodePort access and relaxed PSS.

## When to Use

- Updating the UI and want to see it running on real K8s
- Testing Kustomize changes before pushing to staging
- Verifying the app builds and deploys clean

## Quick Start

```bash
cd /home/jimmie/linkops-industries/GP-copilot/GP-PROJECTS/01-instance/slot-3/Anthra-SecLAB

# 1. Build images (only needed when code changes)
docker build -t portfolio-api:staging -f api/Dockerfile .
docker build -t portfolio-ui:staging -f ui/Dockerfile .

# 2. Create secret (one time — uses key from production slot-1)
kubectl apply -k infrastructure/kustomize/overlays/local/
kubectl create secret generic portfolio-secrets \
  --from-literal=CLAUDE_API_KEY="$(grep CLAUDE_API_KEY ../slot-1/Portfolio-Prod/.env | cut -d'=' -f2)" \
  -n portfolio
kubectl rollout restart deployment portfolio-api -n portfolio

# 3. Wait ~30 seconds, then open
#    UI:  http://localhost:30000
#    API: http://localhost:30080/health
```

## Tear Down

```bash
kubectl delete -k infrastructure/kustomize/overlays/local/
```

## What's Different from Staging

| | Local | Staging (EC2/k3s) | Staging (EKS) |
|---|---|---|---|
| Cluster | Docker Desktop K8s | k3s on EC2 | EKS |
| Images | Built locally, `imagePullPolicy: Never` | GHCR or ECR | GHCR or ECR |
| Access | NodePort (30000, 30080) | Traefik ingress | ALB |
| PSS | baseline (chroma runs as root) | restricted | restricted |
| Cost | $0 | ~$15/mo | ~$133/mo |
