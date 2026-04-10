# Playbook 00: Cluster Deploy — Staging Environment

> **Time:** 30-45 min  |  **Manual:** Full day of clicking through AWS console
> **Replaces:** AWS console + SSH + copy-paste from blog posts
> **Scope:** `deploy`
> **Output:** Running k3s or EKS cluster with ArgoCD, hardened, monitored

> This is the first playbook. Nothing else works until the cluster exists.
> Two paths, same result: a Kubernetes cluster running the Portfolio app
> with security hardening, observability, and GitOps from day one.
>
> **When:** Before everything else. Day 0.

---

## Decision: k3s on EC2 vs EKS

Make this call before you touch Terraform. Once you apply, switching costs a full teardown + rebuild.

| Factor | k3s on EC2 | EKS |
|--------|-----------|-----|
| **Monthly cost** | ~$15 (t3.small) | ~$133 (control plane + 2 nodes) |
| **K8s API** | Same | Same |
| **ArgoCD** | Same | Same |
| **Who manages control plane** | You (k3s binary) | AWS |
| **Who manages nodes** | You (OS, patches, auditd) | AWS (managed node groups) |
| **OS access** | Full SSH, auditd, sysctl | None (managed nodes) |
| **What Ansible does** | Everything: install k3s, harden OS, deploy app | Cluster config only: kubeconfig, addons, deploy app |
| **Break scenarios** | Full control — can break anything | Limited — can't break node OS |
| **Interview story** | "I own every layer" | "I know managed K8s at scale" |
| **Best for** | Learning, pentesting, cost savings | Demonstrating EKS production patterns |

**Recommendation for staging:** Start with k3s. It's cheaper, you own every layer, and the break scenarios in Phase 6 need OS-level access. Switch to EKS later when you want to demonstrate that path too.

---

## Prerequisites

Before you start:

```bash
# 1. AWS CLI configured
aws sts get-caller-identity
# Should return your account ID. If not: aws configure

# 2. Terraform installed
terraform version
# Need >= 1.5.0

# 3. Ansible installed
ansible --version
# Need >= 2.14

# 4. SSH key generated (k3s path only)
ssh-keygen -t ed25519 -f ~/.ssh/anthra-k3s -N ""
cat ~/.ssh/anthra-k3s.pub
# Copy this — you'll paste it into terraform.tfvars

# 5. Know your public IP (for security group lockdown)
curl -s ifconfig.me
```

---

## Step 1: Configure Terraform Variables

```bash
cd /home/jimmie/linkops-industries/GP-copilot/GP-PROJECTS/01-instance/slot-3/Anthra-SecLAB/infrastructure/terraform
```

Edit `environments/staging/terraform.tfvars`:

```bash
# Paste your SSH public key
ssh_public_key = "ssh-ed25519 AAAA... your-key-here"

# Lock down to your IP (from curl ifconfig.me above)
admin_cidr_blocks = ["YOUR.IP.HERE/32"]
```

### If choosing EKS instead of k3s:

1. Open `main.tf`
2. Comment out the `module "ec2"` block
3. Uncomment the `module "eks"`, `module "iam"` blocks
4. In `variables.tf`, uncomment the EKS variables
5. In `terraform.tfvars`, uncomment the EKS section

---

## Step 2: Create Remote State Backend

First time only. The S3 bucket and DynamoDB table store Terraform state.

```bash
# Create state bucket
aws s3api create-bucket \
  --bucket anthra-fedramp-tfstate \
  --region us-east-1

# Enable versioning (so you can recover from bad applies)
aws s3api put-bucket-versioning \
  --bucket anthra-fedramp-tfstate \
  --versioning-configuration Status=Enabled

# Create lock table
aws dynamodb create-table \
  --table-name anthra-fedramp-tflock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region us-east-1
```

---

## Step 3: Terraform Init + Plan

```bash
cd infrastructure/terraform

# Initialize (downloads providers, configures backend)
terraform init -backend-config="key=staging/terraform.tfstate"

# Plan (shows what will be created — READ THIS)
terraform plan -var-file="environments/staging/terraform.tfvars" -out=staging.tfplan
```

**READ THE PLAN.** Look for:

- Number of resources to create (expect 15-25 for k3s path, 40+ for EKS)
- No resources being destroyed (unless you're rebuilding)
- Your IP in the security group rules (not 0.0.0.0/0)
- Instance type matches what you expect

---

## Step 4: Terraform Apply

```bash
terraform apply staging.tfplan
```

When it completes, grab the outputs:

```bash
# k3s path
terraform output k3s_public_ip       # The Elastic IP
terraform output ssh_command          # Ready-to-paste SSH command
terraform output ansible_inventory_line  # For Ansible inventory

# EKS path
# terraform output eks_cluster_name
# terraform output kubeconfig_command
```

---

## Step 5: Verify Infrastructure

### k3s path — SSH to the host

```bash
# Use the SSH command from terraform output
ssh -i ~/.ssh/anthra-k3s ubuntu@$(terraform output -raw k3s_public_ip)

# Verify it's a fresh Ubuntu box
uname -a
df -h        # Check disk space
free -m      # Check memory
```

### EKS path — Get kubeconfig

```bash
aws eks update-kubeconfig \
  --name anthra-staging-eks \
  --region us-east-1

kubectl get nodes
```

---

## Step 6: Update Ansible Inventory

```bash
cd ../ansible

# Edit inventory/hosts.yml — paste the IP from terraform output
# Replace REPLACE_WITH_TERRAFORM_OUTPUT with the actual IP
vim inventory/hosts.yml
```

Or use the one-liner:

```bash
IP=$(cd ../terraform && terraform output -raw k3s_public_ip)
sed -i "s/REPLACE_WITH_TERRAFORM_OUTPUT/$IP/" inventory/hosts.yml
```

---

## Step 7: Run Ansible

### k3s path

```bash
cd infrastructure/ansible

# Full deploy: k3s install → harden → audit → monitoring → SIEM → app
ansible-playbook playbooks/k3s.yml

# Or run one role at a time to watch each step:
ansible-playbook playbooks/k3s.yml --tags install    # k3s only
ansible-playbook playbooks/k3s.yml --tags harden     # OS hardening
ansible-playbook playbooks/k3s.yml --tags audit       # auditd
ansible-playbook playbooks/k3s.yml --tags cloudwatch  # CloudWatch agent
ansible-playbook playbooks/k3s.yml --tags k8s         # cluster hardening (NetworkPolicy, PSS)
ansible-playbook playbooks/k3s.yml --tags loki        # Fluent Bit + Loki + Grafana
ansible-playbook playbooks/k3s.yml --tags deploy      # ArgoCD + portfolio namespace
```

### EKS path

```bash
ansible-playbook playbooks/eks.yml
```

---

## Step 8: Verify the Cluster

```bash
# SSH to k3s host (or use local kubectl for EKS)
ssh -i ~/.ssh/anthra-k3s ubuntu@$(cd ../terraform && terraform output -raw k3s_public_ip)

# Cluster health
kubectl get nodes -o wide
kubectl get pods -A

# ArgoCD running?
kubectl get pods -n argocd

# Portfolio namespace exists with PSS?
kubectl get namespace portfolio --show-labels

# NetworkPolicies applied?
kubectl get networkpolicy -n portfolio

# Monitoring stack running?
kubectl get pods -n monitoring

# Get ArgoCD password
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d && echo
```

---

## Step 9: Run Validation

```bash
# From the repo root
./scripts/security/validate-staging.sh --target http://localhost:8080 --report
```

This runs both manual checks (curl/kubectl) and automated tools (ZAP/Nuclei/trivy if installed). See the report in `reports/validation-*/`.

---

## Completion Checklist

```
[ ] Terraform state bucket + lock table created
[ ] terraform init completed
[ ] terraform plan reviewed (correct resource count, your IP locked down)
[ ] terraform apply completed
[ ] SSH to EC2 works (k3s) OR kubeconfig works (EKS)
[ ] Ansible inventory updated with real IP
[ ] Ansible playbook ran clean
[ ] k3s/EKS cluster shows Ready node(s)
[ ] ArgoCD running in argocd namespace
[ ] portfolio namespace exists with PSS labels
[ ] NetworkPolicies applied (default-deny + allow DNS + allow ingress)
[ ] ResourceQuota + LimitRange applied
[ ] Fluent Bit + Loki + Grafana running in monitoring namespace
[ ] CloudWatch agent shipping logs (k3s path)
[ ] auditd rules loaded (k3s path)
[ ] validate-staging.sh runs and produces report
```

---

## Teardown (when you're done)

```bash
cd infrastructure/terraform
terraform destroy -var-file="environments/staging/terraform.tfvars"

# Confirm: type "yes"
# This deletes: EC2/EKS, VPC, security groups, S3, CloudWatch, everything.
# State bucket and lock table remain (delete manually if needed).
```

---

## Cost Tracking

| Resource | k3s Path | EKS Path |
|----------|---------|----------|
| Compute | t3.small ~$15/mo | Control plane $73 + 2x t3.medium ~$60 |
| Elastic IP | $3.65/mo (when attached) | N/A (ALB) |
| NAT Gateway | ~$32/mo (2 AZ) | ~$32/mo (2 AZ) |
| S3 | <$1/mo | <$1/mo |
| CloudWatch | ~$5/mo | ~$5/mo |
| **Total** | **~$57/mo** | **~$171/mo** |

**FinOps note:** The NAT gateways are the hidden cost in both paths. If you only need the cluster accessible from your IP, you can simplify the VPC to skip private subnets and NAT — drops to ~$20/mo for k3s. That's a Phase 6 optimization.

---

## Next Steps

- [01-cluster-audit.md](01-cluster-audit.md) — audit the fresh cluster
- [02-apply-hardening.md](02-apply-hardening.md) — additional hardening passes
- [03-admission-control.md](03-admission-control.md) — Kyverno policies

---

*Terraform provisions. Ansible configures. GP-Copilot secures.*
