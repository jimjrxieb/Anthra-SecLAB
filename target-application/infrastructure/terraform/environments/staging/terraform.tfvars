# Anthra-SecLAB — Staging Environment
# NIST 800-53: CM-6 (Configuration Settings)
#
# Two deploy methods — toggle by commenting/uncommenting in main.tf:
#
#   k3s path (default):  EC2 module active, EKS commented out
#     terraform apply → ansible-playbook playbooks/k3s.yml
#     Cost: ~$15/mo
#
#   EKS path:            EKS module active, EC2 commented out
#     terraform apply → ansible-playbook playbooks/eks.yml
#     Cost: ~$133/mo
#
# Both produce the same K8s API. Same ArgoCD. Same app.

project_name      = "anthra"
environment       = "staging"
aws_region        = "us-east-1"
vpc_cidr          = "10.0.0.0/16"

# ── k3s path (active) ──────────────────────────────────────────────────

ec2_instance_type = "t3.medium"   # ~$0.04/hr — spin up, break, fix, destroy
ec2_volume_size   = 30            # GB — enough for k3s + images + data

# SSH — generate with: ssh-keygen -t ed25519 -f ~/.ssh/anthra-k3s
ssh_public_key    = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAIYbTICJhs6N70YhHbm86F/q946vFosYRdlfxzCdAHB jimmie@Jimjrx"

# Restrict SSH + K8s API to your IP
# Find yours: curl -s ifconfig.me
admin_cidr_blocks = ["98.242.161.68/32"] # TODO: Lock down to your IP before deploy

# ── EKS path (uncomment these when switching to EKS in main.tf) ───────

# eks_version        = "1.32"
# node_min           = 2
# node_max           = 4
# node_desired       = 2
# node_instance_type = "t3.medium"

# ── Shared ──────────────────────────────────────────────────────────────

alert_email       = "james012506@yahoo.com"
