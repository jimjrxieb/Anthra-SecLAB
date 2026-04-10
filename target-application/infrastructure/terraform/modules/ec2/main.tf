# EC2 Module — Single k3s Host for Staging
# Controls: AC-3 (Access Enforcement), CM-2 (Baseline Config), SC-7 (Boundary Protection)
#
# FinOps decision: EKS control plane = $73/mo. k3s on t3.small = ~$15/mo.
# Same Kubernetes API. Same ArgoCD. Same security posture.
# EKS module preserved at modules/eks/ for reference — this is the deploy path.

data "aws_caller_identity" "current" {}

# --- AMI: Latest Ubuntu 22.04 LTS ---

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# --- SSH Key Pair ---

resource "aws_key_pair" "k3s" {
  key_name   = "${var.project_name}-${var.environment}-k3s"
  public_key = var.ssh_public_key

  tags = { Name = "${var.project_name}-${var.environment}-k3s-key" }
}

# --- Security Group (SC-7) ---

resource "aws_security_group" "k3s" {
  name_prefix = "${var.project_name}-${var.environment}-k3s-"
  description = "k3s staging host - SSH, HTTP/S, K8s API"
  vpc_id      = var.vpc_id

  # SSH — restricted to admin CIDR
  ingress {
    description = "SSH from admin"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidr_blocks
  }

  # HTTP — for Traefik ingress
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTPS — for Traefik ingress
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # K8s API — restricted to admin CIDR
  ingress {
    description = "K8s API"
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = var.admin_cidr_blocks
  }

  # All outbound
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-${var.environment}-k3s-sg" }

  lifecycle { create_before_destroy = true }
}

# --- IAM Instance Profile (AC-6) ---
# EC2 needs: CloudWatch agent, S3 log writes, Secrets Manager reads

resource "aws_iam_role" "k3s" {
  name = "${var.project_name}-${var.environment}-k3s-host"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Name = "${var.project_name}-${var.environment}-k3s-role" }
}

resource "aws_iam_role_policy" "k3s" {
  name = "k3s-host-policy"
  role = aws_iam_role.k3s.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/k3s/${var.project_name}-${var.environment}/*"
      },
      {
        Sid    = "CloudWatchMetrics"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = { "cloudwatch:namespace" = "${var.project_name}-${var.environment}" }
        }
      },
      {
        Sid    = "ReadSecrets"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "arn:aws:secretsmanager:*:*:secret:${var.project_name}/${var.environment}/*"
      },
      {
        Sid    = "WriteLogs"
        Effect = "Allow"
        Action = ["s3:PutObject"]
        Resource = "arn:aws:s3:::${var.project_name}-*-logs-*/*"
      },
      {
        Sid    = "PullImages"
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "k3s" {
  name = "${var.project_name}-${var.environment}-k3s"
  role = aws_iam_role.k3s.name
}

# --- Elastic IP ---

resource "aws_eip" "k3s" {
  domain = "vpc"
  tags   = { Name = "${var.project_name}-${var.environment}-k3s-eip" }
}

# --- EC2 Instance ---

resource "aws_instance" "k3s" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.k3s.key_name
  subnet_id              = var.public_subnet_id
  vpc_security_group_ids = [aws_security_group.k3s.id]
  iam_instance_profile   = aws_iam_instance_profile.k3s.name

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_size
    encrypted             = true
    delete_on_termination = true

    tags = { Name = "${var.project_name}-${var.environment}-k3s-root" }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only (SC-7)
    http_put_response_hop_limit = 1
  }

  monitoring = true # Detailed CloudWatch monitoring (AU-12)

  tags = {
    Name        = "${var.project_name}-${var.environment}-k3s"
    Role        = "k3s-server"
    Ansible     = "true"
    Environment = var.environment
  }
}

resource "aws_eip_association" "k3s" {
  instance_id   = aws_instance.k3s.id
  allocation_id = aws_eip.k3s.id
}
