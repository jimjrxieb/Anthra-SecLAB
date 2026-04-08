variable "project_name" { type = string }
variable "environment" { type = string }
variable "vpc_id" { type = string }

variable "public_subnet_id" {
  type        = string
  description = "Public subnet for the k3s host (needs internet access for Traefik)"
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type"
  default     = "t3.small"
}

variable "root_volume_size" {
  type        = number
  description = "Root EBS volume size in GB"
  default     = 30
}

variable "ssh_public_key" {
  type        = string
  description = "SSH public key for k3s host access"
}

variable "admin_cidr_blocks" {
  type        = list(string)
  description = "CIDR blocks allowed SSH + K8s API access"
  default     = []
}
