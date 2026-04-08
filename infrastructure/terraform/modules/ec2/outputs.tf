output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.k3s.id
}

output "public_ip" {
  description = "Elastic IP of the k3s host"
  value       = aws_eip.k3s.public_ip
}

output "private_ip" {
  description = "Private IP of the k3s host"
  value       = aws_instance.k3s.private_ip
}

output "security_group_id" {
  description = "Security group ID for the k3s host"
  value       = aws_security_group.k3s.id
}

output "instance_profile_arn" {
  description = "IAM instance profile ARN"
  value       = aws_iam_instance_profile.k3s.arn
}

output "ssh_key_name" {
  description = "SSH key pair name"
  value       = aws_key_pair.k3s.key_name
}
