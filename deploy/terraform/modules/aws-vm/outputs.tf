output "public_ip" {
  description = "Elastic IP of the VM — the target for the service A records."
  value       = aws_eip.this.public_ip
}

output "instance_id" {
  description = "EC2 instance id."
  value       = aws_instance.this.id
}

output "security_group_id" {
  description = "Security group protecting the VM."
  value       = aws_security_group.this.id
}

output "vpc_id" {
  description = "VPC the VM runs in."
  value       = aws_vpc.this.id
}

output "ssh_authorized_keys" {
  # "Rendered for installation", not "installed": Terraform knows what it put
  # in the user data, but it cannot know what cloud-init wrote to disk.
  description = "The authorized_keys lines rendered for installation, by operator name: who is configured to SSH in, and from where. Public keys only — nothing here is secret."
  value       = local.ssh_authorized_keys
}

output "ssh_command" {
  description = "Ready-made SSH command for the operator."
  value       = "ssh ubuntu@${aws_eip.this.public_ip}"
}
