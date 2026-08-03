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

output "ssh_command" {
  description = "Ready-made SSH command for the operator."
  value       = "ssh ubuntu@${aws_eip.this.public_ip}"
}
