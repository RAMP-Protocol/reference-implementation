# Unit tests for the aws-vm module. The AWS provider is MOCKED: no
# credentials, no API calls, no real resources — plan mode against generated
# placeholder values. The one apply-mode run at the bottom is mocked too: it
# exists because computed attributes (EIP address, instance id) stay unknown
# in a plan, and the output wiring can only be asserted against the mock's
# generated values.
#
# Run from the module directory: terraform init && terraform test

mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["us-east-1a", "us-east-1b"]
    }
  }

  mock_data "aws_ami" {
    defaults = {
      id = "ami-0123456789abcdef0"
    }
  }
}

variables {
  name_prefix      = "ramp-test"
  ssh_public_key   = "ssh-ed25519 AAAATESTKEY operator@test"
  ssh_ingress_cidr = "203.0.113.7/32"
  user_data        = "#cloud-config\npackage_update: true\n"
}

run "graviton_instance_types_are_rejected" {
  command = plan

  variables {
    instance_type = "t4g.large"
  }

  expect_failures = [
    var.instance_type,
  ]
}

run "graviton_char_class_families_are_rejected" {
  command = plan

  variables {
    instance_type = "c7g.xlarge"
  }

  expect_failures = [
    var.instance_type,
  ]
}

run "newer_graviton_x8g_is_rejected" {
  command = plan

  variables {
    instance_type = "x8g.large"
  }

  expect_failures = [
    var.instance_type,
  ]
}

run "graviton_hpc_family_is_rejected" {
  command = plan

  variables {
    instance_type = "hpc7g.16xlarge"
  }

  expect_failures = [
    var.instance_type,
  ]
}

# g5 (amd64 GPU) is one character away from g5g (Graviton) — the reject
# pattern must not swallow it.
run "amd64_near_miss_types_are_accepted" {
  command = plan

  variables {
    instance_type = "g5.xlarge"
  }

  assert {
    condition     = aws_instance.this.instance_type == "g5.xlarge"
    error_message = "g5 (amd64) must pass the arm64 reject pattern"
  }
}

run "open_ssh_cidr_is_rejected" {
  command = plan

  variables {
    ssh_ingress_cidr = "0.0.0.0/0"
  }

  expect_failures = [
    var.ssh_ingress_cidr,
  ]
}

# "0.0.0.0/1" is half the internet — as good as open. The validation bounds
# the prefix width, not just the one literal 0.0.0.0/0.
run "half_open_ssh_cidr_is_rejected" {
  command = plan

  variables {
    ssh_ingress_cidr = "0.0.0.0/1"
  }

  expect_failures = [
    var.ssh_ingress_cidr,
  ]
}

run "non_ipv4_ssh_cidr_is_rejected" {
  command = plan

  variables {
    ssh_ingress_cidr = "::/0"
  }

  expect_failures = [
    var.ssh_ingress_cidr,
  ]
}

run "user_data_is_gzipped_within_ec2_limit" {
  command = plan

  assert {
    condition     = aws_instance.this.user_data_base64 == base64gzip("#cloud-config\npackage_update: true\n")
    error_message = "User data must be delivered gzip+base64 (16 KB raw EC2 limit)"
  }

  assert {
    condition     = aws_instance.this.user_data_replace_on_change == true
    error_message = "Config changes must roll the instance by default"
  }
}

run "ssh_is_restricted_and_web_is_public" {
  command = plan

  assert {
    condition = anytrue([
      for rule in aws_security_group.this.ingress :
      rule.from_port == 22 && rule.to_port == 22 && rule.protocol == "tcp" && contains(rule.cidr_blocks, "203.0.113.7/32") && length(rule.cidr_blocks) == 1
    ])
    error_message = "SSH ingress must be TCP port 22 only, limited to exactly the operator CIDR"
  }

  assert {
    condition = anytrue([
      for rule in aws_security_group.this.ingress :
      rule.from_port == 80 && rule.to_port == 80 && rule.protocol == "tcp" && contains(rule.cidr_blocks, "0.0.0.0/0")
    ])
    error_message = "HTTP must be TCP port 80 only, open to the world (ACME HTTP-01)"
  }

  assert {
    condition = anytrue([
      for rule in aws_security_group.this.ingress :
      rule.from_port == 443 && rule.to_port == 443 && rule.protocol == "tcp" && contains(rule.cidr_blocks, "0.0.0.0/0")
    ])
    error_message = "HTTPS must be TCP port 443 only, open to the world (public services)"
  }

  assert {
    condition     = length(aws_security_group.this.ingress) == 3
    error_message = "Exactly three ingress rules: SSH, HTTP, HTTPS"
  }

  # Open egress is a documented decision (first boot needs apt, get.docker.com,
  # the registry, Let's Encrypt; runtime fetches arbitrary publisher origins) —
  # this assert makes the decision enforced instead of a comment.
  assert {
    condition = length(aws_security_group.this.egress) == 1 && anytrue([
      for rule in aws_security_group.this.egress :
      rule.from_port == 0 && rule.to_port == 0 && rule.protocol == "-1" && contains(rule.cidr_blocks, "0.0.0.0/0")
    ])
    error_message = "Exactly one egress rule: all outbound open (staging posture, see main.tf)"
  }
}

run "instance_uses_defaults" {
  command = plan

  assert {
    condition     = aws_instance.this.instance_type == "t3.large"
    error_message = "Default instance type must be t3.large (amd64)"
  }

  assert {
    condition     = aws_instance.this.root_block_device[0].volume_size == 40 && aws_instance.this.root_block_device[0].volume_type == "gp3"
    error_message = "Root volume must default to 40 GiB gp3"
  }

  assert {
    condition     = aws_instance.this.root_block_device[0].encrypted == true
    error_message = "Root volume must be encrypted at rest — it carries the stack's signing keys (user data lands on disk)"
  }

  assert {
    condition     = aws_subnet.public.map_public_ip_on_launch == true
    error_message = "Public subnet must assign public IPs (single public-subnet topology)"
  }

  assert {
    condition     = aws_instance.this.metadata_options[0].http_tokens == "required" && aws_instance.this.metadata_options[0].http_put_response_hop_limit == 1
    error_message = "IMDSv2 must be enforced with hop limit 1 — user data carries key material and containers must not reach the metadata service"
  }
}

run "names_and_wiring_derive_from_inputs" {
  command = plan

  assert {
    condition     = aws_key_pair.this.public_key == "ssh-ed25519 AAAATESTKEY operator@test"
    error_message = "Key pair must install exactly the operator's public key"
  }

  assert {
    condition     = aws_key_pair.this.key_name == "ramp-test-operator" && aws_instance.this.key_name == "ramp-test-operator"
    error_message = "Instance must log in with the key pair this module creates"
  }

  assert {
    condition     = aws_security_group.this.name == "ramp-test-vm"
    error_message = "Security group name must derive from name_prefix"
  }

  assert {
    condition     = aws_vpc.this.tags["Name"] == "ramp-test-vpc" && aws_instance.this.tags["Name"] == "ramp-test-vm" && aws_eip.this.tags["Name"] == "ramp-test-vm-eip"
    error_message = "Name tags must derive from name_prefix"
  }

  assert {
    condition     = aws_vpc.this.enable_dns_support == true && aws_vpc.this.enable_dns_hostnames == true
    error_message = "VPC DNS resolution and hostnames must be on (instances resolve registry/ACME hosts)"
  }
}

run "overrides_are_honored" {
  command = plan

  variables {
    root_volume_gb              = 100
    vpc_cidr                    = "10.99.0.0/28"
    user_data_replace_on_change = false
  }

  assert {
    condition     = aws_instance.this.root_block_device[0].volume_size == 100
    error_message = "root_volume_gb must drive the root volume size"
  }

  # Single public-subnet topology: the one subnet spans the whole VPC.
  assert {
    condition     = aws_vpc.this.cidr_block == "10.99.0.0/28" && aws_subnet.public.cidr_block == "10.99.0.0/28"
    error_message = "vpc_cidr must drive both the VPC and the subnet (subnet spans the VPC)"
  }

  assert {
    condition     = aws_instance.this.user_data_replace_on_change == false
    error_message = "user_data_replace_on_change=false must keep the instance on config changes"
  }
}

# apply (still fully mocked — no credentials, no API) because the EIP address
# and instance id are computed: unknown in a plan, generated placeholders in a
# mocked apply. This is the only way to assert the output wiring.
run "eip_association_and_outputs" {
  command = apply

  assert {
    condition     = aws_eip.this.domain == "vpc"
    error_message = "EIP must be a VPC EIP"
  }

  assert {
    condition     = aws_eip_association.this.allocation_id == aws_eip.this.id && aws_eip_association.this.instance_id == aws_instance.this.id
    error_message = "The EIP must be associated with the instance this module creates"
  }

  assert {
    condition     = output.public_ip == aws_eip.this.public_ip
    error_message = "public_ip output must be the EIP (stable across instance recreation), never the instance's ephemeral address"
  }

  assert {
    condition     = output.ssh_command == "ssh ubuntu@${aws_eip.this.public_ip}"
    error_message = "ssh_command output must target the ubuntu user at the EIP"
  }
}
