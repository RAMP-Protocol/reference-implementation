# Unit tests for the aws-vm module. The AWS provider is MOCKED: no
# credentials, no API calls, no real resources — plan mode against generated
# placeholder values. The one apply-mode run at the bottom is mocked too: it
# exists because computed attributes (EIP address, instance id) stay unknown
# in a plan, and the output wiring can only be asserted against the mock's
# generated values.
#
# Run from the module directory: terraform init && terraform test

# ONLY "aws" is mocked, and the cloudinit provider must stay unmocked. cloudinit
# is a local-only provider, so its data source is read for real during a plan and
# part[*].content and rendered carry real values. Adding mock_provider
# "cloudinit" would replace rendered with a generated placeholder and quietly
# turn every cloud-config assertion in this file into a test of the mock.
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

  # key_name is optional and computed, so an unmocked apply fabricates a random
  # placeholder for it and no assertion could tell "no key pair" from "a key
  # pair" apart. Pinning the default to "" removes the fabrication. This does
  # not make the assertion circular: a mock default only fills an attribute the
  # configuration leaves unset, so reintroducing key_name on the instance
  # produces the configured value and the assertion goes red.
  mock_resource "aws_instance" {
    defaults = {
      key_name = ""
    }
  }
}

# Alice has one address, Bob has two. Every positive run below reads these, so
# the union the security group must open is exactly three addresses and the two
# from= lines must differ from each other.
variables {
  name_prefix = "ramp-test"
  user_data   = "#cloud-config\npackage_update: true\n"

  ssh_operators = {
    alice = {
      public_key   = "ssh-ed25519 AAAAALICE alice@test"
      source_cidrs = ["203.0.113.7/32"]
    }
    bob = {
      public_key   = "ssh-ed25519 AAAABOB bob@test"
      source_cidrs = ["198.51.100.24/32", "198.51.100.25/32"]
    }
  }
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

run "empty_operator_map_is_rejected" {
  command = plan

  variables {
    ssh_operators = {}
  }

  expect_failures = [
    var.ssh_operators,
  ]
}

run "operator_without_any_address_is_rejected" {
  command = plan

  variables {
    ssh_operators = {
      alice = {
        public_key   = "ssh-ed25519 AAAAALICE alice@test"
        source_cidrs = []
      }
    }
  }

  expect_failures = [
    var.ssh_operators,
  ]
}

# This run carries more weight than the others. It fails a check that loops
# operators but not addresses, AND a check that loops addresses but stops at the
# first operator.
#
# Bob's bad address is 203.0.113.7/0 and MUST NOT be "simplified" back to
# 0.0.0.0/0. source_cidrs is a set, and Terraform iterates a set of strings in
# lexicographic order, so 0.0.0.0/0 would be examined FIRST — a validation
# weakened to read only the first address would still reject it and this run
# would still pass, which is the opposite of what it is for. 198.51.100.24/32
# sorts before 203.0.113.7/0, so a weakened check sees the valid address first
# and this run goes red as intended. The value is open-equivalent for the same
# reason 0.0.0.0/0 is: a /0 prefix covers every address regardless of the host
# bits written in front of it.
run "open_cidr_on_the_second_operator_is_rejected" {
  command = plan

  variables {
    ssh_operators = {
      alice = {
        public_key   = "ssh-ed25519 AAAAALICE alice@test"
        source_cidrs = ["203.0.113.7/32"]
      }
      bob = {
        public_key   = "ssh-ed25519 AAAABOB bob@test"
        source_cidrs = ["198.51.100.24/32", "203.0.113.7/0"]
      }
    }
  }

  expect_failures = [
    var.ssh_operators,
  ]
}

run "non_host_cidr_is_rejected" {
  command = plan

  variables {
    ssh_operators = {
      alice = {
        public_key   = "ssh-ed25519 AAAAALICE alice@test"
        source_cidrs = ["203.0.113.0/24"]
      }
    }
  }

  expect_failures = [
    var.ssh_operators,
  ]
}

# Host bits set inside a wider prefix. AWS canonicalizes the security-group rule
# to 203.0.113.0/24 and returns that, while the configuration still says
# 203.0.113.7/24 — a permanent plan diff, and from= keeps the original string so
# the two halves of the design also stop matching.
run "host_bits_cidr_is_rejected" {
  command = plan

  variables {
    ssh_operators = {
      alice = {
        public_key   = "ssh-ed25519 AAAAALICE alice@test"
        source_cidrs = ["203.0.113.7/24"]
      }
    }
  }

  expect_failures = [
    var.ssh_operators,
  ]
}

run "non_ipv4_cidr_is_rejected" {
  command = plan

  variables {
    ssh_operators = {
      alice = {
        public_key   = "ssh-ed25519 AAAAALICE alice@test"
        source_cidrs = ["::/0"]
      }
    }
  }

  expect_failures = [
    var.ssh_operators,
  ]
}

# The comments differ on purpose. OpenSSH matches on the key type and blob and
# ignores the comment, so these two entries are one credential presented twice.
# When a line's key matches but its from= refuses the connecting address,
# OpenSSH logs the refusal and keeps reading the file for another matching line
# — so this blob would be accepted from the union of both address sets. A
# duplicate check written against the whole line is the natural way to write it,
# and it misses this exactly because the comments differ.
run "shared_key_blob_is_rejected" {
  command = plan

  variables {
    ssh_operators = {
      alice = {
        public_key   = "ssh-ed25519 AAAASHARED alice@test"
        source_cidrs = ["203.0.113.7/32"]
      }
      bob = {
        public_key   = "ssh-ed25519 AAAASHARED bob@test"
        source_cidrs = ["198.51.100.24/32"]
      }
    }
  }

  expect_failures = [
    var.ssh_operators,
  ]
}

# An accidental multi-line paste installs a second authorized_keys line, and
# that line carries no from= at all: silent unrestricted access.
run "multiline_public_key_is_rejected" {
  command = plan

  variables {
    ssh_operators = {
      alice = {
        public_key   = "ssh-ed25519 AAAAALICE alice@test\nssh-ed25519 AAAANOBODY nobody@test"
        source_cidrs = ["203.0.113.7/32"]
      }
    }
  }

  expect_failures = [
    var.ssh_operators,
  ]
}

# Operator-supplied options would land in front of ours on the rendered line.
run "public_key_carrying_options_is_rejected" {
  command = plan

  variables {
    ssh_operators = {
      alice = {
        public_key   = "from=\"0.0.0.0/0\" ssh-ed25519 AAAAALICE alice@test"
        source_cidrs = ["203.0.113.7/32"]
      }
    }
  }

  expect_failures = [
    var.ssh_operators,
  ]
}

# override_data rather than a real oversized operator map: the document is
# gzipped before base64, so producing 16 KB of compressed output would need
# hundreds of kilobytes of poorly compressible fixture input. Overriding the
# data source's rendered attribute tests the precondition directly, which is the
# guard actually under test. The instance is what carries the precondition, so
# the instance is what is expected to fail.
run "oversized_user_data_is_rejected" {
  command = plan

  override_data {
    target = data.cloudinit_config.this
    values = {
      # 683 * 32 = 21856 characters, just past the 21848 the precondition
      # compares with <. range() refuses to generate more than 1024 values, so
      # the repetition count stays small and the repeated chunk carries the
      # length.
      rendered = join("", [for _ in range(683) : "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"])
    }
  }

  expect_failures = [
    aws_instance.this,
  ]
}

# The run this replaces was called "user_data_is_gzipped_within_ec2_limit" and
# asserted no limit at all — it compared the encoding and nothing else. The
# limit is now enforced by the precondition on the instance, which evaluates on
# every plan of every run in this file; oversized_user_data_is_rejected above is
# what proves that guard fires.
run "ssh_config_reaches_the_instance" {
  command = plan

  assert {
    condition     = length(data.cloudinit_config.this.part) == 2
    error_message = "user data must carry the stack config and the SSH config"
  }

  # Decoded, not searched with strcontains. yamlencode double-quotes every
  # string it emits, so the inner quotes of from= come out escaped and a literal
  # search for the unescaped form can never match. Both try() fallbacks fail
  # closed: a decode that fails yields the empty set, which never equals a
  # non-empty one.
  assert {
    condition = try(
      toset(yamldecode(trimprefix(
        data.cloudinit_config.this.part[1].content,
        "#cloud-config\n"
      )).ssh_authorized_keys),
      toset([])
    ) == toset(values(local.ssh_authorized_keys))
    error_message = "the SSH cloud-config must contain exactly the restricted operator keys"
  }

  # Its own assertion, because the comparison above decodes only the
  # ssh_authorized_keys key — deleting this flag would leave that one passing.
  # The fallback is cloud-init's own default of true, which is the value this
  # refuses.
  assert {
    condition = try(yamldecode(trimprefix(
      data.cloudinit_config.this.part[1].content,
      "#cloud-config\n"
    )).allow_public_ssh_keys, true) == false
    error_message = "the SSH cloud-config must switch off cloud-init's import of datasource keys"
  }

  assert {
    condition     = aws_instance.this.user_data_base64 == data.cloudinit_config.this.rendered
    error_message = "the instance must boot the multipart document, not something else"
  }

  assert {
    condition     = aws_instance.this.user_data_replace_on_change == true
    error_message = "Config changes must roll the instance by default"
  }
}

# Without this run, dropping the FIDO2 types from the key-shape regex would
# break nothing in the suite. A hardware-backed key is what a security-conscious
# operator brings.
run "hardware_backed_key_is_accepted" {
  command = plan

  variables {
    ssh_operators = {
      alice = {
        public_key   = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5 alice@yubikey"
        source_cidrs = ["203.0.113.7/32"]
      }
    }
  }

  assert {
    condition     = output.ssh_authorized_keys["alice"] == "from=\"203.0.113.7/32\" sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5 alice@yubikey"
    error_message = "a FIDO2 hardware-backed key must be accepted and restricted like any other"
  }
}

run "ssh_is_restricted_and_web_is_public" {
  command = plan

  # The exact set, not a count: three wrong addresses would satisfy a length
  # check. The group opens the union of every operator's addresses and cannot
  # tell one operator's key from another's — the from= option on each
  # authorized_keys line is the half that can.
  assert {
    condition = toset(
      [for r in aws_security_group.this.ingress : r if r.from_port == 22][0].cidr_blocks
      ) == toset([
        "198.51.100.24/32", "198.51.100.25/32", "203.0.113.7/32"
    ])
    error_message = "the SSH rule must open exactly the union of operator addresses"
  }

  assert {
    condition = anytrue([
      for rule in aws_security_group.this.ingress :
      rule.from_port == 22 && rule.to_port == 22 && rule.protocol == "tcp"
    ])
    error_message = "SSH ingress must be TCP port 22 only"
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
    condition     = output.ssh_authorized_keys["alice"] == "from=\"203.0.113.7/32\" ssh-ed25519 AAAAALICE alice@test"
    error_message = "alice's key must be restricted to alice's address, not the union"
  }

  assert {
    condition     = output.ssh_authorized_keys["bob"] == "from=\"198.51.100.24/32,198.51.100.25/32\" ssh-ed25519 AAAABOB bob@test"
    error_message = "bob's key must carry both of bob's addresses and neither of alice's"
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

  # EC2 injects a key pair into authorized_keys with no options, so it works
  # from every address in the union — one unrestricted line defeats every
  # restricted line beside it. This assertion is what fails if a key pair is
  # reintroduced. It lives in the apply-mode run because key_name is an
  # optional computed attribute: it stays unknown in a plan, so the same
  # assertion under command = plan fails to evaluate rather than checking
  # anything.
  assert {
    condition     = aws_instance.this.key_name == null || aws_instance.this.key_name == ""
    error_message = "the instance must carry no EC2 key pair — an unrestricted key defeats every from= restriction"
  }

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
