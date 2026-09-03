# One amd64 EC2 instance in a minimal, self-contained VPC (public subnet +
# internet gateway), with a stable Elastic IP. The whole RAMP stack runs as
# Docker Compose on this instance — TigerBeetle needs IPC_LOCK +
# seccomp=unconfined + io_uring, which rules out Fargate; a plain VM runs it
# with the same flags as local development.

locals {
  # sort() for a stable plan diff; map iteration is already key-ordered.
  ssh_source_cidrs = sort(distinct(flatten([
    for o in var.ssh_operators : tolist(o.source_cidrs)
  ])))

  # Keyed by operator name so the output answers "who has access", not just
  # "what lines exist". from= is what binds a key to its own addresses: the
  # security group opens the union, and this refuses a key presented from
  # someone else's address inside that union.
  ssh_authorized_keys = {
    for name, o in var.ssh_operators :
    name => format("from=%q %s",
      join(",", sort(tolist(o.source_cidrs))),
    trimspace(o.public_key))
  }

  # yamlencode, not a template: from="..." carries quotes that would have to be
  # escaped by hand inside YAML, and the values come from operator input. A YAML
  # mistake here has no recovery path — after this change authorized_keys comes
  # from the user data alone, and a malformed part leaves the instance
  # unreachable while Terraform destroys the original in the same apply.
  # yamlencode does the quoting itself, so malformed YAML cannot happen.
  #
  # allow_public_ssh_keys = false turns off cloud-init's import of keys from
  # datasource metadata, which defaults to true. Removing key_name leaves AWS
  # with nothing to supply today, so this changes no behaviour now. It states
  # the invariant in the configuration instead of leaving it as a consequence
  # of a deletion elsewhere in this file: authorized_keys comes from this user
  # data alone.
  ssh_cloud_config = "#cloud-config\n${yamlencode({
    allow_public_ssh_keys = false
    ssh_authorized_keys   = values(local.ssh_authorized_keys)
  })}"

  # EC2 caps user data at 16384 bytes BEFORE base64, and cloudinit_config
  # returns the document already base64-encoded. Base64 of n bytes is
  # 4*ceil(n/3) characters, so 16384 bytes is 21848 characters. Written once
  # here and read by the precondition below and by the module's tests.
  ec2_user_data_max_base64 = 21848
}

# Zones that are actually usable in the target region/account, so the subnet
# can pick one without hardcoding a zone name (names vary per account/region).
data "aws_availability_zones" "available" {
  state = "available"
}

data "cloudinit_config" "this" {
  gzip          = true
  base64_encode = true

  # Parts are emitted in declaration order. Both are cloud-config and share no
  # top-level key — write_files/runcmd on one side, ssh_authorized_keys and
  # allow_public_ssh_keys on the other — so cloud-init's merge has nothing to
  # resolve. Only a real boot confirms that, which is what the rehearsal does.
  part {
    content_type = "text/cloud-config"
    filename     = "00-stack.yaml"
    content      = var.user_data
  }

  part {
    content_type = "text/cloud-config"
    filename     = "10-ssh-operators.yaml"
    content      = local.ssh_cloud_config
  }
}

# Canonical's official Ubuntu 24.04 LTS amd64 image, newest build.
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical's AWS account — guards against lookalike AMIs

  filter {
    # Pin the release (24.04), float the build: trailing -* plus most_recent
    # always picks the latest patched image of this release.
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.name_prefix}-vpc" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${var.name_prefix}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.vpc_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = { Name = "${var.name_prefix}-public-subnet" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    # 0.0.0.0/0 = every destination: send all non-local traffic to the
    # internet gateway.
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = { Name = "${var.name_prefix}-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "this" {
  name        = "${var.name_prefix}-vm"
  description = "RAMP staging VM: SSH restricted, HTTP/HTTPS public"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "SSH from the operator addresses only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    # The union of every operator's addresses. The group cannot tell one
    # operator's key from another's, so it is only half the control — the
    # from= option on each authorized_keys line is the other half.
    cidr_blocks = local.ssh_source_cidrs
  }

  ingress {
    description = "HTTP (ACME cert validation + Caddy HTTP-to-HTTPS redirect)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS (Caddy fronting exchange/broker/mcp)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Open egress is deliberate for staging: first boot talks to apt mirrors,
  # get.docker.com, the container registry, Let's Encrypt, and — at runtime —
  # arbitrary publisher origins for well-known fetches. An allowlist of those
  # destinations would be brittle (they are CDN-backed, IP ranges churn) and
  # would break first boot silently. Tighten for production, not here.
  egress {
    description = "All outbound (image pulls, ACME, well-known fetches)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-vm-sg" }
}

# No aws_key_pair and no key_name on purpose. EC2 injects a key pair into
# authorized_keys with no options, so it works from every address in the union
# — one unrestricted line defeats every restricted line beside it. Every key
# this instance accepts arrives through the cloud-init document below, carrying
# its own from= restriction.
resource "aws_instance" "this" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.this.id]

  # cloud-init transparently un-gzips; gzip keeps the rendered config (compose
  # file, Caddyfile, key material) under EC2's 16 KB raw user-data limit.
  user_data_base64            = data.cloudinit_config.this.rendered
  user_data_replace_on_change = var.user_data_replace_on_change

  lifecycle {
    # A test asserts over the small fixture map its test file declares, and
    # says nothing about the real ssh_operators in a stack's tfvars. Both
    # halves of the document grow with real input, and the multipart MIME
    # wrapper adds to both. This evaluates the actual deployed value on every
    # plan, turning "the instance silently fails to launch" into a plan-time
    # error — which matters because this stack has no break-glass path.
    precondition {
      condition     = length(data.cloudinit_config.this.rendered) < local.ec2_user_data_max_base64
      error_message = "Rendered cloud-init exceeds EC2's 16 KB user-data limit — the instance would fail to launch"
    }
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = var.root_volume_gb
    # The volume carries every secret in the stack — signing keys, database
    # passwords, the identity plane's key-store and OIDC credentials (via
    # user data → disk); at-rest encryption with the account's default KMS
    # key is free and invisible to the instance.
    encrypted = true
  }

  # IMDSv2 only: user data (readable through the metadata service) carries
  # every secret the stack runs on — including the credentials that would let
  # a reader sign as any registered agent — so the token-required hop must
  # stay closed to any SSRF a container might be tricked into. This is the
  # mitigation that keeps the accepted user-data exposure bounded to the AWS
  # account rather than reachable from a compromised container. Hop limit 1
  # (the AWS default, pinned here on purpose) additionally blocks
  # Docker-bridge containers from reaching the metadata service at all —
  # nothing in the stack consumes IMDS, so nothing legitimate breaks. Do not
  # raise it to 2.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = { Name = "${var.name_prefix}-vm" }
}

# Stable address for the Cloudflare A records: survives instance recreation
# (user_data_replace_on_change) so DNS never has to follow the instance.
resource "aws_eip" "this" {
  domain = "vpc"

  tags = { Name = "${var.name_prefix}-vm-eip" }
}

resource "aws_eip_association" "this" {
  instance_id   = aws_instance.this.id
  allocation_id = aws_eip.this.id
}
