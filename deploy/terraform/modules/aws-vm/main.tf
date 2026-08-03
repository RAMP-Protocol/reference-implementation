# One amd64 EC2 instance in a minimal, self-contained VPC (public subnet +
# internet gateway), with a stable Elastic IP. The whole RAMP stack runs as
# Docker Compose on this instance — TigerBeetle needs IPC_LOCK +
# seccomp=unconfined + io_uring, which rules out Fargate; a plain VM runs it
# with the same flags as local development.

# Zones that are actually usable in the target region/account, so the subnet
# can pick one without hardcoding a zone name (names vary per account/region).
data "aws_availability_zones" "available" {
  state = "available"
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
    description = "SSH from the operator address only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ssh_ingress_cidr]
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

resource "aws_key_pair" "this" {
  key_name   = "${var.name_prefix}-operator"
  public_key = var.ssh_public_key

  tags = { Name = "${var.name_prefix}-operator" }
}

resource "aws_instance" "this" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.this.id]
  key_name               = aws_key_pair.this.key_name

  # cloud-init transparently un-gzips; gzip keeps the rendered config (compose
  # file, Caddyfile, key material) under EC2's 16 KB raw user-data limit.
  user_data_base64            = base64gzip(var.user_data)
  user_data_replace_on_change = var.user_data_replace_on_change

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
