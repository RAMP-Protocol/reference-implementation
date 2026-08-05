# ── AWS ──────────────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region for the demo VM. The Lambda@Edge function and the CloudFront certificate always go to us-east-1 (an AWS requirement), through this stack's aliased provider, whatever is set here."
  type        = string
  default     = "us-east-1"
  nullable    = false
}

variable "aws_profile" {
  description = "AWS CLI profile to authenticate with. Leave unset (null) to use the default AWS credential chain (AWS_PROFILE env var, default profile, or env keys)."
  type        = string
  default     = null
}

variable "name_prefix" {
  description = "Prefix for AWS resource names (VM, security group, Lambda, IAM role)."
  type        = string
  default     = "ramp-demo"
  nullable    = false
}

variable "instance_type" {
  description = "EC2 instance type (amd64 only)."
  type        = string
  default     = "t3.large"
  nullable    = false
}

variable "ssh_public_key" {
  description = "OpenSSH public key installed on the VM for the ubuntu user."
  type        = string
  nullable    = false
}

variable "ssh_ingress_cidr" {
  description = "CIDR allowed to SSH to the VM — your own address as a /32."
  type        = string
  nullable    = false
}

variable "ssh_private_key_path" {
  description = "Local path to the private key matching ssh_public_key, e.g. \"~/.ssh/ramp-demo\". Only used to build the ssh_command output (adds -i <path>); the key itself never leaves your machine. Leave null when the key is one your ssh client tries by default (~/.ssh/id_ed25519, ~/.ssh/id_rsa, or ssh-agent)."
  type        = string
  default     = null
}

# ── DNS (Route 53) ───────────────────────────────────────────────────────────

variable "route53_zone_id" {
  description = "Id of the EXISTING Route 53 hosted zone of `domain`. The zone may be shared with other projects; this stack only ever adds its own records to it and refuses to overwrite records it did not create."
  type        = string
  nullable    = false
}

variable "domain" {
  description = "Zone apex the demo hostnames live under, e.g. publisher.example. Every hostname this stack creates sits under <publisher_subdomain>.<domain>."
  type        = string
  nullable    = false
}

# ── Hostnames ────────────────────────────────────────────────────────────────
#
# Unlike the staging stack, ALL hostnames nest under one label: the publisher
# hostname is <publisher_subdomain>.<domain> and every service sits one level
# below it (exchange.demo.<domain>, mcp.demo.<domain>, ...). One label owns
# the whole demo, so it cannot collide with anything else in a shared zone.

variable "publisher_subdomain" {
  description = "Label under `domain` for the demo publisher hostname CloudFront serves, and the parent label of every service hostname."
  type        = string
  default     = "demo"
  nullable    = false
}

variable "exchange_subdomain" {
  description = "Label for the Exchange hostname, under the publisher label."
  type        = string
  default     = "exchange"
  nullable    = false
}

variable "broker_subdomain" {
  description = "Label for the Broker hostname, under the publisher label."
  type        = string
  default     = "broker"
  nullable    = false
}

variable "identity_subdomain" {
  description = "Label for the Identity Service hostname, under the publisher label — the MCP endpoint agents connect to and the OAuth issuer developers sign up against. Agent Web Bot Auth directories are published one label below it, at <agent-slug>.<identity_subdomain>.<publisher_subdomain>.<domain>, which is why the stack also creates a wildcard record for it."
  type        = string
  default     = "mcp"
  nullable    = false
}

variable "zitadel_subdomain" {
  description = "Label for the bundled Zitadel hostname, under the publisher label — the upstream OIDC provider developer sign-in redirects to."
  type        = string
  default     = "login"
  nullable    = false
}

variable "origin_subdomain" {
  description = "Label for the demo publisher origin hostname, under the publisher label — the custom origin CloudFront fetches verified content from."
  type        = string
  default     = "origin"
  nullable    = false
}

variable "smoke_agent_subdomain" {
  description = "Label for the smoke agent's Web Bot Auth directory hostname, under the publisher label. The full hostname <label>.<publisher_subdomain>.<domain> IS the smoke agent's identity: gen-staging-keys.sh mints the agent key with that kid, seed-staging.sh registers it, and Caddy serves the public key directory at it so the services can verify the smoke signatures. The default matches the label scripts/lib/staging-env.sh derives ids with (run key generation with STAGING_DOMAIN set to the publisher hostname, <publisher_subdomain>.<domain>); seeding and smoke verify the two agree before running."
  type        = string
  default     = "smoke-agent"
  nullable    = false
}

variable "catalog_contributor_subdomain" {
  description = "Label for the catalog contributor's Web Bot Auth directory hostname, under the publisher label. The full hostname <label>.<publisher_subdomain>.<domain> IS the identity that pushes the demo catalog (seed-staging.sh signs ingest with its key; the edge manifest authorizes it), and Caddy serves its public key directory at it. The default matches the label scripts/lib/staging-env.sh derives ids with; seeding and smoke verify the two agree before running."
  type        = string
  default     = "catalog-contributor"
  nullable    = false
}

# ── Container images ─────────────────────────────────────────────────────────

variable "image_registry" {
  description = "Container registry host. GitLab Container Registry by default; GHCR/Docker Hub/ECR work through the same three variables."
  type        = string
  default     = "registry.gitlab.com"
  nullable    = false
}

variable "image_prefix" {
  description = "Path under the registry the images live at, e.g. \"<group>/<project>\". Must be lowercase (Docker repository paths reject uppercase; GitLab publishes under the lowercased project path). Images are <registry>/<prefix>/{exchange,broker,identity,publisher}:<tag> — matching scripts/build-push-images.sh."
  type        = string
  nullable    = false

  validation {
    condition     = lower(var.image_prefix) == var.image_prefix
    error_message = "image_prefix must be lowercase — the registry stores repository paths lowercased, and docker pull on the VM would fail with an uppercase path."
  }
}

variable "image_tag" {
  description = "Image tag to deploy."
  type        = string
  default     = "latest"
  nullable    = false
}

variable "registry_username" {
  description = "Registry username for the VM's docker login (e.g. a GitLab deploy-token username). Null when the images are public."
  type        = string
  default     = null
}

variable "registry_password" {
  description = "Registry password/token for the VM's docker login. Null when the images are public."
  type        = string
  default     = null
  sensitive   = true
}

# ── Stack behavior ───────────────────────────────────────────────────────────

variable "billing_adapter" {
  description = "Exchange billing adapter. Demo default is tigerbeetle — per-article accounting on a real ledger."
  type        = string
  default     = "tigerbeetle"
  nullable    = false
}

variable "acme_email" {
  description = "Email for Let's Encrypt registration (Caddy on the VM mints the certificates for the service hostnames; the publisher hostname is covered by ACM through CloudFront)."
  type        = string
  nullable    = false
}

variable "acme_staging" {
  description = "Use the Let's Encrypt staging CA (untrusted certs, no rate limits). Turn on while iterating on apply/destroy cycles."
  type        = bool
  default     = false
  nullable    = false
}

variable "exa_api_key" {
  description = "Optional EXA API key for Broker discovery."
  type        = string
  default     = null
  sensitive   = true
}

variable "resource_owner_id" {
  description = "resource_owner_id the publisher manifest attests as settlement payee."
  type        = string
  default     = "demo-resource-owner"
  nullable    = false
}

variable "lambda_zip_path" {
  description = "Path to the pre-built Lambda@Edge bundle zip. Default resolves to src/edge/dist/lambda-edge.zip in this repo checkout; build it with deploy/terraform/scripts/build-lambda-edge.sh from the config this stack renders (see the lambda_edge_config output)."
  type        = string
  default     = null
}

variable "deploy_edge" {
  description = "Deploy the CloudFront distribution + Lambda@Edge function fronting <publisher_subdomain>.<domain>. Set false for the FIRST apply on a fresh checkout: the Lambda bundle does not exist yet, and its config comes out of this very stack (the lambda_edge_config output). Bootstrap order: apply with false → terraform output -raw lambda_edge_config > lambda-edge-config.json → build-lambda-edge.sh lambda-edge-config.json → apply with true."
  type        = bool
  default     = true
  nullable    = false
}

variable "ramp_enforce_binding" {
  description = "Override agent-key proof-of-possession in the RENDERED Lambda config (lambda_edge_config output). Null keeps the worker default — enforce, the production posture. Set \"false\" to let a signed URL be fetched without the bound-key proof, e.g. to smoke the backend alone. The value is baked into the bundle: changing it means re-rendering the config, rebuilding the zip, and re-applying."
  type        = string
  default     = null

  validation {
    condition     = var.ramp_enforce_binding == null || contains(["true", "false"], coalesce(var.ramp_enforce_binding, "true"))
    error_message = "ramp_enforce_binding must be \"true\", \"false\", or null."
  }
}
