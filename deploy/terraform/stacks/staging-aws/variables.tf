# ── AWS ──────────────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region for the staging VM."
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
  description = "Prefix for AWS resource names."
  type        = string
  default     = "ramp-staging"
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
  description = "Local path to the private key matching ssh_public_key, e.g. \"~/.ssh/ramp-staging\". Only used to build the ssh_command output (adds -i <path>); the key itself never leaves your machine. Leave null when the key is one your ssh client tries by default (~/.ssh/id_ed25519, ~/.ssh/id_rsa, or ssh-agent)."
  type        = string
  default     = null
}

# ── Cloudflare ───────────────────────────────────────────────────────────────

variable "cloudflare_api_token" {
  description = "Cloudflare API token: DNS:Edit + Workers Routes:Edit on the zone, Workers Scripts:Edit on the account. Keep it in gitignored secrets.auto.tfvars or TF_VAR_cloudflare_api_token."
  type        = string
  sensitive   = true
  nullable    = false
}

variable "cloudflare_account_id" {
  description = "Cloudflare account id."
  type        = string
  nullable    = false
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone id of `domain`."
  type        = string
  nullable    = false
}

variable "domain" {
  description = "Zone apex the staging hostnames live under, e.g. staging-zone.example. All hostnames are <subdomain>.<domain>."
  type        = string
  nullable    = false
}

# ── Hostnames (labels under `domain`) ────────────────────────────────────────

variable "exchange_subdomain" {
  description = "Label for the Exchange hostname."
  type        = string
  default     = "exchange"
  nullable    = false
}

variable "broker_subdomain" {
  description = "Label for the Broker hostname."
  type        = string
  default     = "broker"
  nullable    = false
}

variable "identity_subdomain" {
  description = "Label for the Identity Service hostname — the MCP endpoint agents connect to and the OAuth issuer developers sign up against. Agent Web Bot Auth directories are published one label below it, at <agent-slug>.<identity_subdomain>.<domain>, which is why the stack also creates a wildcard record for it."
  type        = string
  default     = "mcp"
  nullable    = false
}

variable "zitadel_subdomain" {
  description = "Label for the bundled Zitadel hostname, the upstream OIDC provider developer sign-in redirects to."
  type        = string
  default     = "login"
  nullable    = false
}

variable "origin_subdomain" {
  description = "Label for the demo publisher origin hostname (the edge worker's ORIGIN_URL target)."
  type        = string
  default     = "origin"
  nullable    = false
}

variable "publisher_subdomain" {
  description = "Label for the demo publisher hostname the edge worker fronts (the domain agents fetch signed URLs from)."
  type        = string
  default     = "demo"
  nullable    = false
}

variable "default_tenant_domain" {
  description = "Domain of the tenant agent Register reads its activation policy from. Defaults to this stack's own demo publisher hostname. Set it only in the deploy_edge = false mode, to the client publisher's hostname. seed-staging.sh reads the resolved value back from the default_tenant_domain output and creates the tenant under it, so the Exchange and the seeded tenant can never disagree."
  type        = string
  default     = null
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
  description = "Exchange billing adapter. Staging default is tigerbeetle — per-article accounting on a real ledger is the epic's hard requirement."
  type        = string
  default     = "tigerbeetle"
  nullable    = false
}

variable "acme_email" {
  description = "Email for Let's Encrypt registration."
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

variable "catalog_contributor_id" {
  description = "Identity that pushes the demo catalog (seed-staging.sh signs ingest with its key; the edge manifest authorizes it). No default on purpose: the value MUST equal CONTRIBUTOR_ID in scripts/lib/staging-env.sh — set the same value here in tfvars."
  type        = string
  nullable    = false
}

variable "resource_owner_id" {
  description = "resource_owner_id the publisher manifest attests as settlement payee."
  type        = string
  default     = "staging-resource-owner"
  nullable    = false
}

variable "worker_bundle_path" {
  description = "Path to the pre-built worker bundle. Default resolves to src/edge/dist/worker.mjs in this repo checkout; build it first with deploy/terraform/scripts/build-cloudflare-edge.sh."
  type        = string
  default     = null
}

variable "deploy_edge" {
  description = "Deploy staging's own Cloudflare edge worker fronting demo.<domain>. Off = the backend and the demo origin still run in full; use off for the client-simulation mode where a separately applied stacks/edge fronts a client hostname against this backend (see docs/deploy-edge-standalone.md)."
  type        = bool
  default     = true
  nullable    = false
}

variable "ramp_enforce_binding" {
  description = "Override agent-key proof-of-possession on staging's own edge worker (deploy_edge = true). Null keeps the module default — enforce, the production posture. Set \"false\" to let a signed URL be fetched without the bound-key proof, e.g. to smoke the backend alone without minting bound keys."
  type        = string
  default     = null

  validation {
    condition     = var.ramp_enforce_binding == null || contains(["true", "false"], coalesce(var.ramp_enforce_binding, "true"))
    error_message = "ramp_enforce_binding must be \"true\", \"false\", or null."
  }
}

variable "create_waf_skip_rule" {
  description = "Create the zone firewall skip rule for the publisher hostname (see cloudflare-edge module README — only one custom-firewall ruleset per zone)."
  type        = bool
  default     = false
  nullable    = false
}
