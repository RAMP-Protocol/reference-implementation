# This stack deliberately re-declares the cloudflare-edge module's inputs
# instead of passing them through untouched: the stack is the operator-facing
# surface for a standalone hand-off (a publisher applies it with no other
# repo context), so each variable carries the description that operator needs
# — terraform-docs and `terraform apply` prompts read from HERE. Enforcement
# (validation blocks, nullability) intentionally lives once, in the module,
# and still runs on every value that flows through.

# ── Cloudflare credentials / placement ───────────────────────────────────────

variable "cloudflare_api_token" {
  description = "Cloudflare API token with Workers Scripts:Edit, Workers Routes:Edit, and DNS:Edit on the target zone. Put it in a gitignored *.auto.tfvars file or pass via TF_VAR_cloudflare_api_token — never commit it."
  type        = string
  sensitive   = true
  nullable    = false
}

variable "cloudflare_account_id" {
  description = "Cloudflare account id that owns the worker."
  type        = string
  nullable    = false
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone id the publisher hostname lives on."
  type        = string
  nullable    = false
}

# ── Worker ───────────────────────────────────────────────────────────────────

variable "script_name" {
  description = "Worker script name."
  type        = string
  default     = "ramp-edge"
  nullable    = false
}

variable "worker_bundle_path" {
  description = "Path to the pre-built worker bundle. Default resolves to src/edge/dist/worker.mjs in this repo checkout; build it first with deploy/terraform/scripts/build-cloudflare-edge.sh."
  type        = string
  default     = null
}

variable "route_patterns" {
  description = "Worker route patterns. Defaults to [\"<provider_domain>/*\"] — set only when the worker must match more (or other) patterns."
  type        = list(string)
  default     = null
}

variable "worker_hostname" {
  description = "Hostname to create a proxied placeholder DNS record for (leave null when the hostname already has a proxied record)."
  type        = string
  default     = null
}

# ── Worker environment (see modules/cloudflare-edge/variables.tf) ────────────

variable "exchange_url" {
  description = "Base URL of the Exchange."
  type        = string
  nullable    = false
}

variable "exchange_wba_url" {
  description = "URL of the Exchange's Web Bot Auth directory. Defaults to <exchange_url>/.well-known/http-message-signatures-directory, the path the spec fixes — set only for an exchange that serves the directory somewhere else."
  type        = string
  default     = null
}

variable "provider_domain" {
  description = "Publisher domain advertised in ramp.json."
  type        = string
  nullable    = false
}

variable "exchanges_json" {
  description = "JSON array of exchange entries advertised in ramp.json."
  type        = string
  nullable    = false
}

variable "ramp_verify_keys" {
  description = "Optional inline Ed25519 verify keys (JSON array)."
  type        = string
  default     = null
}

variable "ramp_enforce_binding" {
  description = "Optional \"true\"/\"false\" override for agent-key proof-of-possession enforcement."
  type        = string
  default     = null
}

variable "origin_url" {
  description = "Optional origin backend the worker proxies verified requests to. One of origin_url / same_zone_origin must configure an origin mode."
  type        = string
  default     = null
}

variable "same_zone_origin" {
  description = "Optional \"true\" to forward pass-through requests to the incoming URL itself, letting Cloudflare route the same-zone subrequest to the zone's configured origin. The Cloudflare-only alternative to origin_url."
  type        = string
  default     = null
}

variable "bot_ua_allow_json" {
  description = "Optional JSON array of regular-expression sources naming the search crawlers that read for free."
  type        = string
  default     = null
}

variable "bot_ua_deny_json" {
  description = "Optional JSON array of regular-expression sources naming the AI bots sent to negotiate."
  type        = string
  default     = null
}

variable "rsl_body" {
  description = "Optional RSL document body."
  type        = string
  default     = null
}

variable "acme_tokens_json" {
  description = "Optional JSON object of ACME HTTP-01 tokens."
  type        = string
  default     = null
}

variable "catalog_contributors_json" {
  description = "Optional JSON array of authorized catalog contributors."
  type        = string
  default     = null
}

variable "wba_keys_json" {
  description = "Optional JSON array of the publisher's Ed25519 signing keys."
  type        = string
  default     = null
}

variable "wba_revocation_url" {
  description = "Optional revocation channel URL for the publisher's WBA directory."
  type        = string
  default     = null
}

# ── Zone protections ─────────────────────────────────────────────────────────

variable "create_waf_skip_rule" {
  description = "Create a zone firewall skip rule for the worker hostnames (see module README before enabling on a zone that already has a custom-firewall ruleset)."
  type        = bool
  default     = false
  nullable    = false
}

variable "waf_skip_expression" {
  description = "Filter expression for the skip rule; required when create_waf_skip_rule is true."
  type        = string
  default     = null
}
