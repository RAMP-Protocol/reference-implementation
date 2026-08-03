# ── Cloudflare placement ─────────────────────────────────────────────────────

variable "account_id" {
  description = "Cloudflare account id that owns the worker script."
  type        = string
  nullable    = false
}

variable "zone_id" {
  description = "Cloudflare zone id the worker routes (and optional DNS record) are created on."
  type        = string
  nullable    = false
}

variable "script_name" {
  description = "Name of the worker script as it appears in the Cloudflare dashboard."
  type        = string
  default     = "ramp-edge"
  nullable    = false
}

variable "worker_bundle_path" {
  description = "Path to the pre-built worker bundle (dist/worker.mjs). Build it with deploy/terraform/scripts/build-cloudflare-edge.sh before apply — this module never builds it."
  type        = string
  nullable    = false

  # Fail at plan with a clear message instead of at apply inside file():
  # the default path in the stacks is derived relative to the repo tree, so
  # a missing build (or a moved stack) should surface immediately.
  validation {
    condition     = fileexists(var.worker_bundle_path)
    error_message = "worker_bundle_path points at a file that does not exist — run deploy/terraform/scripts/build-cloudflare-edge.sh first."
  }
}

variable "route_patterns" {
  description = "Worker route patterns on the zone, e.g. [\"news.example.com/*\"]. Every hostname matched here must have a proxied DNS record on the zone (see worker_hostname)."
  type        = list(string)
  nullable    = false

  validation {
    condition     = length(var.route_patterns) > 0
    error_message = "At least one route pattern is required — a worker without routes never runs."
  }
}

variable "worker_hostname" {
  description = "Optional hostname to create a proxied placeholder DNS record for (AAAA 100::), so the worker routes on it execute. Set it when the hostname has no other DNS record; leave null when the hostname already resolves (e.g. an existing proxied record)."
  type        = string
  default     = null
}

# ── Worker runtime (mirrors src/edge/wrangler.toml) ──────────────────────────

variable "compatibility_date" {
  description = "Workers runtime compatibility date. Mirrors src/edge/wrangler.toml — bump both together; scripts/test-terraform.sh fails when the two drift."
  type        = string
  default     = "2026-07-01"
  nullable    = false
}

variable "compatibility_flags" {
  description = "Workers runtime compatibility flags. Mirrors src/edge/wrangler.toml."
  type        = list(string)
  default     = ["nodejs_compat"]
  nullable    = false
}

variable "logpush" {
  description = "Enable Workers Trace Events Logpush for the script. Workers Logs (dashboard observability) is a separate account-level toggle the 4.x provider cannot manage — enable it in the dashboard."
  type        = bool
  default     = false
  nullable    = false
}

# ── Worker environment: required bindings (src/edge/src/config.ts) ───────────

variable "exchange_url" {
  description = "EXCHANGE_URL binding: base URL of the Exchange, e.g. https://exchange.example.com."
  type        = string
  nullable    = false
}

variable "exchange_wba_url" {
  description = "EXCHANGE_WBA_URL binding: absolute URL of the Exchange's Web Bot Auth directory (/.well-known/http-message-signatures-directory) — the source the worker resolves delivery-URL verify keys from."
  type        = string
  nullable    = false
}

variable "provider_domain" {
  description = "PROVIDER binding: publisher identifier advertised as the `domain` field of the served /.well-known/ramp.json."
  type        = string
  nullable    = false
}

variable "exchanges_json" {
  description = "EXCHANGES_JSON binding: JSON array of exchange entries ({domain, endpoint, supported_profiles, ext}) advertised in ramp.json. The Broker reads this to route resolves for the publisher."
  type        = string
  nullable    = false

  # Malformed JSON in a binding only surfaces as a worker boot failure —
  # catch it at plan time instead. concat() rejects any non-array decode.
  validation {
    condition     = can(concat(jsondecode(var.exchanges_json), []))
    error_message = "exchanges_json must be a JSON array of exchange entries ({domain, endpoint, ...})."
  }
}

# ── Worker environment: optional bindings (unset = binding not created) ──────

variable "ramp_verify_keys" {
  description = "RAMP_VERIFY_KEYS binding: optional JSON array of inline Ed25519 JWKs to verify delivery URLs against without fetching the WBA directory (rotation still falls back to the fetch)."
  type        = string
  default     = null

  validation {
    condition     = var.ramp_verify_keys == null || can(concat(jsondecode(coalesce(var.ramp_verify_keys, "[]")), []))
    error_message = "ramp_verify_keys must be a JSON array of Ed25519 JWKs (or null)."
  }
}

variable "ramp_enforce_binding" {
  description = "RAMP_ENFORCE_BINDING binding: \"true\"/\"false\". Default (unset) enforces agent-key proof-of-possession — the production posture. Set \"false\" only for edges whose fetcher cannot hold the bound key."
  type        = string
  default     = null

  validation {
    condition     = var.ramp_enforce_binding == null || contains(["true", "false"], coalesce(var.ramp_enforce_binding, "true"))
    error_message = "ramp_enforce_binding must be \"true\", \"false\", or null."
  }
}

variable "origin_url" {
  description = "ORIGIN_URL binding: backend the worker proxies verified requests to. One of origin_url / same_zone_origin must configure an origin mode — the Cloudflare worker refuses to run without one."
  type        = string
  default     = null
}

variable "same_zone_origin" {
  description = "SAME_ZONE_ORIGIN binding: \"true\" forwards pass-through requests to the incoming URL itself (signature params stripped), letting Cloudflare route the same-zone subrequest to the zone's configured origin — the Cloudflare-only alternative to origin_url. One of origin_url / same_zone_origin must configure an origin mode."
  type        = string
  default     = null

  validation {
    condition     = var.same_zone_origin == null || contains(["true", "false"], coalesce(var.same_zone_origin, "true"))
    error_message = "same_zone_origin must be \"true\", \"false\", or null."
  }
}

variable "bot_ua_allow_json" {
  description = "BOT_UA_ALLOW_JSON binding: optional JSON array of regular-expression sources naming the search crawlers that read for free. Unset = the worker's built-in defaults."
  type        = string
  default     = null

  validation {
    condition     = var.bot_ua_allow_json == null || can(concat(jsondecode(coalesce(var.bot_ua_allow_json, "[]")), []))
    error_message = "bot_ua_allow_json must be a JSON array of regular-expression sources (or null)."
  }
}

variable "bot_ua_deny_json" {
  description = "BOT_UA_DENY_JSON binding: optional JSON array of regular-expression sources naming the AI bots sent to negotiate. Unset = the worker's built-in defaults."
  type        = string
  default     = null

  validation {
    condition     = var.bot_ua_deny_json == null || can(concat(jsondecode(coalesce(var.bot_ua_deny_json, "[]")), []))
    error_message = "bot_ua_deny_json must be a JSON array of regular-expression sources (or null)."
  }
}

variable "rsl_body" {
  description = "RSL_BODY binding: optional RSL document body served by the worker."
  type        = string
  default     = null
}

variable "acme_tokens_json" {
  description = "ACME_TOKENS_JSON binding: optional JSON object of ACME HTTP-01 tokens the worker answers for the publisher hostname."
  type        = string
  default     = null

  validation {
    condition     = var.acme_tokens_json == null || can(keys(jsondecode(coalesce(var.acme_tokens_json, "{}"))))
    error_message = "acme_tokens_json must be a JSON object of token -> keyAuthorization pairs (or null)."
  }
}

variable "catalog_contributors_json" {
  description = "CATALOG_CONTRIBUTORS_JSON binding: optional JSON array of {domain, relationship} entries authorizing third parties to push catalog resources for this publisher."
  type        = string
  default     = null

  validation {
    condition     = var.catalog_contributors_json == null || can(concat(jsondecode(coalesce(var.catalog_contributors_json, "[]")), []))
    error_message = "catalog_contributors_json must be a JSON array of {domain, relationship} entries (or null)."
  }
}

variable "wba_keys_json" {
  description = "WBA_KEYS_JSON binding: optional JSON array of this publisher's Ed25519 signing keys (served in the publisher's Web Bot Auth directory). Leave null when the publisher issues no keys."
  type        = string
  default     = null

  validation {
    condition     = var.wba_keys_json == null || can(concat(jsondecode(coalesce(var.wba_keys_json, "[]")), []))
    error_message = "wba_keys_json must be a JSON array of Ed25519 signing keys (or null)."
  }
}

variable "wba_revocation_url" {
  description = "WBA_REVOCATION_URL binding: optional absolute URL advertised as the publisher WBA directory's revocation channel. Ignored by the worker unless wba_keys_json is also set."
  type        = string
  default     = null
}

# ── Zone protections ─────────────────────────────────────────────────────────

variable "create_waf_skip_rule" {
  description = "Create a zone custom-firewall skip rule so zone protections (WAF, Bot Fight Mode heuristics, security level) do not block agent traffic before it reaches the worker. A zone can hold only ONE custom-firewall entrypoint ruleset — leave false if the zone already manages one elsewhere, and add an equivalent skip rule there instead."
  type        = bool
  default     = false
  nullable    = false
}

variable "waf_skip_expression" {
  description = "Filter expression for the WAF skip rule, e.g. \"(http.host eq \\\"news.example.com\\\")\". Required when create_waf_skip_rule is true."
  type        = string
  default     = null
}

variable "waf_skip_products" {
  description = "Zone security products the skip rule bypasses for matching requests."
  type        = list(string)
  default     = ["waf", "bic", "securityLevel", "uaBlock"]
  nullable    = false
}
