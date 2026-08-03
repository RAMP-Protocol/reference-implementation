# Standalone RAMP edge worker deployment. Uploads the PRE-BUILT bundle
# (dist/worker.mjs — see scripts/build-cloudflare-edge.sh) and wires its environment as
# plain-text bindings mirroring the Zod contract in src/edge/src/config.ts.
# The worker holds no secrets, so plain-text bindings are the right binding
# type for every variable.

locals {
  required_bindings = {
    EXCHANGE_URL     = var.exchange_url
    EXCHANGE_WBA_URL = var.exchange_wba_url
    PROVIDER         = var.provider_domain
    EXCHANGES_JSON   = var.exchanges_json
  }

  optional_bindings = {
    RAMP_VERIFY_KEYS          = var.ramp_verify_keys
    RAMP_ENFORCE_BINDING      = var.ramp_enforce_binding
    ORIGIN_URL                = var.origin_url
    SAME_ZONE_ORIGIN          = var.same_zone_origin
    RSL_BODY                  = var.rsl_body
    ACME_TOKENS_JSON          = var.acme_tokens_json
    CATALOG_CONTRIBUTORS_JSON = var.catalog_contributors_json
    WBA_KEYS_JSON             = var.wba_keys_json
    WBA_REVOCATION_URL        = var.wba_revocation_url
    BOT_UA_ALLOW_JSON         = var.bot_ua_allow_json
    BOT_UA_DENY_JSON          = var.bot_ua_deny_json
  }

  plain_text_bindings = merge(
    local.required_bindings,
    { for name, value in local.optional_bindings : name => value if value != null },
  )
}

resource "cloudflare_workers_script" "this" {
  account_id = var.account_id
  name       = var.script_name
  content    = file(var.worker_bundle_path)
  module     = true

  compatibility_date  = var.compatibility_date
  compatibility_flags = var.compatibility_flags
  logpush             = var.logpush

  dynamic "plain_text_binding" {
    for_each = local.plain_text_bindings

    content {
      name = plain_text_binding.key
      text = plain_text_binding.value
    }
  }

  lifecycle {
    # Mirrors originModeConfigured in src/edge/src/config.ts: the Cloudflare
    # worker refuses to run without an origin mode, so a plan that configures
    # neither would apply green and then fail every content request in
    # production traffic. Catch it at plan time instead.
    precondition {
      condition     = var.origin_url != null || var.same_zone_origin == "true"
      error_message = "No origin mode configured — set origin_url or same_zone_origin = \"true\". The Cloudflare worker refuses to run without one."
    }
  }
}

resource "cloudflare_workers_route" "this" {
  for_each = toset(var.route_patterns)

  zone_id     = var.zone_id
  pattern     = each.value
  script_name = cloudflare_workers_script.this.name
}

# Placeholder record for a worker-only hostname: routes only execute for
# hostnames that resolve through Cloudflare's proxy, and AAAA 100:: (IPv6
# discard prefix) is the canonical "no origin behind this name" target.
resource "cloudflare_record" "worker_hostname" {
  count = var.worker_hostname == null ? 0 : 1

  zone_id = var.zone_id
  name    = var.worker_hostname
  type    = "AAAA"
  content = "100::"
  proxied = true
  ttl     = 1
  # Hardcoded on purpose (unlike cloudflare-dns's operator-facing comment
  # input): this is a self-describing operational note explaining WHY a
  # 100:: placeholder record exists — it should read the same on every zone.
  comment = "RAMP edge worker placeholder — traffic is handled by the ${var.script_name} worker, not an origin."
}

# Optional skip rule so zone protections do not reject agent traffic before
# the worker sees it (bots presenting signed URLs are exactly what zone bot
# heuristics block). One custom-firewall entrypoint ruleset per zone: keep
# create_waf_skip_rule false on zones that already manage one.
resource "cloudflare_ruleset" "waf_skip" {
  count = var.create_waf_skip_rule ? 1 : 0

  zone_id = var.zone_id
  name    = "${var.script_name}-waf-skip"
  kind    = "zone"
  phase   = "http_request_firewall_custom"

  rules {
    action      = "skip"
    expression  = var.waf_skip_expression
    description = "Skip zone protections for RAMP edge worker traffic"
    enabled     = true

    action_parameters {
      products = var.waf_skip_products
    }
  }

  lifecycle {
    precondition {
      condition     = !var.create_waf_skip_rule || var.waf_skip_expression != null
      error_message = "waf_skip_expression is required when create_waf_skip_rule is true."
    }
  }
}
