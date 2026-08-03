# Standalone edge deployment: ONLY the Cloudflare edge worker, applied against
# the publisher's own Cloudflare account and zone. This is the root
# configuration a publisher runs — it has no AWS, no other
# RAMP infrastructure, and no dependency on any other Terraform state.
#
# See ../../docs/deploy-edge-standalone.md for the step-by-step guide.

locals {
  # Default to the in-repo bundle location (this stack lives at
  # deploy/terraform/stacks/edge, four levels below the repo root). The
  # in-repo default is deliberate: the repo checkout IS the hand-off
  # vehicle, so the normal path needs no extra input — and when the bundle
  # is missing (or the stack is moved out of the tree), the module's
  # fileexists validation fails the plan with a message pointing at
  # build-cloudflare-edge.sh instead of failing obscurely.
  worker_bundle_path = coalesce(var.worker_bundle_path, "${path.module}/../../../../src/edge/dist/worker.mjs")

  # The worker fronts the publisher's own content hostname, so the one route
  # every deployment needs is derivable from provider_domain — the same
  # derivation stacks/staging-aws uses. The variable stays as an override for
  # setups that need more (or other) patterns.
  route_patterns = var.route_patterns == null ? ["${var.provider_domain}/*"] : var.route_patterns

  # The Web Bot Auth spec fixes the directory path, so the URL follows from
  # exchange_url; the variable stays as an override for an exchange that
  # serves it somewhere unusual.
  exchange_wba_url = coalesce(var.exchange_wba_url, "${var.exchange_url}/.well-known/http-message-signatures-directory")
}

module "edge" {
  source = "../../modules/cloudflare-edge"

  account_id         = var.cloudflare_account_id
  zone_id            = var.cloudflare_zone_id
  script_name        = var.script_name
  worker_bundle_path = local.worker_bundle_path

  route_patterns  = local.route_patterns
  worker_hostname = var.worker_hostname

  exchange_url     = var.exchange_url
  exchange_wba_url = local.exchange_wba_url
  provider_domain  = var.provider_domain
  exchanges_json   = var.exchanges_json

  ramp_verify_keys          = var.ramp_verify_keys
  ramp_enforce_binding      = var.ramp_enforce_binding
  origin_url                = var.origin_url
  same_zone_origin          = var.same_zone_origin
  rsl_body                  = var.rsl_body
  acme_tokens_json          = var.acme_tokens_json
  catalog_contributors_json = var.catalog_contributors_json
  wba_keys_json             = var.wba_keys_json
  wba_revocation_url        = var.wba_revocation_url
  bot_ua_allow_json         = var.bot_ua_allow_json
  bot_ua_deny_json          = var.bot_ua_deny_json

  create_waf_skip_rule = var.create_waf_skip_rule
  waf_skip_expression  = var.waf_skip_expression
}
