# Unit tests for the cloudflare-edge module. The Cloudflare provider is
# MOCKED: no token, no API calls, no real worker — plan mode only. The
# uploaded bundle is a local test fixture (tests/fixtures/worker.mjs).
#
# Run from the module directory: terraform init && terraform test

mock_provider "cloudflare" {}

variables {
  account_id         = "0123456789abcdef0123456789abcdef"
  zone_id            = "abcdef0123456789abcdef0123456789"
  worker_bundle_path = "tests/fixtures/worker.mjs"
  route_patterns     = ["news.example.com/*"]

  exchange_url     = "https://exchange.operator.example"
  exchange_wba_url = "https://exchange.operator.example/.well-known/http-message-signatures-directory"
  provider_domain  = "news.example.com"
  exchanges_json   = "[{\"domain\":\"exchange.operator.example\",\"endpoint\":\"https://exchange.operator.example\"}]"

  # The module requires an origin mode (the Cloudflare worker refuses to run
  # without one), so every run carries one; the dedicated run below proves the
  # precondition rejects a plan with neither.
  origin_url = "https://origin.example.com"
}

run "uploads_bundle_with_wrangler_runtime_settings" {
  command = plan

  assert {
    condition     = cloudflare_workers_script.this.content == file("tests/fixtures/worker.mjs")
    error_message = "The module must upload the pre-built bundle content verbatim"
  }

  assert {
    condition     = cloudflare_workers_script.this.module == true
    error_message = "The bundle is an ES module and must be uploaded as one"
  }

  assert {
    condition     = cloudflare_workers_script.this.compatibility_date == "2026-07-01" && contains(cloudflare_workers_script.this.compatibility_flags, "nodejs_compat")
    error_message = "Runtime settings must mirror src/edge/wrangler.toml"
  }

  assert {
    condition     = cloudflare_workers_script.this.logpush == false
    error_message = "Logpush must default off — it needs an account-level destination that plain deployments don't have"
  }
}

run "required_bindings_mirror_config_contract" {
  command = plan

  assert {
    condition = alltrue([
      for name in ["EXCHANGE_URL", "EXCHANGE_WBA_URL", "PROVIDER", "EXCHANGES_JSON"] :
      anytrue([
        for binding in cloudflare_workers_script.this.plain_text_binding :
        binding.name == name
      ])
    ])
    error_message = "All four required config.ts bindings must be present"
  }

  assert {
    # 4 required + the ORIGIN_URL every run carries as its origin mode.
    condition     = length(cloudflare_workers_script.this.plain_text_binding) == 5
    error_message = "Unset optional bindings must NOT be created (the worker's Zod schema treats empty strings as set)"
  }

  assert {
    condition = anytrue([
      for binding in cloudflare_workers_script.this.plain_text_binding :
      binding.name == "PROVIDER" && binding.text == "news.example.com"
    ])
    error_message = "PROVIDER binding must carry the publisher domain"
  }
}

run "optional_bindings_render_when_set" {
  command = plan

  variables {
    origin_url                = "https://origin.example.com"
    catalog_contributors_json = "[{\"domain\":\"contrib.example\",\"relationship\":\"operator\"}]"
  }

  assert {
    condition     = length(cloudflare_workers_script.this.plain_text_binding) == 6
    error_message = "Exactly the four required plus the two set optional bindings"
  }

  assert {
    condition = anytrue([
      for binding in cloudflare_workers_script.this.plain_text_binding :
      binding.name == "ORIGIN_URL" && binding.text == "https://origin.example.com"
    ])
    error_message = "ORIGIN_URL binding must carry the origin backend"
  }

  assert {
    condition = anytrue([
      for binding in cloudflare_workers_script.this.plain_text_binding :
      binding.name == "CATALOG_CONTRIBUTORS_JSON"
    ])
    error_message = "CATALOG_CONTRIBUTORS_JSON must be the other rendered optional binding"
  }
}

# Every optional binding at once: pins the full config.ts env contract. A typo
# in one optional_bindings map key would pass every other run (they set at
# most two optionals) but fails the name check here.
run "all_optional_bindings_render" {
  command = plan

  variables {
    ramp_verify_keys          = "[{\"kty\":\"OKP\",\"crv\":\"Ed25519\"}]"
    ramp_enforce_binding      = "false"
    origin_url                = "https://origin.example.com"
    same_zone_origin          = "false"
    rsl_body                  = "<rsl/>"
    acme_tokens_json          = "{\"token\":\"keyAuthorization\"}"
    catalog_contributors_json = "[{\"domain\":\"contrib.example\",\"relationship\":\"operator\"}]"
    wba_keys_json             = "[{\"kty\":\"OKP\",\"crv\":\"Ed25519\"}]"
    wba_revocation_url        = "https://news.example.com/wba/revoked"
    bot_ua_allow_json         = "[\"Googlebot\"]"
    bot_ua_deny_json          = "[\"GPTBot\"]"
  }

  assert {
    condition     = length(cloudflare_workers_script.this.plain_text_binding) == 15
    error_message = "Four required plus all eleven optional bindings must render"
  }

  assert {
    condition = alltrue([
      for name in [
        "RAMP_VERIFY_KEYS", "RAMP_ENFORCE_BINDING", "ORIGIN_URL", "SAME_ZONE_ORIGIN",
        "RSL_BODY", "ACME_TOKENS_JSON", "CATALOG_CONTRIBUTORS_JSON", "WBA_KEYS_JSON",
        "WBA_REVOCATION_URL", "BOT_UA_ALLOW_JSON", "BOT_UA_DENY_JSON",
      ] :
      anytrue([
        for binding in cloudflare_workers_script.this.plain_text_binding :
        binding.name == name
      ])
    ])
    error_message = "Every optional binding must render under exactly the name config.ts reads"
  }

  # The opt-out half of the tri-state: unset means no binding (worker enforces,
  # asserted elsewhere); "false" must actually reach the worker as a binding.
  assert {
    condition = anytrue([
      for binding in cloudflare_workers_script.this.plain_text_binding :
      binding.name == "RAMP_ENFORCE_BINDING" && binding.text == "false"
    ])
    error_message = "ramp_enforce_binding=\"false\" must render as a binding carrying \"false\""
  }
}

# The Cloudflare worker refuses to run without an origin mode; a plan that
# configures neither must fail at plan time, not as a production outage.
run "no_origin_mode_fails_at_plan" {
  command = plan

  variables {
    origin_url = null
  }

  expect_failures = [cloudflare_workers_script.this]
}

# same_zone_origin = "true" is the other valid origin mode.
run "same_zone_origin_satisfies_origin_mode" {
  command = plan

  variables {
    origin_url       = null
    same_zone_origin = "true"
  }

  assert {
    condition = anytrue([
      for binding in cloudflare_workers_script.this.plain_text_binding :
      binding.name == "SAME_ZONE_ORIGIN" && binding.text == "true"
    ])
    error_message = "same_zone_origin=\"true\" must render as a binding carrying \"true\""
  }
}

# Everything downstream is named after / wired to the worker script; override
# the name to prove propagation rather than defaults.
run "script_name_propagates_to_all_consumers" {
  command = plan

  variables {
    script_name          = "custom-edge"
    worker_hostname      = "news.example.com"
    create_waf_skip_rule = true
    waf_skip_expression  = "(http.host eq \"news.example.com\")"
  }

  assert {
    condition     = cloudflare_workers_script.this.name == "custom-edge"
    error_message = "script_name must name the worker script"
  }

  assert {
    condition     = cloudflare_workers_route.this["news.example.com/*"].script_name == "custom-edge"
    error_message = "Routes must point at the worker script this module uploads"
  }

  assert {
    condition     = cloudflare_ruleset.waf_skip[0].name == "custom-edge-waf-skip"
    error_message = "WAF skip ruleset name must derive from script_name"
  }

  assert {
    condition     = strcontains(cloudflare_record.worker_hostname[0].comment, "custom-edge")
    error_message = "The placeholder record's operational note must name the worker handling the traffic"
  }

  assert {
    condition     = cloudflare_workers_script.this.account_id == "0123456789abcdef0123456789abcdef"
    error_message = "The worker script must land on the given account"
  }

  assert {
    condition = alltrue([
      cloudflare_workers_route.this["news.example.com/*"].zone_id == "abcdef0123456789abcdef0123456789",
      cloudflare_record.worker_hostname[0].zone_id == "abcdef0123456789abcdef0123456789",
      cloudflare_ruleset.waf_skip[0].zone_id == "abcdef0123456789abcdef0123456789",
    ])
    error_message = "Routes, the placeholder record, and the skip rule must all land on the given zone"
  }
}

run "routes_and_placeholder_record" {
  command = plan

  variables {
    route_patterns  = ["news.example.com/*", "news.example.com/api/*"]
    worker_hostname = "news.example.com"
  }

  assert {
    condition     = length(cloudflare_workers_route.this) == 2
    error_message = "One worker route per pattern"
  }

  assert {
    condition     = length(cloudflare_record.worker_hostname) == 1 && cloudflare_record.worker_hostname[0].type == "AAAA" && cloudflare_record.worker_hostname[0].content == "100::" && cloudflare_record.worker_hostname[0].proxied == true
    error_message = "worker_hostname must create a proxied AAAA 100:: placeholder record"
  }

  assert {
    condition     = cloudflare_record.worker_hostname[0].ttl == 1
    error_message = "Proxied records require ttl = 1 (automatic)"
  }
}

run "no_placeholder_record_by_default" {
  command = plan

  assert {
    condition     = length(cloudflare_record.worker_hostname) == 0
    error_message = "No worker_hostname -> no DNS record is touched"
  }

  assert {
    condition     = length(cloudflare_ruleset.waf_skip) == 0
    error_message = "WAF skip rule is opt-in and must default off"
  }
}

run "waf_skip_rule_renders_when_enabled" {
  command = plan

  variables {
    create_waf_skip_rule = true
    waf_skip_expression  = "(http.host eq \"news.example.com\")"
  }

  assert {
    condition     = length(cloudflare_ruleset.waf_skip) == 1
    error_message = "create_waf_skip_rule=true must create the zone ruleset"
  }

  assert {
    condition     = cloudflare_ruleset.waf_skip[0].kind == "zone" && cloudflare_ruleset.waf_skip[0].phase == "http_request_firewall_custom"
    error_message = "The skip rule must be a zone custom-firewall entrypoint ruleset"
  }

  assert {
    condition     = cloudflare_ruleset.waf_skip[0].rules[0].action == "skip" && cloudflare_ruleset.waf_skip[0].rules[0].expression == "(http.host eq \"news.example.com\")"
    error_message = "The rule must skip on exactly the given expression"
  }

  assert {
    condition     = contains(cloudflare_ruleset.waf_skip[0].rules[0].action_parameters[0].products, "waf") && contains(cloudflare_ruleset.waf_skip[0].rules[0].action_parameters[0].products, "bic")
    error_message = "The default product list must bypass at least WAF and browser-integrity-check"
  }
}

run "waf_skip_rule_without_expression_is_rejected" {
  command = plan

  variables {
    create_waf_skip_rule = true
  }

  expect_failures = [
    cloudflare_ruleset.waf_skip,
  ]
}

run "empty_route_patterns_are_rejected" {
  command = plan

  variables {
    route_patterns = []
  }

  expect_failures = [
    var.route_patterns,
  ]
}

run "invalid_enforce_binding_value_is_rejected" {
  command = plan

  variables {
    ramp_enforce_binding = "yes"
  }

  expect_failures = [
    var.ramp_enforce_binding,
  ]
}

# The module promises a clear plan-time error instead of file() failing later.
run "missing_worker_bundle_is_rejected" {
  command = plan

  variables {
    worker_bundle_path = "tests/fixtures/does-not-exist.mjs"
  }

  expect_failures = [
    var.worker_bundle_path,
  ]
}

# ── JSON binding validations: malformed values must fail the PLAN, not the
# worker boot (the module's whole reason for validating them). Two failure
# flavors for the array-shaped ones: not JSON at all, and valid JSON of the
# wrong shape. ──

run "non_json_exchanges_json_is_rejected" {
  command = plan

  variables {
    exchanges_json = "not json"
  }

  expect_failures = [
    var.exchanges_json,
  ]
}

run "object_exchanges_json_is_rejected" {
  command = plan

  variables {
    exchanges_json = "{\"domain\":\"exchange.operator.example\"}"
  }

  expect_failures = [
    var.exchanges_json,
  ]
}

run "non_array_ramp_verify_keys_is_rejected" {
  command = plan

  variables {
    ramp_verify_keys = "{\"kty\":\"OKP\"}"
  }

  expect_failures = [
    var.ramp_verify_keys,
  ]
}

# acme_tokens_json is the object-shaped one — an ARRAY is the wrong shape here.
run "array_acme_tokens_json_is_rejected" {
  command = plan

  variables {
    acme_tokens_json = "[\"token\"]"
  }

  expect_failures = [
    var.acme_tokens_json,
  ]
}

run "non_array_catalog_contributors_json_is_rejected" {
  command = plan

  variables {
    catalog_contributors_json = "{\"domain\":\"contrib.example\"}"
  }

  expect_failures = [
    var.catalog_contributors_json,
  ]
}

run "non_array_wba_keys_json_is_rejected" {
  command = plan

  variables {
    wba_keys_json = "{\"kty\":\"OKP\"}"
  }

  expect_failures = [
    var.wba_keys_json,
  ]
}
