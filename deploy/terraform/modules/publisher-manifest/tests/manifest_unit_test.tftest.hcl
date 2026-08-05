# Two properties, pinned separately.
#
# The first two runs pin the exact rendered strings, because both consumers treat
# them as opaque env values: the cloudflare-edge worker bindings and the baked
# Lambda@Edge config must stay byte-identical for the same inputs, or a running
# deployment's plan shows a phantom diff after a refactor here.
#
# The third run pins something else: that this rendering still matches the shape
# deploy/publisher-wellknown/template-env.json states by hand. That file is the
# worked example operators are told to compare their own deployment against, so
# the module and the example are two producers of one shape and nothing else
# keeps them agreeing. It compares through jsonencode(jsondecode(...)) rather
# than raw strings because jsonencode rewrites the angle brackets around the
# payee placeholder as unicode escape sequences. The round-trip lets the fixture
# keep the readable form an operator needs while both sides are still compared
# after identical escaping.

variables {
  exchange_fqdn          = "exchange.demo.publisher.example"
  resource_owner_id      = "example-resource-owner"
  catalog_contributor_id = "catalog-contributor.example"
}

run "exchanges_json_renders_the_single_direct_exchange" {
  command = plan

  assert {
    condition     = output.exchanges_json == "[{\"domain\":\"exchange.demo.publisher.example\",\"endpoint\":\"https://exchange.demo.publisher.example\",\"ext\":{\"resource_owner_id\":\"example-resource-owner\"},\"supported_profiles\":[\"ramp-news-v1\"]}]"
    error_message = "exchanges_json must render the exchange entry with the derived https endpoint, the ramp-news-v1 profile, and the resource owner in ext — byte-identical to what deployed workers already carry."
  }
}

run "catalog_contributors_json_renders_the_operator_entry" {
  command = plan

  assert {
    condition     = output.catalog_contributors_json == "[{\"domain\":\"catalog-contributor.example\",\"relationship\":\"operator\"}]"
    error_message = "catalog_contributors_json must render the contributor with the operator relationship — byte-identical to what deployed workers already carry."
  }
}

run "renders_the_shape_the_publisher_wellknown_worked_example_states" {
  command = plan

  variables {
    exchange_fqdn          = "exchange.example"
    resource_owner_id      = "<the payee id the Exchange operator assigns — fill in>"
    catalog_contributor_id = "catalog-contributor.example"
  }

  assert {
    condition = output.exchanges_json == jsonencode(jsondecode(
      jsondecode(file("../../../publisher-wellknown/template-env.json"))["EXCHANGES_JSON"]
    ))
    error_message = "exchanges_json no longer matches EXCHANGES_JSON in deploy/publisher-wellknown/template-env.json. The module and that worked example are the two producers of this string; an operator sent to the module would now serve a document that does not match the reference copy they were told to compare against. Change both together."
  }

  assert {
    condition = output.catalog_contributors_json == jsonencode(jsondecode(
      jsondecode(file("../../../publisher-wellknown/template-env.json"))["CATALOG_CONTRIBUTORS_JSON"]
    ))
    error_message = "catalog_contributors_json no longer matches CATALOG_CONTRIBUTORS_JSON in deploy/publisher-wellknown/template-env.json. Change both together."
  }
}
