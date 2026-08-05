# The edge worker's publisher-manifest env values, rendered once for every
# deployment shape: the cloudflare-edge module takes them as worker bindings
# (EXCHANGES_JSON / CATALOG_CONTRIBUTORS_JSON), and the Lambda@Edge bundle
# takes the same strings baked into its config zip. This is the only place
# Terraform renders that JSON shape, so a change to the worker's env contract
# changes the rendering here and nowhere else in Terraform.
#
# The shape is written out by hand one more time outside Terraform, in
# deploy/publisher-wellknown/template-env.json — the worked example operators are
# told to compare their own deployment against. The test suite pins this
# rendering to that file, so the two cannot drift apart.

output "exchanges_json" {
  description = "JSON array of exchange entries the worker advertises in ramp.json (EXCHANGES_JSON)."
  value = jsonencode([{
    domain             = var.exchange_fqdn
    endpoint           = "https://${var.exchange_fqdn}"
    supported_profiles = ["ramp-news-v1"]
    ext                = { resource_owner_id = var.resource_owner_id }
  }])
}

output "catalog_contributors_json" {
  description = "JSON array of catalog contributors the worker advertises and the Exchange authorizes for signed catalog pushes (CATALOG_CONTRIBUTORS_JSON)."
  value = jsonencode([{
    domain       = var.catalog_contributor_id
    relationship = "operator"
  }])
}
