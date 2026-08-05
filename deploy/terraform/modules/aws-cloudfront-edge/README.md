# aws-cloudfront-edge

CloudFront + Lambda@Edge deployment of the RAMP edge worker — the AWS
counterpart of the `cloudflare-edge` module, for deployments whose DNS stays
in Route 53. The same shared edge application runs as a viewer-request
Lambda@Edge function: it verifies Ed25519 signed URLs (and runs the bot gate
and well-known routes), then passes authorized requests through so CloudFront
fetches the custom origin. Content bodies never transit the function, which
keeps it inside the ~40 KB viewer-request response cap.

Unlike `cloudflare-edge`, this module takes no worker environment inputs:
Lambda@Edge has no environment variables, so the per-deployment config is
baked INTO the bundle zip by `deploy/terraform/scripts/build-lambda-edge.sh`.
Changing config means rebuilding the zip and re-applying.

## Placement requirements

- Instantiate with a **us-east-1** provider (`providers = { aws = ... }`).
  Lambda@Edge functions and CloudFront's ACM certificate are only accepted
  from us-east-1; a precondition fails the plan otherwise.
- DNS for `hostname` is NOT created here. Point it at the distribution with
  the `route53-dns` module's `alias_records`, using this module's
  `distribution_domain_name` / `distribution_hosted_zone_id` outputs.
- Teardown caveat: after removing the association, CloudFront needs up to a
  few hours to delete the function's edge replicas; destroying the function
  fails until then. Destroy the distribution first, wait, then the function.

## Inputs

| Name | Description | Default |
|------|-------------|---------|
| `name_prefix` | Prefix every named resource carries, so an ARN-scoped deployer policy can enumerate them | `"ramp"` |
| `lambda_zip_path` | Pre-built bundle zip (config baked in); plan fails with a pointer to the build script when missing | — |
| `hostname` | Publisher hostname the distribution serves (certificate domain + alias) | — |
| `zone_id` | Route 53 zone id for the certificate's DNS-validation record | — |
| `origin_domain` | Custom origin CloudFront fetches verified content from (must serve TLS for its own name) | — |
| `price_class` | CloudFront price class | `"PriceClass_100"` |

## Outputs

| Name | Description |
|------|-------------|
| `distribution_domain_name` | Alias target for the `route53-dns` module |
| `distribution_hosted_zone_id` | CloudFront's alias hosted zone id |
| `distribution_id` | For invalidations and console lookups |
| `lambda_qualified_arn` | The published (versioned) ARN CloudFront runs |
| `certificate_arn` | The validated ACM certificate |

## Design decisions encoded here

- **One default cache behavior, no `/.well-known/*` bypass**: the shared app
  serves well-known routes before its bot gate, so nothing can 403-lock
  discovery, and one behavior keeps one code path.
- **`Managed-CachingDisabled`**: correctness first for a demo; the
  viewer-request placement keeps any later caching decision safe because the
  function also runs on cache hits.
- **`Managed-AllViewerExceptHostHeader`**: the origin virtual-hosts and
  serves TLS for its own name, so the viewer's Host header must not reach it.
- **`trusted_key_groups = []` explicitly**: CloudFront's native signed-URL
  check is RSA-only and stays off — Ed25519 verification lives in the
  function. Empty is stated, never omitted.
- **Log permissions span `arn:aws:logs:*`** (name-scoped): Lambda@Edge logs
  land in the region that served the request, under
  `/aws/lambda/us-east-1.<function>` in each serving region.

## Tests

`tests/edge_unit_test.tftest.hcl` runs offline against a mocked AWS provider
(`terraform init -backend=false && terraform test` from this directory; also
wired into `deploy/terraform/scripts/test-terraform.sh`).
