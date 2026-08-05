# publisher-manifest

Resource-free module that renders the edge worker's publisher-manifest env
values — the `EXCHANGES_JSON` and `CATALOG_CONTRIBUTORS_JSON` strings — from a
deployment's hostnames and ids. Both edge deployment shapes consume the same
strings: the `cloudflare-edge` module wires them as worker bindings, and the
Lambda@Edge build bakes them into its bundle. Rendering them here, once, means
a change to the worker's env contract has exactly one Terraform home.

Because the module creates no resources, it is safe to evaluate even while an
edge module is counted out (e.g. a bootstrap apply that renders the Lambda
config before the bundle exists).

## Inputs

| Name | Description |
|------|-------------|
| `exchange_fqdn` | Full Exchange hostname; the endpoint URL is derived as `https://<exchange_fqdn>` |
| `resource_owner_id` | Settlement payee attested in the exchange entry's `ext` object |
| `catalog_contributor_id` | Identity authorized to push the publisher's catalog |

## Outputs

| Name | Description |
|------|-------------|
| `exchanges_json` | JSON array of exchange entries (`EXCHANGES_JSON`) |
| `catalog_contributors_json` | JSON array of catalog contributors (`CATALOG_CONTRIBUTORS_JSON`) |

## Tests

`tests/manifest_unit_test.tftest.hcl` pins the exact rendered strings, and pins
them a second time against `deploy/publisher-wellknown/template-env.json` — the
operator-facing worked example that states the same shape by hand
(`terraform init -backend=false && terraform test` from this directory; also
wired into `deploy/terraform/scripts/test-terraform.sh`).
