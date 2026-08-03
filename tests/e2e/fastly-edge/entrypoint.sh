#!/bin/sh
# Fastly Compute runtime entry: materializes a config_store in fastly.toml from
# runtime env vars, then starts `fastly compute serve` under Viceroy.
#
# Fastly's env() is limited to built-in vars; arbitrary demo config arrives via
# a ConfigStore named `ramp_edge` (see src/index.ts).

set -eu

REQUIRED="EXCHANGE_URL EXCHANGE_WBA_URL ORIGIN_URL PROVIDER EXCHANGES_JSON"
for name in $REQUIRED; do
  eval "v=\${$name:-}"
  if [ -z "$v" ]; then
    echo "fastly-edge: missing env $name" >&2
    exit 2
  fi
done

cat >/app/fastly.toml <<EOF
manifest_version = 3
name = "ramp-fastly-edge"
description = "RAMP edge verifier on Fastly Compute (WASM)"
authors = ["ramp-demo"]
language = "javascript"
service_id = ""

[local_server]
  [local_server.backends]
    [local_server.backends.exchange]
    url = "${EXCHANGE_URL}"
    [local_server.backends.publisher]
    url = "${ORIGIN_URL}"

  [local_server.config_stores]
    [local_server.config_stores.ramp_edge]
    format = "inline-toml"
      [local_server.config_stores.ramp_edge.contents]
      EXCHANGE_URL = "${EXCHANGE_URL}"
      ORIGIN_URL = "${ORIGIN_URL}"
      PROVIDER = "${PROVIDER}"
      EXCHANGES_JSON = $(printf '%s' "$EXCHANGES_JSON" | node -e 'process.stdout.write(JSON.stringify(require("fs").readFileSync(0,"utf8")))')
      EXCHANGE_WBA_URL = "${EXCHANGE_WBA_URL:-}"
      RAMP_ENFORCE_BINDING = "${RAMP_ENFORCE_BINDING:-}"
      RSL_BODY = "${RSL_BODY:-}"
      CATALOG_CONTRIBUTORS_JSON = $(printf '%s' "${CATALOG_CONTRIBUTORS_JSON:-}" | node -e 'process.stdout.write(JSON.stringify(require("fs").readFileSync(0,"utf8")))')
      WBA_KEYS_JSON = $(printf '%s' "${WBA_KEYS_JSON:-}" | node -e 'process.stdout.write(JSON.stringify(require("fs").readFileSync(0,"utf8")))')
      WBA_REVOCATION_URL = "${WBA_REVOCATION_URL:-}"

[setup]
EOF

exec fastly compute serve --skip-build --addr="${FASTLY_SERVE_ADDR:-0.0.0.0:7676}"
