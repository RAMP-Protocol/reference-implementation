# Unit tests for the cloudflare-dns module. The Cloudflare provider is
# MOCKED: no token, no API calls, no real records.
#
# Run from the module directory: terraform init && terraform test

mock_provider "cloudflare" {}

# Mirrors what stacks/staging-aws actually passes, wildcard included, so the
# whole-map assertions below cover the shapes the real caller uses rather than
# a reduced fixture.
variables {
  zone_id = "abcdef0123456789abcdef0123456789"
  a_records = {
    exchange = "198.51.100.10"
    broker   = "198.51.100.10"
    mcp      = "198.51.100.10"
    login    = "198.51.100.10"
    origin   = "198.51.100.10"
    "*.mcp"  = "198.51.100.10"
  }
}

run "one_record_per_service_dns_only" {
  command = plan

  assert {
    condition     = length(cloudflare_record.this) == 6
    error_message = "Exactly one A record per map entry"
  }

  assert {
    condition = alltrue([
      for record in cloudflare_record.this :
      record.type == "A" && record.content == "198.51.100.10"
    ])
    error_message = "Every record must be an A record pointing at the given address"
  }

  assert {
    condition = alltrue([
      for record in cloudflare_record.this : record.proxied == false
    ])
    error_message = "Service records default to DNS-only (Caddy terminates TLS; ACME must reach the origin)"
  }

  assert {
    condition     = cloudflare_record.this["exchange"].ttl == 300
    error_message = "DNS-only records carry the configured TTL"
  }
}

run "wildcard_label_survives_verbatim_and_dns_only" {
  command = plan

  # The map key is the record name. Nothing may normalise or escape it: the
  # agent Web Bot Auth directories live at <agent>.mcp.<zone>, hostnames that
  # do not exist until a developer signs up, so a wildcard is the only record
  # Terraform can create for them ahead of time.
  assert {
    condition     = cloudflare_record.this["*.mcp"].name == "*.mcp"
    error_message = "The wildcard label must reach Cloudflare unchanged — a sanitised name would silently cover nothing"
  }

  # Coupled to Caddy's on-demand issuance, which is what mints each agent
  # subdomain's certificate: proxying these names would terminate TLS at
  # Cloudflare, the ACME challenge would never reach the VM, and every agent
  # directory would fail to serve.
  assert {
    condition     = cloudflare_record.this["*.mcp"].proxied == false
    error_message = "The wildcard must stay DNS-only or on-demand certificate issuance cannot complete"
  }
}

run "proxied_mode_forces_automatic_ttl" {
  command = plan

  variables {
    proxied = true
  }

  assert {
    condition = alltrue([
      for record in cloudflare_record.this : record.proxied == true && record.ttl == 1
    ])
    error_message = "Proxied records must use Cloudflare's automatic TTL (1)"
  }
}
