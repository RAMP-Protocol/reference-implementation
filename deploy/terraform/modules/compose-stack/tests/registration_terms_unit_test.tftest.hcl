# Rendering tests for the Exchange's published registration schema and terms
# documents. Separate from render_unit_test.tftest.hcl only because that file
# is already at the repository's test-file length cap — same split, and same
# reason, as smtp_unit_test.tftest.hcl beside it.
#
# Same properties as its siblings: `command = apply` is needed because the
# templates interpolate random_password, and the module's only resources ARE
# those in-memory random strings — nothing is created outside the test process.
#
# Run from the module directory: terraform init && terraform test

variables {
  exchange_hostname = "exchange.staging.example"
  broker_hostname   = "broker.staging.example"
  identity_hostname = "mcp.staging.example"
  zitadel_hostname  = "login.staging.example"

  default_tenant_domain = "demo.staging.example"

  exchange_image = "registry.example.com/group/proj/exchange:test"
  broker_image   = "registry.example.com/group/proj/broker:test"
  identity_image = "registry.example.com/group/proj/identity:test"

  acme_email = "ops@example.com"

  # Dummy key material — shape only, never used cryptographically.
  ed25519_private_pem     = "-----BEGIN PRIVATE KEY-----\ndGVzdA==\n-----END PRIVATE KEY-----\n"
  broker_relay_key_json   = "{\"kid\":\"broker.test.v1\"}"
  broker_identity_key_pem = "-----BEGIN ED25519 PRIVATE KEY-----\nZmFrZSBicm9rZXIgaWRlbnRpdHkgZml4dHVyZTogZXhhY3RseSBzaXh0eS1mb3VyIGJ5dGVzIGZvciB0ZnRlcw==\n-----END ED25519 PRIVATE KEY-----\n"
}

# ---------------------------------------------------------------------------
# Registration schema and terms publishing.
#
# The unset case is a DATA-SAFETY property, not tidiness: the Caddyfile is
# embedded in user_data, aws-vm defaults user_data_replace_on_change to true,
# and staging-aws shares this module — so a byte of drift here replaces that
# VM on its next apply.
# ---------------------------------------------------------------------------

run "registration_schema_and_terms_absent_by_default" {
  command = apply

  assert {
    condition     = !strcontains(output.compose_yaml, "EXCHANGE_REGISTRATION_SCHEMA")
    error_message = "No schema configured -> the Exchange must publish and enforce nothing"
  }

  assert {
    condition = (
      !strcontains(output.compose_yaml, "EXCHANGE_TERMS_URI") &&
      !strcontains(output.compose_yaml, "EXCHANGE_TERMS_DIGEST")
    )
    error_message = "No terms configured -> neither terms variable may reach the Exchange"
  }

  assert {
    condition     = !strcontains(output.compose_yaml, "/srv/exchange-terms")
    error_message = "No terms configured -> Caddy must not get the terms bind mount"
  }

  assert {
    condition     = !strcontains(output.user_data, "/opt/ramp/exchange-terms")
    error_message = "No terms configured -> cloud-init must write no terms documents"
  }

  # The Exchange site block must stay EXACTLY as it renders without this
  # feature: a bare reverse_proxy, one tab, no handler wrapper. Wrapping it in
  # `handle { ... }` unconditionally is behaviour-preserving for Caddy and
  # still replaces every VM built from this module.
  assert {
    condition     = strcontains(output.user_data, "exchange.staging.example {\n      \treverse_proxy exchange:8081\n      }")
    error_message = "Unset terms must leave the Exchange site block byte-identical: a bare, tab-indented reverse_proxy with no handle wrapper"
  }

  assert {
    condition     = !strcontains(output.user_data, "handle_path /terms/*")
    error_message = "No terms configured -> no terms route in the Caddyfile"
  }
}

run "registration_schema_survives_both_encoding_layers" {
  command = apply

  variables {
    exchange_registration_schema = "{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"type\":\"object\",\"required\":[\"legal_entity\"]}"
  }

  # Layer one, YAML: jsonencode wraps the schema in a quoted scalar so the
  # quotes a JSON Schema is full of survive the parse.
  assert {
    condition     = strcontains(output.compose_yaml, "EXCHANGE_REGISTRATION_SCHEMA: \"{\\\"")
    error_message = "The schema must reach the compose file as a quoted, escaped YAML scalar"
  }

  # Layer two, Compose: docker compose interpolates $VAR in the compose file
  # itself and a JSON Schema opens with \"$schema\". Unescaped, Compose warns
  # that `schema` is unset, substitutes an empty string, and the Exchange gets
  # a schema whose first key is \"\" — silent corruption of a value it refuses
  # to boot without understanding.
  #
  # This assertion proves the file carries the escaped form. It CANNOT prove
  # Compose resolves it back: terraform test does not run Compose. That half is
  # verified by running `docker compose config` (and reading the value inside a
  # container) against the rendered bundle.
  assert {
    condition     = strcontains(output.compose_yaml, "$$schema")
    error_message = "The schema's $ must be doubled or Compose silently empties the $schema key"
  }
}

run "terms_documents_are_written_mounted_and_served" {
  command = apply

  variables {
    exchange_terms_uri    = "https://exchange.staging.example/terms/revision-1.txt"
    exchange_terms_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    exchange_terms_documents = {
      "revision-1.txt" = "DEMO TERMS revision 1\n"
    }
  }

  assert {
    condition     = strcontains(output.user_data, "/opt/ramp/exchange-terms/revision-1.txt")
    error_message = "Each terms document must be written to the host directory Caddy's mount points at"
  }

  # Base64 is what makes the served bytes equal the bytes filesha256()
  # measured; a YAML block scalar could re-wrap or renormalize them and the
  # mismatch would look like a stale digest rather than a delivery problem.
  assert {
    condition     = strcontains(output.user_data, base64encode("DEMO TERMS revision 1\n"))
    error_message = "Terms documents must travel base64 so the served bytes match the published digest"
  }

  # Caddy runs in a container: without this mount `root * /srv/exchange-terms`
  # resolves to an empty path inside it and file_server serves nothing.
  assert {
    condition     = strcontains(output.compose_yaml, "/opt/ramp/exchange-terms:/srv/exchange-terms:ro")
    error_message = "Caddy must bind-mount the terms directory or it cannot see the documents"
  }

  # handle_path, not handle: handle matches without stripping the prefix, so
  # the file would be looked for at /srv/exchange-terms/terms/revision-1.txt.
  assert {
    condition     = strcontains(output.user_data, "handle_path /terms/*")
    error_message = "The terms route must strip the /terms prefix, so it must use handle_path"
  }

  # With a handler block present the proxy has to move inside one too, or it
  # swallows /terms/* before file_server sees it.
  assert {
    condition     = strcontains(output.user_data, "handle {\n      \t\treverse_proxy exchange:8081")
    error_message = "When the terms route is present the Exchange proxy must be wrapped in handle {} or it swallows /terms/*"
  }

  assert {
    condition = (
      strcontains(output.compose_yaml, "EXCHANGE_TERMS_URI: \"https://exchange.staging.example/terms/revision-1.txt\"") &&
      strcontains(output.compose_yaml, "EXCHANGE_TERMS_DIGEST: \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"")
    )
    error_message = "Both terms variables must reach the Exchange environment"
  }
}

run "unparseable_registration_schema_is_rejected" {
  command = plan

  # The Exchange refuses to BOOT on a schema it cannot use, so a typo here
  # takes the deployment down. The validation moves that failure to plan.
  variables {
    exchange_registration_schema = "{\"type\": \"object\",}"
  }

  expect_failures = [var.exchange_registration_schema]
}

run "malformed_terms_digest_is_rejected" {
  command = plan

  variables {
    exchange_terms_digest = "sha256:deadbeef"
  }

  expect_failures = [var.exchange_terms_digest]
}

run "terms_document_key_that_escapes_its_directory_is_rejected" {
  command = plan

  # The map keys become cloud-init write_files paths, so they are the half
  # that reaches rendered configuration verbatim.
  variables {
    exchange_terms_documents = {
      "../../etc/cron.d/pwn" = "x"
    }
  }

  expect_failures = [var.exchange_terms_documents]
}
