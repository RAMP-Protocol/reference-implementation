# Provider-neutral templating: renders the Docker Compose bundle, Caddyfile,
# Postgres init SQL, and the cloud-init user data that delivers them to a VM.
#
# The rendered compose file is the reference bundle for an own-DC deployment,
# and staging runs the exact artifact we hand over. Note that it now carries
# the whole agent-identity plane (the Identity Service, its Vault, and a
# Zitadel) alongside the publisher-facing services. A publisher operating only
# an Exchange and Broker does not need those three; splitting the bundle in two
# is future work, not something a caller can switch off today.

resource "random_password" "postgres" {
  # Alphanumeric only: the password is embedded in postgres:// DSNs, so it
  # must stay URL-safe without encoding.
  length  = 32
  special = false

  lifecycle {
    # Cross-variable pairing rules live here because preconditions must hang
    # off a resource, and this one is created unconditionally. A `check` block
    # would read nicer but only WARNS — it cannot fail the plan, so it cannot
    # gate.

    # Pairing rule for the demo publisher: origin_hostname gates the
    # service, publisher_image names what it runs. One without the other
    # would render an empty `image:` and fail confusingly at first boot —
    # fail the plan instead.
    precondition {
      condition     = (var.origin_hostname == null) == (var.publisher_image == null)
      error_message = "origin_hostname and publisher_image must be set together (or both left null)."
    }

    # docker login needs all three registry settings. A server without
    # credentials would fail the template render with an opaque null-value
    # error; credentials without a server would silently skip the login and
    # the VM could never pull private images. Fail the plan clearly instead.
    precondition {
      condition = (
        (var.registry_server == null) == (var.registry_username == null) &&
        (var.registry_server == null) == (var.registry_password == null)
      )
      error_message = "registry_server, registry_username, and registry_password must be set together (or all left null)."
    }
  }
}

# ── Identity-plane secrets ───────────────────────────────────────────────────
# Generated here rather than taken as inputs: nothing outside this bundle ever
# needs to know them, and an operator-supplied value would only be one more
# secret to store. They land in Terraform state like the Postgres password.
#
# They also land in the rendered cloud-init, which the caller delivers as EC2
# user data — readable by anyone holding ec2:DescribeInstanceAttribute in the
# account. Two of them are worth more than a database password: the Vault root
# token unlocks every agent signing key the service custodies, and the Zitadel
# admin password controls the provider that gates developer sign-up. Together
# they are enough to sign RAMP requests as any agent registered on the
# instance.
#
# Accepted for staging — throwaway VM, test identities — and NOT acceptable
# for production, where delivery has to move to a secrets store fetched at
# boot with an instance role. Adding a secret here puts it on the same
# footing, so weigh it against that before reaching for one. The full
# statement of the trade-off is in the README's "Secrets — read this".

resource "random_password" "zitadel_db" {
  # Alphanumeric for the same reason as the Postgres password: it travels in
  # connection settings that are not URL-escaped.
  length  = 32
  special = false
}

resource "random_password" "vault_root_token" {
  length  = 32
  special = false
}

resource "random_password" "zitadel_masterkey" {
  # Zitadel rejects a masterkey that is not EXACTLY 32 characters.
  length  = 32
  special = false
}

resource "random_password" "zitadel_admin" {
  # Console login for the operator (username zadmin). Zitadel's default
  # password policy wants all four character classes. The symbol set excludes
  # quotes, backslash and $ so the value stays safe to embed in the rendered
  # YAML without escaping.
  length           = 24
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1
  override_special = "!@#%^&*-_+="
}

resource "random_bytes" "identity_session_key" {
  # Cookie encryption key for the sign-up flow: 32 raw bytes, base64 to env.
  length = 32
}

resource "random_bytes" "identity_token_signing_key" {
  # Ed25519 seed the service signs its own bearer tokens with. Generated once
  # and held in state on purpose: if it changed per boot, every bearer the
  # service ever issued would be rejected after a restart.
  length = 32
}

locals {
  # Static compose-network addressing: EXCHANGE_BILLING_TB_ADDRESS rejects
  # hostnames (IP:port only), so TigerBeetle gets a fixed address — host 10
  # on the (overridable) IPAM subnet.
  tigerbeetle_ip = cidrhost(var.network_subnet, 10)

  # Two databases beyond the shared `ramp` one, both prepended rather than left
  # to the caller: each belongs to a service that is an unconditional part of
  # the bundle, so a stack that forgot to list it would boot a container that
  # crash-loops on a missing database.
  #
  #   identity  The Identity Service's own store (its migrations create an
  #             `identity` schema in it).
  #   sor       The Exchange's System of Record. EXCHANGE_SOR_DSN opens a
  #             SECOND pool distinct from EXCHANGE_DSN, and the Exchange
  #             applies the SoR migrations against it at boot but never
  #             CREATE DATABASEs — so the database has to exist first.
  databases = concat(["identity", "sor"], var.extra_databases)

  tigerbeetle_enabled = var.billing_adapter == "tigerbeetle"
  publisher_enabled   = var.origin_hostname != null

  compose_yaml = templatefile("${path.module}/templates/docker-compose.yml.tftpl", {
    exchange_hostname = var.exchange_hostname
    broker_hostname   = var.broker_hostname
    identity_hostname = var.identity_hostname
    zitadel_hostname  = var.zitadel_hostname
    exchange_image    = var.exchange_image
    broker_image      = var.broker_image
    identity_image    = var.identity_image
    publisher_image   = var.publisher_image
    publisher_enabled = local.publisher_enabled
    postgres_password = random_password.postgres.result

    zitadel_db_password        = random_password.zitadel_db.result
    zitadel_masterkey          = random_password.zitadel_masterkey.result
    vault_root_token           = random_password.vault_root_token.result
    identity_session_key       = random_bytes.identity_session_key.base64
    identity_token_signing_key = random_bytes.identity_token_signing_key.base64
    billing_adapter            = var.billing_adapter
    billing_ledger             = var.billing_ledger
    tigerbeetle_enabled        = local.tigerbeetle_enabled
    tigerbeetle_ip             = local.tigerbeetle_ip
    network_subnet             = var.network_subnet
    broker_id                  = var.broker_id
    default_tenant_domain      = var.default_tenant_domain
    exa_api_key                = var.exa_api_key
    rsa_enabled                = var.rsa_private_pem != null
  })

  caddyfile = templatefile("${path.module}/templates/Caddyfile.tftpl", {
    exchange_hostname = var.exchange_hostname
    broker_hostname   = var.broker_hostname
    identity_hostname = var.identity_hostname
    zitadel_hostname  = var.zitadel_hostname
    origin_hostname   = var.origin_hostname
    acme_email        = var.acme_email
    acme_staging      = var.acme_staging
  })

  init_sql = templatefile("${path.module}/templates/exchange-dbs.sql.tftpl", {
    extra_databases = local.databases
  })

  zitadel_init_steps = templatefile("${path.module}/templates/zitadel-init-steps.yaml.tftpl", {
    zitadel_admin_password = random_password.zitadel_admin.result
  })

  user_data = templatefile("${path.module}/templates/cloud-init.yaml.tftpl", {
    compose_yaml            = local.compose_yaml
    caddyfile               = local.caddyfile
    init_sql                = local.init_sql
    zitadel_init_steps      = local.zitadel_init_steps
    keys_json               = var.keys_json
    ed25519_private_pem     = var.ed25519_private_pem
    rsa_private_pem         = var.rsa_private_pem
    broker_relay_key_json   = var.broker_relay_key_json
    broker_identity_key_pem = var.broker_identity_key_pem
    registry_server         = var.registry_server
    registry_username       = var.registry_username
    registry_password       = var.registry_password
  })
}
