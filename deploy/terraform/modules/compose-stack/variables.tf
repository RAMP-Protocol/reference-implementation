# ── Public hostnames (Caddy terminates TLS for each) ─────────────────────────

variable "exchange_hostname" {
  description = "Public full domain name of the Exchange, e.g. exchange.staging.example.com."
  type        = string
  nullable    = false
}

variable "broker_hostname" {
  description = "Public full domain name of the Broker."
  type        = string
  nullable    = false
}

variable "identity_hostname" {
  description = "Public full domain name of the Identity Service: the MCP endpoint agents connect to and the OAuth issuer developers sign up against. It is ALSO the zone agent directories are published under — an agent provisioned as <slug> serves its Web Bot Auth directory at <slug>.<identity_hostname>, so a wildcard *.<identity_hostname> record must resolve to this VM."
  type        = string
  nullable    = false
}

variable "zitadel_hostname" {
  description = "Public full domain name of the bundled Zitadel, the upstream OIDC provider the Identity Service delegates developer sign-in to. Public because the sign-up flow redirects the developer's browser here, and because the OIDC issuer must be the same URL inside and outside the compose network."
  type        = string
  nullable    = false
}

variable "origin_hostname" {
  description = "Optional public full domain name for the demo publisher origin (the edge worker's ORIGIN_URL target). Requires publisher_image. Null disables the publisher service. Staging-only: the origin is publicly reachable, which a production publisher would restrict."
  type        = string
  default     = null
}

# ── Container images ─────────────────────────────────────────────────────────

variable "exchange_image" {
  description = "Full Exchange image reference, e.g. registry.example.com/group/ramp/exchange:latest."
  type        = string
  nullable    = false
}

variable "broker_image" {
  description = "Full Broker image reference."
  type        = string
  nullable    = false
}

variable "identity_image" {
  description = "Full Identity Service image reference (built by build-push-images.sh from src/identity/Dockerfile)."
  type        = string
  nullable    = false
}

variable "publisher_image" {
  description = "Optional demo publisher origin image (nginx + demo content, built by build-push-images.sh). Required when origin_hostname is set."
  type        = string
  default     = null
}

# ── Registry auth (only for private registries) ──────────────────────────────

variable "registry_server" {
  description = "Registry hostname to docker-login against on first boot (e.g. registry.gitlab.com). Null when the images are public."
  type        = string
  default     = null

  # Interpolated into a root shell command in cloud-init (docker login) —
  # restrict to hostname[:port] characters so no shell syntax can ride in.
  validation {
    condition     = var.registry_server == null || can(regex("^[A-Za-z0-9.-]+(:[0-9]+)?$", var.registry_server))
    error_message = "registry_server must be a plain hostname, optionally with :port."
  }
}

variable "registry_username" {
  description = "Registry username (e.g. a GitLab deploy-token username). Required when registry_server is set."
  type        = string
  default     = null

  # Interpolated into the same root docker-login command as registry_server.
  # Real registry usernames never need anything outside this set; a quote or
  # shell metacharacter here would otherwise run as root on first boot.
  validation {
    condition     = var.registry_username == null || can(regex("^[A-Za-z0-9._+@-]+$", var.registry_username))
    error_message = "registry_username may only contain letters, digits, and . _ + @ - characters."
  }
}

variable "registry_password" {
  description = "Registry password/token. Delivered to the VM base64-encoded in a root-only file and piped to docker login via --password-stdin; any characters are safe."
  type        = string
  default     = null
  sensitive   = true
}

# ── Service configuration ────────────────────────────────────────────────────

variable "billing_adapter" {
  description = "RAMP_BILLING_ADAPTER for the Exchange. \"tigerbeetle\" (staging default — per-article accounting on a real ledger) also enables the TigerBeetle container; \"free\" approves everything with no ledger."
  type        = string
  default     = "tigerbeetle"
  nullable    = false

  validation {
    condition     = contains(["tigerbeetle", "free", "inmemory"], var.billing_adapter)
    error_message = "billing_adapter must be one of: tigerbeetle, free, inmemory."
  }
}

variable "billing_ledger" {
  description = "EXCHANGE_BILLING_LEDGER for the tigerbeetle adapter: ISO 4217 numeric currency of the ledger. Default 978 (EUR) matches the demo feed's pricing currency. Ignored by the free/inmemory adapters."
  type        = string
  default     = "978"
  nullable    = false

  validation {
    condition     = contains(["978", "840"], var.billing_ledger)
    error_message = "billing_ledger must be an ISO 4217 numeric code the Exchange supports: 978 (EUR) or 840 (USD)."
  }
}

variable "broker_id" {
  description = "BROKER_ID the Broker announces."
  type        = string
  default     = "broker-staging"
  nullable    = false
}

variable "exa_api_key" {
  description = "Optional EXA API key for Broker discovery. Null leaves discovery to direct URIs only."
  type        = string
  default     = null
  sensitive   = true
}

variable "extra_databases" {
  description = "Extra Postgres databases created at first cluster init (multi-exchange topologies). Empty for the single-exchange staging stack."
  type        = list(string)
  default     = []
  nullable    = false

  # Rendered into CREATE DATABASE statements in the init SQL. Operator-only
  # input, but restricting to plain identifiers keeps SQL syntax out by
  # construction.
  validation {
    condition     = alltrue([for db in var.extra_databases : can(regex("^[a-z_][a-z0-9_]*$", db))])
    error_message = "extra_databases entries must be plain lowercase identifiers (letters, digits, underscore; not starting with a digit)."
  }
}

variable "network_subnet" {
  description = "IPAM subnet of the compose network. Override when the default range collides with the host's existing networks (the compose bundle also runs in publisher data centers, where 172.28.0.0/24 may already be in use). TigerBeetle gets host 10 of this subnet as its static address."
  type        = string
  default     = "172.28.0.0/24"
  nullable    = false

  validation {
    condition     = can(cidrhost(var.network_subnet, 10))
    error_message = "network_subnet must be a valid CIDR block with room for at least 10 hosts (e.g. 172.28.0.0/24)."
  }
}

# ── TLS / ACME ───────────────────────────────────────────────────────────────

variable "acme_email" {
  description = "Email Caddy registers with Let's Encrypt."
  type        = string
  nullable    = false
}

variable "acme_staging" {
  description = "Use the Let's Encrypt STAGING CA (untrusted certs). Turn on while iterating on apply/destroy cycles to stay clear of production rate limits; off for the real staging environment."
  type        = bool
  default     = false
  nullable    = false
}

# ── Key material (written to /opt/ramp/keys on the VM) ───────────────────────
# Generate everything with deploy/terraform/scripts/gen-staging-keys.sh.
# All of it lands in Terraform state — the state file is a secret.

variable "ed25519_private_pem" {
  description = "Exchange Ed25519 offer/URL signing key (PEM). The Exchange fails closed without it."
  type        = string
  sensitive   = true
  nullable    = false
}

variable "rsa_private_pem" {
  description = "Optional Exchange RSA signing key (PEM), needed only by AWS_CLOUDFRONT_RSA tenants. Null for a stack whose every tenant is on the ED25519 scheme: the Exchange starts without it and refuses only the requests that would need it, naming the setting to add. A key that IS supplied is parsed at boot, so a malformed one fails fast."
  type        = string
  default     = null
  sensitive   = true
}

variable "keys_json" {
  description = "Shared httpsig key registry content (public keys only) read by Exchange and Broker via RAMP_KEYS_FILE/BROKER_KEYS_FILE."
  type        = string
  nullable    = false
}

variable "broker_relay_key_json" {
  description = "Broker relay signing keypair (JSON with private key). Without it the Broker ships unsigned Exchange calls and the Exchange rejects them."
  type        = string
  sensitive   = true
  nullable    = false
}

variable "default_tenant_domain" {
  description = "Domain of the tenant the Exchange reads its agent-activation policy from at Register (EXCHANGE_DEFAULT_TENANT). MUST be the domain the seed step creates the tenant under — the demo publisher hostname for the staging stack, not the Exchange's own hostname. Stated rather than defaulted because the binary's fallback is EXCHANGE_DOMAIN, which is the Exchange hostname: under that fallback no tenant row matches and every agent Register fails with a default-tenant-not-seeded error."
  type        = string
  nullable    = false

  # An empty string is the same trap as an unset variable: the binary treats an
  # empty env var as absent and falls back to EXCHANGE_DOMAIN, the exact broken
  # posture described above — caught here rather than as a runtime Register
  # failure.
  validation {
    condition     = length(trimspace(var.default_tenant_domain)) > 0
    error_message = "default_tenant_domain must not be empty (or whitespace) — an empty EXCHANGE_DEFAULT_TENANT falls back to the Exchange hostname, where no tenant row exists, and every agent Register fails."
  }
}

variable "broker_identity_key_pem" {
  description = "Broker identity private key (PEM with a raw 64-byte ed25519 payload — the shape gen-staging-keys.sh derives into keys/broker-identity-key.pem, NOT what openssl writes), delivered to the VM as a key file and read via BROKER_ED25519_KEY_FILE. A DIFFERENT key from broker_relay_key_json: the Broker publishes this one's public half in its WBA directory with a 90-day validity window, so it must be stable across restarts. The Broker refuses to boot without it rather than mint a throwaway that invalidates the window it just published. A key file rather than a BROKER_ED25519_SEED env value on purpose: the rendered compose file is world-readable on the VM, the per-service key directory is not."
  type        = string
  sensitive   = true
  nullable    = false

  # Two shape checks at plan time, together catching the two likely wrong
  # files: openssl's PKCS#8 (different label AND a 48-byte payload) and a
  # truncated paste. Both would otherwise pass the plan and crash-loop the
  # Broker on "PEM payload must be 64 bytes for ed25519 private key".
  validation {
    # The exact label the generator writes. openssl writes "PRIVATE KEY"
    # (PKCS#8) or "RSA PRIVATE KEY" — neither carries ED25519, so an
    # openssl-generated paste fails here, at plan time. Note this label check
    # is a generator convention and stricter than the Broker's loader, which
    # checks only the payload length: a differently-labelled file the Broker
    # would accept is still refused here.
    condition     = can(regex("-----BEGIN ED25519 PRIVATE KEY-----", var.broker_identity_key_pem))
    error_message = "broker_identity_key_pem must be the ED25519 PRIVATE KEY block gen-staging-keys.sh writes to keys/broker-identity-key.pem — not an openssl-generated PEM, whose PKCS#8 payload the Broker's loader rejects."
  }

  validation {
    # 64 raw bytes base64-encode to exactly 88 characters (padding included).
    # Terraform cannot base64-decode binary key material (base64decode demands
    # UTF-8), so the payload length is checked in its encoded form: strip the
    # header/footer lines, count the base64 characters.
    condition     = length(join("", regexall("[A-Za-z0-9+/=]", replace(var.broker_identity_key_pem, "/-----[A-Z0-9 ]+-----/", "")))) == 88
    error_message = "broker_identity_key_pem's payload must be exactly 64 raw bytes (88 base64 characters) — the ed25519 seed||public shape the Broker's loader requires. A truncated paste or a PKCS#8 body fails this."
  }
}
