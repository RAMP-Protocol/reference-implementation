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

variable "static_wba_directories" {
  description = "Static Web Bot Auth key directories Caddy serves itself: hostname => JWK Set JSON document (public keys only). For identities whose private keys deliberately never reach the VM — e.g. an operator-held smoke signer: a verifier resolves the signer's key by fetching https://<hostname>/.well-known/http-message-signatures-directory, so serving the public document here is what lets the services verify those signatures. Each hostname needs its own DNS record pointing at this VM."
  type        = map(string)
  default     = {}

  validation {
    # Mirrors the required half of the canonical directory schema
    # (internal/rampwellknown/schema/ramp-wba-directory.json): at least one
    # key, and every entry carries all seven members with an unpadded
    # 43-character base64url x and RFC 3339 window bounds. Without this, a
    # document missing `use` or carrying a padded x applies cleanly, serves
    # 200, and fails the first signed request with an error that points at
    # the signature — this check moves that failure to `terraform plan`.
    condition = alltrue([
      for doc in values(var.static_wba_directories) : (
        length(try(jsondecode(doc).keys, [])) > 0 &&
        alltrue([
          for k in try(jsondecode(doc).keys, []) :
          try(k.kty, null) == "OKP" &&
          try(k.crv, null) == "Ed25519" &&
          try(k.use, null) == "sig" &&
          try(k.alg, null) == "EdDSA" &&
          can(regex("^[A-Za-z0-9_-]{43}$", try(k.x, ""))) &&
          can(regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:\\d{2})$", try(k.not_before, ""))) &&
          can(regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:\\d{2})$", try(k.not_after, "")))
        ])
      )
    ])
    error_message = "Every static_wba_directories document must be a JWK Set with at least one key, and every key must carry kty=OKP, crv=Ed25519, use=sig, alg=EdDSA, an unpadded 43-character base64url x, and RFC 3339 not_before/not_after. Verifiers require this exact shape — a malformed document would deploy fine and then fail every signed request."
  }

  validation {
    # The map KEYS are the half that reaches configuration verbatim: each
    # hostname is interpolated into a Caddy site block and rewrite target
    # (Caddyfile.tftpl) and a cloud-init write_files path — the documents
    # themselves travel base64-encoded, so the hostname is the only part
    # that lands in rendered configuration as-is. Same restriction the
    # module's other template-bound string inputs carry (registry_server,
    # registry_username, extra_databases).
    condition = alltrue([
      for hostname in keys(var.static_wba_directories) :
      can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", hostname))
    ])
    error_message = "Every static_wba_directories key must be a lowercase DNS hostname (labels of letters, digits, and inner hyphens, joined by dots) — it is interpolated verbatim into the Caddyfile and a cloud-init file path."
  }
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

variable "default_agent_credit" {
  description = "EXCHANGE_DEFAULT_AGENT_CREDIT for the Exchange: one-time welcome credit granted to each newly registered agent. The value is in WHOLE units of the ledger currency, not minor units — \"100\" on the default EUR ledger grants EUR 100.00 to each new agent, not 100 cents. The default \"0\" disables the grant. This env variable is the sole owner of the default tenant's stored credit value: every Exchange boot overwrites the stored value with it, so changing the credit means re-applying and restarting the stack, and a value edited into the database by hand does not survive a restart."
  type        = string
  default     = "0"
  nullable    = false

  # The Exchange accepts only a plain decimal with at most 8 fraction digits
  # (the ledger asset scale) and STOPS THE BOOT on anything else — exponents,
  # negative values, currency symbols, thousands separators. This check moves
  # that boot failure to `terraform plan`.
  validation {
    condition     = can(regex("^[0-9]+(\\.[0-9]{1,8})?$", var.default_agent_credit))
    error_message = "default_agent_credit must be a plain decimal with at most 8 fraction digits (e.g. \"0\", \"100\", \"9.99\") — anything else stops the Exchange boot. The unit is whole currency units of the ledger currency: \"100\" grants 100.00, not 1.00."
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

# ── Zitadel outbound mail ────────────────────────────────────────────────────
# Zitadel reads these ONLY when it creates its instance on the very first
# start (its FirstInstance setup step). Changing them later has no effect on a
# running instance — the stored provider is edited through the Zitadel console
# or its Admin API instead. Because the values travel in the rendered compose
# file, and that file is the VM's cloud-init user data, changing any of them
# replaces the VM and rebuilds the whole deployment from empty.
#
# Left null the deployment has no mail provider: Zitadel cannot send the
# confirmation code self-registration needs.

variable "smtp_host" {
  description = "SMTP relay as host:port (e.g. \"email-smtp.us-east-1.amazonaws.com:587\"). Null disables outbound mail. Zitadel reads this only when it first creates its instance."
  type        = string
  default     = null

  validation {
    # The port is required, not optional: Zitadel's SMTP client dials the
    # string as given and does not default to 25/587, so a bare hostname
    # fails at send time — long after the apply that introduced it.
    condition     = var.smtp_host == null ? true : can(regex("^[A-Za-z0-9.-]+:[0-9]{1,5}$", var.smtp_host))
    error_message = "smtp_host must be host:port with a numeric port (e.g. email-smtp.us-east-1.amazonaws.com:587). Zitadel dials this string verbatim and supplies no default port."
  }
}

variable "smtp_user" {
  description = "SMTP username. For Amazon SES this is the IAM access key id of the sending user."
  type        = string
  default     = null
}

variable "smtp_password" {
  description = "SMTP password. For Amazon SES this is the region-derived SMTP password (aws_iam_access_key.<name>.ses_smtp_password_v4), NOT the raw secret access key."
  type        = string
  default     = null
  sensitive   = true
}

variable "smtp_from" {
  description = "Envelope and header sender address. Must be an address the relay is allowed to send as — for SES, one under the verified identity."
  type        = string
  default     = null

  validation {
    # Shape plus an explicit CR/LF ban: the value is interpolated into the
    # compose file and then into a mail header, where an embedded newline
    # would let a bad value inject a second header.
    condition     = var.smtp_from == null ? true : can(regex("^[^@\\s]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", var.smtp_from))
    error_message = "smtp_from must be a single email address with no whitespace or line breaks."
  }
}

variable "smtp_from_name" {
  description = "Display name shown next to the sender address. Null renders the address alone."
  type        = string
  default     = null

  validation {
    # Same header-injection reasoning as smtp_from, with a length cap that
    # keeps the rendered YAML line reasonable.
    condition     = var.smtp_from_name == null ? true : (length(var.smtp_from_name) <= 78 && !can(regex("[\r\n]", var.smtp_from_name)))
    error_message = "smtp_from_name must be at most 78 characters and contain no line breaks."
  }
}

variable "exchange_registration_schema" {
  description = "JSON Schema the Exchange publishes as account_registration.data_schema and enforces on Register. Pass the schema as a JSON STRING (build it with jsonencode). Unset publishes no schema and registration accepts any payload. Publishing a schema IS the enforcement switch: a registration that does not conform is refused from the moment this is set."
  type        = string
  default     = null

  validation {
    # The Exchange REFUSES TO BOOT on a schema it cannot use — deliberate, so
    # an operator never believes a requirement is published while it is not.
    # That makes a typo here a demo outage, so catch unparseable JSON at plan
    # time instead of at first boot.
    condition     = var.exchange_registration_schema == null || can(jsondecode(var.exchange_registration_schema))
    error_message = "exchange_registration_schema must be a JSON string. The Exchange refuses to boot on a schema it cannot parse, so a malformed value here takes the deployment down rather than degrading."
  }
}

variable "exchange_terms_uri" {
  description = "URI of the terms document the Exchange publishes as account_registration.terms_uri. Point it at an immutable, revisioned path (…/terms/revision-1.txt), never a mutable one: registrations accepted under a revision must still resolve once the next revision exists."
  type        = string
  default     = null

  validation {
    condition     = var.exchange_terms_uri == null || can(regex("^https://", var.exchange_terms_uri))
    error_message = "exchange_terms_uri must be an https:// URI — a registering client fetches it to read the terms it is accepting."
  }
}

variable "exchange_terms_digest" {
  description = "Digest of the terms document the Exchange publishes as account_registration.terms_digest and holds registering clients to. It must equal the digest of the bytes actually SERVED — derive it with filesha256() over the same file passed in exchange_terms_documents rather than writing it by hand."
  type        = string
  default     = null

  validation {
    # The format the protocol pins for this field.
    condition     = var.exchange_terms_digest == null || can(regex("^(sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96}|sha512:[0-9a-f]{128})$", var.exchange_terms_digest))
    error_message = "exchange_terms_digest must be sha256:<64 hex>, sha384:<96 hex> or sha512:<128 hex>, lowercase."
  }
}

variable "exchange_terms_documents" {
  description = "Terms documents Caddy serves under /terms/ on the Exchange hostname: filename => content. A MAP rather than a single document because every revision you have published must stay online — a digest of a deleted document identifies nothing. Adding a revision later is one entry here plus one digest line, with no Caddy change. Empty serves nothing and leaves the rendered Caddyfile and compose bundle byte-identical to a deployment without this feature."
  type        = map(string)
  default     = {}

  validation {
    # The map KEYS are the half that reaches configuration verbatim: each one
    # becomes a cloud-init write_files path under /opt/ramp/exchange-terms and
    # is served from that directory. The documents themselves travel base64,
    # so the filename is the only part landing in rendered config as-is. Same
    # restriction static_wba_directories puts on its hostname keys, and for
    # the same reason.
    condition = alltrue([
      for name in keys(var.exchange_terms_documents) :
      can(regex("^[A-Za-z0-9][A-Za-z0-9._-]*$", name)) && !strcontains(name, "..")
    ])
    error_message = "Every exchange_terms_documents key must be a plain filename: letters, digits, then letters, digits, dots, underscores or hyphens. No directory separators, no .., no whitespace, no control characters — the key becomes a cloud-init file path."
  }
}
