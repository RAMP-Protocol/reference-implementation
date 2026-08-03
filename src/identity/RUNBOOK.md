# RAMP Identity Service — Runbook

Operated by the Exchange Operator.

**Escalation.** If §3 does not resolve it, contact Postindustria at
`<support channel — fill in before handover>`. Send the `request_id` of a failing
request together with the matching log lines from the Identity Service, the Broker and
the Exchange. Postindustria has no access to your infrastructure, so that correlation
ID is the only way the request can be traced.

> This runbook assumes the Identity Service is already deployed. For installation,
> configuration values, applying or destroying the stack, and deploy-time
> verification, see [`DEPLOYMENT.md`](DEPLOYMENT.md) and
> [`CONFIGURATION.md`](CONFIGURATION.md).

---

## 1. Overview

The Identity Service is the front door for AI agents, and the keeper of their keys.

A developer signs up through your existing identity provider. The service gives them a
subdomain of the identity zone, generates a private key, stores it in Vault, and
publishes the matching public key at that subdomain. The agent then connects to `/mcp`
and calls tools; each call becomes a RAMP request signed with **that agent's** key and
sent to the Broker or an Exchange.

**It holds every agent's private key, and it never gives one out.** That makes this the
most sensitive service in the platform. Whoever can read its Vault store can act as any
agent registered in it — buy content, spend money, and file usage reports in that
agent's name. Treat the Vault backups with the same care as the live system
([`deploy/storage/vault/RUNBOOK.md`](../../deploy/storage/vault/RUNBOOK.md) §5).

**It is not on the delivery path.** It never sees the licensed content. If it is down,
agents cannot discover or buy — but the publisher's site is unaffected and delivery
links already issued keep working.

**One replica only.** See §4.1 before you run more than one.

---

## 2. Monitoring

### 2.1 Health

**`/healthz` pings PostgreSQL and nothing else.** It stays green with Vault
unreachable, with your OIDC provider down, and with the Broker and the Exchange
unreachable. Read it as "the process is up", not "the service works".

The Vault case is the one people miss: the service never checks Vault at start-up, so
a wrong address or an expired token produces a service that boots normally, reports
healthy, and fails every agent operation. Probe the other three things yourself:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://id.example/healthz
# Expect: 200

curl -s https://id.example/.well-known/oauth-authorization-server
# Expect: JSON whose "issuer" is your own address. If the hostname is wrong,
# nobody can sign in — the value is published, not derived from the request.

curl -s -o /dev/null -w '%{http_code}\n' -X POST https://id.example/mcp \
  -H 'Content-Type: application/json' -d '{}'
# Expect: 401 — the endpoint refusing an unauthenticated caller is the healthy
# answer. Anything else means it is not protected.

curl -s -o /dev/null -w '%{http_code}\n' \
  https://nosuch.agents.example/.well-known/http-message-signatures-directory
# Expect: 404 for an agent that does not exist.
# 503 here means VAULT IS UNREACHABLE — see §3.1.
```

The last one is the closest thing to a Vault health check this service offers. Run it
on the same schedule as `/healthz`.

### 2.2 Logs

JSON, one object per line, on stdout — `docker compose logs identity`. **There is no
`/metrics` endpoint and no Prometheus support**, so alerting is on log events.

Every line carries `request_id`, and it is the same value across the Identity Service,
the Broker and the Exchange — grep it in all three to trace one agent's call end to
end. It arrives or is created as the `X-Request-ID` header and is passed outbound.

| Event | Level | Means |
|---|---|---|
| `identity.exit` | ERROR | Refused to start. The message names the cause — the table in [`DEPLOYMENT.md`](DEPLOYMENT.md) §9 decodes it. |
| `identity.directory.error` | ERROR | An agent's document could not be built. The caller got `500`. |
| `identity.rotation.*_failed` | ERROR | Automatic key rotation failed for one agent. The `subdomain` field names which. Other agents are unaffected. |
| `identity.revoke.destroy_failed` | ERROR | A revoked key was recorded as revoked but could not be erased from Vault. The revocation still took effect. |
| `identity.oauthserver.*` (fault) | ERROR | A sign-up step failed server-side. |
| `identity.directory.unavailable` | WARN | Vault or the database is not answering. The caller got `503`. **The first sign of a Vault outage.** |
| `identity.signup.ephemeral_session_key` | WARN | `IDENTITY_SESSION_KEY` is unset. Sign-ups in progress break on every restart. |
| `identity.signup.ephemeral_token_key` | WARN | `IDENTITY_TOKEN_SIGNING_KEY` is unset. **Every agent is signed out on every restart.** |
| `identity.oauthserver.*` (outage) | WARN | A backend was unavailable during sign-up; the caller got `503`. |
| `identity.mcp.register` / `.status` / `.discover` / `.execute` / `.report` | INFO | One agent tool call. One line per call, naming the agent. |
| `identity.rotation.rotated` / `.pruned` | INFO | A key was replaced, or a retired one erased. Routine. |
| `identity.revoke` | INFO | A key was revoked. Carries `subdomain`, `thumbprint` and `as_of` — **this is the audit record**, and the only one. |
| `identity listening` | INFO | Start-up finished. |

### 2.3 Alerts

**These are recommendations, not configured alerts.** Nothing here ships an alerting
rule — the service has no metrics endpoint, so these are log conditions for you to wire
into whatever monitoring you already run.

| Signal | Severity | First action |
|---|---|---|
| `/healthz` non-200 for 2 minutes | **Wake on-call** | PostgreSQL is unreachable. |
| `identity.directory.unavailable` | **Wake on-call** | Almost always Vault: sealed, unreachable, or an expired token. No agent can be created and no one can look up an agent's published key, so agent requests start failing verification across the whole platform. §3.1. |
| An agent subdomain returns `503` | **Wake on-call** | The same condition, seen from outside. |
| `identity.signup.ephemeral_token_key` at start-up | **Wake on-call** | Every agent has just been signed out, and will be again at the next restart. Fix the configuration before anything else. |
| `identity.exit` | **Wake on-call** | The service will not start. Common after an OIDC provider outage — see §3.1. |
| `identity.revoke` | **Wake on-call** | Somebody used the emergency revocation tool. If it was not you, treat it as an incident. |
| `identity.rotation.*_failed` repeating for one agent | Business hours | That agent's key is not being replaced. It keeps working until it expires. |
| `identity.directory.error` | Business hours | A stored record could not be read. Names the `subdomain`. |

---

## 3. Troubleshooting

### 3.1 Symptom → cause → fix

| Symptom | Why | What to do |
|---|---|---|
| **Every agent gets 401 at `/mcp`, right after a restart** | `IDENTITY_TOKEN_SIGNING_KEY` was unset, so the key that signed their tokens was created at the last start and replaced at this one | Set the key ([`DEPLOYMENT.md`](DEPLOYMENT.md) §7) and restart once more. Agents must sign in again — this one time. |
| Agent documents return `503`, no code change | Vault is sealed, unreachable, or the token expired | Check Vault first: [`deploy/storage/vault/RUNBOOK.md`](../../deploy/storage/vault/RUNBOOK.md) §3. `/healthz` will be green throughout. |
| One agent's documents return `503`, others are fine | A single stored record could not be read | Read the `identity.directory.error` or `.unavailable` line; it names the `subdomain` and the error. |
| An agent's documents return `404` | No such agent — or the `Host` header was rewritten in front of the service, or the name has more than one label | Confirm with §3.2. If every agent 404s, suspect the proxy: [`CONFIGURATION.md`](CONFIGURATION.md) §5. |
| Will not start after an outage | The OIDC provider is contacted at boot and the service exits if it cannot reach it | Bring the provider back, then start this service. A running service does not need it; a starting one does. |
| Sign-in fails at the provider, nothing in these logs | The redirect address on file does not match `IDENTITY_AUTH_ISSUER` + `/callback` exactly | [`deploy/zitadel/RUNBOOK.md`](../../deploy/zitadel/RUNBOOK.md) §3. The failure happens before the request ever reaches here, which is why the logs are silent. |
| Sign-ups fail halfway through, only sometimes | `IDENTITY_SESSION_KEY` unset and the service restarted mid-flow | Set the key ([`DEPLOYMENT.md`](DEPLOYMENT.md) §7). |
| **A revoked key still verifies** | Revocation is published in a document other parties cache | Wait out `IDENTITY_DIRECTORY_TTL` (default 5 minutes). This is expected, not a fault — §4.2. |
| Agent calls fail with a signature error at the Broker | Its published key was fetched before a rotation, or clocks disagree | Compare the agent's directory (§3.2) with what the Broker holds; check time sync on both hosts. |
| An agent's purchases are refused | Its account is inactive or was never created | Have it call `ramp_status`; the answer says which. Activation is §4.2. |
| **A delivery URL worked for someone who should not have it** | For an agent whose key this service holds, the delivery URL is a bearer credential — whoever holds it can fetch the content, until it expires | Working as designed today — §6. Reduce exposure by keeping URL lifetimes short. |
| Rotation stopped entirely, no per-agent errors | The `identity.rotation.list_subdomains_failed` line names a Vault problem | §3.2, then Vault's runbook. |
| Two instances are running | Not supported — §4.1 | Scale back to one. |

### 3.2 Diagnostics

**Trace one agent call across all three services**

```bash
docker compose logs identity | grep '"request_id":"<ID>"'
# The same <ID> appears in the Broker's and the Exchange's logs for the legs
# they handled. Start here, then follow it outward.
```

**Read one agent's three published documents**

```bash
AGENT=agent-ovx4iigs.agents.example

curl -s "https://$AGENT/.well-known/http-message-signatures-directory"
# Expect: a JSON key set with at least one key. This is what the Broker and the
# Exchange fetch to check the agent's signature.

curl -s "https://$AGENT/.well-known/signature-agent-card.json"
# Expect: JSON describing the agent — the details captured at sign-up.

curl -s "https://$AGENT/.well-known/ramp-key-revocations.json"
# Expect: this agent's revoked keys. Empty is normal.
```

If DNS is not yet pointing where you expect, address the service directly and set the
name by hand — the service selects the agent from the `Host` header alone:

```bash
curl -s -H "Host: $AGENT" \
  http://<service-address>:8083/.well-known/http-message-signatures-directory
```

**Which agents exist, and what keys each holds**

```bash
vault kv list ramp-agents/agents
# Expect: one entry per agent subdomain.
# "No value found at ramp-agents/metadata/agents" means no agent has ever been
# created. On an established deployment that is a Vault misconfiguration, not an
# empty platform — check IDENTITY_KV_MOUNT and IDENTITY_KV_PREFIX.

vault kv list ramp-agents/agents/agent-ovx4iigs.agents.example
# Expect: one entry per key. Two is normal during a rotation, while the old and
# new keys overlap.
```

**Account and sign-up state**

```sql
-- Who has signed up
SELECT subdomain, client_name, created_at
  FROM identity.agent_card ORDER BY created_at DESC LIMIT 20;

-- What has been revoked. One row per agent; `revoked` is the list of key
-- fingerprints, and `as_of` is when the list last changed.
SELECT subdomain, as_of, revoked FROM identity.key_revocation ORDER BY as_of DESC;

-- Which agent software has registered itself against this service
SELECT client_id, client_name, created_at
  FROM identity.oauth_client ORDER BY created_at DESC;
```

**Migration state**

```bash
psql "$IDENTITY_DSN" -c "SELECT version, dirty FROM public.schema_migrations_identity"
#  version | dirty
# ---------+-------
#        4 | f
#
# Expect on a healthy system: dirty = f
```

### 3.3 Gotchas

- **`/healthz` covers PostgreSQL only** — it is green with Vault dead, with the OIDC
  provider dead, and with both RAMP peers unreachable.
- **Vault is never checked at start-up**, so a Vault misconfiguration always looks like
  a healthy service, and always shows up later as `503`s.
- **A revocation is not instant.** It takes effect within `IDENTITY_DIRECTORY_TTL`,
  because the document carrying it is cached. Plan incident response around minutes,
  not seconds.
- **The emergency revocation tool is not in the container image.** Have a way to run
  it ready before you need it — §4.2.
- **Changing `IDENTITY_BASE_DOMAIN` leaves every agent already created with an address
  that no longer works.** Their published addresses are already stored in what other
  parties cached and in the signatures they make.
- **Changing `IDENTITY_AUTH_ISSUER` breaks sign-in** until the OIDC client's redirect
  address is updated to match.
- **A proxy that rewrites `Host` makes every agent 404.** The agent is selected from
  that header and nothing else.
- **Agent subdomains take exactly one label.** That is what a wildcard certificate
  covers, so anything deeper is refused rather than served on a certificate that does
  not match.

---

## 4. Procedures

### 4.1 Routine operations

**Restart.** Takes a few seconds. It costs nothing *as long as* both keys from
[`DEPLOYMENT.md`](DEPLOYMENT.md) §7 are set — without `IDENTITY_TOKEN_SIGNING_KEY`, a
restart signs out every agent. While the process is down, every agent's published key
is unreachable; the Broker and the Exchange cache them for a few minutes, so a quick
restart is invisible and a long outage is not.

**Everything needs a restart.** There is no live reload for any setting.

**Do not run more than one instance.** The service is otherwise stateless, but each
instance runs its own key-rotation loop with no coordination between them, so two
instances rotate the same agent twice. The result is wasteful rather than harmful — the
extra keys are valid and get cleaned up on a later pass — but it is not a supported
configuration, and the fix is not implemented yet. If you need redundancy, run one
instance and make its restart fast.

**Reading state.** There is no admin API. Agent and account state is read with SQL
(§3.2) and key state with the Vault CLI.

### 4.2 Agent and key procedures

**Registering and activating an agent.** This is self-service by design — an operator
is not involved until the last step.

1. The developer opens the sign-up flow and signs in through your OIDC provider.
2. They complete the registration form. The service gives them a subdomain
   (`agent-` plus eight characters, inside your identity zone), generates a key with a
   one-year lifetime, stores it in Vault, and publishes the public half.
3. Confirm the identity is live:
   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' \
     "https://agent-ovx4iigs.agents.example/.well-known/http-message-signatures-directory"
   # Expect: 200
   ```
4. The agent connects to `/mcp` with its access token and calls **`ramp_register`**,
   which creates its account on the Exchange. Calling it twice is safe.
5. The agent calls **`ramp_status`** to see whether that account is active.
6. **Activation is an Exchange-side decision, applied with SQL.** Whether a new agent
   is active immediately is a per-tenant setting there. The procedure is in
   [`src/exchange/RUNBOOK.md`](../exchange/RUNBOOK.md) §4.2 — this service creates the
   identity, the Exchange decides whether it may spend.

**Rotating an agent's key.** This happens on its own: every key is replaced once it
reaches `IDENTITY_ROTATION_PERIOD` (default 90 days), and the outgoing key keeps
verifying for `IDENTITY_ROTATION_OVERLAP` (default 24 hours) so other parties have time
to refresh what they cached. Nothing is required of you.

To force one early, shorten `IDENTITY_ROTATION_PERIOD` and restart — the check runs
once at start-up and then every `IDENTITY_ROTATION_INTERVAL`. Put the value back
afterwards. Confirm with:

```bash
docker compose logs identity | grep identity.rotation.rotated
# Expect: one line per rotated agent, naming the subdomain
```

Then check the agent's directory (§3.2) — during the overlap it carries **two** keys,
which is correct.

**Revoking a key immediately.** Rotation is the planned path; revocation is the
emergency one, for a key you believe is compromised. There is no HTTP endpoint for it
on purpose — an unauthenticated one would let anyone disable any agent.

The tool is a second binary that is **not in the container image**. Build it or run it
from a checkout, with the same database and Vault settings the service uses:

```bash
IDENTITY_DSN="postgres://..." VAULT_ADDR="https://vault.internal:8200" VAULT_TOKEN="<token>" \
  go run ./src/identity/cmd/operator revoke <subdomain> <thumbprint>
# Expect: revoked <subdomain> <thumbprint>
```

The thumbprint is the key's fingerprint, taken from the agent's published directory
(§3.2), not a name you chose.

What it does, in order: records the revocation in the database, then erases the key
from Vault. **The order matters** — if Vault is the thing that is broken, the
revocation is still recorded and still takes effect, and the erase is retried by
re-running the same command. It is safe to run twice.

> **It takes effect within `IDENTITY_DIRECTORY_TTL`, not immediately.** The command
> writes the durable record; the running service picks it up when it next rebuilds that
> agent's documents, and other parties see it when their own cache expires. With the
> default that is five minutes. Confirm:
>
> ```bash
> curl -s "https://<subdomain>/.well-known/ramp-key-revocations.json"
> # Expect: the thumbprint you revoked
> ```

A revocation is permanent. The agent gets a working key again through the normal
rotation, or by signing up again.

**Removing an agent's access to the endpoint.** Revoking a key stops the agent signing
RAMP requests. To also stop it reaching `/mcp`, remove its registered client:

```sql
DELETE FROM identity.oauth_client WHERE client_id = '<client-id>';
```

List them first with the query in §3.2. Agent software registers itself when it first
connects, so unfamiliar entries are normal — check `client_name` and `created_at`
before deleting.

### 4.3 Upgrade and rollback

**Upgrade:** pull the new tag, stop the container, start the new one. Migrations are
applied on start.

**Roll back:** start the previous tag. The schema stays where the newer version left
it — the binary never migrates backwards. Whether the older image can run against it
depends on what the release's migrations did: one that **added** a table, a column or
an enum value is safe, because the older code never mentions the new object; one that
**renamed or dropped** a column is not, because the older code still queries the old
name. The failure is loud — at boot or on the first query that touches the column. If
you cannot tell which kind a release contained, treat it as the second.

**Do not reverse a migration by hand.** Down-migration files ship inside the image but
nothing runs them; escalate instead. The reasons are in
[`deploy/storage/postgres/RUNBOOK.md`](../../deploy/storage/postgres/RUNBOOK.md) §4.4.

Always deploy a specific tag, never `latest`.

---

## 5. Backup and recovery

**The service owns no durable state of its own.** It holds two things, in two places,
and they are not equally replaceable.

| What | Where | If you lose it |
|---|---|---|
| **Agent private keys** | Vault | **Unrecoverable.** Every agent loses its identity and must sign up again, and every offer it had accepted becomes unusable. This is the one that matters. |
| Agent cards, revocations, developer accounts, OAuth records | PostgreSQL (`identity` schema) | The keys survive in Vault, but the service can no longer say who owns them or which are revoked. **A lost revocation list quietly brings back a key you revoked** — re-run those revocations from your incident records. |
| Access tokens agents currently hold | Nowhere — they are signed, not stored | Nothing to lose. Agents sign in again. |

Both stores have their own operating guides:
[`deploy/storage/vault/RUNBOOK.md`](../../deploy/storage/vault/RUNBOOK.md) §5 and
[`deploy/storage/postgres/RUNBOOK.md`](../../deploy/storage/postgres/RUNBOOK.md) §5.

Three things to plan for rather than react to:

- **A Vault backup is as sensitive as the live store.** It contains every agent's
  private key in usable form. Anyone who can read it can act as any agent.
- **Back up both stores on the same schedule.** Restoring keys without the revocation
  list quietly brings back keys you revoked; restoring the database without the keys
  leaves records pointing at key material that no longer exists.
- **`IDENTITY_SESSION_KEY` and `IDENTITY_TOKEN_SIGNING_KEY` belong in your secret
  manager, not in a backup of these stores.** They are not written to either, so a
  restore that does not also restore them signs every agent out.

---

## 6. Limitations

- **One replica only** — each instance runs its own key-rotation loop with no
  coordination. Running two is wasteful rather than harmful, but the coordination that
  would make it correct is not implemented yet.
- **A revocation takes effect within the document's cache lifetime (TTL), not
  immediately** — §4.2.
- **Vault is the only place keys can be stored.** A local key store is not implemented
  yet, and neither is a hardware security module or a cloud key service (KMS) — the
  signing path needs the raw key, so a backend that never releases one cannot be used.
- **A Vault token is the only way this service can authenticate to Vault.** The
  longer-lived methods Vault offers are not implemented yet.
- **Vault is not checked at start-up**, so a Vault misconfiguration always reaches
  production looking healthy.
- **`/healthz` covers PostgreSQL only.**
- **There is no metrics endpoint.** Alerting is on log events.
- **There is no admin API.** Agent and account state is read and changed with SQL.
- **The emergency revocation tool is not in the container image.**
- **A delivery URL is a bearer credential for these agents.** The design intends a
  delivery URL to be usable only by the agent that bought it, proven with the key it
  signed the purchase with. This service holds that key and never releases it, so an
  agent cannot present it at the CDN — which means edges serving these agents accept
  the URL on its own, and anyone who obtains one can fetch the content until it
  expires. Keep delivery URL lifetimes short. Single-use delivery URLs are not
  implemented yet.
