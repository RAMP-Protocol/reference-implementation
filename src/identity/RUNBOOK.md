# RAMP Identity Service — Runbook

Operated by the Exchange Operator.

**Escalation.** If §3 does not resolve it, contact Postindustria over the
existing communication channel. Send the `request_id` of a failing request
together with the matching log lines from the Identity Service, the Broker and
the Exchange. Postindustria has no access to your infrastructure, so that
correlation ID is the only way the request can be traced.

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

**It is on the delivery path for its agents.** When an agent buys content, the
service does not stop at forwarding the purchase: it follows the delivery link the
Exchange answered with, fetches the licensed content from the publisher's edge —
proving it holds the agent's key — and returns the content inside the tool result.
If it is down, agents cannot discover, buy, or receive content. The publisher's site
is unaffected either way.

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
| `identity.mcp.delivery_failed` | WARN | The agent's purchase went through, but this service could not fetch one of the bought items from the publisher's edge. **The Exchange has already charged for it.** The line names the `subdomain`, the `offer_id` and the reason; the agent was handed the same failure with the delivery link intact, so it can try again. |
| `identity.oauthserver.*` (outage) | WARN | A backend was unavailable during sign-up; the caller got `503`. |
| `identity.mcp.register` / `.status` / `.discover` / `.execute` / `.report` | INFO | One agent tool call. One line per call, naming the agent. |
| `identity.oauthserver.register.ok` / `.signin.ok` / `.consent.approved` | INFO | One sign-up step completed. Together these are the audit record of who signed up and which agent software registered itself. |
| `identity.rotation.rotated` / `.pruned` | INFO | A key was replaced, or a retired one erased. Routine. |
| `identity.revoke` | INFO | A key was revoked. Carries `subdomain`, `thumbprint` and `as_of` — **this is the audit record of the revocation**. |
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
| **A revoked key still verifies** | Two delays add up: this service republishes the revocation within `IDENTITY_DIRECTORY_TTL` (default 5 minutes), and the Broker and the Exchange each notice on their own revocation refresh (about every 5 minutes; their library's default, not set here) | Wait roughly ten minutes end to end. This is expected, not a fault — §4.2. |
| Agent calls fail with a signature error at the Broker | The agent's directory does not serve the key it signed with, or clocks disagree | Read the agent's directory (§3.2) and check the signing key is in it; check time sync on both hosts. The Broker keeps no key list of its own — it fetches this directory on demand, and re-fetches when it meets a key fingerprint it does not know, so a rotation normally corrects itself. |
| An agent's purchases are refused | Its account at that Exchange is inactive or was never created | Have it call `ramp_status` naming that Exchange; the answer says which. Activation is §4.2. |
| **A delivery URL worked for someone who should not have it** | The edge that served it accepts the URL on its own, without asking for proof of the agent's key | The Exchange binds each delivery URL to the agent's key, and this service proves possession of that key when it fetches. An edge that checks the binding refuses the bare URL; one that does not still accepts it until it expires — §6. Keep URL lifetimes short on such edges. |
| Rotation stopped entirely, no per-agent errors | The `identity.rotation.list_subdomains_failed` line names a Vault problem | §3.2, then Vault's runbook. |
| Two instances are running | Not supported — §4.1 | Scale back to one. |

### 3.2 Diagnostics

**Trace one agent call across all three services**

```bash
docker compose logs identity | grep '"request_id":"<ID>"'
# The same <ID> appears in the Broker's and the Exchange's logs for the legs
# they handled. Start here, then follow it outward.
```

**Read one agent's four published documents**

```bash
AGENT=agent-ovx4iigs.agents.example

curl -s "https://$AGENT/.well-known/http-message-signatures-directory"
# Expect: a JSON key set with at least one key. This is what the Broker and the
# Exchange fetch to check the agent's signature.

curl -s "https://$AGENT/.well-known/signature-agent-card.json"
# Expect: JSON describing the agent — the details captured at sign-up.

curl -s "https://$AGENT/.well-known/ramp-key-revocations.json"
# Expect: this agent's revoked keys. Empty is normal.

curl -s "https://$AGENT/.well-known/ramp.json"
# Expect: {"ver":"1.0","role":"ROLE_AGENT","domain":"<the host you asked for>"}
# This is the RAMP commercial overlay every participant serves. For an agent it
# carries the role and nothing else — no keys. Those are in the key directory above.
```

The four documents come from different sources, so they can disagree, and which pair
disagrees tells you where to look:

| Symptom | What it means |
|---|---|
| `ramp.json` 200, key directory 404 | The account exists but has **no currently valid key**. The directory publishes only keys whose validity window covers now, so this covers a sign-up that did not finish minting the key, a key that has expired, one that was destroyed, and one whose `not_before` is still in the future. List the agent's keys (below) to tell them apart. |
| Key directory 200, `ramp.json` 404 | Keys exist for a subdomain that no developer account claims. Nothing in sign-up produces this; suspect a manual operation or a partial delete. |
| Everything 404 | The host is not a registered agent, or it is not a single-label child of the zone. Check the zone (§8). |

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
- **A revocation is not instant.** This service republishes the document carrying it
  within `IDENTITY_DIRECTORY_TTL` (default 5 minutes), and each verifier then
  notices on its own revocation refresh — about every 5 minutes for the Broker and
  the Exchange, a default this service does not control. Plan incident response
  around roughly ten minutes, not seconds.
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
is unreachable; the Broker and the Exchange cache a fetched key directory for up to
an hour, so a quick restart is invisible for agents they already know, and a long
outage is not.

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

1. The developer opens the sign-up flow and signs in through your OIDC provider. As
   soon as that sign-in returns, the service provisions the identity: it gives them a
   subdomain (`agent-` plus eight characters, inside your identity zone), generates a
   key with a one-year lifetime, stores it in Vault, and publishes the public half.
   Sign-up asks for no business details — those are supplied per Exchange in step 4,
   because each Exchange decides what it wants.
2. They then approve the application that started the sign-in. Approval releases the
   authorization code and nothing else, because the identity already exists. A
   developer who clicks Deny still has the subdomain, the Vault key and the published
   agent card from step 1 — only the application is left without access. So an
   operator who finds a provisioned identity that no client ever used is looking at a
   denied or abandoned consent, not at a fault.
3. Confirm the identity is live:
   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' \
     "https://agent-ovx4iigs.agents.example/.well-known/http-message-signatures-directory"
   # Expect: 200
   ```
4. The agent connects to `/mcp` with its access token and calls **`ramp_register`**,
   naming the Exchange it wants an account at and supplying the registration
   details that Exchange asks for. Accounts are per-Exchange, so an agent buying
   from several registers at each. Calling it twice for one Exchange is safe.
5. The agent calls **`ramp_status`** with that Exchange to see whether the account
   is active, or with no argument for the list of Exchanges this service has
   registered it at.
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
IDENTITY_KV_MOUNT="ramp-agents" \
  go run ./src/identity/cmd/operator revoke <subdomain> <thumbprint>
# Expect: revoked <subdomain> <thumbprint>
```

`IDENTITY_KV_MOUNT` (and `IDENTITY_KV_PREFIX`, if you changed it) must match what
the service runs with — the values from [`CONFIGURATION.md`](CONFIGURATION.md) §7.
Left unset, the tool looks in Vault's default `secret` mount, finds nothing there,
and reports the key as unknown.

The thumbprint is the key's fingerprint, taken from the agent's published directory
(§3.2), not a name you chose.

What it does, in order: records the revocation in the database, then erases the key
from Vault. **The order matters** — if Vault is the thing that is broken, the
revocation is still recorded and still takes effect, and the erase is retried by
re-running the same command. It is safe to run twice.

> **It does not take effect immediately.** The command writes the durable record;
> the running service picks it up when it next rebuilds that agent's documents,
> within `IDENTITY_DIRECTORY_TTL` (default 5 minutes). The Broker and the Exchange
> then notice on their own revocation refresh — about every 5 minutes, a default of
> the library they verify with, not a setting of this service. Plan around roughly
> ten minutes end to end. Confirm:
>
> ```bash
> curl -s "https://<subdomain>/.well-known/ramp-key-revocations.json"
> # Expect: the thumbprint you revoked
> ```

A revocation is permanent. The agent gets a working key again through the normal
rotation, or by signing up again.

**Removing an agent's access to the endpoint.** Revoking a key stops the agent
signing RAMP requests — that is the step that actually contains an incident. To also
stop its software signing in again, remove its registered client:

```sql
DELETE FROM identity.oauth_client WHERE client_id = '<client-id>';
```

List them first with the query in §3.2. Agent software registers itself when it first
connects, so unfamiliar entries are normal — check `client_name` and `created_at`
before deleting.

> **Deleting the client does not cut off `/mcp` at once.** An access token is
> checked on its own — signature, issuer, audience, expiry — with no lookup against
> this table, so a token issued before the delete keeps working until it expires
> (one hour from issue, by default). The delete stops the software obtaining the
> next token. If the agent must lose everything now, revoke its key first: `/mcp`
> may still answer for up to an hour, but nothing it signs verifies anywhere.

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

**One-off after the release that drops the developer business columns.** That release
removes `legal_entity`, `address` and `jurisdiction_country` from
`identity.developer_account` — the operator business details sign-up used to collect.
`DROP COLUMN` is a catalog change: Postgres stops returning the columns, but the values
stay in the table's files until the rows are rewritten. Once the release is up and you
are not going to roll it back, rewrite the table:

```bash
psql "$IDENTITY_DSN" -c "VACUUM FULL identity.developer_account"
```

This takes an ACCESS EXCLUSIVE lock, so sign-up and the developer read block while it
runs. The table holds one row per developer, so on any realistic deployment that is
seconds — but run it in a maintenance window rather than at peak.

The rewrite does nothing about copies taken earlier. Every base backup and WAL segment
from before it still carries the values, so decide on those deliberately: either let
them age out of your retention window, or delete them if the point was that the data is
gone.

There is a third copy, and it is not in this service. Before the account tools took an
Exchange argument, sign-up forwarded these same columns to the Exchange as the register
payload. The Exchange stores `legal_entity` and `jurisdiction_country` in typed columns
of `sor.agent_accounts` and the flat `address` key under that table's `extra` JSONB, so
any account opened before that change has a copy sitting there under the same names. On
a deployment that runs both services it is yours to delete. At an Exchange someone else
runs it is not an operation you perform — it is a request you send them, and you cannot
report it done until they answer.

Until all three are settled, "we no longer hold it" is not yet true.

---

## 5. Backup and recovery

**The service owns no durable state of its own.** It holds two things, in two places,
and they are not equally replaceable.

| What | Where | If you lose it |
|---|---|---|
| **Agent private keys** | Vault | **Unrecoverable.** Every agent loses its identity and must sign up again, and every offer it had accepted becomes unusable. This is the one that matters. |
| Agent cards, revocations, developer accounts, OAuth records, exchange-registration notes | PostgreSQL (`identity` schema) | The keys survive in Vault, but the service can no longer say who owns them or which are revoked. **A lost revocation list quietly brings back a key you revoked** — re-run those revocations from your incident records. |
| Access tokens agents currently hold | Nowhere — they are signed, not stored | Nothing to lose. Agents sign in again. |

Both stores have their own operating guides:
[`deploy/storage/vault/RUNBOOK.md`](../../deploy/storage/vault/RUNBOOK.md) §5 and
[`deploy/storage/postgres/RUNBOOK.md`](../../deploy/storage/postgres/RUNBOOK.md) §5.

**What the service records about registrations.** When an agent registers at an
Exchange through `ramp_register`, this service keeps one note: **the Exchange's
domain and when the registration was last confirmed.** It keeps nothing from the
registration details the agent submitted — those are the operator's business data
(legal entity, billing contact, tax identifiers, whatever a given Exchange asks
for), and this service neither logs them nor stores them. A dump of that table
therefore shows which Exchanges an agent does business with, and nothing about
who that operator is.

**The one exception, stated because a promise with an unstated exception is worse
than no promise.** When an Exchange refuses a registration, that Exchange's own
refusal text is written to the `identity.mcp.call_failed` line, truncated to 300
bytes. The text is written by the Exchange, not by this service — but an Exchange
that quotes a submitted value back into its refusal puts that value on the line,
and a short one (a VAT number, a billing contact) fits inside the bound. The
bound removes the case that matters most, an Exchange echoing the whole payload
back; it is not redaction. If that matters for a deployment, the question to ask
is which Exchanges it speaks to, not what this service logs.

The note exists for one purpose: answering `ramp_status` when the agent names no
Exchange, so it can list where it has registered without a network call. It is a
hint rather than a record — it misses a registration made outside this adapter,
and it can name an account the Exchange has since closed, which is why a status
call naming an Exchange is the authoritative answer and this list is marked as
not. It lives exactly as long as the agent's own account record: the notes are
tied to it by a foreign key that cascades, so removing an agent removes them and
there is no separate step to remember.

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
- **Whether a delivery URL works on its own depends on the edge.** The Exchange
  binds each URL to the key that signed the purchase. That key stays in this
  service, which is why the fetch happens here: the service presents proof of the
  key when it retrieves the content. An edge that checks the binding refuses the
  bare URL, so obtaining one is not enough there. An edge that does not check it
  still accepts the URL alone until it expires — keep URL lifetimes short with such
  edges. Single-use delivery URLs are not implemented yet.
