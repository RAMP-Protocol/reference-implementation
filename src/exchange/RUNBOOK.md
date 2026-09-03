# RAMP Exchange — Runbook

Operated by the Exchange Operator.

**Escalation.** If §3 does not resolve it, contact Postindustria over the
existing communication channel. Send the `request_id` of a failing request
together with the matching log lines from the Exchange, the Broker and the Edge.
Postindustria has no access to your infrastructure, so that correlation ID is
the only way the request can be traced.

> This runbook assumes the Exchange is already deployed. For installation,
> configuration values, applying or destroying the stack, and deploy-time
> verification, see [`DEPLOYMENT.md`](DEPLOYMENT.md) and
> [`CONFIGURATION.md`](CONFIGURATION.md).

---

## 1. Overview

The Exchange is the publisher's side of the system. It owns the catalog of
licensed content, prices access to it, signs the offers agents buy, and issues the
signed delivery URL the agent finally fetches. **It is the only component that
charges money** — no other component moves money, and no other component can tell
you what was charged.

**Its dependency on the Broker comes first, because it is the one operators
misread.** The Broker publishes the list of signing keys that have been
withdrawn, and the Exchange treats that list as the final word:

- The Exchange **refuses to start** without `EXCHANGE_BROKER_WELLKNOWN_URL`. The
  address alone satisfies the boot check — the document itself is fetched over
  public HTTPS at runtime, so a Broker that is down, or a hostname
  that does not resolve yet, does not stop the Exchange from starting (§3.3).
- While the document is unreachable, the Exchange **rejects signed requests**
  and logs `exchange.httpsig.broker_wellknown_unavailable` — it holds no local
  copy of the keys to fall back to, cannot prove a key has not been withdrawn,
  and so does not accept it. A Broker outage therefore looks like mass
  authentication failure on the Exchange, while its own health checks stay
  passing.

Withdrawing a key is a Broker procedure even though the Exchange enforces it; see
the Broker's runbook.

---

## 2. Monitoring

### 2.1 Health

**There are two probes, and they answer different questions.**

| | Checks | Answers |
|---|---|---|
| `/healthz` | The catalog database, and nothing else | Is the process alive? |
| `/readyz` | The catalog database **and the ledger**, when a ledger is configured | Can this instance serve paid transactions? |

**`/healthz` pings the catalog database and nothing else.** It stays green with
the ledger dead, the cache dead, the Broker unreachable and the **account
registry** unreachable — while every paid transaction fails. Read it as "the
process is up", not "the service works".

**`/readyz` adds the ledger.** It returns 503 when the billing ledger does not
answer within two seconds, so a load balancer stops sending paid traffic to an
instance that cannot bill and resumes on its own when the ledger returns. With
`RAMP_BILLING_ADAPTER` at its `free` default, or `inmemory`, there is no ledger to
probe and `/readyz` matches `/healthz` exactly.

The split is deliberate: point a **readiness** probe at `/readyz` and a **liveness**
probe at `/healthz`. The other way round, a routine ledger restart would restart the
Exchange — and take down the free resources that need no ledger at all.

Neither probe covers the cache, the Broker or the account registry.

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://exchange.example/healthz
# Expect: 200

curl -s -o /dev/null -w '%{http_code}\n' https://exchange.example/readyz
# Expect: 200. A 503 means the catalog database or the ledger is unreachable;
#         the logs name which.

curl -s https://exchange.example/.well-known/ramp.json
# Expect: "role":"ROLE_EXCHANGE", your own "domain", and an "endpoint"
#         equal to your EXCHANGE_PUBLIC_ORIGIN

curl -s https://exchange.example/.well-known/http-message-signatures-directory
# Expect: a "keys" array with one Ed25519 key ("kty":"OKP","crv":"Ed25519").
# The key MUST be identical across a restart.
```

The two published documents are the real readiness signal. Neither proves the
Broker link is healthy — for that, watch the logs for
`exchange.httpsig.broker_wellknown_unavailable` (§2.3). No endpoint reports it.

### 2.2 Logs

JSON, one object per line, on stdout — `docker compose logs exchange`. **There is
no `/metrics` endpoint and no Prometheus support**, so alerting is on log events.

Every request-path line carries `request_id`, and it is the same value across the
Edge, the Broker and the Exchange — grep it in all three to trace one request end
to end. Boot lines carry no `request_id` — nothing has made a request yet. Some are
free text and some use the same dotted `exchange.*` names as the request path; the
table below gives both.

| Event | Level | Means |
|---|---|---|
| `exchange.exit` | ERROR | Refused to start, or stopped. `err` names the cause. |
| `exchange.httpsig.broker_wellknown_unavailable` | WARN | The Broker's withdrawn-key document could not be read. **The request is rejected, not let through.** |
| `exchange.httpsig.reject` | WARN | A request was rejected before it reached a handler. `outcome` is `signature`, `replay`, `broken_chain`, `hop_budget` or `body_too_large`. The first four are authentication outcomes and point at the caller's key, clock or relay chain, so a request carrying them was signed. `body_too_large` is not one of them and need not be signed at all — the request never reached verification, because its body passed the read cap, and the caller fixes it by sending less. See [`CONFIGURATION.md`](CONFIGURATION.md) §2.7. The line appears for a catalog push as well as for the other RPCs; the two mounts refuse an over-cap body by different means and write the same line. |
| `exchange.admin.ip_reject` | WARN | An admin call came from an address not in `ADMIN_ALLOWED_CIDRS`. Field `client_ip`. |
| `exchange.execute_transaction` | INFO on success, WARN on rejection | One line per purchase attempt. `outcome` is `VALIDATED`, `REJECTED_AUTHZ` or `REJECTED_REPORTING_OVERDUE`; `kind` and `err` carry the detail. A `REJECTED_REPORTING_OVERDUE` line does NOT mean the caller saw an HTTP error: the refusal travels in the response body as the item's `denial_reason`, under a 200. §3.1. |
| `exchange.execute_transaction` with `event=billing_record_failed_best_effort` | **ERROR** | The transaction committed and the agent has its URL, but the charge was never posted to the ledger — a silent under-charge. See §2.3. |
| `exchange.execute_transaction` with `event=release_hold_failed` | ERROR | A failed purchase's reservation could not be released. It expires on its own; money is not lost, but the agent's available balance is understated until it does. |
| `exchange.report_usage` | INFO on success, WARN on rejection | One line per usage report. `outcome` is `VALIDATED`, `REPLAY`, `REJECTED_AUTHZ`, `REJECTED_FIELDS`, `REJECTED_TOLERANCE`, `REJECTED_BILLING_ID`, `REJECTED_TIMESTAMP` or `REJECTED_ALREADY_REPORTED`. `REJECTED_ALREADY_REPORTED` means a second, different report arrived for an obligation that had already been accepted: nothing was written to the obligation row, and this line is the only record of the attempt. Repeated lines from one agent are worth looking at — a settled report cannot be revised, so the agent is either retrying past a success it did not notice or trying to change a record it is the subject of. `REJECTED_WINDOW` is no longer produced — a report is accepted whatever the time — but it survives on rows written before that changed. A report addressed to another Exchange never reaches this line — it is refused before the obligation is read, and appears as `rampaudience.refused` below. |
| `exchange.catalog_push.reject` | WARN | One line per catalog entry a push was refused for, whatever refused it. Carries `uri` and the machine-readable `reason` — the same token the publisher sees in the refusal message — plus `detail` when the refusing check has one. A push is all-or-nothing per submission, so any of these lines means the whole submission was refused and nothing from it was stored. This is what to grep when a publisher reports a refusal and you need to place it; §3.1 lists every reason with its fix. |
| `license term refused at ingest` | WARN | The second line a term refusal writes, one gate deeper than the row above. Carries `uri`, the SDK `rule` id, the entry-relative `path` (`terms[i].…`) and the offending `token`, so you can name the bad value without asking for the publisher's feed. Only the ingest-tier term check produces it; every other reason has the row above and nothing more. |
| `rampaudience.refused` | WARN, **ERROR** for the two below | A request named a recipient other than this Exchange and was refused before the handler ran, so it changed nothing. Carries `path` (the RPC), `verdict`, `self` (the identity this service answers to) and `reason`. `verdict` is `mismatch` (a well-formed domain naming somebody else), `empty` (no recipient at all) or `malformed` (not a bare domain). A steady stream of `mismatch` from one caller usually means their configured Exchange domain disagrees with `EXCHANGE_DOMAIN` here. At **ERROR** level it is not the caller's fault: `no_verdict` means this service's own identity is unusable and **every** caller is being refused, and any other verdict means a value this build does not understand. |
| `migrations applied` | INFO | Boot. Carries `version`, `dirty` and `table`. **Appears twice** — once per database. Read `table` to tell them apart: `schema_migrations_ramp` is the catalog database, `schema_migrations_sor` the account registry. |
| `ed25519 signing key loaded` | INFO | Boot. Must always appear. |
| `rsa signing key loaded` | INFO | Boot. Appears only when an RSA key is configured. Without one, `no RSA signing key configured; AWS_CLOUDFRONT_RSA tenants will be refused` appears instead — fine for an all-Ed25519 deployment, a problem the moment a publisher uses CloudFront. |
| `billing adapter: tigerbeetle` | INFO | Boot. Carries `ledger`, `currency`, `address`. Its **absence** means the `free` adapter. |
| `billing adapter seeded` | INFO | Boot, `inmemory` adapter only. Carries the number of seeded agents. |
| `sor adapter: postgres` | INFO | Boot. The account registry is connected and migrated. Carries `cache_ttl`. **Not optional** — its absence means the Exchange is not running. |
| `default tenant not found yet — Register will fail until it is seeded` | WARN | Boot. No tenant row matches `EXCHANGE_DEFAULT_TENANT` (or `EXCHANGE_DOMAIN`). **No agent can register, so no agent can buy.** Boot continues anyway. Carries `default_tenant_domain`. |
| `could not verify default tenant at boot` | WARN | Boot. The check could not run, usually a brief database problem. Carries `default_tenant_domain` and `err`. Re-check by hand once the service is up. |
| `applied default agent credit to the default tenant` | INFO | Boot. `EXCHANGE_DEFAULT_AGENT_CREDIT` (unset means `0`) was written to the default tenant's column. Appears on every boot with a seeded default tenant; carries `default_tenant_domain` and `default_agent_credit`. A malformed value never reaches this line — it stops the boot instead. |
| `default tenant not seeded yet — default agent credit NOT applied` | WARN | Boot. `EXCHANGE_DEFAULT_AGENT_CREDIT` is set but no default tenant row exists, so the value was not written. Seed the tenant, then restart to apply it. Carries `default_tenant_domain` and `default_agent_credit`. |
| `granted default agent credit` | INFO | One line per welcome-credit grant at Register — the operator's visibility into credit drawn from the ledger's liquidity account, because the grant has no aggregate cap. Carries `billing_ref` and `amount`. |
| `exchange.execute_transaction` with `event=sor_active_check_failed` | WARN | The account registry could not be read during a purchase. The purchase is **allowed through** — the ledger balance still bounds spending — but an account you switched off may buy until the registry answers again. |
| `exchange.httpsig.replay_store_ready` | INFO | Boot. Redis-backed replay protection is live. Carries `addr`. |
| `exchange.httpsig.replay_store_disabled` | INFO | Boot. `REDIS_URL` is unset, so replay protection is per-process — safe at one instance, not above (§3.3). |
| `exchange.httpsig.wellknown_enabled` | INFO | Boot. Carries `well_known_url` and `poll_interval` — where to confirm the interval you configured took effect. |
| `exchange listening` / `admin listening` | INFO | Boot. Both must appear. |

### 2.3 Alerts

**These are recommendations, not configured alerts.** Nothing here ships an
alerting rule — the Exchange has no metrics endpoint, so these are log conditions
for you to wire into whatever monitoring you already run. **"Wake on-call" means
call the engineer on duty, at any hour.**

| Signal | Severity | First action |
|---|---|---|
| `event=billing_record_failed_best_effort` | **Wake on-call** | **The most important row here.** A committed transaction with no ledger posting: the agent has content it was never charged for. Every occurrence is revenue silently lost. §3.1. |
| `exchange.httpsig.broker_wellknown_unavailable` | **Wake on-call** | The Broker is unreachable, so every signed request is being rejected. Check the Broker before chasing key problems. |
| Billing authorization failing in bulk | **Wake on-call** | The ledger is unreachable or misconfigured. Every paid purchase is denied while `/healthz` stays green. |
| `exchange.exit` naming a migration | **Wake on-call** | A migration failed at boot; no instance will start. Do not clear the dirty flag by hand. |
| `/healthz` non-200 for 2 minutes | **Wake on-call** | The catalog database is unreachable. Note that `/healthz` says nothing about the account registry. |
| `exchange.httpsig.reject` rate spikes | Business hours | Key rotation, clocks that are out of sync, or a TLS proxy newly placed in front (§3.1). |
| `event=release_hold_failed` | Business hours | Reservations are not being released promptly. Self-correcting as holds expire. |
| `default tenant not found yet …` at boot | Business hours | No agent can register while this appears, so the deployment cannot take a single new customer. Create the tenant — §4.2. |
| `event=sor_active_check_failed` | Business hours | The account registry is unreadable, so switched-off accounts are not being enforced. Purchases continue. Check the registry database. |

**Do not alert on** transaction denials — an agent asked for something it may not
have and was told no; that is the system working. Nor on
`exchange.admin.ip_reject`: the admin listener refuses everything by default, by
design, and the internet will try it.

---

## 3. Troubleshooting

### 3.1 Symptom → cause → fix

| Symptom | Why | What to do |
|---|---|---|
| **Every signed request rejected, `outcome=signature`** | A proxy in front terminates HTTPS and forwards HTTP, so the URL the caller signed is not the URL the Exchange checks | Set `RAMP_TRUST_PROXY_HEADERS=true` — [`CONFIGURATION.md`](CONFIGURATION.md) §4. Only behind a proxy you control, never on a directly-exposed Exchange. |
| A CloudFront publisher's purchases refused: `no RSA signing key` | An absent RSA key never stops the boot. The Exchange runs, serves every Ed25519 publisher, and refuses only a CloudFront-scheme tenant's requests — per request, with the `failed_precondition` code | Generate the key and supply it: [`DEPLOYMENT.md`](DEPLOYMENT.md) §5. No restart loop to worry about; add the key and restart once. |
| Refuses to start: `EXCHANGE_BROKER_WELLKNOWN_URL is required` | Refusing is deliberate — with nothing to check the withdrawn-key list against, a withdrawn key would keep working | Point it at the Broker's `/.well-known/ramp.json`. |
| **A catalog push refused `resource_exhausted` (HTTP 413), same submission every time** | The ingester splits a feed by entry COUNT (256, the protocol's bound on one request), and the Exchange also bounds the request SIZE at 1 MiB. A feed of unusually large entries builds a submission under the count bound and over the size one, and re-running rebuilds it identically | Split the feed file so the offending range goes as smaller submissions — the report names the entry range that was refused. This refusal is the Exchange's own verdict, so it prints `REFUSED` and nothing from that range is stored; the ranges stored before it stay stored, so re-running the split feed is safe. |
| **Every catalog push rejected, `missing_resource_owner_id`** | The publisher's `ramp.json` names no payee (the one who gets paid) for this Exchange — it does not "attest" one. The payee is never guessed, and there is no fallback to the tenant id | The manifest needs `exchanges[].ext.resource_owner_id` on the entry whose `domain` equals your `EXCHANGE_DOMAIN`. §4.2. |
| Every push rejected, `caller_not_in_catalog_contributors` | The publisher's `ramp.json` does not list the pushing key's identifier, or could not be fetched at all | Add it to `catalog_contributors[].domain`, or make it equal the manifest's own `domain`. §4.2. |
| Every push rejected, `unknown_publisher_domain` | No tenant row exists for the entry's domain | Create the tenant first. §4.2. |
| Every push rejected, `tenant_mismatch` | The push named a `tenant_id` that disagrees with the tenant the entry's `domain` resolves to. The server derives the owner from the domain and does not honour a disagreeing client value | Send no `tenant_id`, or send the one the domain resolves to. The derived tenant is authoritative either way, so omitting it is always correct. |
| A push rejected, `invalid_license_terms` | One of the entry's terms failed an ingest-tier check — a `pricing.unit` or `quota.metric` token that is not in the registry, or a restriction naming the same token as both permitted and prohibited once aliases and letter case are folded (`scrape` and `crawl` are one token, so are `CRAWL` and `crawl`). The wire-tier term rules are refused earlier and never reach this reason | The second line the refusal writes, `license term refused at ingest`, carries the `rule` id, the entry-relative `path` and the offending `token`. For an unregistered token, register it or prefix it `vendor:` to declare it custom. For a collision the `token` is the folded form both spellings resolve to; drop it from one of the two lists. `ramp-ingest --check feed.jsonl` reports both readings of it before a push. |
| A push rejected, `invalid_entry` | The entry would not convert for storage: a missing `domain` or `path`, or terms and metadata that would not marshal. It is a backstop — the wire rules refuse an empty `domain` or `path` earlier, so seeing this reason means the entry got past them | Rare, and worth reporting rather than working around: it means the wire rules and the storage conversion disagree about the same entry. The `uri` names the line. |
| A push rejected, `uri_owned_by_other_resource` | The URI the entry materialises already belongs to a DIFFERENT catalog row, or two lines in the same push claim it under different keys. A URI belongs to exactly one row | Re-pushing the same resource is not a conflict — it updates in place. A real collision means two lines carry the same `domain` + `path` under different `content_id` values; correct the `content_id`. |
| Purchases denied with `currency mismatch` | The catalog's terms are priced in one currency and the ledger is configured for another. A deployment is single-currency | Compare `EXCHANGE_BILLING_LEDGER` (`978`=EUR, `840`=USD) against the currency in the catalog's `pricing`. §3.2. |
| **A committed transaction has no ledger posting** | The posting is best-effort: it happens after the transaction commits and its failure cannot fail the request. A crash, or a brief ledger failure, in that window leaves a charge unposted | Find it in the logs and put it right by hand — §3.2. Nothing does this automatically. |
| Admin API unreachable | The allowlist refuses everything by default **and** has no effect behind a proxy, so "too strict" and "not applied at all" look identical | [`DEPLOYMENT.md`](DEPLOYMENT.md) §7. Bind the port directly; read `exchange.admin.ip_reject` for the address actually seen. |
| **One agent's purchases all denied, `outcome=REJECTED_REPORTING_OVERDUE`** | The agent owes usage reports. It is refused while more than 10 obligations are overdue, or more than one in five of its due obligations is unreported — and with no history, the first missed report is one out of one, so it blocks | The agent files the missing reports through `ReportUsage`. They are accepted however late they are, and each accepted report clears one. Nothing needs doing on this side, and the deadline must never be edited in the database. The denial arrives as the item's `denial_reason` under a 200, not as an HTTP error, so an agent that only checks the status code will look like it is silently getting nothing. |
| **Offer prices are out of date** | The copy the Exchange keeps in memory is rebuilt at boot and after each catalog push — nothing else refreshes it, so a row edited directly in the database is invisible | Run the ingest tool again (§4.2), or restart. Prefer the ingest tool: it re-validates. |
| **Discovery fails for one listed URL instead of returning its offer, and takes the rest of the response with it** | The stored term names the same token as both permitted and prohibited once aliases and letter case are folded — the shape a push is refused for today, in a row written before that refusal existed. Stored terms ride out on offers and the Exchange validates its own responses, so it refuses to answer with that resource. A discovery call naming several URLs fails whole, so healthy resources in the same request stop answering too | The publisher re-pushes the resource with the token dropped from one of the two lists. A push upserts on the row's `resource_id`, which the entry's `content_id` decides, so the corrected push must carry the same `content_id` the stored row was written under; then the corrected term replaces it in place — no row is deleted and nothing is edited in the database. `ramp-ingest --check feed.jsonl` names the offending token before a push, without a key or a running Exchange. |
| Discovery returns nothing for a URL you know is listed | The URL's domain has no tenant, or its stored form differs from the one asked for | Check the catalog rows for that prefix — §3.2. |
| **One agent is denied every paid purchase: `agent is not registered for paid content: call Register first`** | The agent has no account. It authenticates fine and can still fetch free content, but it has nothing to charge. Adding a row to `ramp.agents` by hand does **not** fix this — that row's `billing_ref` stays empty | The agent must call the `Register` RPC itself. **Do not fund it** — there is no account to fund yet. §4.2. |
| One agent denied with `account is switched off: contact the operator to turn it back on` | The agent registered, but its account row in the registry has `active = false` | Switch it back on — §4.2. |
| One agent denied with `no billing account found for this agent: contact the operator` | The agent's `ramp.agents` row carries a `billing_ref` that the registry does not know. The two databases disagree | Escalate. Do not delete the `billing_ref`: the ledger balance is keyed on it. §5. |
| Exchange will not start | `EXCHANGE_DSN` unset, or the catalog database unreachable | Read the `exchange.exit` line; it names the cause. |
| Exchange will not start, `err` begins `sor:` | A **different** database. `EXCHANGE_SOR_DSN` is unset, or the account-registry database does not exist or is unreachable | [`DEPLOYMENT.md`](DEPLOYMENT.md) §8 lists each `sor:` message and its fix. This one does not fix itself. |

### 3.2 Diagnostics

**Trace one request end to end.** The `request_id` is the same in all three
services; no line at all means the request never reached the Exchange, so look at
the Broker.

```bash
docker compose logs exchange | grep '"request_id":"<ID>"'
# Expect: the request-path lines for that request — an exchange.execute_transaction
#         or exchange.report_usage outcome line, plus any httpsig rejection
```

**Inspect a transaction and its evidence row.**

```sql
SELECT transaction_id, tenant_id, agent_id, resource_id, unit_cost, currency,
       billing_id, expiry, denial_reason, created_at
  FROM ramp.transaction_log WHERE idempotency_key = '<idempotency key>';
-- Expect: one row. denial_reason is effectively always NULL — a denied purchase
-- aborts before any row is written, so a row here is a purchase that succeeded.

SELECT transaction_id, offer_id, requester_id, request_id, created_at
  FROM ramp.transaction_evidence WHERE transaction_id = '<transaction id>';
-- Expect: one row, holding the signed offer and both parties' signatures
-- verbatim, so a dispute can be settled from the row alone. Append-once (§4.3).
```

**Find committed transactions with no ledger posting.** Take the ids out of the
error log, then confirm each one really committed:

```bash
docker compose logs exchange | grep 'billing_record_failed_best_effort' \
  | python3 -c "import sys,json;[print(json.loads(l)['transaction_id']) for l in sys.stdin]"
# Expect: one transaction id per unposted charge — empty output is the good case
```

```sql
SELECT transaction_id, agent_id, unit_cost, currency, created_at
  FROM ramp.transaction_log WHERE transaction_id IN ('<id>', '<id>');
-- Expect: one row per id. Each is content delivered and not charged for;
-- put it right in the ledger by hand (§6).
```

**Confirm which billing adapter is live.**

```bash
docker compose logs exchange | grep 'billing adapter'
# Expect: {"level":"INFO","msg":"billing adapter: tigerbeetle","ledger":978,...}
# No output means the free adapter: every charge approved, nothing recorded.
```

**Read the served documents** — the two commands in §2.1. A `domain` that does not
match what the Broker registered, or an `endpoint` that does not match the
Broker's entry for you, produces empty offer lists with no error anywhere.

**List tenants, agents and catalog size.**

```sql
SELECT tenant_id, domain, signing_scheme, fee_rate_bps,
       activate_new_agents_by_default FROM ramp.tenants;
-- Expect: activate_new_agents_by_default is TRUE unless you changed it. Only the
-- default tenant's copy is read (§4.2) — it decides whether a newly registered
-- agent starts able to buy.

SELECT agent_id, billing_ref IS NULL AS cannot_buy, registered_at
  FROM ramp.agents ORDER BY registered_at DESC LIMIT 20;
-- Expect: cannot_buy = f for every agent that has called Register.
-- cannot_buy = t is the single most useful diagnostic here: that agent has no
-- account, so every paid purchase it attempts is denied (§3.1). Funding it does
-- not help; it must call Register.

SELECT tenant_id, count(*) AS rows, max(updated_at) FROM ramp.catalog
 GROUP BY tenant_id;
SELECT resource_id, uri, resource_owner_id, pricing FROM ramp.catalog
 WHERE uri LIKE 'https://www.publisher.example/%' LIMIT 5;
-- Expect: pricing carries the unit cost and currency — the value to compare
-- against EXCHANGE_BILLING_LEDGER when purchases fail on currency mismatch.
```

### 3.3 Gotchas

- **On day one the Exchange starts, but rejects every signed request until the
  Broker answers.** The Broker's document is fetched at runtime, not at boot;
  until DNS, certificates and the Broker are all live the Exchange runs with
  passing health checks and logs
  `exchange.httpsig.broker_wellknown_unavailable` on each rejected request. It
  fixes itself the moment the document is reachable. A process that instead
  exits and restarts has a configuration fault — see
  [`DEPLOYMENT.md`](DEPLOYMENT.md) §8 for both shapes.
- **`ADMIN_ADDR` defaults to `:8082`, which is the Broker's published port.**
  Running both on one host with host networking collides. Change one.
- **A proxy in front makes the admin allowlist useless.** It reads the
  connection's own source address and never `X-Forwarded-For`, so behind a proxy
  every caller looks like the proxy. Bind the admin port directly.
- **Redis-less mode is announced, not silent — but only once, at boot.** With
  `REDIS_URL` unset the Exchange logs `exchange.httpsig.replay_store_disabled` and
  carries on. Requests then succeed exactly as they would with Redis, so that single
  line is the whole signal. Correct at one instance, unsafe above.
- **The image is amd64 only.** There is no ARM build.
- **Every Exchange owns two databases: one catalog database and one account
  registry.** The Exchange builds its in-memory catalog by reading the whole
  catalog table without filtering by tenant, so every row in that database is
  discoverable through this Exchange. Two publishers who must not appear in each
  other's discovery results need two Exchanges with two catalog databases, not one
  Exchange with two tenants — and each of those Exchanges needs its own account
  registry as well, because an agent's `billing_ref` is issued by one Exchange and
  means nothing to another.
- **There is no shared key file.** The Exchange learns every verification key
  from the key owner's own published documents: the Broker's directory for the
  relay key and the withdrawn-key list, and each signer's own directory for
  that signer's key.

---

## 4. Procedures

### 4.1 Routine operations

**Restart.**

```bash
docker compose restart exchange
# Expect: the boot sequence from DEPLOYMENT.md §6, ending in
#         "exchange listening" and "admin listening"
```

It costs about ten seconds and loses nothing durable, but three things happen
worth knowing: the in-memory catalog is rebuilt from the database, in-process
replay memory is discarded if `REDIS_URL` is unset, and any purchase in progress
fails — its ledger reservation is not released explicitly and expires on its own
about six minutes later. Delivery URLs already issued keep working; the CDN
verifies them without asking the Exchange.

**Configuration needs a restart.** There is no live reload of any setting: not
the signing keys, not the Broker URL, not the billing configuration. Two
exceptions: a fee rate or reporting policy set through the admin API (§4.2)
takes effect immediately, and **verification keys were never configuration** —
they are fetched from the key owners' published documents and refresh on their
own as the cached copies expire (`EXCHANGE_DIRECTORY_TTL`,
`EXCHANGE_REVOCATION_POLL_INTERVAL`), with no restart involved.

**Running more than one instance.** Above one instance `REDIS_URL` is mandatory
and every instance must use the **same** Redis. Check each instance's boot log for
`exchange.httpsig.replay_store_ready`; a `replay_store_disabled` line on any of them
means that instance is replay-protecting itself alone.
Start one instance first so it applies migrations alone, confirm `/healthz`, then
add the rest.

**Read a tenant's configuration by SQL.** The admin API only writes values — there
is no RPC that reads them, and that is deliberate: the write calls return the
values they saved, so tooling confirms a write without a separate read call.

```sql
SELECT tenant_id, domain, signing_scheme, fee_rate_bps, fee_rate_notes,
       reporting_policy, activate_new_agents_by_default
  FROM ramp.tenants WHERE tenant_id = '<tenant>';
-- Expect: one row. fee_rate_bps is basis points — 1500 means 15%.
-- activate_new_agents_by_default decides whether a newly registered agent can buy
-- straight away (TRUE) or waits for you to switch it on (FALSE). It is read from
-- the default tenant only (§4.2); on any other row it is never read.
```

### 4.2 Publisher, catalog and key procedures

#### Onboard a publisher

**1. Create the tenant.** There is no RPC for this; it is a database row.

```sql
INSERT INTO ramp.tenants (tenant_id, domain, ed25519_key_ref,
                          signing_scheme, fee_rate_bps,
                          activate_new_agents_by_default)
VALUES ('publisher', 'www.publisher.example', 'exchange-primary',
        'ED25519', 1500, TRUE);
-- Expect: INSERT 0 1
```

`domain` is the publisher's real hostname and is globally unique.
`signing_scheme` is `ED25519` for a Cloudflare- or Fastly-fronted publisher, or
`AWS_CLOUDFRONT_RSA` for one behind CloudFront — the latter also requires
`rsa_key_ref` and `cloudfront_key_pair_id`, and the row is refused without them.
`fee_rate_bps` is your commission and can be changed later without a restart.

`activate_new_agents_by_default` decides whether a newly registered agent can buy
immediately. **Name it explicitly, as above.** Omit it and the row still succeeds,
silently taking `TRUE` — every new agent is admitted the moment it registers, with
no review. Set it to `FALSE` if you want to approve each agent by hand (see
"Register an agent" below).

**Only one tenant's copy of that column is ever read.** The Exchange takes the
policy from the tenant named by `EXCHANGE_DEFAULT_TENANT`, or by `EXCHANGE_DOMAIN`
if that is unset — whichever publisher the agent later buys from. The column on
every other tenant row is never read. And until that one row exists, **every**
agent registration fails.

**2. Generate the catalog-contributor key** — the key the ingest tool signs
pushes with, not the Exchange's own key:

```bash
scripts/gen-contributor-key.sh <contributor-id>
# → deploy/publisher-keys/<contributor-id>-key.json
```

The contributor id is the hostname of the contributor's key directory. The
public half must be published in the contributor's own well-known directory
(the Exchange learns it by fetching that directory — there is no shared key
file to update); the private half is what you pass to `--key` below, so treat
it as a secret and keep it out of the repository.

**3. Have the publisher publish `/.well-known/ramp.json`.** The document's shape,
with every field traced to the setting that produces it, is in
[`../../deploy/publisher-wellknown/`](../../deploy/publisher-wellknown/); the copy
there is the one the test suite pins to the Edge Worker's output. Two fields
matter from this side, and both fail silently when wrong:

- `exchanges[].domain` must equal your `EXCHANGE_DOMAIN` **exactly**, and that
  entry's `ext.resource_owner_id` is the **payee** — the one who gets paid. Every
  euro of this publisher's revenue goes to it. Absent or empty, every push is
  rejected. Present but wrong, nothing is rejected: the value is stored and paid
  out as written.
- `catalog_contributors[].domain` must contain the kid from step 2 — unless that
  kid equals the manifest's own `domain`, which is also accepted.

**4. Verify end to end.** Load the catalog (below), then confirm a real agent can
discover and buy. The Edge and Broker each own a half of that path — see
`src/edge/RUNBOOK.md` §4.2 and `src/broker/RUNBOOK.md` §4.2 rather than repeating
their checks here. On the Exchange side:

```bash
curl -s https://www.publisher.example/.well-known/ramp.json
# Expect: the document described above — matching the reference copy in
#         deploy/publisher-wellknown/ — served over HTTPS with a valid certificate
```

```sql
SELECT count(*) FROM ramp.catalog WHERE tenant_id = 'publisher';
-- Expect: the number of entries you pushed
```

#### Register an agent, and switch its account on or off

An agent must have an **account** before it can buy anything. Free content is
unaffected — an agent with no account can still fetch it — but every paid
purchase is denied.

The account is created once, by the agent, through the `Register` RPC. It cannot
be created by you, and it cannot be created with SQL: the Exchange takes the
agent's identity from the signature on the request, so only the agent itself can
ask. What one `Register` call produces:

| Step | Where | What lands |
|---|---|---|
| 1 | Account registry (`EXCHANGE_SOR_DSN`) | A row in `sor.agent_accounts`, keyed on a fresh `billing_ref`. Its `active` column is copied from the default tenant's `activate_new_agents_by_default`. |
| 2 | Ledger | An account for that same `billing_ref`. This is where the agent's money lives. |
| 3 | Catalog database (`EXCHANGE_DSN`) | The `billing_ref` is written onto the agent's `ramp.agents` row. |

`billing_ref` is a random identifier the Exchange creates. It is the one string
that ties the three together. Calling `Register` again returns the same
`billing_ref` and changes nothing.

**Adding a row to `ramp.agents` by hand does not register an agent.** Such an
agent authenticates normally and can fetch free content, but its `billing_ref` is
empty, so every paid purchase is denied with `agent is not registered for paid
content: call Register first`. There is nothing you can do from your side; the
agent has to call `Register`.

Check whether an agent is registered:

```sql
SELECT agent_id, billing_ref FROM ramp.agents WHERE agent_id = '<agent>';
-- Expect: one row. A NULL billing_ref means not registered — it cannot buy.
```

Then look up the account itself, in the **other** database:

```sql
SELECT billing_ref, subdomain, active, legal_entity, email
  FROM sor.agent_accounts WHERE billing_ref = '<billing_ref from above>';
-- Expect: one row. subdomain is the agent's identity; active decides whether it
-- may buy right now.
```

**Switching an account off and on again** is a direct update in the registry
database. **There is no RPC and no admin endpoint for this yet.**

```sql
UPDATE sor.agent_accounts SET active = FALSE WHERE billing_ref = '<billing_ref>';
-- Expect: UPDATE 1
```

The change takes effect within **30 seconds** — the Exchange re-reads the status
at most that often, tuned by `EXCHANGE_SOR_CACHE_TTL`. No restart is needed. A
switched-off agent is then denied with `account is switched off: contact the
operator to turn it back on`. Set `active = TRUE` to reverse it.

Two behaviours worth knowing. If the registry is **unreadable** during a
purchase, the Exchange lets the purchase through and logs
`event=sor_active_check_failed` — a switched-off agent may buy until the registry
answers again; the ledger balance is what still limits it. And the columns
holding the agent's company details (`legal_entity`, the address columns, `email`)
are all optional: the Exchange stores whatever the agent sent and checks none of
it. Deciding that a registration is complete enough is your judgement, expressed
through `active`.

#### Run the ingestion pipeline

`ramp-ingest` reads a JSON-L feed (one JSON object per line), maps each record to
a catalog entry, signs the batch and pushes it over the Exchange's catalog RPC.
There is no way to write to the catalog directly by SQL.
**The binary is not built into any distributable image today**,
so build it first, then run it with its **three required flags** — none has a
default, and there is no committed contributor key to fall back on:

```bash
go build ./src/exchange/cmd/ramp-ingest
# Expect: no output, and a ./ramp-ingest binary

./ramp-ingest \
  --exchange-url https://exchange.example \
  --tenant publisher \
  --key /secrets/catalog-contributor.json \
  feed.jsonl
# Expect: push: accepted=1284 warnings=3
#         followed, for a feed larger than one submission, by one line per
#         submission naming the entry range it carried and whether it was stored
```

The feed path is an optional positional argument; omit it and the feed is read
from standard input, so piping `feed.jsonl` in works identically.

**Read the result as pass or fail: exit status 0 is the only passing result.**
The Exchange stores or refuses a submission whole — never part of one — and the
binary exits non-zero on the first failure, so a partial catalog never passes
silently. A feed larger than the wire bound on one submission (256 entries at
the pinned protocol revision) is sent as several submissions in feed order; on a
failure the report says which entry ranges were stored, which submission the run
stopped at and why, and which entries were not sent, and re-running the same
feed is safe — the catalog push is an upsert, so entries already stored are
stored again unchanged.

**A submission the run stopped at is printed one of two ways, and they mean
different things.** `REFUSED` is the Exchange's own verdict: the request reached
it, it refused the submission whole, and **nothing from that range is stored**.
`NOT CONFIRMED` means no verdict came back — the call timed out, the connection
dropped, or the Exchange answered success over a count that disagreed with what
was sent — so **that range may or may not be stored**, and only a re-run
settles it. Do not read `NOT CONFIRMED` as "absent"; re-running is safe either
way, because the push upserts. A rerun clears a refusal a later run would not repeat: a
transient failure, or an entry you have corrected. It does not clear one the
same feed reproduces — see the `resource_exhausted` row in §3.1. Warnings are
notes about small problems and do not block. Each refusal names its URL and
reason; the common ones are in §3.1.

Before pushing, `./ramp-ingest --check feed.jsonl` runs the same parse and
mapping plus the SDK's entry validation locally — no key, no Exchange, no
tenant — and exits 1 listing every violation with its record, rule id and field
path, so a feed is fixed in one round rather than one refusal at a time.

**Scheduled runs are not implemented yet**: there is no cron entry, timer or
watcher, so the pipeline is run by hand and the catalog reflects the last time
someone ran it.

#### Rotate the tenant signing key

This is the Exchange's own Ed25519 key — the one that signs offers and Ed25519
delivery URLs.

```bash
openssl genpkey -algorithm ED25519 -out ed25519-private-v2.pem
# Expect: a file beginning -----BEGIN PRIVATE KEY-----

docker compose up -d exchange     # live reload is not implemented yet
# Expect: {"level":"INFO","msg":"ed25519 signing key loaded"}

curl -s https://exchange.example/.well-known/http-message-signatures-directory
# Expect: a "keys" array whose single key is the NEW one
```

Then fetch one real delivery URL end to end before declaring it done.

**Two things outlast the old key, and both last only a limited time.** Delivery
URLs already issued stay valid for **five minutes** and were signed with the old
key, so the Edge must still verify them; and the Edge caches the key directory for
**one hour**, so until that expires a worker may hold only the old key and URLs
signed with the *new* one can fail. Rotate at a quiet time and expect a period
where one side or the other of that overlap fails. There is no way to run the old
and new key side by side for a while.

#### Override a fee rate or reporting policy at runtime

Both take effect immediately, without a restart. Reach the admin listener from an
address inside `ADMIN_ALLOWED_CIDRS` — over an SSH tunnel or from a jump host (a
bastion) in the range, never through a proxy (§3.3).

```bash
# Fee rate: basis points, 0 <= bps < 10000. 1500 is 15%.
curl -s -X POST http://10.0.4.11:8082/ramp.admin.v1.AdminService/SetTenantFeeRate \
  -H 'Content-Type: application/json' \
  -d '{"ver":"1.0","rate":{"tenant_id":"publisher","fee_rate_bps":1500,"notes":"rate change"}}'
# Expect: {"ver":"1.0","rate":{"tenant_id":"publisher","fee_rate_bps":1500,...}}
#         — the response returns the values exactly as saved

# Reporting policy: a FULL REPLACE, not a merge. Any field you omit is cleared
# and the Exchange's own defaults then apply.
curl -s -X POST http://10.0.4.11:8082/ramp.admin.v1.AdminService/SetReportingPolicy \
  -H 'Content-Type: application/json' \
  -d '{"ver":"1.0","policy":{"tenant_id":"publisher","required_fields":["consumed_quantity"],"quantity_tolerance":0.05,"window_seconds":86400}}'
# Expect: the policy echoed back exactly as sent
```

Every successful write call adds an audit row in the same transaction as the
change, so a row exists if and only if the change landed:

```sql
SELECT created_at, action, source_addr, request_id, detail FROM ramp.audit_log
 WHERE tenant_id = 'publisher' ORDER BY created_at DESC LIMIT 5;
-- Expect: a row whose action is SetTenantFeeRate or SetReportingPolicy and whose
-- detail JSON carries the values you sent.
```

A call naming an unknown tenant changes nothing and writes no audit row. Read
current values with the query in §4.1. **Two overrides are not implemented yet**:
a per-resource price override (the price comes from the catalog entry, so change
it by re-ingesting) and a delivery-witness override.

### 4.3 Upgrade and rollback

**Always deploy a specific image tag, never `latest`.** The migration a release
carries is applied automatically at boot, so an unpinned tag means you cannot tell
which schema version you are about to move to.

**Upgrade:** pull the new tag, stop the container, start the new one. Migrations
are applied on start, so **start one instance first**, confirm `/healthz` and the
migration line, then start the rest.

```bash
docker compose logs exchange | grep 'migrations applied'
# Expect: TWO lines, one per database. Check the "table" field, not just the
#         version — the two sequences are numbered independently.
#   {"level":"INFO","msg":"migrations applied","version":<new>,"dirty":false,"table":"schema_migrations_ramp"}
#   {"level":"INFO","msg":"migrations applied","version":<new>,"dirty":false,"table":"schema_migrations_sor"}
```

**Roll back:** start the previous tag. The schema stays where the newer version
left it — the binary never migrates backwards. Whether the older image can run
against it depends on what the release's migrations did:

| The migration | Result |
|---|---|
| **Added** a table, a column or an enum value | **Safe** — the older code never mentions the new object |
| **Renamed or dropped** a column | **Not safe** — the older code still queries the old name |

Three migrations in this schema are of the second kind: `000016` renamed
`tx_request_id` to `idempotency_key`, `000021` renamed `manifest_url` to
`discovery_url`, and `000031` dropped `tenants.hmac_secret_ref`. Rolled back
across any of them, the older image fails on the first query that touches the
column — loudly, at boot or on that query, not silently. Across `000031` that
is every tenant read, so no offer, catalog lookup or signed URL is served.
If you cannot tell which kind a release contained, treat it as the second.

**Do not reverse a migration by hand.** Down-migration files exist in the source
tree and ship inside the image, but nothing runs them, and reverting the migration
that created `ramp.transaction_evidence` would drop the table — the signed offer
and both parties' signatures with it. If a rollback needs the schema moved
backwards, escalate; the reasons are in
[`deploy/storage/postgres/RUNBOOK.md`](../../deploy/storage/postgres/RUNBOOK.md) §4.4.

---

## 5. Backup and recovery

**PostgreSQL is the only durable store this service owns — but it owns two
databases in it.** Back up both: the catalog database (`EXCHANGE_DSN`) and the
account registry (`EXCHANGE_SOR_DSN`). A backup job written before the registry
existed will silently cover only the first. The Exchange holds no other state on
disk beyond the key files you mounted, which live in your secret store. Redis is a
cache, and TigerBeetle is backed up separately. Schedules, retention and restore
steps for the databases are in
[`deploy/storage/postgres/RUNBOOK.md`](../../deploy/storage/postgres/RUNBOOK.md).

**The one non-obvious step is restoring into a schema carrying the append-once
triggers.** `ramp.transaction_evidence` has `BEFORE UPDATE OR DELETE` and
`BEFORE TRUNCATE` triggers that raise an exception unconditionally; inserts are
unaffected. So **restore into a fresh, empty database** — the schema is created
first and rows are then inserted, and the triggers never fire. A data-only
restore into a database that already holds the table **will fail**, because the
restore truncates the target first and the trigger refuses. Do not disable the
triggers to force one through: that removes the guarantee the table exists to
provide, and a restore is exactly when the evidence matters.

| What | Where | If you lose it |
|---|---|---|
| Catalog | `ramp.catalog` | Re-ingest it (§4.2). **No financial impact** — pricing is re-derived from the feed. Discovery returns nothing until the ingest completes. |
| Tenants | `ramp.tenants` | Re-create the rows (§4.2). Fee rates and policies set through the admin API are reconstructible from `ramp.audit_log`, if that survived. |
| Transaction log and evidence | `ramp.transaction_log`, `ramp.transaction_evidence` | **Financial impact.** Reconstructible: the amounts, from the ledger's own postings, which TigerBeetle holds independently. Not reconstructible: the signed offers and both parties' signatures — the proof of what was agreed. A dispute after this loss cannot be settled from your records. Back these up first. |
| Audit log | `ramp.audit_log` | The only record of who changed a fee rate or policy and when. No functional impact; nothing reads it at runtime. |
| **Agent accounts** | `sor.agent_accounts` — in the **other** database | **Financial impact, and not reconstructible.** This table holds the mapping from each agent's identity to its `billing_ref`. The ledger stores no identity of its own: it derives each account from a one-way hash of the `billing_ref` text, which lives only here. Lose this table and no agent's balance can be reached — the money is still in the ledger, but nothing can say whose it is. Re-registering an agent creates a **new** `billing_ref` and therefore a new, empty ledger account. Back this up alongside the transaction log. |
| Replay records | Redis | A **five-minute window** in which an old signed request could be replayed. Losing Redis entirely is safe — an empty replay store is a safe starting state. |

`ramp.transaction_log`, `ramp.transaction_evidence` and `ramp.audit_log` all grow
forever: nothing removes old rows and there is no retention setting. Size the
database accordingly.

---

## 6. Limitations

- **No dispute operation.** The evidence to settle a dispute is stored
  (`ramp.transaction_evidence`), but there is no RPC, tool or workflow that acts
  on it. Disputes are handled outside the platform.
- **Delivery URLs are not single-use.** A URL is valid for five minutes and may be
  fetched any number of times within that window by anyone holding it.
- **No live signing-key reload.** Changing either signing key requires a restart.
- **No per-resource price override and no delivery-witness override.** Prices come
  from the catalog and change by re-ingesting.
- **No admin read API and no per-operator admin accounts.** The admin listener can
  only write values, never read them; read current values by SQL (§4.1). There is
  no operator login — being able to reach the port is the only check, and the
  audit log records a source address rather than a person.
- **No API for agent accounts.** Switching an agent's account on or off is a
  direct `UPDATE` in the account-registry database (§4.2), and it writes no audit
  row. Listing or searching accounts is SQL as well.
- **One default tenant decides the activation policy for every agent.** The
  policy is read from the single tenant named by `EXCHANGE_DEFAULT_TENANT`,
  whichever publisher the agent goes on to buy from. A per-publisher activation
  policy is not implemented yet.
- **No self-service reporting and no dashboards.** Every question about revenue,
  volume or agent behaviour is answered with SQL against the tables in §3.2.
- **One currency per deployment.** `EXCHANGE_BILLING_LEDGER` fixes it, and a
  purchase priced in any other currency is denied. A second currency means a
  second Exchange.
- **The job that would find and re-post missed charges is not built.** Nothing
  re-posts a charge that failed after its transaction committed; finding and
  correcting those is manual (§3.2).
- **Behind a TLS-terminating proxy, `RAMP_TRUST_PROXY_HEADERS=true` is
  required** — and forbidden anywhere else.
  [`CONFIGURATION.md`](CONFIGURATION.md) §4.
