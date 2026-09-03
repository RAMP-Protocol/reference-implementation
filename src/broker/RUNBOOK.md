# RAMP Broker — Runbook

Operated by the Exchange Operator.

**Escalation.** If §3 does not resolve it, contact Postindustria over the
existing communication channel. Send the `request_id` of a failing request
together with the matching log lines from the Broker, the Exchange and the Edge.
Postindustria has no access to your infrastructure, so that correlation ID is
the only way the request can be traced.

> This runbook assumes the Broker is already deployed. For installation,
> configuration values, applying or destroying the stack, and deploy-time
> verification, see [`DEPLOYMENT.md`](DEPLOYMENT.md) and
> [`CONFIGURATION.md`](CONFIGURATION.md).

---

## 1. Overview

The Broker is the front door for AI agents, and everything it does is relaying.
Agents ask it what a set of URLs would cost; it asks the Exchange, ranks the answers
and returns them. When the agent buys, it forwards the purchase and returns the
signed download links.

**It is not on the delivery path.** It never holds an agent's private key, never
creates a download link, never sees the content. If it is down, agents cannot
discover or buy — but the publisher's site is unaffected and links already issued
keep working.

**The Exchange depends on it for withdrawn keys.** The Broker publishes the list of
withdrawn keys, and the Exchange consults it before trusting any caller's key. The
Exchange refuses to start only when it has no address configured for that document;
with the address set but the Broker down, the Exchange stays up and instead rejects
every signed request with `401` (it fails closed, logging
`exchange.httpsig.broker_wellknown_unavailable`). So the Broker must be up before
any agent can authenticate, and withdrawing a key (§4.2) is a Broker procedure even
though the Exchange enforces it.

---

## 2. Monitoring

### 2.1 Health

**`/healthz` pings PostgreSQL and nothing else.** It stays green with Redis dead,
with every Exchange unreachable, and with an empty Exchange list. Read it as "the
process is up", not "the service works".

The three published documents are the real readiness signal:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://broker.example/healthz
# Expect: 200

curl -s https://broker.example/.well-known/ramp.json
# Expect: "role":"ROLE_BROKER" and your own domain

curl -s https://broker.example/.well-known/http-message-signatures-directory
# Expect: a "keys" array plus "revocation_url".
# The keys MUST be identical across a restart — if not, see §3.1.

curl -s https://broker.example/.well-known/ramp-key-revocations.json
# Expect: an "as_of" you recognise. "1970-01-01T00:00:00Z" means the
# withdrawn-keys file is unset or missing, so the Exchange believes
# nothing has ever been withdrawn.
```

### 2.2 Logs

JSON, one object per line, on stdout — `docker compose logs broker`. **There is no
`/metrics` endpoint and no Prometheus support**, so alerting is on log events.

Every line carries `request_id`, and it is the same value across the Edge, the
Broker and the Exchange — grep it in all three to trace one request end to end.

| Event | Level | Means |
|---|---|---|
| `broker.exit` | ERROR | Refused to start. The message names the cause. |
| `broker.revocation.unavailable` | ERROR | The withdrawn-keys file is unreadable or malformed. |
| `broker.resolve.record` | ERROR | Could not write the audit row. The request itself succeeded. |
| `broker.httpsig.reject` | WARN | A request was rejected before it reached a handler. `outcome` says why: `signature`, `replay`, `broken_chain`, `hop_budget` or `body_too_large`. The first four are authentication outcomes and point at the caller's key, clock or relay chain. `body_too_large` is not one of them — the body passed the read cap before verification, and the caller fixes it by sending less. This Broker sets no cap of its own, so the bound is the SDK's own default rather than nothing. **On this Broker the line appears only for a request that carried a `Signature-Input` header.** The verification seam is what writes it, and this Broker admits an unsigned request to the handler without entering that seam, so an unsigned body past the cap is still refused and still bounded but leaves no audit line. Watching this line for over-size abuse therefore does not show you unauthenticated callers. |
| `rampaudience.refused` | WARN, **ERROR** for an unusable identity | A request named a recipient other than this Broker and was refused before the handler ran. Carries `path` (the RPC — the same key `broker.httpsig.reject` uses), `verdict`, `self` (the identity this service answers to) and `reason`. No agent-facing RPC names a recipient today, so on this service the line should be rare; at **ERROR** it means this Broker's own identity is unusable and every addressed request would be refused. |
| `broker.registry.no_bootstrap` | WARN | No Exchange registry file — the Broker routes to no Exchange until one is registered. |
| `broker.relay.key_absent` | WARN | No relay key — calls to the Exchange go unsigned and get 401. |
| `broker.registry.set_probe_result` | WARN | Could not **write** what a health probe pass learned — the health flag, the endpoint, or both. Fires on a failed write, not on a change. Field `exchange_id`. |
| `broker.registry.health_changed` | INFO | An Exchange went down or came back. Fields `exchange_id`, `domain`, `healthy`. This is the only line that timestamps an outage; the routing-skip line says an Exchange is down now but not when it went down. |
| `broker.registry.endpoint_changed` | INFO | The address an Exchange advertises in its own `ramp.json` differs from the one the registry held, and the registry now holds the advertised one. Fields `exchange_id`, `domain`, `was`, `now`. Expected once after a bootstrap file names an address the Exchange has outgrown; repeating every polling interval means the Exchange is advertising an address that does not stay put. |
| `broker.registry.resolve` | **INFO** | A probe pass could not read an Exchange's own `ramp.json`, so it learned nothing about where that Exchange is. Fields `domain`, `err`. The pass keeps the address already stored and marks the row unhealthy, because routing resolves the same way and could not reach it either. Note the level: this is the one probe-loop fault logged below WARN, while the same failure on the request path (`broker.routing.resolve`) is a WARN. Filtering at WARN shows you the request-path copy and hides the probe that took the Exchange out of service. |
| `broker.registry.list` | WARN | A probe pass could not read the registry at all and did no work. Field `err`. Every Exchange keeps its last known state until the next pass. |
| `broker.registry.refresh` | WARN | The same fault, reported by the polling loop. Field `err`. Paired with the line above for one failure. |
| `broker.routing.skipped` | INFO (`unhealthy`, `blocked`), DEBUG (`unregistered`) | A manifest named an Exchange that discovery then declined. Fields `domain`, `reason`. `unhealthy` clears when the Exchange answers `/healthz` again; `blocked` only when an operator restores trust; `unregistered` means the manifest names an Exchange this Broker has never heard of, which is common and logged at DEBUG. |
| `broker.batch.total_cost_aggregation_failed` | WARN | The relay could not total a batch's cost. The transaction itself is unaffected. |
| `broker.discover` | WARN | An Exchange failed the discovery call. Field `exchange`. |
| `broker.discover.offer_rejected` | WARN | An offer arrived but failed signature verification. Fields `exchange`, `uri`, `reason`. |
| `broker.routing.resolve` | WARN | An Exchange is healthy but its `ramp.json` gave no endpoint. |
| `broker.resolve.probe` | WARN | Could not read a publisher's `ramp.json`. Field `domain`. |
| `broker.routing.lookup` | WARN | Reading a registered Exchange from the database failed with a real error (not "not registered"). Field `domain`. That Exchange is skipped for the current request. |
| `broker.discover_relay` / `broker.exchange_relay` | INFO on success, WARN on a fault | The relay audit trail: one record per relay attempt, carrying `outcome` and `endpoint`. The outcomes are listed below. |
| `broker.redis.ready` / `.disabled` | INFO | Whether replay protection is shared or per-process. |
| `broker.exa.disabled` | INFO | `EXA_API_KEY` is unset. Logged once at start-up; free-text query requests will fail with `no domains for query`. |
| `broker.exa.init_failed` | WARN | The key is set but the search client could not be built. Field `err`. The Broker starts anyway, and free-text query requests fail exactly as if the key were unset. |
| `broker.relay.signing` | INFO | The relay key in use. `keyid` is a fingerprint, not the name you chose. |

### 2.3 Alerts

**These are recommendations, not configured alerts.** Nothing here ships an alerting
rule — the Broker has no metrics endpoint, so these are log conditions for you to wire
into whatever monitoring you already run. **"Wake on-call" means call the engineer
on duty, at any hour.**

| Signal | Severity | First action |
|---|---|---|
| `/healthz` non-200 for 2 minutes | **Wake on-call** | PostgreSQL is unreachable. |
| Redis unreachable | **Wake on-call** | The Broker rejects requests rather than letting them through, but this **shows up as mass authentication failures, not 503s**. Check Redis before chasing key problems — the most misread outage on this service. |
| Every Exchange unhealthy for more than 3 polling intervals (~90s) | **Wake on-call** | Agents get empty offer lists. A single interval is not an alert: the Broker re-probes every Exchange it has not blocked, so one failed probe clears itself on the next pass. Sustained means the Exchanges really are unreachable, or the Broker cannot make outbound calls at all. |
| `broker.httpsig.reject` rate spikes | **Wake on-call** | Key rotation, clocks that are out of sync, or a TLS proxy newly placed in front. |
| `broker.revocation.unavailable` | **Wake on-call** | While broken, the Exchange cannot learn of any withdrawal. |
| `broker.discover.offer_rejected` in bulk | Business hours | Exchange key rotation, or clocks that are out of sync between the two. |

**Relay `outcome` values.** Every refusal begins with `REJECTED_`, so one filter on
that prefix catches all of them, and each stays searchable on its own.

| `outcome` | Means |
|---|---|
| `VALIDATED` | The request passed every gate and was forwarded. |
| `REJECTED_ENDPOINT` | The caller named an address no registered Exchange advertises. This is the shape an SSRF attempt takes; a `BLOCKED` Exchange also lands here, because an agent is owed no distinction between "withdrawn" and "never registered". |
| `REJECTED_ENDPOINT_DOWN` | The Exchange is registered and still trusted, and its last health probe failed. Routine, and it clears on its own — this is the one to exclude before reading a `REJECTED_` rate as an attack signal. |
| `REJECTED_AUTHZ` | Either the agent's own signature did not verify at the Broker boundary, or the transaction named an Exchange that is registered but not approved to be paid (`DISCOVERED`). The message says which. |
| `REJECTED_REPLAY` | The signature had already been used. |
| `REJECTED_UPSTREAM` | Reaching the Exchange failed in a way the Exchange owns. |
| `REJECTED_INTERNAL` | The Broker's own fault, such as a registry read that failed. Nothing is wrong with the Exchange; do not chase it. |
| `RELAY_UPSTREAM_ERROR` | The Exchange was reached and answered with an error. |

---

## 3. Troubleshooting

### 3.1 Symptom → cause → fix

| Symptom | Why | What to do |
|---|---|---|
| **Agents get empty offer lists, and it does not clear within a couple of minutes** | Every Exchange is failing its health probe. The Broker keeps probing an unhealthy Exchange and brings it back on its own once `/healthz` answers 200, so a state that persists is a real outage rather than a stuck flag. | §4.1 — find out why the probe fails; do not edit the flag. |
| **One Exchange is unroutable while others work** | Its probe is failing, or an operator has `BLOCKED` it. `broker.routing.skipped` names the Exchange and says which. | Read the `reason` on that line. `unhealthy` points at the Exchange's `/healthz`; `blocked` is an operator decision and only an operator reverses it. |
| Every signed request rejected, `outcome=signature` | A proxy in front terminates HTTPS and forwards HTTP, so the URL the agent signed is not the URL the Broker checks | Set `RAMP_TRUST_PROXY_HEADERS=true` — [`CONFIGURATION.md`](CONFIGURATION.md) §4. Only behind a proxy you control, never on a directly-exposed Broker. |
| Mass authentication failures, no code change | Redis is down; the Broker rejects the request rather than letting it through, and the error reaches the client as an auth failure | Check Redis first. |
| Discovery returns nothing **and the logs are empty** | Several paths return "no offers" silently | §3.2 — read the `absence_reason` the agent got. |
| Refuses to start: "no Broker identity key" | Neither `BROKER_ED25519_SEED` nor `BROKER_ED25519_KEY_FILE` is set. The Broker will not mint one for you, because the key it publishes must survive a restart | Set a seed: [`DEPLOYMENT.md`](DEPLOYMENT.md) §5. |
| The Exchange answers the Broker with 401 | Relay key missing, or its public half not loaded by the Exchange | Check for `broker.relay.signing` at start-up, then confirm the key with the Exchange operator. |
| Broker will not start | `BROKER_DSN` unset or the database unreachable | Read the `broker.exit` line; it names the cause. |
| Ed25519 PEM rejected at start-up | `openssl genpkey` writes a format the Broker does not accept | Use `BROKER_ED25519_SEED`: [`CONFIGURATION.md`](CONFIGURATION.md) §3. |
| A withdrawn key still works | The published list is empty — file unset or missing, or `as_of` did not move forward | Fetch the revocations document (§2.1). Procedure: §4.2. |
| Revocations route returns 500 | The withdrawn-keys file is malformed | **Urgent** — while broken the Exchange learns of no withdrawal. The `broker.revocation.unavailable` line carries the exact error. |
| An agent starts getting `NOT_AUTHORIZED` part-way through the month | Spend accumulates per agent per calendar month: every admitted discovery adds the winning offer's value to that agent's counter, and a request is refused once the counter has reached the request's budget limit. The counters live in Redis (or per process without Redis) and reset at the month boundary. | Working as designed — §6. |

### 3.2 Diagnostics

**Which Exchanges are registered, and their health**

```sql
SELECT exchange_id, domain, endpoint, trust_level, healthy, last_health_check
  FROM broker.exchanges ORDER BY priority DESC;
```

Two things to watch for in that output. `last_health_check` is **not a regular
check-in time** — it is written only when a pass learns something the row does not
already say, either a health change or a new address, so an Exchange that has been
healthy and stationary since bootstrap shows `NULL` forever. And `healthy` is a
live reading, not a latch: the Broker probes every non-`BLOCKED` Exchange each
interval and clears the flag by itself once `/healthz` answers 200 again. A row
sitting at `false` means the probe is still failing right now.

**Why one discovery returned no offers.** Start with the logs, but expect nothing:

```bash
docker compose logs broker | grep '"request_id":"<ID>"'
```

An Exchange declined for its registry state does leave a line:
`broker.routing.skipped` carries the `domain` and a `reason` of `unhealthy` or
`blocked`, at INFO. The quiet causes are the rest — the publisher has no
`ramp.json`, its hostname could not be read, or the manifest names an Exchange
this Broker has never heard of (that last one logs at DEBUG, below the default
floor). A zero-offer discovery also writes **no audit row**, so there is no
database trail either. The reliable signal is the `absence_reason` in the response
the agent received:

| `absence_reason` | Meaning |
|---|---|
| `NOT_IN_CATALOG` | A publisher returned 404 for its `ramp.json` — or, as a fallback, everything routed nowhere. Check the Exchange list next. |
| `TEMPORARILY_UNAVAILABLE` | Manifest fetches or Exchange calls failed. Correlate with `broker.resolve.probe` and `broker.discover`. |
| `SCOPE_INSUFFICIENT` | The caller's credentials unlocked nothing. |
| `NOT_AUTHORIZED` | The budget check refused — the agent's accumulated spend this month has reached the request's limit, or the top-ranked offer would push it past. This path **does** write an audit row (`outcome=budget_exhausted`). |

An `absence_reason` may also be passed through unchanged from the Exchange. When the
Broker's logs are clean, the answer is in the Exchange's logs, same `request_id`.

**Audit trail for one request**

```sql
SELECT log_id, rationale->>'outcome', created_at
  FROM broker.selection_log WHERE request_id = '<ID>';
```

No row means the discovery produced no offers. `outcome` is `discovered` or
`budget_exhausted`.

### 3.3 Gotchas

- **Redis-less mode is silent and per-process** — correct at one instance, unsafe
  above one, marked by a single `INFO` line.
- **The Exchange authenticates nobody while the Broker is down.** The Exchange
  starts and stays up without the Broker (only the document address must be
  configured), but it fails closed: every signed request is rejected with `401`
  until the Broker's published documents are reachable again. Both processes look
  healthy while nothing works.
- **Free-text search needs `EXA_API_KEY` — and still returns no offers.** Without
  the key, a request that carries only a free-text query fails at once with
  `no domains for query`. With it, EXA supplies candidate publisher domains, but
  the query itself is never forwarded to the Exchange: the Exchange receives a
  call with no URLs, a compliant Exchange rejects that, and the agent sees
  `TEMPORARILY_UNAVAILABLE`. Requests that name URLs work without the key.
- **There is no shared key file.** The Broker learns an agent's public key by
  fetching that agent's own published directory, and publishes its own keys
  (identity and relay) in its own directory for the Exchange to fetch.

---

## 4. Procedures

### 4.1 Routine operations

**Restart.** Takes about ten seconds and loses nothing — *provided*
`BROKER_ED25519_SEED` is set. Without it the restart silently changes the Broker's
published identity and everyone who cached the old key stops recognising it. While
the Broker is stopped, the **Exchange** rejects every signed request (§1).

**Everything needs a restart** except the withdrawn-keys file, which is re-read
whenever it changes.

**Add an Exchange.** Add it to the YAML that `BROKER_REGISTRY_FILE` points at (format
in [`DEPLOYMENT.md`](DEPLOYMENT.md) §7) and restart. That file is the source of truth
and is applied to the database at every start.

**Remove or quarantine one.** Start-up only adds and updates, so deleting an entry
from the file does **not** delete the row — do it directly. Quarantining keeps the
row but takes it out of service:

```bash
psql "$BROKER_DSN" -c "DELETE FROM broker.exchanges WHERE exchange_id = '<id>'"
psql "$BROKER_DSN" -c \
  "UPDATE broker.exchanges SET trust_level = 'BLOCKED' WHERE exchange_id = '<id>'"
```

**Bring an Exchange back after it was marked unhealthy.** There is nothing to do in
the database, and editing `healthy` by hand is not a supported fix. The Broker
re-probes every Exchange it has not blocked, once per 30-second cycle, and clears
the flag itself on the first pass where `/healthz` answers 200. A row that stays
at `false` is telling you the probe is still failing.

Fix the cause instead. The Broker probes the address the Exchange advertises in
its **own** `/.well-known/ramp.json`, never the `endpoint` column, so check that
address:

```bash
# What the Exchange says about itself, and whether that address answers.
curl -s https://<exchange-domain>/.well-known/ramp.json | jq -r '.endpoint'
curl -sS -o /dev/null -w '%{http_code}\n' "$(curl -s https://<exchange-domain>/.well-known/ramp.json | jq -r '.endpoint')/healthz"
```

The usual causes are that the Exchange is down, that its `ramp.json` advertises an
address that no longer answers, or that the address it advertises is one the
Broker's outbound guard refuses — a private or link-local target. `/healthz`
answering 200 from your own shell but not from the Broker points at the last one.
Once it answers, recovery costs at most one polling interval; `broker.registry.health_changed`
records the moment it comes back.

**Running more than one instance.** Above one instance `REDIS_URL` is mandatory and
every instance must use the **same** Redis, or replay protection is per-process and
nothing warns you.
Start one instance first so it applies migrations alone, confirm `/healthz`, then
add the rest.

### 4.2 Key and identity procedures

**Rotate the identity key.** Other parties re-fetch the Broker's directory on their
own cache schedule — on the Exchange that is `EXCHANGE_DIRECTORY_TTL`, one hour by
default — so the change is not instant. Generate a new seed
([`DEPLOYMENT.md`](DEPLOYMENT.md) §5), set `BROKER_ED25519_SEED`, restart. Then
**wait for those caches to refresh** before assuming every other party has the new
key — verify with the directory command in §2.1 from a machine that has not talked
to the Broker before. Signatures made with the old key stop being recognised once
the other parties refresh, so pick a quiet time. There is no live reload. Separately,
every published key carries a 90-day validity window, so a key that is never
rotated or re-published stops verifying on its own after that window.

**Rotate the relay key.**

1. `BROKER_RELAY_ROTATE=1 BROKER_RELAY_KID=broker.example.v2
   scripts/gen-broker-relay-key.sh` — replaces the private keypair file.
   Without `BROKER_RELAY_ROTATE=1` the script keeps an existing file and
   changes nothing — a plain re-run must never rotate the live identity.
2. Point `BROKER_RELAY_KEY_FILE` at the new private key and restart. The Broker
   publishes the new public key in its own directory at start-up; the Exchange
   picks it up from there on its next directory fetch — there is no file to
   hand over.
3. Check `docker compose logs broker | grep relay.signing` — the `keyid` must be
   the new one — then run one real agent request. If the first request after the
   switch fails with `401`, the Exchange is still serving its cached copy of
   your directory; it refreshes within its directory cache lifetime
   (`EXCHANGE_DIRECTORY_TTL` on the Exchange side).

**Withdraw a key immediately.** Rotation is the planned path; withdrawal is the
emergency one. It takes effect **without restarting either service**. There is no
tool — you edit the file `BROKER_REVOCATION_FILE` points at, and the Broker re-reads
it as soon as it changes.

Keys are identified by fingerprint, not by the name you gave them. For the relay key
it is the `keyid` in the `broker.relay.signing` log line; for any published key:

```bash
curl -s https://broker.example/.well-known/http-message-signatures-directory \
| python3 -c "
import sys,json,hashlib,base64
for k in json.load(sys.stdin)['keys']:
    jwk=json.dumps({'crv':'Ed25519','kty':'OKP','x':k['x']},separators=(',',':'),sort_keys=True)
    print(base64.urlsafe_b64encode(hashlib.sha256(jwk.encode()).digest()).rstrip(b'=').decode(), k['x'])
"
# Expect: one "<fingerprint> <key>" line per published key
```

Write the file — a complete list every time, not an addition to the old one — then
confirm:

```json
{ "as_of": "2026-07-27T13:11:29Z", "revoked": ["9Ck0OUYRJ7PQ_02CfEhVXztFlFD99KVOkcEiTYpf95M"] }
```

```bash
curl -s https://broker.example/.well-known/ramp-key-revocations.json
# Expect: your as_of, and your fingerprint in "revoked"
```

> **`as_of` must move forward every time you edit this file.** Consumers ignore a
> snapshot that is not newer than the one they hold, so a repeated timestamp silently
> does nothing. Per ADR-003, verifiers treat a list that goes backwards as an attempt
> to undo a withdrawal (a rollback attack) and reject it.

A `500` on that route means the file is malformed; the `broker.revocation.unavailable`
log line carries the exact error. **Fix it immediately** — while broken, the Exchange
cannot learn about any withdrawal at all. A withdrawal is permanent: to bring a key
back, generate a new one and rotate to it.

**Onboarding a publisher — the Broker's part.** The Broker holds no publisher
configuration. Its only involvement: the publisher's `ramp.json` must name an
Exchange that is in the Broker's list, healthy and not `BLOCKED`, or that publisher's
URLs return no offers silently (§3.2). Add it per §4.1 before the publisher goes
live. The rest belongs to the Exchange and is covered by its own runbook.

### 4.3 Upgrade and rollback

**Upgrade:** pull the new tag, stop the container, start the new one. Migrations are
applied on start, so start one instance first, confirm `/healthz`, then start the
rest.

**Roll back:** start the previous tag. The schema stays where the newer version left
it — the binary never migrates backwards. Whether the older image can run against it
depends on what the release's migrations did: one that **added** a table, a column or
an enum value is safe, because the older code never mentions the new object; one that
**renamed or dropped** a column is not, because the older code still queries the old
name. The failure is loud — at boot or on the first query that touches the column.
If you cannot tell which kind a release contained, treat it as the second.

**Do not reverse a migration by hand.** Down-migration files ship inside the image but
nothing runs them; escalate instead. The reasons are in
[`deploy/storage/postgres/RUNBOOK.md`](../../deploy/storage/postgres/RUNBOOK.md) §4.4.

Always deploy a specific tag, never `latest`.

---

## 5. Backup and recovery

**The Broker owns no durable state of its own — there is nothing to back up.**
Everything lives in PostgreSQL and Redis, which are backed up separately.

| What | Where | If you lose it |
|---|---|---|
| Exchange list | `broker.exchanges` | Re-created from `BROKER_REGISTRY_FILE` on the next start — provided that file is set, since nothing else fills it. Brief discovery outage, no data loss. Health needs no restoring: the first probe pass after start-up sets each flag from what the Exchange actually answers. |
| Selection audit log | `broker.selection_log` | An audit-trail gap. No functional impact; nothing reads it at runtime. |
| Replay records | Redis | A short window in which an old signed request could be replayed. Losing Redis entirely is safe — an empty replay store is a safe starting state. |

Two things to plan for rather than react to:

- **`broker.selection_log` grows forever** — append-only, nothing removes rows, one
  row per discovery that produced offers, each carrying the full offer set as JSON.
  How long to keep them is your decision; nothing removes old rows for you.
- **A restore brings back out-of-date health flags**, and they correct themselves
  within one 30-second probe pass. Nothing to do; if a flag is still `false` after
  a couple of minutes, the Exchange really is unreachable (§4.1).

PostgreSQL and Redis are covered by their own operating guides.

---

## 6. Limitations

- **Behind a TLS-terminating proxy, `RAMP_TRUST_PROXY_HEADERS=true` is
  required** — and forbidden anywhere else. [`CONFIGURATION.md`](CONFIGURATION.md) §4.
- **The identity key cannot be reloaded without a restart**, and there is no built-in
  way to persist one — you must supply `BROKER_ED25519_SEED` yourself.
- **Withdrawing a key means editing a file by hand** — no tool, and no validation
  until after you save, so a typo stops the withdrawn-keys route from working until
  it is fixed.
- **The budget cap is a discovery-side guard, not a billing record.** Every admitted
  discovery adds the winning offer's value to the agent's counter for the current
  calendar month (in Redis, or per process without Redis), and later discoveries
  are refused once that counter reaches the request's limit. The counter is never
  shown to the agent, and the Exchange remains the only component that charges
  money — this guard bounds brokered offer value, it does not bill.
- **No rate-limit information is returned to agents.**
- **The reported discovery method depends on the path.** Offers for requests that
  name URLs are reported as `EXCHANGE`; offers for free-text query requests are
  reported as `SEARCH`. On the relay surface the Broker passes through whatever
  method the queried Exchange stated.
- **Free-text search discovery is incomplete.** With `EXA_API_KEY` set, EXA supplies
  candidate publisher domains, but the query is never forwarded to the Exchange, so
  a compliant Exchange returns no offers for a free-text request (§3.3).
