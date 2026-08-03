# RAMP Broker — Runbook

Operated by the Exchange Operator.

**Escalation.** If §3 does not resolve it, contact Postindustria at
`<support channel — fill in before handover>`. Send the `request_id` of a failing
request together with the matching log lines from the Broker, the Exchange and the
Edge. Postindustria has no access to your infrastructure, so that correlation ID is
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
withdrawn keys; the Exchange polls it and **refuses to start** if it cannot read it.
So the Broker must be up before the Exchange will boot, and withdrawing a key (§4.2)
is a Broker procedure even though the Exchange enforces it.

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
| `broker.httpsig.reject` | WARN | Signature rejected. `outcome` says why: `signature`, `replay`, `broken_chain`, `hop_budget`. |
| `broker.registry.absent` | WARN | No trusted-key file — every signed request will be rejected. |
| `broker.relay.key_absent` | WARN | No relay key — calls to the Exchange go unsigned and get 401. |
| `broker.registry.set_health` | WARN | Could not **write** a health flag. Fires on a failed write, not on a health change — a health change itself logs nothing. |
| `broker.discover` | WARN | An Exchange failed the discovery call. Field `exchange`. |
| `broker.discover.offer_rejected` | WARN | An offer arrived but failed signature verification. Fields `exchange`, `uri`, `reason`. |
| `broker.routing.resolve` | WARN | An Exchange is healthy but its `ramp.json` gave no endpoint. |
| `broker.resolve.probe` | WARN | Could not read a publisher's `ramp.json`. Field `domain`. |
| `broker.redis.ready` / `.disabled` | INFO | Whether replay protection is shared or per-process. |
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
| Every Exchange unhealthy | **Wake on-call** | Agents get empty offer lists, and health does not recover on its own (§3.1). |
| `broker.httpsig.reject` rate spikes | **Wake on-call** | Key rotation, clocks that are out of sync, or a TLS proxy newly placed in front. |
| `broker.revocation.unavailable` | **Wake on-call** | While broken, the Exchange cannot learn of any withdrawal. |
| `broker.discover.offer_rejected` in bulk | Business hours | Exchange key rotation, or clocks that are out of sync between the two. |

---

## 3. Troubleshooting

### 3.1 Symptom → cause → fix

| Symptom | Why | What to do |
|---|---|---|
| **Agents get empty offer lists and it never recovers** | An Exchange that fails one health probe is marked unhealthy and then **excluded from all future probes**. It cannot come back on its own — not when the Exchange recovers, not when the Broker restarts. | Manual fix only — §4.1. |
| Every signed request rejected, `outcome=signature` | A proxy in front terminates HTTPS and forwards HTTP, so the URL the agent signed is not the URL the Broker checks | Set `RAMP_TRUST_PROXY_HEADERS=true` — [`CONFIGURATION.md`](CONFIGURATION.md) §4. Only behind a proxy you control, never on a directly-exposed Broker. |
| Mass authentication failures, no code change | Redis is down; the Broker rejects the request rather than letting it through, and the error reaches the client as an auth failure | Check Redis first. |
| Discovery returns nothing **and the logs are empty** | Several paths return "no offers" silently | §3.2 — read the `absence_reason` the agent got. |
| Refuses to start: "no Broker identity key" | Neither `BROKER_ED25519_SEED` nor `BROKER_ED25519_KEY_FILE` is set. The Broker will not mint one for you, because the key it publishes must survive a restart | Set a seed: [`DEPLOYMENT.md`](DEPLOYMENT.md) §5. |
| The Exchange answers the Broker with 401 | Relay key missing, or its public half not loaded by the Exchange | Check for `broker.relay.signing` at start-up, then confirm the key with the Exchange operator. |
| Broker will not start | `BROKER_DSN` unset or the database unreachable | Read the `broker.exit` line; it names the cause. |
| Ed25519 PEM rejected at start-up | `openssl genpkey` writes a format the Broker does not accept | Use `BROKER_ED25519_SEED`: [`CONFIGURATION.md`](CONFIGURATION.md) §3. |
| A withdrawn key still works | The published list is empty — file unset or missing, or `as_of` did not move forward | Fetch the revocations document (§2.1). Procedure: §4.2. |
| Revocations route returns 500 | The withdrawn-keys file is malformed | **Urgent** — while broken the Exchange learns of no withdrawal. The `broker.revocation.unavailable` line carries the exact error. |
| The budget cap stops nothing | It is a per-request price limit; spend is never added up | Working as designed — §6. |

### 3.2 Diagnostics

**Which Exchanges are registered, and their health**

```sql
SELECT exchange_id, domain, endpoint, trust_level, healthy, last_health_check
  FROM broker.exchanges ORDER BY priority DESC;
```

Two things to watch for in that output: `last_health_check` is **not a regular
check-in time** — it is written only when health *changes*, so a
permanently-healthy Exchange shows `NULL` forever. And once `healthy` is false it
never changes back on its own (§3.1, §4.1).

**Why one discovery returned no offers.** Start with the logs, but expect nothing:

```bash
docker compose logs broker | grep '"request_id":"<ID>"'
```

Several causes log no line at all — the publisher has no `ramp.json`, its hostname
could not be read, the Exchange named in the manifest is not registered, or it is
registered but unhealthy or `BLOCKED`. A zero-offer discovery also writes **no audit
row**, so there is no database trail either. The reliable signal is the
`absence_reason` in the response the agent received:

| `absence_reason` | Meaning |
|---|---|
| `NOT_IN_CATALOG` | A publisher returned 404 for its `ramp.json` — or, as a fallback, everything routed nowhere. Check the Exchange list next. |
| `TEMPORARILY_UNAVAILABLE` | Manifest fetches or Exchange calls failed. Correlate with `broker.resolve.probe` and `broker.discover`. |
| `SCOPE_INSUFFICIENT` | The caller's credentials unlocked nothing. |
| `NOT_AUTHORIZED` | The budget check refused — the cheapest single offer exceeded the cap. This path **does** write an audit row. |

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
- **The Exchange will not boot without the Broker.** On a first deployment it
  starts, fails and restarts over and over — a *crash-loop* — until DNS,
  certificates and the Broker are live. Not a fault.
- **Free-text search discovery is not implemented** — the `EXA_API_KEY` setting does
  nothing, so do not obtain a key for it.
- **The Broker and the Exchange read the same key file under different variable
  names** (`BROKER_KEYS_FILE`, `RAMP_KEYS_FILE`). Deliberate — one shared list of
  public keys. Update both, or the two disagree about who is trusted.

---

## 4. Procedures

### 4.1 Routine operations

**Restart.** Takes about ten seconds and loses nothing — *provided*
`BROKER_ED25519_SEED` is set. Without it the restart silently changes the Broker's
published identity and everyone who cached the old key stops recognising it. A
stopped Broker also prevents the **Exchange** from starting (§1).

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

**Bring an Exchange back after it was marked unhealthy.** Once `healthy` is false the
Broker stops probing that Exchange entirely, so it never recovers by itself — not
when the Exchange returns, not on a Broker restart. Fix the Exchange, confirm it
answers `200` on its own `/healthz`, then clear the flag by hand:

```bash
psql "$BROKER_DSN" -c \
  "UPDATE broker.exchanges SET healthy = TRUE WHERE exchange_id = '<id>'"
# Expect: UPDATE 1
```

Probing resumes on the next 30-second cycle and stays healthy while the Exchange
answers.

**Running more than one instance.** Above one instance `REDIS_URL` is mandatory and
every instance must use the **same** Redis, or replay protection is per-process and
nothing warns you.
Start one instance first so it applies migrations alone, confirm `/healthz`, then
add the rest.

### 4.2 Key and identity procedures

**Rotate the identity key.** Other parties cache it for up to 90 days, so this is not
instant. Generate a new seed ([`DEPLOYMENT.md`](DEPLOYMENT.md) §5), set
`BROKER_ED25519_SEED`, restart. Then **wait for that cache to expire** before
assuming every other party has it — verify with the directory command in §2.1 from a
machine that has not talked to the Broker before. Signatures made with the old key
stop being recognised once the other parties refresh, so pick a quiet time. There is
no live reload.

**Rotate the relay key.**

1. `BROKER_RELAY_KID=broker.example.v2 scripts/gen-broker-relay-key.sh` — the
   public half is appended to `keys.json`, the old entry stays.
2. Give the updated `keys.json` to the Exchange operator and **confirm it is loaded
   before you switch**, or your calls start failing with `401`.
3. Point `BROKER_RELAY_KEY_FILE` at the new private key and restart.
4. Check `docker compose logs broker | grep relay.signing` — the `keyid` must be the
   new one — then run one real agent request.
5. Once traffic is confirmed, remove the old entry from `keys.json` and have the
   Exchange operator reload.

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
| Exchange list | `broker.exchanges` | Re-created from `BROKER_REGISTRY_FILE` on the next start — provided that file is set, since nothing else fills it. Brief discovery outage, no data loss. The `healthy` flag is **not** restored — see §4.1. |
| Selection audit log | `broker.selection_log` | An audit-trail gap. No functional impact; nothing reads it at runtime. |
| Replay records | Redis | A short window in which an old signed request could be replayed. Losing Redis entirely is safe — an empty replay store is a safe starting state. |

Two things to plan for rather than react to:

- **`broker.selection_log` grows forever** — append-only, nothing removes rows, one
  row per discovery that produced offers, each carrying the full offer set as JSON.
  How long to keep them is your decision; nothing removes old rows for you.
- **A restore brings back out-of-date health flags** — check the list (§3.2)
  afterwards and clear any `healthy = false` that no longer reflects reality (§4.1).

PostgreSQL and Redis are covered by their own operating guides.

---

## 6. Limitations

- **Behind a TLS-terminating proxy, `RAMP_TRUST_PROXY_HEADERS=true` is
  required** — and forbidden anywhere else. [`CONFIGURATION.md`](CONFIGURATION.md) §4.
- **An unhealthy Exchange never recovers on its own** — manual database update (§4.1).
- **The identity key cannot be reloaded without a restart**, and there is no built-in
  way to persist one — you must supply `BROKER_ED25519_SEED` yourself.
- **Withdrawing a key means editing a file by hand** — no tool, and no validation
  until after you save, so a typo stops the withdrawn-keys route from working until
  it is fixed.
- **Agent budget counters are never written**, so the monthly cap is really a
  per-request price limit. Deliberate: the Exchange is the only component that
  charges money, and recording spend here too would double-count.
- **No rate-limit information is returned to agents.**
- **Discovery is always reported as coming from an Exchange** — the only discovery
  path that is implemented.
- **Free-text search discovery is not implemented.**
