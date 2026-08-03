# RAMP Redis — Runbook

Operated by the Exchange Operator. Written for you, the DevOps engineer running
the cache for the RAMP platform: you do not need to read the source code, and
words that may be new are explained the first time they appear.

**Escalation.** If §3 does not resolve it, contact Postindustria at
`<support channel — fill in before handover>`. Send the `request_id` of a failing
request together with the matching log lines from the Exchange and the Broker.
Postindustria has no access to your infrastructure, so that correlation ID is the
only way the request can be traced.

> This runbook assumes Redis is already running and both services are pointed at
> it. For setting it up and first-boot verification, see
> [`DEPLOYMENT.md`](DEPLOYMENT.md) and [`CONFIGURATION.md`](CONFIGURATION.md).

---

## 1. Overview

Redis holds one class of data that matters: **RFC 9421 replay nonces** — a marker
per accepted request signature, recording that the signature has been used. "RFC
9421" is the HTTP Message Signatures standard; the markers are what stop the same
signed request being sent twice. Every marker expires after five minutes. Both
the Exchange and the Broker write them, under five namespaces that never overlap
(§4.1), which is why one instance and one database serve both.

**Almost every operator instinct about Redis is wrong here.** There is nothing to
back up (§5), no eviction policy to tune (§4.1), and nothing to shard (§3.3) —
the data rebuilds itself as traffic arrives, and an empty replay store is a safe
starting state. The one thing that *really matters*: **all replicas of both
services must see the same instance**, or the protection silently stops working.

---

## 2. Monitoring

### 2.1 Health

```bash
redis-cli -u "$REDIS_URL" ping && redis-cli -u "$REDIS_URL" dbsize
# Expect: PONG, then a small integer. 0 is normal when idle — every key
# expires after five minutes.
```

> **`/healthz` on the Exchange and the Broker does not cover Redis.** Both ping
> PostgreSQL and nothing else, so both stay green — `200` — through a total cache
> outage. Do not use them to infer anything about Redis.

### 2.2 Logs

Redis has no log line the platform depends on. The signals live in the two
services' logs (Broker & Exchange). Each service logs exactly one of these at start-up, and the event
names differ because each names it after the subsystem that uses it:

| Service | Signal at start-up | Meaning |
|---|---|---|
| Broker | `broker.redis.ready` (INFO) | Shared replay store in use. |
| Broker | `broker.redis.disabled` (INFO) | `REDIS_URL` unset — per-process store. |
| Exchange | `exchange.httpsig.replay_store_ready` (INFO) | Shared replay store in use. |
| Exchange | `exchange.httpsig.replay_store_disabled` (INFO) | `REDIS_URL` unset — per-process store. |

**Check the line after every deploy of either service.** It is emitted once, at
boot, and never repeated — and a service on a per-process store answers requests
exactly as it would with Redis, so nothing else will ever tell you.

**Memory.** Watch resident memory, because nothing limits it (§2.3):

```bash
redis-cli -u "$REDIS_URL" info memory | grep -E 'used_memory_rss_human|maxmemory_human'
# Expect: used_memory_rss_human in the low megabytes; maxmemory_human:0B
# (0B means no limit is set — see CONFIGURATION.md §4)
```

### 2.3 Alerts

**These are recommendations, not configured alerts** — conditions for you to wire
into whatever monitoring you already run.

| Signal | Severity | First action |
|---|---|---|
| `redis-cli ping` fails for 2 minutes | **Wake on-call** | The platform refuses requests rather than letting them through, but the outage **shows up as mass authentication failures, not 503s** — see §3.1. Restore Redis. |
| `used_memory_rss` growing steadily and not plateauing | Business hours | No `maxmemory` is set anywhere in the platform, so memory can grow forever until the instance is killed for running out of memory, rather than keys being thrown out early. Confirm keys are expiring (§3.2), then size the instance or set `maxmemory` with `noeviction`. |

---

## 3. Troubleshooting

### 3.1 Symptom → cause → fix

| Symptom | Why | What to do |
|---|---|---|
| **Mass authentication failures with no code change** | Redis is unreachable. The replay check refuses the request rather than letting it through, and the store error is recorded as a *signature* failure — it reaches the client as `CodeUnauthenticated` (HTTP `401`) and is audit-logged with `outcome=signature`. **The outage looks like a key problem.** | **Check Redis before chasing keys.** `redis-cli -u "$REDIS_URL" ping`. |
| A service refuses to start, error mentions redis | `REDIS_URL` is set but the instance did not answer the start-up ping, or the URL is malformed. | Verify with the commands in [`DEPLOYMENT.md`](DEPLOYMENT.md) §4. |
| Replay rejections behave oddly after a restart — signatures accepted that were used moments before | Expected when `REDIS_URL` is unset: the per-process store is discarded with the process. | Set `REDIS_URL`. Confirm with §3.2. |
| **The same signed request succeeds against two different replicas** | `REDIS_URL` is unset on that service, so each process has its own store and neither knows what the other has seen. The boot log said so once (§2.2) and nothing has repeated it since. Note the Exchange is **not** given `REDIS_URL` in any compose file in this repository. | Set `REDIS_URL` on every replica of both services, pointing at the **same** instance. |
| A relay route returns `500` instead of `401` during a Redis outage | The Broker's two hand-written relay routes treat a store error as internal rather than as a signature failure. Same root cause, different code. | Same fix — restore Redis. |

### 3.2 Diagnostics

**Inspect the five key namespaces**, and confirm keys really expire — the guard
against memory growing forever. Run within five minutes of live traffic, or the
keys will already have gone:

```bash
redis-cli -u "$REDIS_URL" --scan --pattern 'httpsig:*' | cut -d: -f1-4 | sort | uniq -c
# Expect: counts under the prefixes carrying traffic — httpsig:exchange:replay,
# httpsig:broker:replay, httpsig:broker:relay:execute, httpsig:broker:relay:discover

redis-cli -u "$REDIS_URL" --scan --pattern 'budget:*' | wc -l
# Expect: 0 — those keys are never written (§6)

redis-cli -u "$REDIS_URL" --scan --pattern 'httpsig:*' | head -1 | \
  xargs -I{} redis-cli -u "$REDIS_URL" ttl {}
# Expect: an integer between 1 and 300 (seconds). -1 would mean no TTL was set.
```

**Which store each service actually selected at boot:**

```bash
docker compose logs broker | grep -c broker.redis.ready
# Expect: 1 — a 0 means the Broker is on a per-process store

docker compose logs exchange | grep -c exchange.httpsig.replay_store_ready
# Expect: 1 — a 0 means the Exchange is on a per-process store, and
# exchange.httpsig.replay_store_disabled will be there instead
```

### 3.3 Gotchas

- **One shared logical instance is mandatory once you run more than one
  replica.** Do not shard, partition, or give each service replica its own Redis.
  Every replica of both services must see the same instance, or replay protection
  stops working while every request still succeeds. Each replica reports its own
  choice once at boot (§2.2); no line reports a *mismatch* between them.
- **`docker-compose.e2e.cache.yml` is not about Redis.** Despite the name it is a
  BuildKit registry layer cache overlay for CI image builds. There is no Redis
  configuration in it.

---

## 4. Procedures

### 4.1 Routine operations

**The five key namespaces, and why one database serves both services.** Four
replay prefixes — `httpsig:exchange:replay:` from the Exchange, and
`httpsig:broker:replay:`, `httpsig:broker:relay:execute:` and
`httpsig:broker:relay:discover:` from the Broker — plus `budget:<agent-id>:<YYYY-MM>`.
They never overlap, so no two parts of the platform can produce the same key and
the Exchange and every Broker replica share one database safely. Full table in
[`CONFIGURATION.md`](CONFIGURATION.md) §3.

**All five lifetimes are hardcoded in the service binaries — five minutes for
every replay prefix, 35 days for `budget:`. There is nothing to tune:** no
environment variable, no config file, no runtime setting.

**Flushing the instance.**

```bash
redis-cli -u "$REDIS_URL" flushall
# Expect: OK
```

The cost is **a five-minute replay window and nothing else**: for the next five
minutes, a signature captured just before the flush could be replayed. No request
fails, no state is lost, no service needs restarting.

**Changing the password or moving the instance.** Authentication and TLS are part
of `REDIS_URL`; there is no separate variable for either. Update the URL on
the Exchange and every Broker replica and restart them — it is read only at boot.

**Memory limit.** Nothing in the platform sets one. If you set a `maxmemory`, pair
it with `noeviction`:

```bash
redis-cli -u "$REDIS_URL" config set maxmemory-policy noeviction
# Expect: OK
```

Never use an `allkeys-*` or `volatile-*` policy: evicting a replay nonce before
its five minutes are up silently reopens the replay window it exists to close.

### 4.2 Onboarding and key procedures

**None run against Redis.** Key rotation, revocation, publisher onboarding and
every other periodic operator procedure are owned by the Exchange and Broker —
see `src/exchange/RUNBOOK.md` and `src/broker/RUNBOOK.md`.

### 4.3 Upgrade

The image is pinned to `redis:7-alpine`. Upgrading within the 7.x line needs no
coordination with the services.

```bash
docker compose pull redis && docker compose up -d redis
# Expect: the redis service reaches state "healthy" within about 15 seconds
```

A rolling restart, a failover or a full replacement of the instance is
**harmless** and costs a five-minute replay window (§4.1). No service restart is
needed afterwards — both reconnect on their own. Deploy a specific tag, never
`latest`.

---

## 5. Backup and recovery

**Backup is not required. There is nothing to back up, and no restore procedure
exists because none is needed.**

Every key Redis holds for this platform is a replay nonce with a five-minute
lifetime, and it rebuilds itself as traffic arrives — each is simply a record
that a signature was seen, re-created the next time a caller signs a request.
(The `budget:` counters, at 35 days, would be the one longer-lived class of data,
but they are never written — §6.)

**An empty replay store is a safe starting state.** A fresh, empty instance can
only allow a replay of a signature created in the preceding five minutes; older
signatures are refused on their own expiry, independently of Redis. The whole
cost of losing this data is a five-minute replay window. That is all of it.

This is why [`DEPLOYMENT.md`](DEPLOYMENT.md) §3 turns persistence off, and why
both compose files in this repository run Redis with `--save ""` and no volume.

---

## 6. Limitations

- **The budget counters are never written.** The Broker checks an agent's period
  budget before returning offers but never records spend against it, so no
  `budget:` key is ever created and the monthly cap is really a per-request price
  ceiling. Deliberate: the Exchange is the only component that charges money, and
  recording spend here too would double-count.
- **There is no Redis-backed discovery cache.** The publisher-manifest cache is
  per-process and in-memory; it is not shared between replicas and does not
  survive a restart.
- **Nothing in the platform sets `maxmemory`.** Memory can grow forever until the
  instance is killed for running out of memory, rather than keys being thrown out
  early — §2.3.
