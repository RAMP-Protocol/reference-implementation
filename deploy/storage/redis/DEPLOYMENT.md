# RAMP Redis — Deployment Instructions

This document tells you, the DevOps engineer running the cache for the RAMP
platform, how to set up Redis and point the services at it. You do not need to
read the source code. Words that may be new are explained the first time they
appear. Follow the steps in order.

Every setting mentioned here is described in full in
[`CONFIGURATION.md`](CONFIGURATION.md). Once Redis is running, day-to-day
operation is in [`RUNBOOK.md`](RUNBOOK.md).

---

## 1. What Redis is used for, and how little it needs

The Exchange and the Broker authenticate their callers with HTTP Message
Signatures (RFC 9421): each caller signs its request, and the receiving service
must remember every signature it has accepted so the same one cannot be sent
twice. Redis is where that memory lives, so that all replicas of both services
share one view of it.

That is the entire job. The data is a set of short-lived markers, each expiring
five minutes after it is written, each rebuilt the next time a caller signs a
request.

**A managed Redis with no persistence and default settings is a good fit and
needs no special preparation.** Concretely, this deployment needs none of the
following:

| Not needed | Why |
|---|---|
| Persistence (RDB snapshots or AOF) | Nothing stored is durable data — §5 of [`RUNBOOK.md`](RUNBOOK.md). |
| Backups | Same reason. There is nothing to restore. |
| Replication or failover | An empty replay store is a safe starting state; a fresh instance is correct, just briefly empty. |
| Cluster mode or sharding | The whole data set is a few minutes of request volume, and every service replica must see the *same* instance. |
| Redis modules, Lua, keyspace notifications, pub/sub | The platform issues `PING` at start-up and then only `SET … NX EX`, `EXISTS`, `GET`, and `INCRBY` + `EXPIRE` in a transaction. Nothing else. |
| A tuned eviction policy | See [`CONFIGURATION.md`](CONFIGURATION.md) §4 — the correct answer is `noeviction`, or nothing at all. |
| More than one database | The five key prefixes are disjoint, so a single database serves both services. |

Redis 7 is what the platform is developed and tested against.

---

## 2. What you need before you start

| What | How to check you have it |
|---|---|
| A Redis 7 instance reachable from the Exchange and from every Broker replica | Step 2 below |
| Its connection URL, including any password, held in `REDIS_URL` | `echo "${REDIS_URL:?not set}"` prints a `redis://` or `rediss://` URL |
| The `redis-cli` client, to run the checks in this document | `redis-cli --version` prints a version |

---

## 3. Step 1 — set up the instance

Create one Redis 7 instance however you normally would — managed service or your
own container (§7). Settings to apply:

| Setting | Value | Why |
|---|---|---|
| Persistence | **Off** | Nothing here is durable data. Leaving it on is harmless but suggests there is something to protect when there is not. |
| TLS | **On** | The URL carries a password, and the values themselves are what protects the platform from replays. Use the `rediss://` scheme. |
| Authentication | **On** | Create a password, or an ACL user with a password. |
| `maxmemory-policy` | `noeviction`, or leave unset | An `allkeys-*` policy silently reopens the replay window it exists to close — [`CONFIGURATION.md`](CONFIGURATION.md) §4. |

Then collect the connection URL — see [`CONFIGURATION.md`](CONFIGURATION.md) §2
for the accepted forms.

---

## 4. Step 2 — verify reachability

From a host on the same network as the services:

```bash
redis-cli -u "$REDIS_URL" ping
# Expect: PONG
```

```bash
redis-cli -u "$REDIS_URL" info server | grep redis_version
# Expect: redis_version:7.x.x
```

If `ping` hangs, the network path or the port is wrong. If it returns
`NOAUTH Authentication required` or `WRONGPASS`, the credentials in the URL are
wrong. Fix this before continuing — both services **refuse to start** when
`REDIS_URL` is set but the instance does not answer.

---

## 5. Step 3 — set `REDIS_URL` on both services

The same value goes to the Exchange and to every Broker replica. There is no
per-service variant and no separate variable for the password or for TLS — they
are inside the URL.

```yaml
services:
  exchange:
    environment:
      REDIS_URL: "rediss://:${REDIS_PASSWORD}@cache.internal:6379/0"
  broker:
    environment:
      REDIS_URL: "rediss://:${REDIS_PASSWORD}@cache.internal:6379/0"
```

> **The Exchange is not given `REDIS_URL` in any compose file in this
> repository.** If you copy a compose file from here as a starting point, adding
> that line to the Exchange service is a step you must not skip.

Restart both services so they pick the value up.

---

## 6. Step 4 — confirm the boot signals

Each service logs its choice once at boot. The event names differ — each names the
subsystem that owns the store — but the shape is the same: one line, always.

**The Broker:**

```bash
docker compose logs broker | grep broker.redis
# Expect: {"level":"INFO","msg":"broker.redis.ready","addr":"cache.internal:6379"}
# broker.redis.disabled instead means REDIS_URL is unset — see CONFIGURATION.md §5.
```

**The Exchange:**

```bash
docker compose logs exchange | grep replay_store
# Expect: {"level":"INFO","msg":"exchange.httpsig.replay_store_ready","addr":"cache.internal:6379"}
# exchange.httpsig.replay_store_disabled instead means REDIS_URL is unset.
```

> **No output at all is the failure case** — not a pass. Every boot emits one of
> the two lines, so an empty result means you are reading the wrong container or
> the wrong time range, and you have learned nothing about the replay store.

**Then confirm both are really writing to the instance.** Send any signed request
through the platform — one agent discovery is enough — and look for keys:

```bash
redis-cli -u "$REDIS_URL" --scan --pattern 'httpsig:*' | head
# Expect: at least one httpsig:exchange:replay:… and one httpsig:broker:… key.
# Keys expire after five minutes, so run this within that window.
```

That is the deployment verified. Note that neither service's `/healthz` covers
Redis — see [`RUNBOOK.md`](RUNBOOK.md) §2.1.

---

## 7. If you self-host it

Both compose files in this repository use the same image and the same Redis
command line, with persistence deliberately off. This is the e2e stack's service
definition; the development one differs only in its healthcheck timings:

```yaml
services:
  redis:
    image: redis:7-alpine
    command: ["redis-server", "--save", "", "--loglevel", "warning"]
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 2s
      timeout: 3s
      retries: 20
```

`--save ""` disables snapshotting. Add `--requirepass` and TLS for anything
beyond a private local network.

```bash
docker compose up -d redis
# Expect: the service reaches state "healthy" within about 15 seconds
```

What you must still add before this leaves a private network is a password and
TLS — see [`CONFIGURATION.md`](CONFIGURATION.md) §6.

---

## 8. Where to go next

| Task | Where |
|---|---|
| What to alert on | `RUNBOOK.md` §2.3 |
| Mass authentication failures after no code change | `RUNBOOK.md` §3.1 |
| Inspecting what is in the instance | `RUNBOOK.md` §3.2 |
| Upgrading Redis | `RUNBOOK.md` §4.3 |
| Why there is no backup procedure | `RUNBOOK.md` §5 |
