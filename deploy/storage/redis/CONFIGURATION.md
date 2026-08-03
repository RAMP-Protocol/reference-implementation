# RAMP Redis — Configuration Reference

This document tells you, the DevOps engineer running the cache for the RAMP
platform, what the platform needs from Redis and what every setting does. You do
not need to read the source code. Words that may be new are explained the first
time they appear.

For the step-by-step install see [`DEPLOYMENT.md`](DEPLOYMENT.md); for day-to-day
operation see [`RUNBOOK.md`](RUNBOOK.md).

---

## 1. What the platform needs from Redis

**One logical Redis instance, one database, shared by every replica of the
Exchange and the Broker.** That is the whole requirement.

| Consumer | What it stores in Redis |
|---|---|
| Exchange | A record of which signed requests it has already accepted, so the same one cannot be sent twice (the "replay" protection required by RFC 9421). |
| Broker | The same, for three kinds of request, plus a spend counter per agent. |

"RFC 9421" is the HTTP Message Signatures standard: callers sign their requests,
and the receiving service must remember each signature so the same one cannot be
sent twice. That memory is what Redis holds. Nothing else in the platform uses
Redis — not the Edge worker, not the Identity Service, and no cache of any other
kind.

Two consequences worth stating before you start, because they are the opposite of
the usual Redis advice:

- **Nothing here needs to survive a restart.** Every value has a short lifetime
  and rebuilds itself as traffic arrives. Persistence is not required — see
  [`RUNBOOK.md`](RUNBOOK.md) §5.
- **There is nothing to shard.** The data set is tiny and the services must all
  see the *same* instance for the protection to work at all (§5).

A managed Redis with no persistence, no replication and default settings is a
good fit. Redis 7 is what the platform is developed and tested against.

---

## 2. Environment variables

Configuration is one variable, read by both services.

| Name | Required? | What it is | Example |
|---|---|---|---|
| `REDIS_URL` | Optional, **set it** | The Redis connection string. Set it identically on the Exchange and on every Broker replica. Leave it unset and each process remembers signatures on its own — see §5. | `rediss://:PASSWORD@cache.internal:6379/0` |

**There is no separate variable for the username, the password, the port, the
database number or TLS.** All of them travel inside the URL. There is no Redis
config file the platform reads, and no command-line flag.

Accepted URL forms:

| Form | Meaning |
|---|---|
| `redis://host:6379/0` | Plain TCP, no auth, database 0. |
| `rediss://host:6379/0` | **TLS.** The extra `s` is the only thing that turns encryption on. |
| `redis://user:password@host:6379/0` | Username and password (Redis 6+ ACL user). |
| `rediss://:password@host:6379/0` | Password only (the default `default` user), over TLS. |
| `unix:///path/to/redis.sock` | Unix socket. |

The trailing `/0` is the database number and defaults to `0` when omitted. Any
database number works — the platform does not care which one, it only reads what
the URL gives it.

---

## 3. The five key namespaces

Everything the platform writes lands under one of five prefixes. They **never
overlap**: no two parts of the platform can ever produce the same key, which is
what makes a single instance and a single database safe for both services.

| Prefix | Written by | Holds | Lifetime |
|---|---|---|---|
| `httpsig:exchange:replay:` | Exchange | Signature nonces for every Exchange RPC | 5 minutes |
| `httpsig:broker:replay:` | Broker | Signature nonces for the agent-facing `BrokerService` RPC | 5 minutes |
| `httpsig:broker:relay:execute:` | Broker | Signature nonces for the execute relay route | 5 minutes |
| `httpsig:broker:relay:discover:` | Broker | Signature nonces for the discover relay route | 5 minutes |
| `budget:<agent-id>:<YYYY-MM>` | Broker | Per-agent monthly spend counter | 35 days |

The four replay keys are a fixed-length hash of the caller's key id and
signature, with the value `1` — a few hundred bytes each, at most. The three
Broker prefixes are deliberately distinct so a signature used on one route
cannot be spent against another.

`budget:` keys are **never written today** — see [`RUNBOOK.md`](RUNBOOK.md) §6.

### Nothing here is tunable

All five lifetimes are compiled into the binaries. There is no environment
variable, no config file and no runtime setting for any of them:

| Value | Where it comes from |
|---|---|
| 5-minute replay window | `internal/replay/store.go`, constant `ReplayTTL` |
| 35-day budget-counter lifetime | `src/broker/internal/budget/budget.go`, the `NewRedis` default |
| The five prefixes | Fixed strings at each service's wiring point |

If you need a different replay window, that is a code change, not a
configuration change.

---

## 4. Memory use

**Nothing in the platform sets `maxmemory` or `maxmemory-policy`, and no Redis
config file ships with it.** Whatever your Redis instance defaults to is what you
get.

So the risk is that **memory grows forever until the instance is killed for
running out of memory**, not that keys are thrown out early. In practice the risk
is low: every key expires in five minutes and every value is tiny, so the memory
it settles at is roughly five minutes of request volume. This is arithmetic, not
a measurement: one key is on the order of 200 bytes including Redis's own per-key
overhead, so a sustained 1,000 requests per second occupies well under 100 MB.
Watch resident memory (RSS) anyway — [`RUNBOOK.md`](RUNBOOK.md) §2.2.

If you do set a `maxmemory` — recommended on a shared or small managed instance
— pair it with **`noeviction`**:

> **Never use an `allkeys-*` eviction policy.** `allkeys-lru`, `allkeys-lfu` and
> `allkeys-random` all evict live keys under pressure. Evicting a replay nonce
> before its five minutes are up reopens exactly the replay window it exists to
> close, and nothing anywhere reports that it happened. `noeviction` turns memory
> pressure into a loud write error instead of quietly weakening security.
>
> `volatile-*` policies are equally unsafe here for the same reason: every key
> the platform writes has a lifetime (a TTL), so "volatile" covers all of them.

---

## 5. What `REDIS_URL` unset costs

With `REDIS_URL` unset **both services still start**. Each process then keeps its
own private, in-memory record of the signatures it has seen.

| Service | Behaviour when `REDIS_URL` is unset |
|---|---|
| Broker | Starts, logs one `INFO` line — `broker.redis.disabled` — and uses a per-process store. |
| Exchange | Starts, logs one `INFO` line — `exchange.httpsig.replay_store_disabled` — and uses a per-process store. |

Both announce it once, at boot, and never again. That single line is the whole
signal: a service on a per-process store serves requests exactly as it would with
Redis, so nothing in the traffic will tell you.

- With **one** replica of a service, a per-process store is correct.
- With **two or more**, it is not: a signature already used against replica A is
  unknown to replica B, so it can be replayed there. **Nothing warns you.**

**If more than one replica of either service runs, `REDIS_URL` is mandatory, and
every replica must point at the same Redis.** Do not give each replica its own
instance and do not give the Exchange and the Broker separate instances — the
prefixes in §3 exist so that they can share one.

The reverse case is loud, not silent: with `REDIS_URL` **set** but Redis
unreachable, both services fail their start-up ping and **refuse to start**.

---

## 6. Development defaults you must not copy

The Redis service in this repository's development compose file exists to run
local stacks. Both compose files now run with persistence off — `--save ""` and
no volume — which is the honest configuration and safe to copy. One setting is
not:

| Setting | Why it is there | Why it must not ship |
|---|---|---|
| Port published to the host, no password, no TLS | The stack is a private local bridge. | Replay state would be readable and changeable by anything that can reach the port. Use `rediss://` and an ACL password (§2). |

---

## 7. Worked example

One value, set identically on the Exchange and on every Broker replica:

```
REDIS_URL=rediss://:<password>@<redis-host>:6379/0
```

Everything else is left at the Redis instance's own defaults. In particular the
platform sets no `maxmemory`, no `maxmemory-policy` and no persistence settings.
The URL above ends in `/0` only because `0` is the database Redis gives you by
default; any number works, as long as it is the same one everywhere (§2).

`REDIS_URL` is read as a plain environment variable and contains a password, so
treat it as a secret. The services do not know or care where it came from — the
secret store and the tooling that supplies it are your choice; the only
requirement is that the variable is present in the environment when each process
starts.
