# RAMP PostgreSQL — Deployment Instructions

This document tells you, the DevOps engineer or DBA running PostgreSQL for the RAMP
platform, how to prepare a PostgreSQL cluster so the RAMP services can use it. You do
not need to read the source code. Words that may be new are explained the first time
they appear.

**This is not an install guide.** Setting PostgreSQL up — installing, hosting,
sizing — is not RAMP's job; your vendor's documentation, or the PostgreSQL
project's own, covers it. What follows covers only the database, the role and the
connection strings RAMP needs, and how to confirm the services built the schema
they expect.

Every setting mentioned is described in full in
[`CONFIGURATION.md`](CONFIGURATION.md). Once the services are running, day-to-day
operation is in [`RUNBOOK.md`](RUNBOOK.md).

---

## 1. Before you start

| What | How to check you have it |
|---|---|
| A PostgreSQL 16 cluster you can reach from where the services will run | `pg_isready -h db.internal.example.net -p 5432` → `db.internal.example.net:5432 - accepting connections` |
| Administrative access to that cluster, enough to create a role and **two** databases | `psql -h db.internal.example.net -U <admin-role> -c "SELECT rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = current_user"` — both must be `t`. A superuser has both, but superuser is not required, which matters on managed services where the admin user is not one. |
| A decision on whether the Exchange and Broker share one database | Sharing is supported, and it is what this repository's Docker Compose files do — see [`CONFIGURATION.md`](CONFIGURATION.md) §3 |
| TLS enabled on the cluster | Required in production — [`CONFIGURATION.md`](CONFIGURATION.md) §2.3 |

**The Exchange needs two databases, not one.** One holds the catalog, the tenants and
the transactions. The second holds the System of Record — the Exchange's register of
agent accounts. They must be separate databases ([`CONFIGURATION.md`](CONFIGURATION.md) §3).

**You must create both yourself.** The Exchange builds its schemas at boot, but it
never issues `CREATE DATABASE`. A missing database is a boot failure, not something
the service repairs.

**No PostgreSQL extensions are needed.** Do not pre-create any schema or table; the
services create their own.

---

## 2. Step 1 — create the role and the databases

The connecting role must **own** each database. The services run their own schema
migrations, which create schemas, types, tables, a function and triggers; a
non-owning read-write role cannot do that.

```bash
psql -h db.internal.example.net -U postgres -c \
  "CREATE ROLE ramp LOGIN PASSWORD '<password>'"
# Expect: CREATE ROLE

psql -h db.internal.example.net -U postgres -c \
  "CREATE DATABASE ramp OWNER ramp"
# Expect: CREATE DATABASE

psql -h db.internal.example.net -U postgres -c \
  "CREATE DATABASE ramp_sor OWNER ramp"
# Expect: CREATE DATABASE
```

If you are also deploying the Identity Service, it needs a third:

```bash
psql -h db.internal.example.net -U postgres -c \
  "CREATE DATABASE identity OWNER ramp"
# Expect: CREATE DATABASE
```

The names are yours to choose; `ramp`, `ramp_sor` and `identity` are used throughout
these documents. What matters is that they are **different databases** on the same
cluster.

Confirm they exist before you go on:

```bash
psql -h db.internal.example.net -U postgres -c \
  "SELECT datname FROM pg_database
    WHERE datname IN ('ramp','ramp_sor','identity') ORDER BY datname"
# Expect: identity, ramp, ramp_sor — or just ramp and ramp_sor if you are not
# deploying the Identity Service
```

If you are running two Exchanges that serve different tenants, each needs **its own
pair** of databases — see [`CONFIGURATION.md`](CONFIGURATION.md) §3.1. Two replicas
of the same Exchange share one pair.

---

## 3. Step 2 — verify reachability as that role

Run this from a host on the same network path the services will use, with the DSN
you intend to give them.

```bash
export EXCHANGE_DSN='postgres://ramp:<password>@db.internal.example.net:5432/ramp?sslmode=require'
export EXCHANGE_SOR_DSN='postgres://ramp:<password>@db.internal.example.net:5432/ramp_sor?sslmode=require'

psql "$EXCHANGE_DSN" -c "
SELECT current_user,
       current_database(),
       current_user = (SELECT rolname FROM pg_roles
                        WHERE oid = (SELECT datdba FROM pg_database
                                      WHERE datname = current_database())) AS is_owner"
# Expect: one row, is_owner = t
#  current_user | current_database | is_owner
# --------------+------------------+----------
#  ramp         | ramp             | t
```

Run the same query against the second database:

```bash
psql "$EXCHANGE_SOR_DSN" -c "
SELECT current_user,
       current_database(),
       current_user = (SELECT rolname FROM pg_roles
                        WHERE oid = (SELECT datdba FROM pg_database
                                      WHERE datname = current_database())) AS is_owner"
# Expect: one row, is_owner = t, and current_database = ramp_sor
#  current_user | current_database | is_owner
# --------------+------------------+----------
#  ramp         | ramp_sor         | t
```

**If `is_owner` is `f` on either, stop here.** The first migration will fail with a
permission error and the service will not start.

**If both name the same database, stop here too.** The two DSNs must point at
different databases ([`CONFIGURATION.md`](CONFIGURATION.md) §3).

---

## 4. Step 3 — point each service at its database

Set **both** `EXCHANGE_DSN` and `EXCHANGE_SOR_DSN` on the Exchange, and `BROKER_DSN`
on the Broker. Then start them. All three variables are described in
[`CONFIGURATION.md`](CONFIGURATION.md) §2.

**The Exchange will not start without `EXCHANGE_SOR_DSN`.** It is not optional and it
has no default. Leaving it out gives you this, and the process exits:

```
{"level":"ERROR","msg":"exchange.exit","err":"sor: EXCHANGE_SOR_DSN is required for RAMP_SOR_ADAPTER=postgres"}
```

**You do not run migrations yourself.** Each service applies its own on start, before
it begins listening. A failed migration aborts the boot rather than serving traffic
on a half-built schema.

**Start one instance of each service first**, confirm it is healthy, then start the
rest. Two replicas starting together are safe — they coordinate with a database
lock — but starting one first keeps a failure easy to see.

---

## 5. Step 4 — confirm the schema after first boot

Three checks. Run them in order. Each one covers **both** Exchange databases.

**Check A — each migration sequence reported itself.** The Broker logs one line when
it finishes migrating. The Exchange logs **two** — one per database:

```bash
docker compose logs exchange | grep 'migrations applied'
# Expect: two lines, in this order:
# {"level":"INFO","msg":"migrations applied","version":25,"dirty":false,"table":"schema_migrations_ramp"}
# {"level":"INFO","msg":"migrations applied","version":1,"dirty":false,"table":"schema_migrations_sor"}

docker compose logs broker | grep 'migrations applied'
# Expect: {"level":"INFO","msg":"migrations applied","version":3,"dirty":false,"table":"schema_migrations_broker"}
```

If you are running the Identity Service, it logs one line of its own:

```bash
docker compose logs identity | grep 'migrations applied'
# Expect: {"level":"INFO","msg":"migrations applied","version":4,"dirty":false,"table":"schema_migrations_identity"}
```

`dirty` must be `false` on every line.

**One Exchange line and not two** means the catalog database migrated but the SoR did
not. The Exchange has exited. Read the `exchange.exit` line for the reason; the usual
one is a missing or wrong `EXCHANGE_SOR_DSN` (§4).

**No line at all** means the service never reached its database. Check the DSN. The
service is not running: no RAMP service stays up without a database
([`CONFIGURATION.md`](CONFIGURATION.md) §2.1). A `/healthz` reply of any kind means a
DSN was configured and the service reached the database.

**Check B — the schemas exist and are populated.** Two queries, because schema `sor`
lives in the other database and the first query cannot see it.

```bash
psql "$EXCHANGE_DSN" -c "
SELECT n.nspname AS schema, count(c.oid) AS tables
  FROM pg_namespace n
  LEFT JOIN pg_class c ON c.relnamespace = n.oid AND c.relkind = 'r'
 WHERE n.nspname IN ('ramp','broker')
 GROUP BY n.nspname ORDER BY n.nspname"
#  schema | tables
# --------+--------
#  broker |      2
#  ramp   |      8
#
# Expect: exactly these two rows with these counts. A `broker` row is present only
# if the Broker shares this database.

psql "$EXCHANGE_SOR_DSN" -c "
SELECT n.nspname AS schema, count(c.oid) AS tables
  FROM pg_namespace n
  LEFT JOIN pg_class c ON c.relnamespace = n.oid AND c.relkind = 'r'
 WHERE n.nspname = 'sor'
 GROUP BY n.nspname"
#  schema | tables
# --------+--------
#  sor    |      1
#
# Expect: exactly this one row. The one table is sor.agent_accounts.
```

If the second query returns **no rows**, the SoR migration never ran against this
database — re-read Check A.

If the second query returns a `sor` row against `$EXCHANGE_DSN` as well, both DSNs
point at the same database. Separate them ([`CONFIGURATION.md`](CONFIGURATION.md) §3).

**Check C — the tracking tables landed in `public`, one per migration sequence.**

```bash
psql "$EXCHANGE_DSN" -c "\dt public.schema_migrations_*"
#  Schema |           Name           | Type  | Owner
# --------+--------------------------+-------+-------
#  public | schema_migrations_broker | table | ramp
#  public | schema_migrations_ramp   | table | ramp
#
# Expect: both in `public`, and nowhere else.

psql "$EXCHANGE_SOR_DSN" -c "\dt public.schema_migrations_*"
#  Schema |          Name          | Type  | Owner
# --------+------------------------+-------+-------
#  public | schema_migrations_sor  | table | ramp
#
# Expect: this one, in `public`, and nowhere else.
```

If a tracking table appears in the `ramp`, `broker` or `sor` schema instead, the DSN
carries its own `search_path` — remove it and see
[`CONFIGURATION.md`](CONFIGURATION.md) §2.4.

---

## 6. When a migration fails

A migration that is interrupted part-way leaves a **dirty marker** — a flag in the
tracking table saying "the last attempt did not finish". While it is set, that
service refuses to start, and every replica of it refuses too:

```
{"level":"ERROR","msg":"exchange.exit","err":"migrate up: Dirty database version 25. Fix and force version."}
```

Read the current state. Which tracking table to read depends on which sequence
failed — the `table` field on the last `migrations applied` line tells you how far the
boot got:

```bash
psql "$EXCHANGE_DSN" -c "SELECT version, dirty FROM public.schema_migrations_ramp"
#  version | dirty
# ---------+-------
#       25 | t
#
# Expect on a healthy system: dirty = f

psql "$EXCHANGE_SOR_DSN" -c "SELECT version, dirty FROM public.schema_migrations_sor"
#  version | dirty
# ---------+-------
#        1 | f
#
# Expect on a healthy system: dirty = f
```

**Do not clear the flag by hand.** The flag says the schema is in an unknown state,
not merely that an old marker was left behind — clearing it tells the service to
carry on from a version it may not actually be at. Escalate:
[`RUNBOOK.md`](RUNBOOK.md) header.

---

## 7. Where to go next

This document ends once the services have applied their migrations and the checks in
§5 pass. Everything afterwards is in [`RUNBOOK.md`](RUNBOOK.md):

| Task | Where |
|---|---|
| What to monitor, and what to alert on | `RUNBOOK.md` §2 |
| A service will not boot | `RUNBOOK.md` §3.1 |
| Reading and changing tenant configuration by SQL | `RUNBOOK.md` §4.1 |
| Onboarding a tenant — the SQL half | `RUNBOOK.md` §4.2 |
| Upgrading PostgreSQL | `RUNBOOK.md` §4.3 |
| Backup, and the one restore step that is not obvious | `RUNBOOK.md` §5 |
| What the platform does not do for you | `RUNBOOK.md` §6 |
