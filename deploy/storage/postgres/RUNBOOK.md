# RAMP PostgreSQL — Runbook

Operated by the Exchange Operator, on infrastructure you provide.

**Escalation.** If §3 does not resolve it, contact Postindustria over the
existing communication channel. Send the failing service's log lines around the
migration output, the output of the diagnostics in §3.2, and your PostgreSQL
version. Postindustria has no access to your infrastructure, so those outputs
are the only way the problem can be traced.

> This runbook assumes PostgreSQL is already running and RAMP is pointed at it. For
> preparing a cluster and first-boot verification, see
> [`DEPLOYMENT.md`](DEPLOYMENT.md) and [`CONFIGURATION.md`](CONFIGURATION.md).

---

## 1. Overview

PostgreSQL holds all of the platform's business data. It is spread over **two
databases**, and the Exchange connects to both.

| Schema | Database | Written by | Holds |
|---|---|---|---|
| `ramp` | `$EXCHANGE_DSN` | Exchange | Tenant configuration, the content catalog, every transaction, the signed evidence for every transaction, the admin audit log. |
| `broker` | `$BROKER_DSN` | Broker | The list of Exchanges the Broker routes to, and a log of what discovery returned. |
| `sor` | `$EXCHANGE_SOR_DSN` | Exchange | One table, `sor.agent_accounts`: the register of agent accounts. See §5.2 before you plan a backup. |
| `public` | all of them | the migration runner | Three small tables recording which migrations have been applied: `schema_migrations_ramp` and `schema_migrations_broker` in the first database, `schema_migrations_sor` in the second. |

The *System of Record*, or **SoR**, is the Exchange's account register. One row per
registered agent: its billing reference, whether the account is switched on, and the
registration details it supplied. It lives in its own database, which nothing creates
for you ([`CONFIGURATION.md`](CONFIGURATION.md) §3).

**PostgreSQL is not quite the only place data is kept.** Two things live elsewhere.
If you run the Exchange against a TigerBeetle ledger, agent balances are in
TigerBeetle ([`../tigerbeetle/RUNBOOK.md`](../tigerbeetle/RUNBOOK.md)). If you run the
Identity Service, agents' private keys are in Vault
([`../vault/RUNBOOK.md`](../vault/RUNBOOK.md)).

The Identity Service's own tables are in a third PostgreSQL database (`IDENTITY_DSN`),
and everything in this runbook applies to it. **Back it up together with Vault**, not
on its own schedule — restoring one without the other leaves the keys and the records
that describe them no longer matching each other
([`../vault/RUNBOOK.md`](../vault/RUNBOOK.md) §5.3).

**If PostgreSQL is unavailable, the platform stops.** Agents cannot discover or buy,
and no service can start. Download links already issued keep working — they are
verified at the edge, which never touches the database — and visitors reading the
publisher's site are unaffected.

**A SoR database outage behaves differently, and you should know how.** An Exchange
that is already running stays up, and paid transactions keep going through: a SoR it
cannot reach is treated as a temporary fault, so the account check is skipped and a
warning is logged each time (§2.2). This never stops on its own. For as long as the
outage lasts, accounts you have switched off can still buy. Watch for that warning
line.

Two things do fail. An Exchange that **restarts** during the outage will not boot —
it applies the SoR migrations at start-up. And a clear "no such account" answer, as
opposed to a database it cannot reach, denies the transaction.

**One table behaves unlike the others.** `ramp.transaction_evidence` carries triggers
that refuse `UPDATE`, `DELETE` and `TRUNCATE` outright, for every role including the
database owner. It is the one thing here that will surprise you, and it limits
how you restore a backup — §5.

It is also the **only** table so protected. `ramp.audit_log` and
`broker.selection_log` are append-only by convention — the code never updates or
deletes a row — but nothing in the database enforces that, so a stray `DELETE`
against either succeeds silently.

---

## 2. Monitoring

### 2.1 Health

**RAMP itself produces no database metrics.** Everything below comes from PostgreSQL
itself or from your own monitoring. The signal from the services is each service's
health check, which **pings PostgreSQL and nothing else**; a `503` from either means
that service cannot reach the database.

```bash
pg_isready -h db.internal.example.net -p 5432
# Expect: db.internal.example.net:5432 - accepting connections

curl -s -o /dev/null -w '%{http_code}\n' https://exchange.example.net/healthz
# Expect: 200
curl -s -o /dev/null -w '%{http_code}\n' https://broker.example.net/healthz
# Expect: 200
```

> A `200` means the service reached the database and is still connected. It does
> not tell you the migrations applied cleanly — confirm that separately
> ([`DEPLOYMENT.md`](DEPLOYMENT.md) §5). No service starts without its DSN, so a
> reply of any kind means one was configured.
>
> **The Exchange's health check pings the catalog database only.** It does not touch
> the SoR database. A `200` from the Exchange says nothing about `$EXCHANGE_SOR_DSN`
> — watch for the warning line in §2.2 instead, and monitor the SoR database with
> `pg_isready` like any other.

### 2.2 Logs

Both services log JSON, one object per line, to standard output.

| What | When | Line |
|---|---|---|
| Migration outcome | Once per migration sequence, per start. The Broker has one sequence, the Exchange two. | `{"level":"INFO","msg":"migrations applied","version":25,"dirty":false,"table":"schema_migrations_ramp"}` then `{"level":"INFO","msg":"migrations applied","version":1,"dirty":false,"table":"schema_migrations_sor"}` |
| SoR adapter ready | Once per Exchange start, after both migration lines | `{"level":"INFO","msg":"sor adapter: postgres","cache_ttl":30000000000}` — `cache_ttl` is in nanoseconds, so this is 30 seconds |
| Failed query | On every query error | `{"level":"ERROR","msg":"Query","sql":"...","args":[...],"err":"..."}` |
| SoR unreachable during a transaction | Each time the account check fails on a transient error. The transaction proceeds. | `{"level":"WARN","msg":"exchange.execute_transaction","event":"sor_active_check_failed","err":"..."}` |
| Boot aborted | When a migration or an adapter fails | `{"level":"ERROR","msg":"exchange.exit","err":"migrate up: ..."}`, or `broker.exit` |

The `table` field is what tells the two Exchange migration lines apart. Read it, not
the order.

**Successful queries are not logged** — a quiet log is the healthy state. A failed
query logs **its arguments** alongside its SQL, truncated at 64 characters each, so
treat these logs as carrying request data.

**A full connection pool produces no log line.** Queries simply wait for a free
connection; the symptom is rising latency then timeouts, with nothing naming the
cause. The signal is the connection count in §3.2, read against the limit in
[`CONFIGURATION.md`](CONFIGURATION.md) §5. Exhausting the **server's**
`max_connections` does log, as `too many clients already`.

### 2.3 Alerts

**Recommendations, not configured alerts.** Nothing in the platform produces a
database metric, so each has to be wired into the monitoring you already run.
**"Wake on-call" means call the engineer on duty, at any hour.**

| Signal | Severity | First action |
|---|---|---|
| `pg_isready` failing for 2 minutes | **Wake on-call** | The whole platform is down. |
| Connections above 80% of `max_connections` | **Wake on-call** | §3.2; compare with [`CONFIGURATION.md`](CONFIGURATION.md) §5. |
| Data volume above 80% of the disk | **Wake on-call** | Nothing removes old rows from this database (§5.3). A full disk fails every write. |
| `dirty = t` in any tracking table | **Wake on-call** | §3.1. Every replica of that service is refusing to start. |
| `"event":"sor_active_check_failed"` WARN lines | **Wake on-call** | The Exchange cannot reach the SoR database and is letting paid transactions through unchecked. Check `$EXCHANGE_SOR_DSN`. |
| Replication lag longer than the amount of data you can afford to lose (your RPO) | **Wake on-call** | Only if you run replicas; RAMP neither requires nor is aware of them. |
| `"msg":"Query"` ERROR lines in volume | Business hours | Correlate with the constraints in [`CONFIGURATION.md`](CONFIGURATION.md) §4.1. |
| Growth rate of `ramp.transaction_evidence` | Business hours | Old rows are never removed. Watch how fast it grows against the free space you have left (§5.3). |

---

## 3. Troubleshooting

### 3.1 Symptom → cause → fix

| Symptom | Why | What to do |
|---|---|---|
| A service will not start; the log ends near the migration line | A migration failed. Boot aborts before the listener rather than serving on a half-built schema. | Read the `exchange.exit` / `broker.exit` line — it names the failure. |
| `migrate up: Dirty database version N. Fix and force version.` | A migration was interrupted part-way. Every replica of that service now refuses to start. | The flag is the `dirty` column in `public.schema_migrations_ramp`, `…_broker` or `…_sor`, set to `t`. The last `migrations applied` line names which. **Do not clear it by hand** — neither by `UPDATE … SET dirty = false` nor by `migrate force`. It says the schema state is unknown, not that an old marker was left behind. Escalate (header). |
| Migration fails with `permission denied for database …` or `must be owner of …` | The connecting role does not own the database; migrations create schemas, types, tables, a function and triggers. | Make the role the owner — [`DEPLOYMENT.md`](DEPLOYMENT.md) §2. |
| Two replicas started together; one seems to hang at boot | The migration runner takes a database-wide lock; the second waits, then finds nothing to do. | Nothing is wrong. Avoid it by starting one, confirming health, then scaling. |
| A service exits at once: `EXCHANGE_DSN is required` or `BROKER_DSN is required` | That service has no DSN configured. Neither runs without a database. | Set the DSN — [`CONFIGURATION.md`](CONFIGURATION.md) §2.1. |
| The Exchange exits at once: `sor: EXCHANGE_SOR_DSN is required for RAMP_SOR_ADAPTER=postgres` | The Exchange has no SoR DSN configured. It is required and has no default. | Set `EXCHANGE_SOR_DSN`, pointing at a database of its own — [`CONFIGURATION.md`](CONFIGURATION.md) §2.1, §3. |
| The Exchange exits at once: `sor: unknown RAMP_SOR_ADAPTER "<value>"` | `RAMP_SOR_ADAPTER` is set to something other than `postgres`. Usually a typo. | Set it to `postgres`, or unset it — `postgres` is the default and the only accepted value. |
| The Exchange exits at once: `sor: invalid EXCHANGE_SOR_CACHE_TTL: ...` | `EXCHANGE_SOR_CACHE_TTL` is not a valid duration. It needs a unit: `30s`, `2m`. A bare `30` is rejected. | Fix the value, or unset it — the default is 30 seconds. |
| The Exchange exits at once: `sor: setup database: ...` | The SoR DSN is set but the database is unreachable, the role does not own it, or the database does not exist. Nothing creates it for you. | Read the rest of the message. Then [`DEPLOYMENT.md`](DEPLOYMENT.md) §2 and §3. |
| A tracking table sits in the `ramp`, `broker` or `sor` schema, not `public` | The DSN carries its own `search_path`, overriding the pin RAMP applies. | Remove it — [`CONFIGURATION.md`](CONFIGURATION.md) §2.4. |
| An agent is refused with `agent is not registered for paid content: call Register first` | Its `ramp.agents` row has no `billing_ref`, so it has no account to charge. Usually the row was inserted by SQL (§4.1). | The agent must call the `Register` RPC. You cannot fix this by SQL — see §4.1. |
| An agent is refused with `no billing account found for this agent: contact the operator` | The agent's row carries a `billing_ref`, but the SoR has no account under it. The SoR database was restored from an older backup, or points somewhere new. | Check `$EXCHANGE_SOR_DSN` first. If the row is genuinely gone, escalate — see §5.2. |
| An agent is refused with `account is switched off: contact the operator to turn it back on` | Its SoR account has `active = false`. | Expected if someone switched it off. Change it in `sor.agent_accounts`; the Exchange picks the change up within 30 seconds. |
| `duplicate key value violates unique constraint "catalog_uri_key"` | A catalog URL is unique **globally**, not per tenant; another row already claims it. | Expected, not a fault — [`CONFIGURATION.md`](CONFIGURATION.md) §4.1. |
| `ramp.transaction_evidence is append-once: UPDATE is prohibited` (or `DELETE`, `TRUNCATE`) | The append-once triggers, which fire for every role. | Expected. If it happened during a restore, read §5.1. |
| A table dropped by hand did not come back after a restart | Migrations only run forward from the recorded version, so the migration that created it is never re-applied. | Escalate. Restore instead (§5). |

### 3.2 Diagnostics

**Migration state.** Two queries. The SoR sits in another database, so it cannot join
the union.

```bash
psql "$EXCHANGE_DSN" -c "
SELECT 'ramp' AS sequence, version, dirty FROM public.schema_migrations_ramp
UNION ALL
SELECT 'broker', version, dirty FROM public.schema_migrations_broker"
# Expect: `ramp | 25 | f` and `broker | 3 | f`. dirty must be f on both. The
# broker row exists only if the Broker shares this database.

psql "$EXCHANGE_SOR_DSN" -c "
SELECT 'sor' AS sequence, version, dirty FROM public.schema_migrations_sor"
# Expect: `sor | 1 | f`. dirty must be f.
```

**What is taking the space.**

```bash
psql "$EXCHANGE_DSN" -c "
SELECT schemaname AS schema, relname AS table_name,
       pg_size_pretty(pg_total_relation_size(relid)) AS total,
       n_live_tup AS approx_rows
  FROM pg_stat_user_tables
 WHERE schemaname IN ('ramp','broker')
 ORDER BY pg_total_relation_size(relid) DESC"
# Expect: transaction_log and transaction_evidence at the top on any live
# system, both only ever growing. Nothing removes old rows (§5.3).

psql "$EXCHANGE_DSN" -c "SELECT pg_size_pretty(pg_database_size(current_database())) AS db_size"
# Expect: one row, one value, e.g. `8351 kB`.
```

Both queries read one database only. The SoR database is not included. It holds one
row per registered agent and does not grow with traffic, so it stays small — but
measure it rather than assume:

```bash
psql "$EXCHANGE_SOR_DSN" -c "SELECT pg_size_pretty(pg_database_size(current_database())) AS sor_db_size"
# Expect: one row, a small value.
```

**Connections.**

```bash
psql "$EXCHANGE_DSN" -c "
SELECT (SELECT count(*) FROM pg_stat_activity) AS in_use,
       (SELECT setting::int FROM pg_settings WHERE name='max_connections') AS max_connections"
# Expect: one row, e.g. `6 | 100` — in_use well under max_connections. RAMP's own
# limit is pool_max_conns × total pools, counting two pools per Exchange process
# (CONFIGURATION.md §5). max_connections is a server limit, so connections to the
# SoR database count against the same number.
```

### 3.3 Gotchas

- **A constraint name does not match its column.** `\d ramp.transaction_log` shows
  `transaction_log_tx_request_id_key UNIQUE (idempotency_key)` — the constraint kept
  its original name when the column was renamed. Nothing is wrong.
- **The append-once triggers do not block `DROP TABLE`.** They stop changes to table
  *content*, not removal of the table — and a dropped table does not come back on
  restart (§3.1).
- **Two Exchanges serving different tenants must not share a database** —
  discovery reads the whole catalog without filtering by tenant
  ([`CONFIGURATION.md`](CONFIGURATION.md) §3.1).

---

## 4. Procedures

### 4.1 Routine operations

**Read tenant configuration.** The admin API can only write values — there is no RPC
that reads them — so **SQL is the documented way to read them**:

```bash
psql "$EXCHANGE_DSN" -c "
SELECT tenant_id, domain, signing_scheme, fee_rate_bps, allow_broker_relay,
       activate_new_agents_by_default
  FROM ramp.tenants ORDER BY tenant_id"
# Expect: one row per tenant you have onboarded, e.g.
#   t1 | example.test | ED25519 | 0 | f | t
# Add reporting_policy to the column list to read the usage-reporting rules.
```

`activate_new_agents_by_default` decides whether an agent that registers starts
switched on in the SoR. It defaults to `t`. Set it to `f` if you want to approve each
new agent by hand before it can buy.

**Change tenant configuration.** Two settings have an admin RPC; the rest do not.

| Setting | How to change it |
|---|---|
| `fee_rate_bps`, `fee_rate_notes` | Prefer the admin RPC — it writes a `ramp.audit_log` row in the same transaction. Changing it by SQL leaves no audit trail. |
| `reporting_policy` | Same. |
| `allow_broker_relay` | **SQL only** — no API writes this column. |
| `activate_new_agents_by_default` | **SQL only** — no API writes this column yet. |
| Creating a tenant | **SQL only** — no API creates a tenant row (§4.2). |
| `ramp.tenant_resource_owner_fee` overrides | **SQL only.** |

**Adding an agent by SQL — only half of what is needed.** Agents normally register
themselves — on an agent's first call the Exchange fetches its published key document
and writes the row. You can write that row yourself to let an agent in before it ever
calls, or to correct a key.

**What the SQL below gives you is authentication, not the ability to buy.** It leaves
`ramp.agents.billing_ref` NULL, and an agent with no `billing_ref` has no account to
charge. It can discover content and fetch free content. Every paid transaction is
refused:

```
agent is not registered for paid content: call Register first
```

**Only the `Register` RPC finishes the job.** The agent calls it; the Exchange
creates the `billing_ref`, writes the SoR account, opens the ledger account, and saves
the reference on the agent's row. Those three writes go to three different systems,
so there is no SQL equivalent — do not try to insert a `billing_ref` by hand.

`public_key` is the raw 32-byte Ed25519 key as 64 hex characters. Agents publish it
as a JWK (`kty: OKP`, `crv: Ed25519`), where `x` carries those same 32 bytes in
base64url without padding. Decode `x` and re-encode it as hex:

```bash
python3 -c "import base64,sys; x=sys.argv[1]; print(base64.urlsafe_b64decode(x + '=' * (-len(x) % 4)).hex())" '<x-from-jwk>'
# Expect: 64 hex characters
```

`requester_type` records what kind of caller the row is for: `AGENT` (autonomous
agent), `HUMAN_TOOL` (a person using an AI tool), `SERVICE` (service account),
`DELEGATED` (an agent acting for a user), `RESEARCH` (batch collection or
model-training pipeline) or `BROKER`.

```bash
psql "$EXCHANGE_DSN" -c "
INSERT INTO ramp.agents (agent_id, public_key, requester_type)
VALUES ('agent.example.net', decode('<64-hex-chars>','hex'), 'AGENT')
ON CONFLICT (agent_id) DO UPDATE SET public_key = EXCLUDED.public_key"
# Expect: INSERT 0 1
```

Check whether an agent has finished registering:

```bash
psql "$EXCHANGE_DSN" -c "
SELECT agent_id, billing_ref IS NOT NULL AS registered FROM ramp.agents ORDER BY agent_id"
# Expect: registered = t for every agent that can buy. f means it has only
# authenticated, never called Register.
```

**Switching an account off.** The on/off flag is SoR-side, in the other database:

```bash
psql "$EXCHANGE_SOR_DSN" -c "
UPDATE sor.agent_accounts SET active = false WHERE billing_ref = '<billing-ref>'"
# Expect: UPDATE 1
```

The Exchange caches the flag for 30 seconds, so the change takes effect within that.
Read the `billing_ref` from `ramp.agents` in the other database.

**The tracking tables** belong to the migration runner. Read them (§3.2); never
write them. Their names differ on purpose, so the migration sequences neither
overwrite each other's state nor block each other at boot.

### 4.2 Onboarding and configuration by SQL

Bringing a tenant live has an Exchange half (keys, catalog ingest, edge
configuration) and a database half. **The database half is: insert one
`ramp.tenants` row** — no API creates a tenant. The full procedure, and the value each
column must carry, is in the Exchange's runbook, `src/exchange/RUNBOOK.md`, and is not
repeated here. What this document adds is the constraints that will reject the write:

- `domain` is globally unique. Two tenants cannot share a domain.
- `signing_scheme` is `ED25519` or `AWS_CLOUDFRONT_RSA`. The latter **requires** both
  `rsa_key_ref` and `cloudfront_key_pair_id`; a check constraint rejects the row
  otherwise.
- `fee_rate_bps` is the commission, in whole basis points. One basis point is
  0.01%, so `0` is no commission, `100` is 1%, `250` is 2.5% and `1000` is 10%.
  The allowed range is `0 <= bps < 10000`: the largest value is `9999`, which is
  99.99%, and `10000` (100%) is rejected. The Exchange keeps
  `floor(gross × bps / 10000)`.
- Catalog rows reference the tenant, so the tenant row must exist first.

```bash
psql "$EXCHANGE_DSN" -c "SELECT tenant_id, domain, signing_scheme FROM ramp.tenants WHERE domain = '<tenant-domain>'"
# Expect: exactly one row
```

### 4.3 Upgrade and rollback

**Upgrading PostgreSQL.** RAMP does not care how you do it. Nothing in the schema
depends on an extension and no identifier is generated by the database, so
`pg_upgrade` and dump-and-restore both work — but if you dump and restore,
**read §5.1 first**. Take the services down for the upgrade and bring them back one at
a time; each re-runs its migration check and logs `migrations applied` at an unchanged
version.

**Upgrading the RAMP services.** A release may add migrations, applied automatically
at the new version's first boot. Start one instance, confirm the `migrations applied`
line shows the expected version with `dirty` false, then start the rest.

**Rolling a release back.** The schema stays where the newer version left it — the
services never migrate backwards (§4.4). Whether the older image can run against it
depends on what the release's migrations did, so check before you do it:

| The migration | Effect on the older image | Verdict |
|---|---|---|
| **Added** a table, a column or an enum value | The older code never mentions the new object | **Safe.** Roll the tag back |
| **Renamed or dropped** a column | The older code still queries the old name, which is gone | **Not safe.** Fix forward, or restore (§5.1) |

The failure is loud — at boot or on that first query — not silent corruption. If you
cannot tell which kind a release contained, treat it as the second.

### 4.4 Rolling back a migration

**There is no rollback command, anywhere in the platform.** Each service applies its
own migrations when it starts, and only ever moves forward. No binary, script,
Makefile target or CLI ships that moves the schema backwards, and there is no flag to
ask for one — the services read no command-line arguments at all.

This section is about the **schema**. Rolling the *service* back to a previous image
is §4.3, and is usually what people actually want.

**Then what are the down files for?** Every migration has a matching `.down.sql`, and
they are compiled into every image. They are real SQL, and they are still used:

- The migration library pairs up and down by convention and reads the directory as a
  set; the code generator reads the same directory for the schema.
- **The tests run them.** Some of the Exchange's migrations are applied and then
  reverted under `make test-integration` — including the one that creates
  `ramp.transaction_evidence`, which asserts that reverting leaves no orphaned
  trigger function behind.
- They are the written record of how a change would be reversed, for whoever ends up
  doing it by hand.

**Why nothing runs them: a down migration deletes, it does not undo.** Going back
far enough removes `ramp.transaction_evidence` — the signed offer and both parties'
signatures, your only proof of what was agreed — then `ramp.audit_log`, the sole
record of who changed a fee rate, and finally `ramp.transaction_log`, the billing
record, taking the catalog, the agents, the tenants and the whole `ramp` schema with
it. All three are marked **not reconstructible** in §5.2.

Going back a version does not restore yesterday's data; it discards today's. Forward
is always recoverable, because another migration can be written. Backward is not.

**What to do instead.** Three supported paths, and between them they cover every case:

| Situation | Do this |
|---|---|
| The new schema is wrong | **Fix forward** — ship a migration that corrects it. This is the normal answer |
| You need the data as it was | **Restore into a fresh database** (§5.1), then point the services at it |
| The schema genuinely has to move backwards | **Escalate** — see the header of this runbook. Moving it back is done entirely by hand, with no support in the platform, and the down migrations delete rather than undo. Do not attempt it alone |

A dirty marker blocks movement in either direction until it is cleared (§3.1).

---

## 5. Backup and recovery

**Your existing `pg_dump` and point-in-time-recovery practice applies unchanged.**
RAMP adds no backup tooling and needs none. Back these databases up the way you back
up any database holding financial records.

**Back up both Exchange databases, and back them up at the same point in time.** The
catalog database and the SoR database reference each other: `ramp.agents.billing_ref`
names a row in `sor.agent_accounts`. PostgreSQL cannot enforce that across two
databases, so nothing stops them drifting apart. Restore one from Monday and the
other from Tuesday and some agents will be refused with `no billing account found for
this agent` (§3.1) until you match them up again by hand.

### 5.1 Restoring past the append-once triggers

`ramp.transaction_evidence` refuses `UPDATE`, `DELETE` and `TRUNCATE` for every role,
the database owner included. That limits how you can restore:

| Restore shape | Result |
|---|---|
| Into a **fresh, empty database** | **Works.** The dump loads the table, then the rows, then re-creates the triggers. This is the supported path. |
| `pg_restore --clean` over an existing database | Works. `--clean` issues `DROP`, which changes the table definition, not its content. |
| `pg_restore --data-only` into a populated database | **Fails**, on duplicate keys. |
| Clearing the table first, then loading data | **Impossible.** `TRUNCATE` and `DELETE` are both refused; `DROP TABLE` is the only statement that removes a row, and dropping it does not bring it back, because migrations only run forward (§3.1). |

Always restore into a fresh database, then point the services at it:

```bash
createdb -h db.internal.example.net -U postgres -O ramp ramp_restored
pg_restore -h db.internal.example.net -U ramp -d ramp_restored /backups/ramp.dump
# Expect: no output from either command, exit status 0
```

Restore the SoR database in the same operation, from the matching backup. It has no
append-once triggers, so nothing here constrains it — but leaving it behind puts the
two databases out of step (§5):

```bash
createdb -h db.internal.example.net -U postgres -O ramp ramp_sor_restored
pg_restore -h db.internal.example.net -U ramp -d ramp_sor_restored /backups/ramp_sor.dump
# Expect: no output from either command, exit status 0
```

Verify the triggers came back — a restore that silently lost them would leave the
evidence table open to changes:

```bash
# pg_trigger is PostgreSQL's own list of triggers. Casting the table name with
# ::regclass keeps only the triggers on that one table, and NOT tgisinternal drops
# the ones PostgreSQL creates by itself behind constraints such as foreign keys, so
# what is left is the two the migration declared. tgenabled says whether a trigger
# fires; O is the normal enabled state.
psql -h db.internal.example.net -U ramp -d ramp_restored -c "
SELECT tgname, tgenabled FROM pg_trigger
 WHERE tgrelid = 'ramp.transaction_evidence'::regclass AND NOT tgisinternal"
# Expect: two rows, tgenabled = O (enabled) —
#   trg_transaction_evidence_no_row_mutation | O
#   trg_transaction_evidence_no_truncate     | O

psql -h db.internal.example.net -U ramp -d ramp_restored -c "UPDATE ramp.transaction_evidence SET offer_id='x'"
# Expect: ERROR:  ramp.transaction_evidence is append-once: UPDATE is prohibited
```

The error is the pass condition. `UPDATE 0` means the table is empty — re-run against
a restore that contains rows. Anything else means the triggers did not survive;
escalate.

### 5.2 What a loss costs, per table

| Table | If you lose it |
|---|---|
| `ramp.catalog` | **Reconstructible** — re-ingest the publisher's feed through the Exchange. |
| `ramp.agents` | **Reconstructible** — agents re-register on their next call, or re-insert by SQL (§4.1). |
| `broker.exchanges` | **Reconstructible** — re-created from the Broker's registry file at its next start. |
| `ramp.tenants`, `ramp.tenant_resource_owner_fee` | Reconstructible **only from your own records** — no API creates these rows (§4.2). |
| `ramp.transaction_log` | **Not reconstructible.** One row per delivered resource; the billing record. Loss is unbillable revenue. |
| `ramp.transaction_evidence` | **Not reconstructible, and the costliest.** The signed offer plus both parties' signatures — the only proof of what was agreed, and it can be checked without any service running. Losing it removes your ability to answer a billing dispute. |
| `ramp.reporting_obligations`, `ramp.audit_log`, `broker.selection_log` | Not reconstructible. Expected usage reports, and two audit trails; no functional impact, nothing reads them at runtime. |
| `sor.agent_accounts` (other database) | **Not reconstructible, and it carries money.** See below. |

**Losing `sor.agent_accounts` cuts off every agent's money.** It holds each agent's
`billing_ref`, and the `billing_ref` is the only key to that agent's balance in the
ledger. The ledger hashes the text into an account number and stores none of it, so
the ledger cannot tell you which agent an account belongs to. Lose this table and no
agent's balance can be reached: the money is still there, and nothing can get to it.

It gets worse than an unreachable balance. Once the table is gone, every paid
transaction from every registered agent is refused with `no billing account found
for this agent`, and **the agents cannot fix it by registering again** — the
Exchange sees a `billing_ref` already on their `ramp.agents` row and returns an
error instead of creating a new account.

| What you lose with it | Recoverable? |
|---|---|
| The `billing_ref` values | Only from `ramp.agents.billing_ref` in the **other** database — so only if that database survived. This is why §5 says to back up both together. |
| Which agent owns which `billing_ref` | Same — from `ramp.agents`, or not at all. |
| `active`, the on/off flag | No. You decide each one again. |
| Registration details: email, legal entity, jurisdiction, address | **No. Gone.** Only the agent has them. |

Plan your backups around `ramp.transaction_evidence` and `sor.agent_accounts`. If you
back up either of them less often than `ramp.transaction_log`, the copies disagree
after a restore and matching them up again is manual work.

### 5.3 Retention and sizing

**Nothing in the platform removes old rows.** No table is partitioned, nothing
expires rows, no scheduled job deletes anything. Partitioning is the planned way to
remove old rows, and **is not implemented yet**.

The intent recorded in the schema is that **financial records are kept for at least
13 months** — a monthly billing cycle plus a buffer — and nothing enforces it either
way: nothing deletes a row at 13 months, and nothing stops one being deleted
earlier except the append-once triggers. The schema states it outright for the
evidence table: *"NO MECHANISM FOR REMOVING THEM EXISTS TODAY […] the only statement
that removes a row is DROP TABLE."*

So the database only ever grows with traffic, forever. Two rows are written per
delivered resource — one in `ramp.transaction_log`, one in
`ramp.transaction_evidence`. The evidence row is much the bigger of the two, because
it keeps the whole signed offer twice: once as JSON you can read and query, and once
as the exact bytes the signature was made over. Nothing in this repository states a
target size or a growth rate, so **sizing has to be measured, not looked up**: read
`pg_total_relation_size` on both tables (§3.2) through your first week of production,
work out how many bytes each transaction costs you, and size the disk from that.
Alert on free disk space, not on row count.

---

## 6. Limitations

| Limitation | Where |
|---|---|
| **Nothing removes old rows.** Nothing deletes a row from any table, ever; the database only ever grows with traffic. | §5.3 |
| **No per-table retention.** The 13-month intent is recorded in the schema and enforced by nothing. Partitioning, the planned way to remove old rows, is not implemented yet. | §5.3 |
| **The append-once triggers limit every restore.** `ramp.transaction_evidence` cannot be cleared by any statement but `DROP TABLE`, so a data-only restore into a populated database is impossible. | §5.1 |
| **Nothing in the platform tunes the connection pool.** No RAMP variable sets pool size; the library defaults apply unless you override them through the DSN. | [`CONFIGURATION.md`](CONFIGURATION.md) §5 |
| **No service produces a database metric**, and a full connection pool is invisible in the logs. | §2.2, §2.3 |
| **Nothing keeps the two Exchange databases in step.** `ramp.agents.billing_ref` names a row in another database, and PostgreSQL cannot enforce that across databases. Back them up together; restore them together. | §5, §5.2 |
| **The Exchange's health check covers one of its two databases.** A `200` says nothing about the SoR database. | §2.1 |
| **There is no schema rollback.** Down migrations ship inside every image; nothing runs them, and one of them does nothing at all. | §4.4 |
| **Tenant creation has no API** — it is a SQL insert, as is every change to `allow_broker_relay` and to per-owner fee overrides. | §4.1, §4.2 |
