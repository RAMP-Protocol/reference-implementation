# RAMP TigerBeetle — Runbook

Operated by the Exchange Operator.

**Escalation.** If §3 does not resolve it, contact Postindustria over the
existing communication channel. Send the `request_id` and `billing_id` of a
failing transaction together with the matching Exchange log lines and the
ledger's own container log. Postindustria has no access to your infrastructure,
so those correlation IDs are the only way a transaction can be traced.

> This runbook assumes the ledger is already deployed. For installation,
> configuration values and deploy-time verification, see
> [`DEPLOYMENT.md`](DEPLOYMENT.md) and [`CONFIGURATION.md`](CONFIGURATION.md).

---

## 1. Overview

TigerBeetle is the **financial ledger** the Exchange settles into. It holds every
number that decides who has to be paid, and how much: each agent's prepaid
balance in `agent:{billing_ref}`, money **reserved** for a purchase in flight and
not yet confirmed, settled charges, each publisher's earned revenue in
`owner:revenue:{resource_owner_id}`, and the platform's commission in
`platform:fee`.

**`billing_ref` is the agent's account number.** The Exchange creates it — a
random UUID — when the agent registers, and stores it on the agent's row in
PostgreSQL (ADR-021). It is **not** the agent's name and cannot be worked out
from it. To act on an agent's account you must read its `billing_ref` out of the
database first (§4.1). Owner and platform accounts are different: those two ids
are calculated straight from ids you already have.

It is a **ready-made product from another company** — the only part of this
platform your team has probably never run before. Its behaviour, its command line
and its file format are decided by that company, not by Postindustria.

Only the Exchange talks to it. Agents, the Broker and the CDN never do. If it is
down, **every paid transaction is denied**; free resources, the publisher's site,
and download links already issued are unaffected.

---

## 2. Monitoring

### 2.1 Health

**Two signals cover the ledger, and one deliberately does not.** Knowing which is
which is the most important monitoring fact here.

| Signal | Covers the ledger? | Use it for |
|---|---|---|
| The container's own health check | **Yes** | Is the replica accepting connections? |
| The Exchange's `/readyz` | **Yes** | Can this Exchange serve paid transactions? |
| The Exchange's `/healthz` | **No, by design** | Is the Exchange process alive? |

**`/healthz` stays green through a ledger outage on purpose.** It reports the
Exchange's own liveness — its database — and nothing else. If it went red with the
ledger, a routine ledger restart (§4.1) would look like a dead Exchange and an
orchestrator would restart it, taking down free resources that need no ledger at
all. Use `/readyz` to decide whether to send an Exchange paid traffic, and
`/healthz` to decide whether the process needs restarting.

```bash
docker compose ps tigerbeetle
# Expect: STATUS shows "(healthy)". "(unhealthy)" means the replica is not
# accepting connections; "(health: starting)" is normal for a few seconds after
# boot, and longer on the very first boot while the data file is formatted.

curl -s -o /dev/null -w '%{http_code}\n' https://exchange.example.net/readyz
# Expect: 200. 503 means either the catalog database or the ledger is
# unreachable — the Exchange logs which.

curl -s -o /dev/null -w '%{http_code}\n' https://exchange.example.net/healthz
# Expect: 200, including while the ledger is down.
```

Two limits worth knowing. The container check is a TCP connect, so it proves the
port is open, not that the cluster answers. `/readyz` is stronger — it reads from
the cluster and so fails when the cluster is gone rather than merely unreachable —
but it gives up after **2 seconds**, so a ledger that is only very slow reads as
unavailable. Neither proves the ledger is answering *correctly*; the only complete
test of the path is one paid transaction
([`DEPLOYMENT.md`](DEPLOYMENT.md) §7 Check E).

The Exchange also checks the cluster **once at boot** and refuses to start if it
does not answer, rather than running without billing.

### 2.2 Logs

The ledger logs to stdout — `docker compose logs tigerbeetle`. The Exchange logs
structured JSON, one object per line, and that is where the billing events are.
**The boot lines naming the selected backend:**

```bash
docker compose logs exchange | grep tigerbeetle
# Expect these two lines. The Exchange emits one JSON object per line; they are
# wrapped here to fit the page.
#   {"level":"INFO","msg":"tigerbeetle connected","cluster":1,
#    "addresses":["10.0.1.7:3000"]}
#   {"level":"INFO","msg":"billing adapter: tigerbeetle","ledger":978,
#    "currency":"EUR","address":"10.0.1.7:3000","hold_timeout":"6m0s"}
```

**If those lines are absent, the Exchange is billing nothing.** An unrecognised
`RAMP_BILLING_ADAPTER` value falls back to the no-charge default with only a
warning ([`CONFIGURATION.md`](CONFIGURATION.md) §3).

**One ERROR line matters more than everything else here:**
`exchange.execute_transaction` carrying `event=billing_record_failed_best_effort`
means the transaction succeeded and the charge was never posted. See §2.3.

**Latency expectations.** Measured against a production-configured ledger — Direct
I/O enforced, ext4 on a local SSD, ledger and Exchange on the same machine, 50
calls each. If the numbers stay much higher than this, the ledger or its disk is in
trouble. A client session carries **one request at a time**, so these are
single-call times under light load, not a limit on how many requests per second the
ledger can handle.

| Call | median | p95 |
|---|---|---|
| Authorize (reserve funds) | 3.1 ms | 3.9 ms |
| Record (settle the charge) | 2.2 ms | 2.8 ms |
| Release (cancel a reservation) | 0.5 ms | 0.6 ms |
| Refund | 3.7 ms | 4.5 ms |
| GetBalance | 0.5 ms | 0.6 ms |

Enforcing Direct I/O did not move these — they match what the same calls measure
with `--development`. Durability is not costing you latency here.

### 2.3 Alerts

**These are recommendations, not configured alerts.** There is no metrics
endpoint, so these are log conditions for you to wire into whatever monitoring
you already run. **"Wake on-call" means call the engineer on duty, at any hour.**

| Signal | Severity | First action |
|---|---|---|
| **`event=billing_record_failed_best_effort` — any occurrence** | **Wake on-call** | **The transaction succeeded and the agent was under-charged.** See below. |
| Exchange exits at boot with `billing: TigerBeetle health check` | **Wake on-call** | The ledger is unreachable. The Exchange refuses to start and will not serve at all. |
| `billing denied` lines rising sharply | **Wake on-call** | Authorize is failing — every paid transaction is being refused. §3.1. |
| Ledger container reports `(unhealthy)`, or `/readyz` returns 503 (§2.1) | **Wake on-call** | All paid transactions denied. `/healthz` stays green — that is by design, not a second fault. |
| Free space on the data volume below 20% | Business hours | The data file only grows and there is no pruning. |
| `billing denied: currency mismatch` at all | Business hours | A catalog term is priced in the wrong currency. §3.1. |

#### The most important alert in this document

`event=billing_record_failed_best_effort` means the agent's money was
**reserved**, the transaction was **committed** and the agent was given its
download link, settling the reservation into a posted charge then **failed**, and
the reservation **expired by itself** — returning the money to the agent.

**The agent got the content and was not charged for it.** The transaction is
recorded as successful in PostgreSQL, so nothing else reports a problem.

The error always goes the same way — the agent pays too little, never too much —
but **nothing corrects it automatically.** The job that would find these charges
and post them again is not built (§6), so every one of these lines is money
earned and never collected. The line carries `transaction_id` and `billing_id`;
§3.2 shows how to confirm it on the ledger.

---

## 3. Troubleshooting

### 3.1 Symptom → cause → fix

| Symptom | Why | What to do |
|---|---|---|
| Ledger will not start: `failed to initialize IO: PermissionDenied` | `seccomp=unconfined` was not granted, so the runtime's default filter blocks `io_uring`. | Add it. Not fixable in configuration — [`CONFIGURATION.md`](CONFIGURATION.md) §1.1. |
| Ledger will not start: `error: SystemResources` | The `IPC_LOCK` capability was not granted, so TigerBeetle cannot lock memory. | Add it. Same section. |
| Exchange exits at boot: `billing: TigerBeetle health check: ...` | The cluster did not answer within the per-call deadline: it is down, unreachable, or **the cluster id does not match the one the data file was formatted with**. | Confirm the ledger is listening (§2.1), then compare `EXCHANGE_BILLING_TB_CLUSTER_ID` against the `--cluster` used at format time ([`DEPLOYMENT.md`](DEPLOYMENT.md) §4). |
| Exchange exits at boot: `billing: connect TigerBeetle at ...` | The address is invalid — most often **a hostname instead of an IP**. The client rejects hostnames. | Use `IP:port`. |
| **`event=billing_record_failed_best_effort` in the Exchange log** | **The transaction committed but the charge never posted. The agent got the content free.** | §2.3, then §3.2 to confirm on the ledger. There is no automatic recovery. |
| Every paid transaction denied, `/healthz` still green | The ledger is down. `/healthz` does not check it (§2.1). | Restart the ledger (§4.1). Free resources keep working throughout, which makes this easy to misread as a catalog problem. |
| `billing denied: currency mismatch` | The catalog term's currency differs from the deployment's single ledger currency. | Fix the term's price currency. One deployment, one currency — [`CONFIGURATION.md`](CONFIGURATION.md) §4. |
| `billing denied: insufficient balance` | The agent **has** an account, and it is empty — never funded, or the balance is spent. An agent cannot spend more than it has. | Fund it — §4.1. A newly registered agent always starts at zero. |
| `agent is not registered for paid content: call Register first` | The agent **has no account**: it never called `Register`, so no `billing_ref` was ever created for it and there is nothing to charge. The Exchange refuses this before the ledger is consulted at all, so nothing reaches TigerBeetle. | The agent must call `Register` — you cannot fix this from the ledger side, and funding anything now credits an account no transaction will touch. Confirm with the query in §4.1: `billing_ref` is NULL for that agent. Free content is unaffected; only paid purchases are refused. |
| Transaction denied, log names a resource owner the publisher's manifest never named (never "attested") | The catalog row has no `resource_owner_id`, so there is nobody to pay. Refused rather than paid into a shared account. | Fill in the missing owner — §4.3. |
| Ledger will not start after a config change: format error | `format` refuses to run against an existing data file, and the cluster/replica values written into the file at format time cannot be changed. | Do not re-format. Changing them means a new, empty ledger. Escalate. |

### 3.2 Diagnostics

**Calculate an account id.** Account ids are `sha256(prefix + business id)`,
truncated to the low 16 bytes and read little-endian. In production nothing extra
is added to the input (the hashing is **unsalted**), so this calculator gives the
real ids. Put your own ids in, and note the prefix for the one who gets paid is
`owner:`, not `publisher:`.

**For an agent, the business id is its `billing_ref`, not its name.** Read the
`billing_ref` from PostgreSQL first (§4.1) and paste it in below. Owner and
platform ids need no lookup.

```bash
python3 - <<'PY'
import hashlib
def account_id(s):
    return int.from_bytes(hashlib.sha256(s.encode()).digest()[:16], "little")
print("agent          ", account_id("agent:7c9e6679-7425-40de-944b-e07fc1f90ae7"))
print("owner revenue  ", account_id("owner:revenue:acme"))
print("platform fee   ", account_id("platform:fee"))
PY
# Expect:
#   agent           160256804321604199934357490248810311770
#   owner revenue   253662641582529055044389689734124561153
#   platform fee    3790524022861224602083356447743275029
```

**Read the account.** `repl` is TigerBeetle's own interactive command line — you
type ledger statements into it and it answers.

Open it:

```bash
docker compose exec tigerbeetle /tigerbeetle repl \
  --cluster=1 --addresses=127.0.0.1:3000
# Expect: "TigerBeetle CLI Client 0.17.8" and a "> " prompt.
```

Then type this **at that prompt** — it is a ledger statement, not a shell command,
and the trailing semicolon is required:

```
lookup_accounts id=160256804321604199934357490248810311770;
```

You get back one account record. The three fields worth reading are
`debits_posted`, `credits_posted` and `debits_pending`; what each means is
explained below. Press Ctrl+D to leave.

> **`repl` needs a real terminal.** It draws its own prompt, so it cannot be fed
> from a pipe or a script — `echo '...' | tigerbeetle repl` answers
> `ANSI escape sequences not supported.` and does nothing at all, without reporting
> an error. Run it interactively, or use `docker compose exec` (not `exec -T`).
> There is no batch mode, so none of the diagnostics here can be automated.

Nothing returned means the account does not exist, and what that tells you
depends on which class of account you looked up:

| Account | Nothing returned means |
|---|---|
| Agent, id derived from a stored `billing_ref` | **A fault.** Registration creates the account, so a stored `billing_ref` must have one. Check you pasted the `billing_ref` in exactly, then escalate. |
| Owner revenue, `platform:fee` | Normal before the first settlement — those two are created on first use. |

**How to read the numbers.** `credits_posted` is settled money in,
`debits_posted` settled money out, and `debits_pending` is money **reserved** for
purchases in flight — not yet spent.

> **Settled balance = `credits_posted` − `debits_posted`.** Pending amounts are
> excluded — a live reservation is not yet a charge.

**Amounts are integers at 10⁻⁸ of the currency unit.** `€1.00` reads as
`100000000`. Divide by 100,000,000, not by 100
([`CONFIGURATION.md`](CONFIGURATION.md) §5).

**What one settled charge looks like.** The agent's `debits_posted` rises by the
full price; the owner-revenue account's `credits_posted` rises by the net; and
`platform:fee`'s rises by the commission. The two credits sum to the debit — the
revenue split of ADR-010. At the default commission rate of zero there is no
`platform:fee` leg at all and the whole amount credits the owner.

**Detect a committed transaction with no matching charge** — the check for the
under-charge in §2.3. The `billing_id` recorded against a transaction is the
32-character hex id of its reservation, and the settlement's own transfer id is
derived from it, so you can ask the ledger whether the charge landed:

```bash
psql "$EXCHANGE_DSN" -c \
  "SELECT transaction_id, billing_id, unit_cost, created_at
     FROM ramp.transaction_log
    WHERE billing_id IS NOT NULL AND created_at > now() - interval '1 day'"
# Expect: one row per transaction that reserved funds.
```

```bash
python3 - <<'PY'
import hashlib
BILLING_ID = "9f2c4d1ea7b3085c6d40f1329ab7de10"   # from the query above
low16 = lambda b: int.from_bytes(hashlib.sha256(b).digest()[:16], "little")
print("reservation ", int.from_bytes(bytes.fromhex(BILLING_ID), "little"))
print("settlement  ", low16(("post:" + BILLING_ID).encode()))
print("cancellation", low16(("void:" + BILLING_ID).encode()))
PY
# Expect:
#   reservation  22424061733013787014766389642956450975
#   settlement   75084889087094951755629154175200726280
#   cancellation 177718281729006885974919074814351343587
```

```
> lookup_transfers id=75084889087094951755629154175200726280;
# Expect: one transfer record — the charge posted, all is well.
# NOTHING returned means the charge never posted: the transaction succeeded and
# the agent was not charged. That is the under-charge from §2.3.
```

**Nothing does this automatically** across all transactions (§6); run it against
the `billing_id` values from the alert lines.

### 3.3 Gotchas

- **The host capabilities are needed on both containers** — `seccomp=unconfined`
  and `IPC_LOCK` on the ledger *and* on the Exchange, which embeds the TigerBeetle
  client and uses `io_uring` too.
- **There is no managed TigerBeetle service anywhere.** No cloud provider offers
  one; patching, capacity, monitoring and backup are entirely yours.
- **A single replica means no spare copy** — one process, one file, nothing to
  fail over to. Losing the file loses the ledger.
- **The Exchange is amd64 only** — the TigerBeetle client links a native library
  through CGO, which cannot build for a different processor type.
- **Currency is deployment-wide** — one ledger, one currency, fixed at boot.
- **The client port has no authentication and no TLS.** Anything that can reach
  it can move money. Keep it private.
- **`/healthz` tells you nothing about the ledger, deliberately** — `/readyz` is the
  one that does (§2.1).

---

## 4. Procedures

### 4.1 Routine operations

**The production command line.** Both commands run **without `--development`** —
that flag turns off Direct I/O, and a host crash can then lose transactions the
ledger already reported as committed
([`CONFIGURATION.md`](CONFIGURATION.md) §6). Format once — the file test is not
optional, because `format` errors out against an already-formatted file and would
fail on every restart — then start:

```bash
[ -f /var/lib/tigerbeetle/0_0.tigerbeetle ] || tigerbeetle format \
    --cluster=1 --replica=0 --replica-count=1 /var/lib/tigerbeetle/0_0.tigerbeetle
# Expect on the first run:
#   info(io): allocating 1.06298828125GiB...
#   info(main): 0: formatted: cluster=1 replica_count=1
# On a second run it prints nothing and still exits 0.

# --cache-grid: total RAM - 3GiB (TigerBeetle) - 1GiB (system).
tigerbeetle start --addresses=0.0.0.0:3000 --cache-grid=12GiB \
    /var/lib/tigerbeetle/0_0.tigerbeetle
# Expect:
#   info(main): 0: Allocated 2574MiB during replica init
#   info(main): 0: Grid cache: 512MiB, LSM-tree manifests: 128MiB
#   info(main): 0: cluster=1: listening on 0.0.0.0:3000
# (those two figures are from a 512MiB cache; yours scale with the value above)
```

**The three account classes.** Every account is one of these; there are no
others.

| Class | Account name | Created | Rule |
|---|---|---|---|
| Agent | `agent:{billing_ref}` | When the agent registers. | Limited — an agent can never spend more than it has been given. |
| Resource-owner revenue | `owner:revenue:{resource_owner_id}` | On first use — when a purchase from that owner is first authorised. | Accrues credits. |
| Platform fee | `platform:fee` | On first use — the first non-zero commission. | One account for the whole deployment. |
| Operator liquidity | `platform:liquidity` | On first credit — by a funding script or the Register default credit. | Unlimited — goes negative by the total credit extended. |

**Funding an agent account.** Adding money is done outside the platform on
purpose. Per ADR-009 D2, an operator invoices the agent however they normally
would, then adds the matching credit into the ledger by hand. One narrow
exception exists (the ADR-009 amendment of 2026-08-13): a tenant with
`default_agent_credit` above 0 grants that amount automatically, once, when an
agent first registers — under the `service-welcome:{billing_ref}` transfer id,
the same slot the funding scripts' reserved `service-welcome` label uses, so
the two can never stack. With
the setting at its default of 0 a freshly deployed stack starts with an empty
ledger, and the first paid transaction is denied until you fund it.

**Step 1 — read the agent's `billing_ref` from PostgreSQL.** You cannot calculate
it and you cannot guess it. Everything below depends on this value:

```bash
psql "$EXCHANGE_DSN" -c \
  "SELECT agent_id, billing_ref FROM ramp.agents WHERE agent_id = 'acme-agent'"
# Expect: one row, billing_ref holding a UUID such as
#         7c9e6679-7425-40de-944b-e07fc1f90ae7.
#         A blank column is NULL — read the warning below before going further.
```

> **A NULL `billing_ref` means the agent never registered.** It has no ledger
> account, and every purchase it attempts is denied `billing denied: billing ref
> required` — not `insufficient balance`. **Stop here.** Money credited now goes
> into an account nothing will ever debit: the agent's real balance stays zero,
> its purchases keep failing, and the funds sit in the ledger looking correct. The
> agent must call `Register` first; then repeat the query and carry on.

**Step 2 — post the credit.** TigerBeetle records every movement twice — once as
money leaving one account, once as money arriving in another — so money cannot
appear from nowhere. You need a source account to move it from.

The platform's source account is `platform:liquidity`. Its id, and the agent's, come
from the calculator in §3.2:

```bash
python3 - <<'PY'
import hashlib
def account_id(s):
    return int.from_bytes(hashlib.sha256(s.encode()).digest()[:16], "little")
print("liquidity", account_id("platform:liquidity"))
print("agent    ", account_id("agent:7c9e6679-7425-40de-944b-e07fc1f90ae7"))
PY
# Expect (the liquidity id is the same in every deployment; the agent's is not):
#   liquidity 336127876051426545196802061685315751094
#   agent     160256804321604199934357490248810311770
```

Open `repl` (§3.2) and type these **at its prompt**, substituting your own agent id
and amount. Each statement ends in a semicolon.

**1. Create the funding source**, once per deployment. It starts at zero and goes
negative by whatever it hands out — that is correct for a source, so it gets **no**
spending limit. `code=3` marks it a platform account.

```
create_accounts id=336127876051426545196802061685315751094 code=3 ledger=978 flags=history;
```

**2. Make sure the agent's account exists.** Registration already created it, so
**`exists` is the answer you want** — it confirms you have the right id. If this
instead creates a new account, the `billing_ref` you pasted is wrong: stop and
recheck Step 1 before moving any money.

```
create_accounts id=160256804321604199934357490248810311770 code=1 ledger=978 flags=debits_must_not_exceed_credits;
```

**3. Post the credit.** Amounts are in units of 10⁻⁸ of the currency, so **€10.00 is
`1000000000`**. The transfer id must be unique and is yours to choose — derive it
from something that names this top-up, so a retry cannot double-credit:

```
create_transfers id=<unique id> debit_account_id=336127876051426545196802061685315751094 credit_account_id=160256804321604199934357490248810311770 amount=1000000000 ledger=978 code=1;
```

Derive that id the same way as an account id, from a string naming the top-up:

```bash
python3 - <<'PY'
import hashlib
print(int.from_bytes(hashlib.sha256(
    b"fund:7c9e6679-7425-40de-944b-e07fc1f90ae7:1000000000:2026-07-invoice"
).digest()[:16], "little"))
PY
# Expect: one number. Re-running it gives the same number, which is the point —
# TigerBeetle rejects a duplicate transfer id, so a repeated top-up cannot
# double-credit the agent.
```

**4. Confirm.**

```
lookup_accounts id=160256804321604199934357490248810311770;
```

`credits_posted` has risen by the amount. That number, minus `debits_posted`, is
what the agent can now spend.

> **The spending limit is set once and cannot be changed.** An agent account
> created without `debits_must_not_exceed_credits` can spend more money than it
> has, without limit, and the only fix is a new account. Copy the flags above
> exactly.

Calculate both account ids with the calculator in §3.2 — the agent's from
`agent:{billing_ref}` — and build the transfer id from something stable that
names the top-up, for example `sha256("fund:{billing_ref}:{amount}:{label}")`.
Keying it on the `billing_ref` keeps the audit trail on the same value the account
itself is keyed on. TigerBeetle rejects a duplicate transfer id, so a derived id
makes the whole procedure safe to re-run: running it twice does not double the
balance. Change the label when you genuinely want to add more money.

**Restart.** Stop and start the container; the data file is untouched and nothing
is lost. It costs you: every paid transaction is denied while it is down. Links
already issued keep working and free resources are unaffected. There is no way to
let work in progress finish first, and no queue, so pick a quiet time.

While it is down the container reports `(unhealthy)` and the Exchange's `/readyz`
returns 503, so a load balancer stops sending it paid traffic and resumes on its
own once the ledger is back. **The Exchange's `/healthz` stays green throughout**
(§2.1) — a ledger restart is not a reason to restart the Exchange, and the two
probes are split precisely so this stays true.

### 4.2 Account and funding procedures

**Reading a publisher's earned revenue.** Calculate the account id for
`owner:revenue:{resource_owner_id}` (§3.2) and look it up; `credits_posted` is
the total earned before the platform's commission, at 10⁻⁸ per currency unit.
**There is no revenue-report RPC** (§6), so looking the account up in the
interactive command line is the only way to read it. The same applies to the
platform's commission in `platform:fee` — if that account does not exist, no
transaction has ever carried a non-zero commission.

**Changing a commission rate** is an Exchange procedure, not a ledger one — the
rate lives in the Exchange's database and is saved into each reservation when it
is taken and never changed after, so a change does not alter reservations already
in flight. See [`src/exchange/RUNBOOK.md`](../../../src/exchange/RUNBOOK.md).

**Reversing a charge** is not available. The ledger supports a proportional
refund, but **no part of the platform calls it** — there is no dispute RPC and no
operator procedure (§6).

### 4.3 Upgrade

**Keep the version pinned.** The image is `ghcr.io/tigerbeetle/tigerbeetle:0.17.8`
— an exact tag, never `latest`. Both containers must agree: the Exchange embeds a
TigerBeetle client of a matching version, so upgrading the ledger alone is not
safe.

**Whether a new version can read the existing data file is decided by the company
that makes TigerBeetle, not by Postindustria.** Before changing the pin, read
their release notes for that version range and confirm the existing data file is
readable by the new binary. **Take a backup first** (§5.1) and verify it opens
(§5.2) — that is your only way back if the new binary refuses the file.

**Moving a cluster off `--development` is supported; moving it on is not.**
`--development` shrinks the internal batch size as well as relaxing Direct I/O.
TigerBeetle's own documentation states that the batch size can always be
*increased* by restarting without the flag, but that shrinking an existing
cluster's batch size is possible and **not** recommended. So a cluster that was
formatted in development mode can be promoted by restarting it without the flag —
provided its data file now sits on a filesystem that supports Direct I/O (§3.1 of
[`DEPLOYMENT.md`](DEPLOYMENT.md)). Going the other way is a one-way door you should
not walk through.

**`tigerbeetle recover` is not a repair tool for you.** It rebuilds one replica's
data file by syncing from the *other* replicas. On a single-replica cluster there is
nothing to sync from, so it cannot help — restore from a backup instead (§5.3).

**Before enabling settlement on a database that already holds catalog rows — fill
in the missing owners first.** Each catalog entry carries the `resource_owner_id`
its revenue is paid to. Entries pushed **after** that column was introduced are
guaranteed to have one; rows that are older carry an empty value. An empty owner
is **refused with a clear error** at settlement — the transaction is denied rather
than paid into a shared, wrong account. So an older row does not pay the wrong
person; it **cannot sell at all** until its owner is filled in.

Do this before you enable settlement — re-push the affected manifests, or set the
owner on the catalog row directly — then check none remain:

```bash
psql "$EXCHANGE_DSN" -c \
  "SELECT uri FROM ramp.catalog WHERE resource_owner_id = ''"
# Expect: zero rows before settlement is enabled.
```

**This changes nothing on a new deployment** — migrations run before any catalog
push, so no empty-owner row is ever created. It matters only when settlement is
switched on against a database already holding catalog rows.

---

## 5. Backup and recovery

**TigerBeetle has no backup or restore command.** No snapshot, no point-in-time
recovery, no export. The whole procedure is: stop the cluster, copy the one data
file, keep the copy somewhere else.

`tigerbeetle recover` exists and does **not** help you here. It rebuilds one
replica's file by syncing from the other replicas in the cluster. With a single
replica there is nothing to sync from, so the file copy below is the only path.

### 5.1 Taking a backup

**Stop the cluster first.** Copying the file while the ledger is running is not a
supported backup: nothing in TigerBeetle guarantees that a copy taken mid-write is
consistent, and a backup you cannot trust is worse than none. The copy itself takes
about a second (§5.4), so the stop is short.

```bash
docker compose stop tigerbeetle
# Expect: "Container tigerbeetle  Stopped"

cp /var/lib/tigerbeetle/0_0.tigerbeetle \
   /backups/tigerbeetle/0_0.tigerbeetle.$(date -u +%Y%m%dT%H%M%SZ)

docker compose start tigerbeetle
# Expect: "Container tigerbeetle  Started"
```

Keep the copy on different hardware. A backup on the same disk protects you
against nothing that is likely to happen.

### 5.2 Verifying a backup

A copy you have never opened is not a backup. Check both of these — the first is
cheap enough to run every time, the second is the one that actually proves it.

**Byte-for-byte identical:**

```bash
sha256sum /var/lib/tigerbeetle/0_0.tigerbeetle /backups/tigerbeetle/0_0.tigerbeetle.<stamp>
# Expect: the same digest twice, e.g.
# 02d287762b72c72c6fbe580522bff13539e505709126466a881dcf9b73f9c3a9  ...
# 02d287762b72c72c6fbe580522bff13539e505709126466a881dcf9b73f9c3a9  ...
```

**It opens.** Copy the backup into a scratch directory and start a ledger on it,
on a spare port so it cannot be mistaken for the live one:

```bash
docker run --rm --security-opt seccomp=unconfined --cap-add IPC_LOCK \
  -v /tmp/restore-check:/data -p 13001:3000 \
  ghcr.io/tigerbeetle/tigerbeetle:0.17.8 \
  start --addresses=0.0.0.0:3000 --cache-grid=512MiB /data/0_0.tigerbeetle
# Expect, within a second or two:
#   info(replica): superblock release=0.17.8
#   info(main): 0: Allocated 2574MiB during replica init
#   info(main): 0: Grid cache: 512MiB, LSM-tree manifests: 128MiB
#   info(main): 0: cluster=1: listening on 0.0.0.0:3000
```

Then look up one account you know the balance of (§3.2) and confirm it matches.
Stop the scratch ledger afterwards.

Do this on a schedule, not once. The failure you are protecting against is a
backup that has been silently broken for months.

### 5.3 Restoring

```bash
docker compose stop tigerbeetle
mv /var/lib/tigerbeetle/0_0.tigerbeetle /var/lib/tigerbeetle/0_0.tigerbeetle.damaged
cp /backups/tigerbeetle/0_0.tigerbeetle.<stamp> /var/lib/tigerbeetle/0_0.tigerbeetle
docker compose start tigerbeetle
# Expect: the four lines from §5.2, then LEDGER-LISTENING on the checks in §2.1
```

**Do not delete the damaged file.** Move it aside. If the restore turns out to be
older than you thought, it is the only other copy of anything that happened since.

**Everything after the backup's timestamp is gone.** The Exchange's PostgreSQL
transaction log still has those transactions, so you can see what was lost — but
nothing replays them into the ledger, so balances and publisher revenue will be
short by exactly that window. Reconcile by hand against `ramp.transaction_log`.

### 5.4 How long it takes, and how much you can lose

Measured on a 1.16 GB data file, ext4 on a local SSD:

| Step | Measured |
|---|---|
| Copy the file | **0.5 s** with the file in the host's page cache |
| `sha256sum` one copy | about 5 s |
| Start a ledger on the copy | 1–2 s |

The copy time is page-cache-warm and therefore optimistic. Budget your disk's
sequential read speed instead: at 200 MB/s a 1.1 GB file is about 6 seconds. Either
way the stop-copy-start cycle is **seconds, not minutes**, which is what makes a
frequent backup practical.

**Recovery time** is that copy plus a restart — call it under a minute of machine
time. The real recovery time is however long it takes someone to notice and decide,
because nothing alerts on ledger corruption.

**How much you can lose is your choice, and it is the interval between backups.**
Nothing here is incremental: every transaction since the last copy is gone. Since a
backup costs a few seconds of downtime, hourly is affordable; pick the interval by
asking how much revenue an hour of transactions represents.

### 5.5 What losing it costs

| Lost | Consequence |
|---|---|
| The data file, no backup | **Every balance, every settled charge and every publisher's revenue.** Nothing else holds them. PostgreSQL knows which transactions happened, not who was charged what. |
| The data file, backup in hand | The window since that backup, as above. |
| A backup copy leaks | Balances and transaction volumes disclosed. No keys, no personal data — it is a ledger. |

The Exchange's PostgreSQL database is a **partial** cross-check, not a second copy:
it records that a transaction happened and for how much, so it can tell you the
shape of what was lost. It cannot rebuild the ledger, because the ledger is the only
place the money actually moved.

---

## 6. Limitations

- **A failed settlement is never posted again.** The job that would find
  committed transactions whose charge never landed is not built, so every
  `event=billing_record_failed_best_effort` line is an under-charge that stays
  uncollected unless someone acts on it (§2.3).
- **There is no revenue-report RPC.** Publisher earnings and the platform
  commission can only be read by looking the accounts up in the interactive
  command line (§4.2).
- **Reversing a charge is not available.** The proportional refund exists in the
  ledger but no part of the platform ever calls it — no dispute RPC, no operator
  procedure.
- **No end-to-end test stack exercises the ledger.** That suite runs against the
  in-memory billing backend, so the ledger's only automated coverage is the
  integration suite.
- **A single replica has no failover** — one process, one file. Recovery means
  restoring a backup (§5.3), which costs downtime plus every transaction since that
  backup was taken.
- **Multiple currencies are not implemented yet.**
- **Health coverage stops at "is it listening".** The container check is a TCP
  connect and `/readyz` is a single round-trip; neither tells you the ledger is
  answering *correctly*, only that it answers (§2.1).
