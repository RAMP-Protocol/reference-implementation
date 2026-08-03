# RAMP Storage — overview

The platform uses four stores. They have almost nothing in common operationally, so
each one has its own set of three documents rather than a shared chapter. This page
tells you which is which, and which you actually need.

Audience: the DevOps engineer deploying the platform. Words that may be new are
explained the first time they appear.

---

## The four stores

| Store | What it holds | Required? | Durable? | Operated by |
|---|---|---|---|---|
| **[PostgreSQL](postgres/)** | The catalog of licensed content, the transaction log, the audit log, the agent account registry, and the Broker's Exchange registry. | **Yes** — neither service starts without it. The Exchange needs **two** databases, not one. | **Yes.** This is the system of record. | You, on infrastructure you already run. |
| **[Redis](redis/)** | Replay protection for signed requests — nothing else that matters. | Strongly recommended. Mandatory above one replica of either service. | **No.** Everything in it expires in five minutes and is reconstructible by definition. | You. A managed Redis with no persistence is a fine fit. |
| **[TigerBeetle](tigerbeetle/)** | The financial ledger: agent balances, pending reservations, settled charges, publisher revenue, the platform fee. | Only when you want per-article accounting. Without it the Exchange runs on a free adapter that approves everything. | **Yes**, and it has no backup command. | You, on a machine you administer. There is no managed TigerBeetle service anywhere. |
| **[Vault](vault/)** | Every agent's **private key**, one secret per key. | Only when you run the Identity Service — which nothing else needs. It has no alternative backend. | **Yes**, and there is no second copy of what it holds. | You. A managed Vault is a fine fit. |

Each store has three documents, in the same shape as every other component:

| | What it answers |
|---|---|
| `CONFIGURATION.md` | Every setting, what it does, and what happens if you leave it out |
| `DEPLOYMENT.md` | The ordered procedure to get it running and verify it |
| `RUNBOOK.md` | It is live and something happened — now what |

One file here is not documentation: `postgres/10-create-exchange-dbs.sql` creates the
databases the automated test stack needs, which runs three Exchanges at once. **Do
not run it against a deployment** — [`postgres/CONFIGURATION.md`](postgres/CONFIGURATION.md)
§3 lists the databases a real deployment does need.

---

## Read this before you plan anything

Four facts decide how much work each store is, and they are not obvious:

- **PostgreSQL is infrastructure you already run.** Its documents are operating
  guidance for a database you own, not an install story. The one genuinely
  non-obvious constraint is that `ramp.transaction_evidence` refuses `UPDATE`,
  `DELETE` and `TRUNCATE` at the trigger level, which changes how a restore has to
  be performed. See [`postgres/RUNBOOK.md`](postgres/RUNBOOK.md) §5.

- **Redis needs no backup, and the development compose file disagrees.** That file
  enables persistence and mounts a volume, implying a durability obligation that
  does not exist. An empty replay store is a *safe* starting state. See
  [`redis/RUNBOOK.md`](redis/RUNBOOK.md) §5.

- **TigerBeetle can veto your platform.** It requires `IPC_LOCK`,
  `seccomp=unconfined` and `io_uring` (Linux ≥ 5.6) — on the ledger container **and**
  on the Exchange container. If your platform forbids those, the ledger cannot run
  there at all, and there is no managed alternative to fall back on. Check this
  before anything else: [`tigerbeetle/CONFIGURATION.md`](tigerbeetle/CONFIGURATION.md) §1.

- **Vault is the one store whose loss cannot be undone.** It holds agents' private
  keys, nothing else has a copy, and a read of it is as damaging as a write — whoever
  can read it can act as any agent in it. Its backups need the same protection as the
  live system. See [`vault/CONFIGURATION.md`](vault/CONFIGURATION.md) §1.

The Identity Service also needs a **second PostgreSQL database** of its own, alongside
the Exchange's two. It is covered in [`postgres/CONFIGURATION.md`](postgres/CONFIGURATION.md) §3
with the rest of the layout.

---

## What is not covered here

Nothing in these documents is a health signal for the services themselves.
**`/healthz` on the Exchange and the Broker pings one PostgreSQL database and nothing
else** — it stays green with the cache dead, the ledger dead, and the Exchange's
second database dead, while every paid transaction fails. The Identity Service's
`/healthz` is the same shape, and stays green with **Vault** dead. The services' own
runbooks explain what to watch instead:

- [`../../src/exchange/RUNBOOK.md`](../../src/exchange/RUNBOOK.md)
- [`../../src/broker/RUNBOOK.md`](../../src/broker/RUNBOOK.md)
- [`../../src/identity/RUNBOOK.md`](../../src/identity/RUNBOOK.md)
