# RAMP TigerBeetle — Deployment Instructions

This document tells you, the DevOps engineer deploying the ledger, everything you
need to stand TigerBeetle up on your own infrastructure. You do not need to read
the source code. Follow the steps in order. Words that may be new are explained
the first time they appear.

Every setting mentioned here is described in full in
[`CONFIGURATION.md`](CONFIGURATION.md). Once the ledger is running, day-to-day
operation is in [`RUNBOOK.md`](RUNBOOK.md).

---

## 1. What TigerBeetle is, and where it sits

TigerBeetle is the **financial ledger** the Exchange settles into. It is a
ready-made product from another company — the only part of this platform that is
new to your set of tools, and the only one nobody on your team has run before.

It holds:

- each AI agent's **prepaid balance**;
- **reservations** — money set aside the moment a purchase is authorised, before
  it is confirmed;
- **settled charges** — money that has actually moved;
- each publisher's **earned revenue**, and the **platform's commission**.

```
Agent ──► Broker ──► Exchange ──► (signed link) ──► CDN ──► Origin
                        │
                        └──► TigerBeetle   (reserve · settle · release)
```

Only the Exchange talks to it. Agents never do, the Broker never does, the CDN
never does.

> **Check §2 before you plan anything else.** TigerBeetle needs three things from
> the machine and the container runtime that run it — a new enough Linux kernel,
> permission to use `io_uring`, and permission to lock memory — and some
> platforms will not give them. There is no managed TigerBeetle service anywhere
> to fall back on. If your platform cannot grant them, TigerBeetle cannot run
> there. See [`CONFIGURATION.md`](CONFIGURATION.md) §1.

---

## 2. Step 1 — prove the host can run it

Three checks. Run all three before you set anything up.

**Check A — the kernel is new enough for `io_uring`.** `io_uring` is the Linux
interface for disk and network work that runs in the background; TigerBeetle does
all of its work through it, and it exists only on kernel 5.6 or newer.

```bash
uname -r
# Expect: 5.6 or higher, e.g. 6.8.0-134-generic

sysctl kernel.io_uring_disabled
# Expect: kernel.io_uring_disabled = 0   (1 also works)
# 2 disables io_uring for the whole machine. No container setting overrides it,
# so stop here and ask the host owner — see `CONFIGURATION.md` §1.1.
```

**Check B — the container runtime will grant the capabilities.** This runs the
real image with the real flags and formats a throwaway file inside the container,
which `--rm` discards when it exits — nothing is left on your disk. It is the only
check that really proves the runtime allows what TigerBeetle needs.

```bash
docker run --rm --security-opt seccomp=unconfined --cap-add IPC_LOCK \
  ghcr.io/tigerbeetle/tigerbeetle:0.17.8 \
  format --cluster=0 --replica=0 --replica-count=1 --development \
  /tmp/probe.tigerbeetle && echo CAPABILITIES-OK
# Expect: CAPABILITIES-OK on the last line, and neither "PermissionDenied" nor
#         "SystemResources" anywhere in the output.
```

`--development` is used **here only**, because this check is about the runtime's
capabilities, not about the disk — the container's own `/tmp` cannot do Direct
I/O. In production you remove the flag (§5).

If it fails, read the message against
[`CONFIGURATION.md`](CONFIGURATION.md) §1.1: `failed to initialize IO:
PermissionDenied` means `seccomp=unconfined` was not honoured, `error:
SystemResources` means `IPC_LOCK` was not. **Neither is fixable in
configuration.** Either the platform grants them or you deploy elsewhere.

If you want, you can see the error this protects you from — the same command
without the two flags:

```bash
docker run --rm ghcr.io/tigerbeetle/tigerbeetle:0.17.8 \
  format --cluster=0 --replica=0 --replica-count=1 --development \
  /tmp/probe.tigerbeetle
# Expect on Docker 25 or newer, and a non-zero exit status:
#   error(io): io_uring is not available
#   error(io): likely cause: the syscall is disabled by sysctl, try 'sysctl -w kernel.io_uring_disabled=0'
#   error: PermissionDenied
```

Note the message blames the sysctl even when the real cause is the container
filter, as it is here — Check A already ruled the sysctl out. If Check A showed
`kernel.io_uring_disabled = 0` and this still fails, it is the runtime's filter,
which is exactly what Check B's two flags remove.

On a runtime that does **not** filter `io_uring`, this command succeeds instead.
Keep the flags regardless: a runtime upgrade will start filtering it.

**Check C — the same capabilities on the Exchange host.** The Exchange embeds the
TigerBeetle client, which uses `io_uring` too. If the Exchange runs on a
different host or a different platform tier, run Check B there as well. Its
container needs the same `seccomp=unconfined` and `IPC_LOCK`.

Note also that the Exchange image is **amd64 only** — the TigerBeetle client
links a native library through CGO, which cannot build for a different processor
type. There is no ARM build.

---

## 3. Step 2 — set up storage that supports Direct I/O

The ledger is **one file on one disk**. That file must live on a filesystem that
supports `O_DIRECT` — the mode that skips the operating system's page cache so a
confirmed write is genuinely on the device. Without it, a host crash can lose
transactions the ledger already reported as committed
([`CONFIGURATION.md`](CONFIGURATION.md) §6).

Set up a **real block device** with **ext4 or xfs**, and mount it at the path you
will bind into the container:

```bash
findmnt -no FSTYPE --target /var/lib/tigerbeetle
# Expect: ext4  (or xfs)
# "overlay" means you are on a container layer, not a real disk — wrong.
```

Then prove `O_DIRECT` actually works there, rather than trusting the filesystem
name:

```bash
dd if=/dev/zero of=/var/lib/tigerbeetle/.odirect-probe bs=4096 count=1 oflag=direct
# Expect:
#   1+0 records in
#   1+0 records out
# "dd: failed to open ...: Invalid argument" means the filesystem cannot do
# O_DIRECT. Do not proceed — see CONFIGURATION.md §6.

rm /var/lib/tigerbeetle/.odirect-probe
```

Do **not** put the data file on a Docker overlay filesystem, a Docker bind mount
of a developer machine, or a network filesystem. Those are exactly the cases
`--development` exists to work around, and working around them costs you the
guarantee that saved data survives a crash.

Size the volume for growth. TigerBeetle reserves its disk space in advance and the
file only ever grows — there is no pruning and no compaction that gives space back.

| Measured | |
|---|---|
| A freshly formatted data file | **1,141,374,976 bytes — 1.06 GiB**, allocated immediately at `format` |
| Is it sparse? | **No.** The file consumes its full size on disk from the moment it is created. |

So the volume needs a little over 1 GiB before a single transaction is recorded.
Growth beyond that is driven by transaction volume; give it room well beyond your
projected first year and monitor free space ([`RUNBOOK.md`](RUNBOOK.md) §2.3), since
a full disk fails every write and nothing reclaims space.

---

## 4. Step 3 — format the data file, once

`format` creates the ledger. It is a **one-time** operation: run against a file
that already exists, it errors out. That is why the command below tests for the
file first — a container that restarts against a persistent volume must not try
to format again.

```bash
docker run --rm \
  --security-opt seccomp=unconfined --cap-add IPC_LOCK \
  -v /var/lib/tigerbeetle:/data \
  ghcr.io/tigerbeetle/tigerbeetle:0.17.8 \
  sh -c '[ -f /data/0_0.tigerbeetle ] || /tigerbeetle format \
      --cluster=1 --replica=0 --replica-count=1 /data/0_0.tigerbeetle'
# Expect, on the first run:
#   info(io): creating "0_0.tigerbeetle"...
#   info(io): allocating 1.06298828125GiB...
#   info(main): 0: formatted: cluster=1 replica_count=1
# On a second run it prints nothing and still exits 0.

ls -l /var/lib/tigerbeetle/0_0.tigerbeetle
# Expect: 1141374976 bytes, owned by root, mode 0600.
```

Note what is **absent** from that command line compared with the development
compose file: **`--development` is gone.** This is the production format, which
requires the `O_DIRECT` support you proved in §3.

Three values are written into the file at this moment and cannot be changed
afterwards — changing any of them means formatting a new file and losing the
ledger's contents:

| Fixed when you format | Value used here | Must match |
|---|---|---|
| `--cluster` | `1` | the Exchange's `EXCHANGE_BILLING_TB_CLUSTER_ID` |
| `--replica` | `0` | — |
| `--replica-count` | `1` | — |

---

## 5. Step 4 — start the cluster

The production command line, with `--development` dropped from `start` as well:

```yaml
services:
  tigerbeetle:
    image: ghcr.io/tigerbeetle/tigerbeetle:0.17.8
    restart: unless-stopped
    entrypoint: ["/tigerbeetle"]
    command:
      - start
      - --addresses=0.0.0.0:3000
      - --cache-grid=12GiB          # total RAM − 3GiB − 1GiB; see below
      - /data/0_0.tigerbeetle
    security_opt:
      - "seccomp=unconfined"
    cap_add:
      - "IPC_LOCK"
    volumes:
      - /var/lib/tigerbeetle:/data
    # The image is busybox-based, so `nc` is available for a TCP probe. This is
    # what lets the Exchange wait for the ledger (§6) instead of crash-looping
    # until it appears. First boot stays "starting" for longer than a restart,
    # because the data file is formatted before the port opens.
    healthcheck:
      test: ["CMD", "nc", "-z", "127.0.0.1", "3000"]
      interval: 5s
      timeout: 3s
      retries: 5
```

```bash
docker compose up -d tigerbeetle
# Expect: "Container tigerbeetle  Started"

docker compose logs tigerbeetle | tail -5
# Expect (the two memory figures scale with your --cache-grid; these are 512MiB):
#   info(replica): superblock release=0.17.8
#   info(main): 0: Allocated 2574MiB during replica init
#   info(main): 0: Grid cache: 512MiB, LSM-tree manifests: 128MiB
#   info(main): 0: cluster=1: listening on 0.0.0.0:3000
#
# "PermissionDenied" or "SystemResources" here means §2 was skipped.
# "exited with code 137" and no log line at all means --cache-grid is too large
# for this machine — the replica allocates several times the cache figure.
```

Two things are deliberately different from the development compose file:

- **`--development` is gone** from both `format` and `start`. Direct I/O is
  enforced, which is why §3 mattered.
- **`--cache-grid` needs a value chosen for this machine.** The development
  file's `256MiB` was picked to fit a build machine's memory, not to handle your
  traffic.

**Do not publish port 3000 beyond the Exchange.** The client port has no
authentication and no TLS ([`CONFIGURATION.md`](CONFIGURATION.md) §2) — anything
that can reach it can move money.

---

## 6. Step 5 — point the Exchange at it

Add the ledger settings to the Exchange's environment
([`CONFIGURATION.md`](CONFIGURATION.md) §3):

```
RAMP_BILLING_ADAPTER=tigerbeetle
EXCHANGE_BILLING_LEDGER=978
EXCHANGE_BILLING_TB_ADDRESS=10.0.1.7:3000
EXCHANGE_BILLING_TB_CLUSTER_ID=1
```

Three things that often go wrong in those four lines:

1. **`EXCHANGE_BILLING_TB_ADDRESS` must be `IP:port`.** The client rejects
   hostnames, so `tigerbeetle:3000` does not work. Use the address literally.
2. **`EXCHANGE_BILLING_LEDGER` fixes the deployment's currency.** `978` means
   every catalog term must be priced in EUR; anything else is denied
   ([`CONFIGURATION.md`](CONFIGURATION.md) §4).
3. **`EXCHANGE_BILLING_TB_CLUSTER_ID` must match the `--cluster` you formatted
   with** (§4), or the Exchange's boot health check fails.

The Exchange container needs `seccomp=unconfined` and `IPC_LOCK` too (§2).

**Make the Exchange wait for the ledger.** The Exchange checks the cluster once at
boot and exits if it does not answer, so starting the two together is a race the
Exchange loses. The ledger's health check (§5) exists to settle it — declare the
dependency on the Exchange service:

```yaml
services:
  exchange:
    # ... image, environment, ports
    restart: unless-stopped
    depends_on:
      tigerbeetle:
        condition: service_healthy
```

`service_healthy` waits for the health check to pass, not merely for the container
to exist, which is the distinction that matters here: the ledger opens its port
only after formatting finishes.

Keep `restart: unless-stopped` as well. `depends_on` orders the *initial* start; it
does nothing if the ledger is restarted later, so the restart policy is still what
carries the Exchange through a ledger outage that happens after boot.

---

## 7. Step 6 — verify the deployment

Five checks, in order. Each one builds on the last.

**Check A — the cluster answers.**

```bash
docker compose ps tigerbeetle
# Expect: STATUS contains "(healthy)". "(health: starting)" for the first minute
# of a first boot is normal — the data file is formatted before the port opens.

timeout 2 bash -c '</dev/tcp/10.0.1.7/3000' && echo LEDGER-LISTENING
# Expect: LEDGER-LISTENING
```

**Check B — the Exchange selected the ledger at boot.**

```bash
docker compose logs exchange | grep tigerbeetle
# Expect these two INFO lines. The Exchange emits one JSON object per line;
# they are wrapped here to fit the page.
#   {"level":"INFO","msg":"tigerbeetle connected","cluster":1,
#    "addresses":["10.0.1.7:3000"]}
#   {"level":"INFO","msg":"billing adapter: tigerbeetle","ledger":978,
#    "currency":"EUR","address":"10.0.1.7:3000","hold_timeout":"6m0s"}
```

If neither line appears, the Exchange is running on a different billing backend
and **charges nothing**. The most common cause is a typo in
`RAMP_BILLING_ADAPTER` — an unrecognised value falls back to the no-charge
default with only a warning ([`CONFIGURATION.md`](CONFIGURATION.md) §3).

**Check C — the Exchange reports itself ready to take paid traffic.**

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://exchange.example.net/readyz
# Expect: 200 — the catalog database AND the ledger both answered.

curl -s -o /dev/null -w '%{http_code}\n' https://exchange.example.net/healthz
# Expect: 200 — and it would stay 200 even with the ledger down. That is the
# difference between the two: /readyz gates paid traffic, /healthz reports
# whether the process is alive. See `RUNBOOK.md` §2.1.
```

Point your load balancer's readiness probe at `/readyz`, and its liveness probe —
if it has one — at `/healthz`. Getting them the wrong way round means a ledger
restart restarts the Exchange.

**Check D — the accounts exist and can be found.** An agent's account is created
when the agent registers; the owner and platform accounts are created on first
use. So before any traffic the ledger is correctly empty. Have one agent register,
fund it — the procedure is [`RUNBOOK.md`](RUNBOOK.md) §4.1 — then calculate its
account id and look it up.

The agent's account id is hashed from its `billing_ref`, **not** from its name. A
`billing_ref` is a UUID the Exchange creates at registration and stores in
PostgreSQL; read it out first (`RUNBOOK.md` §4.1) and paste it in below in place
of the example:

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

Then look the account up. `repl` is TigerBeetle's own interactive command line —
you type ledger statements into it and it answers:

```bash
docker compose exec tigerbeetle /tigerbeetle repl \
  --cluster=1 --addresses=127.0.0.1:3000
# Expect: "TigerBeetle CLI Client 0.17.8" and a "> " prompt.
```

At that prompt — this is a ledger statement, not a shell command, and the trailing
semicolon is required:

```
lookup_accounts id=160256804321604199934357490248810311770;
```

Expect one account record whose `credits_posted` equals the amount you funded, in
units of 10⁻⁸ of the currency — €1.00 reads as `100000000`.

If the agent is registered and this returns nothing, something is wrong; it does
not mean the ledger is simply still empty. See [`RUNBOOK.md`](RUNBOOK.md) §3.2.

> `repl` needs a real terminal — it cannot be fed from a pipe or a script, and
> answers `ANSI escape sequences not supported.` if you try. Use
> `docker compose exec`, never `exec -T`.

**Check E — one paid transaction moves the balances you expect.** Have an agent
buy one resource, then look up all three accounts:

| Account | What must change |
|---|---|
| `agent:{billing_ref}` | `debits_posted` rises by the full price |
| `owner:revenue:{resource_owner_id}` | `credits_posted` rises by the price minus the commission |
| `platform:fee` | `credits_posted` rises by the commission |

The two credits sum to the debit. At the default commission rate of zero there
is **no `platform:fee` account at all** — it is created on the first transaction
that carries a non-zero fee, and the whole amount credits the owner. That is
correct, not a fault.

The interpretation of these fields, and the calculator above, are in
[`RUNBOOK.md`](RUNBOOK.md) §3.2.

---

## 8. Stopping and removing

```bash
docker compose stop tigerbeetle
# Expect: "Container tigerbeetle  Stopped". The data file is untouched.

docker compose down
# Expect: "Container tigerbeetle  Removed". The data file survives, because it
#         is a host directory, not a Docker volume.
```

**What a stopped ledger costs you.** Every **paid** transaction is denied for as
long as it is down: the Exchange cannot reserve funds, so it refuses the
purchase. Agents see a denial, not a delay.

What keeps working:

- **Download links already issued keep working.** They are signed URLs verified
  at the CDN, which never consults the ledger.
- **The publisher's own site is unaffected.** Ordinary visitors never touch this
  path.
- **Free resources keep working.** They never reserve funds.

The Exchange itself stays up and its `/healthz` stays green — it does not check
the ledger ([`RUNBOOK.md`](RUNBOOK.md) §2.1). Nothing shows you the outage except
the denials themselves.

**Removing the data file destroys the ledger**, and there is no backup to
restore from ([`RUNBOOK.md`](RUNBOOK.md) §5). Every balance, every settled
charge, every publisher's earned revenue is in that one file.

---

## 9. Where to go next

This document ends once the ledger is deployed and verified. Everything you do to
it afterwards lives in [`RUNBOOK.md`](RUNBOOK.md):

| Task | Where |
|---|---|
| Funding an agent's balance | `RUNBOOK.md` §4.1 |
| Reading account balances and diagnosing a charge | `RUNBOOK.md` §3.2 |
| What to alert on, and what to ignore | `RUNBOOK.md` §2.3 |
| Upgrading the ledger version | `RUNBOOK.md` §4.3 |
| Backup and recovery | `RUNBOOK.md` §5 |
| Something is broken and you need to know why | `RUNBOOK.md` §3 |
