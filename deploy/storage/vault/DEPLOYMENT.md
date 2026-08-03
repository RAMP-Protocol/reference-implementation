# RAMP Vault — Deployment Instructions

This document tells you, the DevOps engineer running the key store for the RAMP
platform, how to prepare HashiCorp Vault and point the Identity Service at it. You do
not need to read the source code. Words that may be new are explained the first time
they appear. Follow the steps in order.

Every setting mentioned here is described in full in
[`CONFIGURATION.md`](CONFIGURATION.md). Once Vault is running, day-to-day operation is
in [`RUNBOOK.md`](RUNBOOK.md).

---

## 1. What Vault holds, and why it is the sensitive one

The Identity Service creates a private key for every agent that signs up, and stores it
in Vault. It never gives that key out — when an agent asks it to buy something, the
service signs the request on the agent's behalf.

That makes Vault the one store where a read is as damaging as a write. **Anyone who can
read it can act as any agent in it**: buy content, spend the agent's money, and file
usage reports in its name. Set it up with that in mind, and treat its backups the same
way.

Nothing else in the platform uses Vault. The Exchange and the Broker do not touch it.

---

## 2. What you need before you start

| What | Where it goes | How to check you have it |
|---|---|---|
| A running Vault, unsealed | `VAULT_ADDR` | `vault status` → `Sealed  false` |
| A token that can create engines and policies (an operator token, used for this setup only) | your shell | `vault token lookup` succeeds |
| The Vault CLI, or the API | — | `vault version` |

If you do not have a Vault yet, a managed Vault service works well here and is the
quickest way. Whatever you use, read [`CONFIGURATION.md`](CONFIGURATION.md) §4 before
you set it up — auto-unseal, TLS, storage you can snapshot and an audit device are all
much easier to put in place now than later.

**Do not use a `-dev` Vault.** It keeps nothing across a restart, so every agent key in
it is lost when the process stops.

---

## 3. Step 1 — enable the secrets engine

Give the platform its own KV version 2 engine rather than sharing the default one.
"KV version 2" is Vault's ordinary key/value engine with version history; version 1
will not work.

```bash
vault secrets enable -path=ramp-agents -version=2 kv
# Expect: Success! Enabled the kv secrets engine at: ramp-agents/
```

Confirm it is there and is version 2:

```bash
vault secrets list
# Expect a row for ramp-agents/ with Type "kv", e.g.
# Path             Type    Accessor       Description
# ----             ----    --------       -----------
# ramp-agents/     kv      kv_8f7715da    n/a
```

Note the path you chose — it becomes `IDENTITY_KV_MOUNT`.

---

## 4. Step 2 — write the policy

The Identity Service needs four operations on one prefix and nothing else. Replace
`ramp-agents` and `agents` with your own mount and prefix if they differ.

```bash
cat > ramp-identity.hcl <<'EOF'
# Read, create and update one agent key.
path "ramp-agents/data/agents/*" {
  capabilities = ["create", "update", "read"]
}

# List the agents, list one agent's keys, and erase a key completely.
path "ramp-agents/metadata/agents/*" {
  capabilities = ["read", "list", "delete"]
}
EOF

vault policy write ramp-identity ramp-identity.hcl
# Expect: Success! Uploaded policy: ramp-identity
```

> **`delete` on the metadata path is not optional.** It is what erases every version of
> a secret. Without it a revoked key is recorded as revoked but its private key stays
> sitting in Vault's version history — readable by anyone who can read the store, which
> is the exact leak a revocation exists to close.
> [`CONFIGURATION.md`](CONFIGURATION.md) §3 has the full failure table.

---

## 5. Step 3 — create the service's token

```bash
vault token create -policy=ramp-identity -period=768h -field=token
# Expect: a token beginning "hvs."
```

`-period=768h` makes it renewable rather than simply expiring after 32 days; renewal
is §3 of [`RUNBOOK.md`](RUNBOOK.md). Store the token in your secret manager and supply
it to the Identity Service as `VAULT_TOKEN`.

**Do not use your operator token, and do not use a root token.** The setup token above
was needed only for §3 and §4; the service gets this narrow one.

---

## 6. Step 4 — verify the token can do exactly what is needed

Run these **as the new token**, not as your operator token. They prove the policy is
right before the Identity Service depends on it.

```bash
export VAULT_TOKEN=<the token from §5>
TP=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA   # a placeholder key name

vault kv put ramp-agents/agents/probe.example.org/$TP seed=x
# Expect: a table ending with
# version            1

vault kv list ramp-agents/agents
# Expect:
# Keys
# ----
# probe.example.org/

vault kv list ramp-agents/agents/probe.example.org
# Expect: the placeholder name above

vault kv metadata delete ramp-agents/agents/probe.example.org/$TP
# Expect: Success! Data deleted (if it existed) at:
#         ramp-agents/metadata/agents/probe.example.org/AAAA...
```

If the last one answers `permission denied`, the policy is missing `delete` on the
metadata path — go back to §4. That failure will not show up again until the first time
someone tries to revoke a compromised key, which is the worst possible moment to find
it.

Clean up the probe entry if anything is left:

```bash
vault kv list ramp-agents/agents
# Expect: "No value found at ramp-agents/metadata/agents" on a fresh deployment
```

---

## 7. Step 5 — point the Identity Service at it

Set these three on the Identity Service and restart it:

```
VAULT_ADDR=https://vault.internal:8200
VAULT_TOKEN=<the token from §5>
IDENTITY_KV_MOUNT=ramp-agents
```

**There will be no confirmation in the logs.** The Identity Service does not contact
Vault at start-up, so a wrong address or a bad token produces a service that boots
cleanly and reports healthy. The check that actually proves it is Check C in
[`src/identity/DEPLOYMENT.md`](../../../src/identity/DEPLOYMENT.md) §10 — run it now.

---

## 8. Step 6 — set up backups before the first agent exists

There is no second copy of these keys anywhere. If Vault's storage is lost, every agent
loses its identity permanently and must sign up again.

Snapshot however your Vault is deployed — `vault operator raft snapshot save` for
Integrated Storage, your provider's mechanism for a managed Vault, the storage layer's
own backup otherwise. The procedure and the restore drill are in
[`RUNBOOK.md`](RUNBOOK.md) §5.

> **A snapshot of this store is as sensitive as the store itself.** It contains every
> agent's private key in usable form. Encrypt it, restrict who can read it, and keep it
> out of general-purpose backup buckets.

Back it up **on the same schedule as the Identity Service's PostgreSQL database**.
Restoring keys without the revocation list quietly brings back keys you revoked;
restoring the database without the keys leaves records pointing at key material that no
longer exists.

---

## 9. Where to go next

| Task | Where |
|---|---|
| Vault is sealed and nothing works | [`RUNBOOK.md`](RUNBOOK.md) §3 |
| Renewing or rotating the service's token | [`RUNBOOK.md`](RUNBOOK.md) §4 |
| Taking and testing a snapshot | [`RUNBOOK.md`](RUNBOOK.md) §5 |
| What to alert on | [`RUNBOOK.md`](RUNBOOK.md) §2.3 |
| The settings from the service's side | [`src/identity/CONFIGURATION.md`](../../../src/identity/CONFIGURATION.md) §4 |
