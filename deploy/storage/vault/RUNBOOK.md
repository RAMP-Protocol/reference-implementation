# RAMP Vault — Runbook

Operated by the Exchange Operator, on infrastructure you provide. Written for you, the
DevOps engineer running the key store for the RAMP platform: you do not need to read
the source code, and words that may be new are explained the first time they appear.

**Escalation.** If §3 does not resolve it, contact Postindustria at
`<support channel — fill in before handover>`. Send the `request_id` of a failing
request together with the matching log lines from the Identity Service. Postindustria
has no access to your infrastructure, so that correlation ID is the only way the
request can be traced. Vault's own operation is a HashiCorp product question, not a
RAMP one.

> This runbook assumes Vault is already running and the Identity Service is pointed at
> it. For setting it up, the policy and first-boot verification, see
> [`DEPLOYMENT.md`](DEPLOYMENT.md) and [`CONFIGURATION.md`](CONFIGURATION.md).

---

## 1. Overview

Vault holds one class of data, and it is the most sensitive in the platform: **every
agent's private key**, one secret per key, under `<mount>/<prefix>/<subdomain>/<key>`.

Only the Identity Service reads or writes it. The Exchange and the Broker never touch
it.

**A read is as damaging as a write.** An agent's private key is what proves a purchase
came from that agent, so anyone who can read this store can buy content, spend money
and file usage reports in any agent's name. That applies to snapshots as much as to the
live system.

**If it is unavailable, no agent can be created and no one can look up an agent's
published key.** Agents that are already running keep working for as long as the Broker
and the Exchange have their keys cached — a few minutes — and then start failing
signature checks. Nothing else in the platform is affected: the publisher's site,
delivery links already issued, and the Exchange and Broker themselves all carry on.

---

## 2. Monitoring

### 2.1 Health

```bash
vault status
# Expect: Sealed  false
#
# Key             Value
# ---             -----
# Seal Type       shamir
# Initialized     true
# Sealed          false
```

**Nothing in the RAMP platform will tell you Vault is down.** The Identity Service does
not contact Vault at start-up and does not include it in `/healthz`, so it boots
cleanly and reports healthy against a sealed or unreachable Vault. Monitor Vault
directly, and add this as a second signal:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  https://nosuch.agents.example/.well-known/http-message-signatures-directory
# Expect: 404 — an agent that does not exist.
# 503 means the Identity Service cannot reach Vault.
```

### 2.2 Logs

Vault's own logs are in its usual place, and its format is a HashiCorp matter. Two
things are worth arranging on the RAMP side:

- **Enable an audit device.** Vault's audit log is the only record of who read a key.
  Without one, you cannot work out afterwards how far a break-in went — you will not be
  able to say which keys were read. This cannot be reconstructed later.
- **Watch the Identity Service's logs for the Vault-shaped events**, listed in
  [`src/identity/RUNBOOK.md`](../../../src/identity/RUNBOOK.md) §2.2. The ones that mean
  Vault: `identity.directory.unavailable` (WARN),
  `identity.rotation.list_subdomains_failed` (ERROR), `identity.revoke.destroy_failed`
  (ERROR).

### 2.3 Alerts

**These are recommendations, not configured alerts.** Nothing here ships an alerting
rule.

| Signal | Severity | First action |
|---|---|---|
| `Sealed  true` | **Wake on-call** | Unseal it — §4. Until you do, no agent can be created and published keys stop resolving. |
| Vault unreachable | **Wake on-call** | Same consequence. Check the network path from the Identity Service, not just from your workstation. |
| `identity.directory.unavailable` in the Identity Service | **Wake on-call** | The service is failing to reach Vault. This is usually the first place an operator sees it. |
| The service token is within a week of expiry | **Wake on-call** | Renew it — §4. An expired token fails exactly like a sealed Vault, but does not show up in `vault status`. |
| `identity.revoke.destroy_failed` | **Wake on-call** | A revoked key was not erased. The policy is probably missing `delete` — §3. |
| `identity.rotation.list_subdomains_failed` repeating | Business hours | Automatic key rotation has stopped platform-wide. Existing keys keep working until they expire. |
| A snapshot has not succeeded in 24 hours | Business hours | There is no other copy of these keys — §5. |

---

## 3. Troubleshooting

### 3.1 Symptom → cause → fix

| Symptom | Why | What to do |
|---|---|---|
| **Agent documents return `503`, `/healthz` is green** | The Identity Service cannot reach Vault. It never checks at start-up, so this is what a Vault problem always looks like. | Work down this table. |
| `vault status` shows `Sealed  true` | Vault restarted and has no auto-unseal | Unseal — §4. Set up auto-unseal so it does not recur. |
| Connection refused or a TLS error from the service, but not from your workstation | Network path or trust store differs inside the container | Check `VAULT_ADDR` and whether the container trusts Vault's certificate authority (`VAULT_CACERT`). |
| `permission denied` on reads, Vault is up and unsealed | The token expired, was revoked, or its policy is wrong | `vault token lookup` as that token. If it fails, the token is gone — §4. If it succeeds, compare its policy against [`CONFIGURATION.md`](CONFIGURATION.md) §3. |
| **`identity.revoke.destroy_failed`** | The policy is missing `delete` on the metadata path | Fix the policy ([`CONFIGURATION.md`](CONFIGURATION.md) §3), then **re-run the revocation** — it is safe to repeat and completes the erase. Until then the revoked key material is still readable in Vault. |
| Rotation stopped for every agent | The policy is missing `list` on the metadata path | Same fix, same document. |
| The service says an agent has no keys, but you know it does | The mount or prefix is wrong, so it is looking in an empty place | Compare `IDENTITY_KV_MOUNT` and `IDENTITY_KV_PREFIX` with what `vault secrets list` shows. |
| Every agent disappeared after a restart | Vault was running in `-dev` mode, which keeps nothing | The keys are gone and cannot be recovered. Every agent must sign up again. Deploy a real Vault — [`DEPLOYMENT.md`](DEPLOYMENT.md) §2. |

### 3.2 Diagnostics

**Which agents hold keys**

```bash
vault kv list ramp-agents/agents
# Expect: one entry per agent subdomain.
# "No value found at ramp-agents/metadata/agents" on an established deployment
# means the mount or prefix is wrong — it is not the same as "no agents".
```

**One agent's keys**

```bash
vault kv list ramp-agents/agents/agent-ovx4iigs.agents.example
# Expect: one entry per key. Two is normal during a rotation, while the old and
# new keys overlap.
```

**What the service's token is allowed to do**

```bash
VAULT_TOKEN=<the service's token> vault token lookup
# Expect: a "policies" row listing your policy, and a "ttl" that is not close to
# zero. A failure here means the token is expired or revoked.
```

### 3.3 Gotchas

- **Nothing in RAMP health-checks Vault.** The Identity Service starts and reports
  healthy against a Vault that is sealed, unreachable, or refusing its token.
- **An expired token looks exactly like an outage** from the RAMP side, and `vault
  status` looks perfectly healthy throughout.
- **A `-dev` Vault keeps nothing.** If one reached an environment where agents signed
  up, those keys are gone at the next restart.
- **An ordinary KV delete does not erase a key.** It hides the current version and
  leaves the private key in the version history. Only a metadata delete erases it, and
  that is why the policy needs `delete`.
- **A snapshot contains every agent's private key in usable form.** Guard it like the
  live system.

---

## 4. Procedures

### 4.1 Routine operations

**Unseal after a restart.** Follow your Vault's own unseal procedure — key shares, or
whatever your auto-unseal is backed by. Nothing on the RAMP side needs restarting
afterwards: the Identity Service builds a fresh Vault request per operation, so it
recovers on its own within a few seconds of Vault answering again.

Confirm from the RAMP side rather than only from `vault status`:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  https://nosuch.agents.example/.well-known/http-message-signatures-directory
# Expect: 404 (not 503)
```

**Renew the service's token.** A token created with `-period` stays alive as long as it
is renewed within its period. Renew it well before expiry:

```bash
VAULT_TOKEN=<the service's token> vault token renew
# Expect: a table whose ttl is back at the full period
```

An expired token is not recoverable — create a new one, as below.

**Rotate the service's token.** Creating a replacement does not interrupt anything,
because the service only reads the value at start-up.

1. Create a new token on the same policy:
   ```bash
   vault token create -policy=ramp-identity -period=768h -field=token
   # Expect: a token beginning "hvs."
   ```
2. Put it in your secret manager as `VAULT_TOKEN` and restart the Identity Service.
3. Confirm the service can reach Vault again — the `curl` above, expecting `404`.
4. Only then revoke the old token:
   ```bash
   vault token revoke -accessor <old accessor>
   # Expect: Success! Revoked token (if it existed)
   ```

Revoking before step 3 leaves the service unable to serve any agent, with `/healthz`
still green.

**Change the policy.** Write the updated policy and the change applies to existing
tokens immediately; no restart is needed. Re-run the verification in
[`DEPLOYMENT.md`](DEPLOYMENT.md) §6 afterwards.

### 4.2 Agent key procedures

There are none here. Creating, rotating and revoking agent keys is done through the
Identity Service, never by writing to Vault directly —
[`src/identity/RUNBOOK.md`](../../../src/identity/RUNBOOK.md) §4.2.

Editing a key in Vault by hand leaves it no longer matching the agent card and
revocation records in PostgreSQL, and the Identity Service has no way to notice.

### 4.3 Upgrade

Vault upgrades are a HashiCorp procedure and are unconstrained by RAMP: nothing in the
platform depends on a Vault version or feature beyond KV version 2. Take a snapshot
first (§5).

The Identity Service tolerates Vault being away for the length of a restart — agent
documents return `503` for that window and recover on their own.

---

## 5. Backup and recovery

**This is the store with no second copy.** Everything else in the platform can be
rebuilt from something; agent private keys cannot.

### 5.1 Snapshots

Snapshot however your Vault is deployed — `vault operator raft snapshot save` for
Integrated Storage, your provider's mechanism for a managed Vault, the storage layer's
own backup otherwise.

```bash
vault operator raft snapshot save ramp-vault-$(date -u +%Y%m%dT%H%M%SZ).snap
# Expect: the command to exit 0 and the file to exist and be non-empty
```

Three requirements specific to this store:

- **Treat the snapshot as live key material.** Encrypt it at rest, restrict who can
  read it, and keep it out of general-purpose backup buckets. Anyone who can read it
  can act as every agent in the platform.
- **Back it up on the same schedule as the Identity Service's PostgreSQL database.**
  The two must be restored as a pair — see below.
- **Test a restore.** An untested snapshot of an unrecoverable store is not a backup.
  Restore into a throwaway Vault and confirm `vault kv list` shows the agents you
  expect.

How often you back up, and how fast you must recover, are yours to set; nothing in the
platform imposes either.

### 5.2 Data loss

| What is lost | Consequence |
|---|---|
| The whole store | **Every agent loses its identity permanently.** Each must sign up again and receives a new subdomain and a new key. Offers they had accepted become unusable. Nothing reconstructs a private key. |
| One agent's keys | That agent alone is in the state above. |
| A snapshot falls into the wrong hands | Treat as a full compromise: every key in it must be revoked and every agent re-keyed. This is why the audit device matters — without it you cannot tell whether it happened. |

### 5.3 Restoring alongside PostgreSQL

Restore Vault and the Identity Service's database **to the same point in time**. They
disagree in dangerous ways otherwise:

- **Vault newer than the database:** keys exist that no agent card describes. They are
  invisible to the service and never published.
- **Database newer than Vault:** agent cards refer to keys that are not there. Those
  agents' documents return errors until they are re-keyed.
- **Vault restored past a revocation:** the revocation list in the database still names
  the key, so it stays revoked — but the key material is back in Vault, readable again.
  Re-run the revocation ([`src/identity/RUNBOOK.md`](../../../src/identity/RUNBOOK.md)
  §4.2) to erase it.

That last one is the case worth practising: a restore can silently undo the *erasure*
half of a revocation while leaving the *record* half intact, so nothing looks wrong.

---

## 6. Limitations

- **A static token is the only way the Identity Service can authenticate to Vault.**
  The longer-lived methods Vault offers are not implemented yet, so the token is a
  credential you must renew and rotate by hand — §4.1.
- **Nothing in the platform health-checks Vault**, so every Vault problem shows up late
  and looks like an Identity Service problem.
- **The Identity Service has no fallback if Vault is unavailable.** There is no local
  or file-based key store; it is not implemented yet.
- **No key can ever be exported.** That is deliberate — it is what keeps an agent's key
  from ever leaving the store — but it means a lost store is a lost store.
- **RAMP does not say how often you back up, how long you keep the copies, or how fast
  you must recover.** You set them.
