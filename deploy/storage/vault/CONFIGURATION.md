# RAMP Vault — Configuration Reference

This document tells you, the DevOps engineer running the key store for the RAMP
platform, what the platform needs from HashiCorp Vault and what every setting does.
You do not need to read the source code. Words that may be new are explained the
first time they appear.

For the step-by-step install see [`DEPLOYMENT.md`](DEPLOYMENT.md); for day-to-day
operation see [`RUNBOOK.md`](RUNBOOK.md).

---

## 1. What the platform needs from Vault

**One KV version 2 secrets engine, one folder inside it, and one token limited to
that folder.** That is the whole requirement.

Only the Identity Service uses Vault. Neither the Exchange nor the Broker touches it.

| Consumer | What it stores in Vault |
|---|---|
| Identity Service | Every agent's **private key**, one secret per key. |

"KV version 2" is Vault's key/value engine with version history — the ordinary one, and
the default in a new Vault. Version 1 will not work: the Identity Service relies on
version 2's paths and on its ability to erase a secret's whole history at once.

**Read this before you plan anything else.** An agent's private key is what proves a
purchase came from that agent. Whoever can read this store can act as any agent in it:
buy content, spend the agent's money, and file usage reports in its name. It is by far
the most sensitive store in the platform, so treat it the way you would treat a
production certificate authority — a sealed Vault, TLS, an audit device, and a backup
routine whose copies are guarded as carefully as the live system.

There is no alternative to configure. A local or file-based key store is **not
implemented yet**, so Vault is not optional for a deployment that runs the Identity
Service.

---

## 2. Settings

These are read by the Identity Service, and are described from its side in
[`src/identity/CONFIGURATION.md`](../../../src/identity/CONFIGURATION.md) §2.

| Name | Required? | What it is | Example |
|---|---|---|---|
| `VAULT_ADDR` | Optional, **set it** | Vault's address. Read by the Vault client library rather than by the service, so leaving it unset does not fail — it silently means `https://127.0.0.1:8200`, and every key operation then fails. | `https://vault.internal:8200` |
| `VAULT_TOKEN` | Optional, **set it** | The token the Identity Service authenticates with. A token is the only authentication method implemented; the longer-lived methods Vault offers are not implemented yet. | `hvs.CAESI…` |
| `IDENTITY_KV_MOUNT` | Optional | Which secrets engine holds the keys. Default `secret`, which is the engine a new Vault already has. Give it a dedicated one instead. | `ramp-agents` |
| `IDENTITY_KV_PREFIX` | Optional | The folder inside that engine. Default `agents`. It exists so the engine can hold unrelated secrets without colliding. | `agents` |
| `VAULT_CACERT` | Optional | Path to the certificate authority that signed Vault's TLS certificate, if it is not already trusted by the container. Read by the client library. | `/secrets/vault-ca.pem` |
| `VAULT_NAMESPACE` | Optional | Vault Enterprise namespace, if you use them. | *(leave unset)* |

**Neither `VAULT_ADDR` nor `VAULT_TOKEN` is checked at start-up.** The Identity Service
builds its Vault client and carries on without testing it, so a wrong address, a
missing token, an expired token and a sealed Vault all produce a service that starts
normally and reports healthy. §3 of
[`src/identity/RUNBOOK.md`](../../../src/identity/RUNBOOK.md) covers what that looks
like from the outside; the short version is that agent documents start returning `503`
while `/healthz` stays green.

---

## 3. The token's policy

**Do not give the Identity Service a root token.** It performs four operations on one
path prefix and needs nothing else.

Two rules are enough. Replace `ramp-agents` and `agents` with your own mount and
prefix:

```hcl
# Read, create and update one agent key.
path "ramp-agents/data/agents/*" {
  capabilities = ["create", "update", "read"]
}

# List the agents, list one agent's keys, and erase a key completely.
path "ramp-agents/metadata/agents/*" {
  capabilities = ["read", "list", "delete"]
}
```

The `data/` and `metadata/` split is how KV version 2 works: the secret's contents live
under `data/`, and its listing and version history live under `metadata/`.

Two capabilities are easy to leave out, and each fails in its own way:

| Missing | What breaks |
|---|---|
| `list` on the metadata path | Automatic key rotation stops for every agent, logging `identity.rotation.list_subdomains_failed` once per cycle. Existing keys keep working until they expire. |
| `delete` on the metadata path | **Key revocation half-works.** The revocation is recorded and takes effect, but the key material is never erased from Vault — the service logs `identity.revoke.destroy_failed`. A key you revoked because it leaked stays readable by anyone who can read this store. |

`delete` on the metadata path is what erases **every version** of a secret. An ordinary
delete would only hide the current one and leave the private key sitting in the version
history, which is exactly the leak a revocation exists to close.

---

## 4. Running it in production

The Identity Service does not care how Vault is run, so everything here is your
decision. These four are the ones that matter for this store:

| Setting | What to do | Why |
|---|---|---|
| Seal | Use auto-unseal, backed by a cloud KMS or an HSM | A sealed Vault answers nothing, and every restart needs a manual unseal otherwise. §3 of [`RUNBOOK.md`](RUNBOOK.md). |
| TLS | On, with a certificate the Identity Service trusts | The traffic is agent private keys. |
| Storage | A backend you can snapshot | There is no other copy of these keys — §5 of [`RUNBOOK.md`](RUNBOOK.md). |
| Audit device | Enabled, writing somewhere durable | Vault's audit log is the only record of who read a key. Without it, you cannot work out afterwards how far a break-in went. |

A managed Vault service works well here and removes most of the above.

---

## 5. Development defaults you must not copy

The compose files in this repository start Vault in `-dev` mode:

| Setting | Why it is there | Why it must not ship |
|---|---|---|
| `vault server -dev` | Starts unsealed, ready in a second, no configuration. | It keeps nothing across a restart. Every agent key in it is lost when the container stops. |
| `VAULT_DEV_ROOT_TOKEN_ID` set to a fixed value | Tests need a known token. | It is published in this repository, and it is a root token. |
| No TLS | The test network has no certificates. | Agent private keys would cross the network in the clear. |
| The default `secret/` mount | It is already there in dev mode. | Works, but mixes agent keys with anything else that ends up in the default engine. Use a dedicated mount. |

---

## 6. Worked example

Values marked *fill in* are specific to your environment.

```
VAULT_ADDR=https://vault.internal:8200
VAULT_TOKEN=<fill in — see DEPLOYMENT.md §5>
IDENTITY_KV_MOUNT=ramp-agents
IDENTITY_KV_PREFIX=agents
```

Set these on the **Identity Service**, not on Vault. Nothing else in the platform reads
them.

`VAULT_TOKEN` is read as a plain environment variable. Vault itself is configured
however you normally run it — this document only specifies the engine, the policy and
the way of running it that the platform depends on.
