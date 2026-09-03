# RAMP Sign-in Provider — Configuration Reference

This document tells you, the DevOps engineer running the sign-in provider for the RAMP
platform, what the Identity Service needs from an OIDC provider and how to satisfy it
with Zitadel. You do not need to read the source code. Words that may be new are
explained the first time they appear.

For the step-by-step install see [`DEPLOYMENT.md`](DEPLOYMENT.md); for day-to-day
operation see [`RUNBOOK.md`](RUNBOOK.md).

---

## 1. What the platform needs from a sign-in provider

Developers who want to use RAMP sign in somewhere before the Identity Service will
create an agent for them. The Identity Service does not hold their passwords — it hands
sign-in to a provider you run, and trusts the answer.

"OIDC" is OpenID Connect, the standard way one service hands sign-in over to another.

The requirements are ordinary, and any provider that follows the standard meets them:

| Requirement | Detail |
|---|---|
| OIDC discovery | The provider publishes `/.well-known/openid-configuration`. The Identity Service reads it **at start-up** and exits if it cannot. |
| Authorization-code flow | The standard browser sign-in flow. |
| A **confidential** client | One that authenticates with a client secret. A public browser client will not work. |
| An exact redirect address | `IDENTITY_AUTH_ISSUER` + `/callback`, matching character for character. |
| The scopes `openid profile email` | The default. The service needs the developer's identity and email address. |

**Zitadel is the provider RAMP is tested against**, and the rest of this document is
Zitadel-specific. If you already run an OIDC provider, use it instead —
only §1 and §5 apply to you, and the four values in §5 are all the Identity Service
ever learns about it.

---

## 2. What the platform does not need

Worth stating, because operators reasonably look for these:

- **No user management on the RAMP side.** Accounts, passwords, multi-factor settings
  and social sign-in are entirely the provider's business. The Identity Service reads
  who signed in and nothing else.
- **No dynamic client registration at the provider.** The Identity Service's own client
  is created once, by you. (It does offer dynamic registration to *agent software*
  connecting to it — that is a separate mechanism, on the Identity Service, described
  in [`src/identity/RUNBOOK.md`](../../src/identity/RUNBOOK.md) §4.2.)
- **No role or group mapping.** Anyone who can sign in can create an agent. Whether
  that agent may spend is decided on the Exchange —
  [`src/exchange/RUNBOOK.md`](../../src/exchange/RUNBOOK.md) §4.2.

---

## 3. Zitadel settings

| Setting | Value | Why |
|---|---|---|
| Image | `ghcr.io/zitadel/zitadel:v3.4.9` | Pinned. v4.x has a known crash at start-up, during its own migrations, that is not yet fixed. Do not move to v4 without testing it against a copy of your data first. |
| `ZITADEL_EXTERNALDOMAIN` | The public hostname developers reach | **Written into Zitadel's storage at first start** — see below. |
| `ZITADEL_EXTERNALPORT` | `443` | With `EXTERNALSECURE` on. |
| `ZITADEL_EXTERNALSECURE` | `"true"` | Makes the published issuer `https`. |
| `ZITADEL_TLS_ENABLED` | `"true"`, or terminate TLS in front | The traffic is sign-in credentials. |
| `--masterkey` | 32 characters, from your secret manager | Encrypts everything Zitadel stores. **Lose it and the data is unreadable.** |
| `ZITADEL_DATABASE_POSTGRES_*` | Its own PostgreSQL database | Separate from the RAMP databases. |

### The external domain is fixed at first start

Zitadel writes its own address into its storage the first time it starts, and it is
what appears as the `issuer` in everything it publishes. **Changing it later is not a
configuration edit** — the stored value stays, the published issuer stops matching, and
the Identity Service refuses the sign-in responses it gets back.

The only way to change it is to start a fresh instance with empty storage, which loses
every account. Decide the hostname before the first start.

The same is true from the other side: `IDENTITY_AUTH_ISSUER` on the Identity Service
determines the redirect address this provider must have on file, so changing that means
updating the client here ([`RUNBOOK.md`](RUNBOOK.md) §3).

### Outbound mail, and why it is also a first-start setting

Self-registration sends a confirmation code, and Zitadel does not treat the account
as usable until the code is entered. Without a mail provider that code is never
delivered, so a developer who registers is stuck. If nobody self-registers — every
account is created by an operator or arrives through an external provider such as
Google, which vouches for the address — no mail provider is needed.

A provider can be configured in two ways, and they behave differently:

| Setting | Value | Why |
|---|---|---|
| `ZITADEL_DEFAULTINSTANCE_SMTPCONFIGURATION_SMTP_HOST` | `host:port` | Dialled verbatim. There is no default port — a bare hostname fails at send time. |
| `ZITADEL_DEFAULTINSTANCE_SMTPCONFIGURATION_SMTP_USER` | Relay username | For Amazon SES, the IAM access key id of the sending user. |
| `ZITADEL_DEFAULTINSTANCE_SMTPCONFIGURATION_SMTP_PASSWORD` | Relay password | For SES, the region-derived SMTP password — **not** the raw secret access key. |
| `ZITADEL_DEFAULTINSTANCE_SMTPCONFIGURATION_TLS` | `"true"` | STARTTLS. Off, the password crosses the network in the clear. |
| `ZITADEL_DEFAULTINSTANCE_SMTPCONFIGURATION_FROM` | Sender address | Must be one the relay is allowed to send as. |
| `ZITADEL_DEFAULTINSTANCE_SMTPCONFIGURATION_FROMNAME` | Display name | Shown next to the address. |

**These are read only when Zitadel creates its instance on the first start**, the same
`FirstInstance` step that creates the admin user. Setting or changing them on an
instance that already exists does nothing at all: the provider is stored in Zitadel's
database, and the environment is no longer consulted. This is the same trap as the
external domain above, with one difference — a wrong mail setting is recoverable
without losing data, because the stored provider can be edited afterwards.

Editing the stored provider is the second way: Zitadel console → Default settings →
Notifications → SMTP provider, or the Admin API's email-provider endpoints. That is
how a running deployment changes relays or rotates a password. An edit made there
does not travel back into the environment, so a later rebuild from empty storage
starts from whatever the environment says.

The address in `FROM` matters beyond Zitadel. A relay that pins the sender — SES does,
when the credential's policy names the address — rejects any send whose `FROM` differs,
and the failure appears as unsent mail rather than as a configuration error.

### The OIDC client

The Identity Service's client is an ordinary confidential web application:

| Property | Value |
|---|---|
| Application type | Web |
| Authentication method | Client secret (Basic) |
| Grant types | Authorization code (plus refresh token) |
| Response type | Code |
| Redirect address | `IDENTITY_AUTH_ISSUER` + `/callback`, exactly |
| Development mode | **Off** |

Development mode exists so Zitadel will accept a plain `http` address on your own
machine as the redirect. Leaving it on in a deployment removes a check on the redirect
address, so turn it off.

**Zitadel never shows a client secret twice.** If you lose it, you cannot read it back
— you generate a new one, which is the rotation procedure in
[`RUNBOOK.md`](RUNBOOK.md) §4.

---

## 4. Development defaults you must not copy

The compose files and `init-steps.yaml` in this directory set up a throwaway Zitadel
for automated tests:

| Setting | Why it is there | Why it must not ship |
|---|---|---|
| `--masterkey MasterkeyNeedsToHave32Characters` | A fixed key so tests are reproducible. | It is published in this repository. Anyone could decrypt everything Zitadel stores. |
| `--tlsMode disabled`, `ZITADEL_EXTERNALSECURE: "false"` | The test network has no certificates. | Sign-in credentials in the clear. |
| The passwords in `init-steps.yaml` | Setting up a throwaway instance. | Published in this repository. The file says so itself. |
| `ZITADEL_EXTERNALDOMAIN: zitadel` | A container name on a private network. | Not reachable, and fixed permanently once started. |
| `devMode: true` on the OIDC client | Lets a laptop use an `http://localhost` redirect. | Relaxes redirect-address checking. |
| A test user with a known password | Tests need someone to sign in as. | An account with a published password. |

`init-steps.yaml` carries its own warning: *"The passwords here are local-development
defaults published in a tracked file. Nothing outside a laptop stack may use this
file."*

---

## 5. What the Identity Service is told

Four values, and this is the entire interface between the two systems.

| Value | Identity Service variable | Where it comes from |
|---|---|---|
| The provider's address | `IDENTITY_OIDC_ISSUER` | The `issuer` in its discovery document — copy it exactly, do not assume it |
| The client id | `IDENTITY_OIDC_CLIENT_ID` or `..._FILE` | §3, at creation |
| The client secret | `IDENTITY_OIDC_CLIENT_SECRET` or `..._FILE` | §3, at creation — shown once |
| This service's own public address | `IDENTITY_AUTH_ISSUER` | Your choice; it decides the redirect address |

The `_FILE` variants let the two secrets arrive as mounted files rather than
environment variables. A file that is set but unreadable stops the Identity Service
starting — it is not treated as "not configured".

---

## 6. Worked example

Values marked *fill in* are specific to your environment.

Zitadel:

```
ZITADEL_EXTERNALDOMAIN=login.example
ZITADEL_EXTERNALPORT=443
ZITADEL_EXTERNALSECURE=true
ZITADEL_TLS_ENABLED=true
ZITADEL_DATABASE_POSTGRES_HOST=<fill in>
ZITADEL_DATABASE_POSTGRES_DATABASE=zitadel
--masterkey <fill in — 32 characters, from your secret manager>
```

The Identity Service:

```
IDENTITY_OIDC_ISSUER=https://login.example
IDENTITY_OIDC_CLIENT_ID_FILE=/secrets/oidc_client_id
IDENTITY_OIDC_CLIENT_SECRET_FILE=/secrets/oidc_client_secret
IDENTITY_AUTH_ISSUER=https://id.example
```

which gives the client this redirect address, and no other:

```
https://id.example/callback
```
