# RAMP Sign-in Provider — Runbook

Operated by the Exchange Operator, on infrastructure you provide. Written for you, the
DevOps engineer running the sign-in provider for the RAMP platform: you do not need to
read the source code, and words that may be new are explained the first time they
appear.

**Escalation.** If §3 does not resolve it, contact Postindustria over the
existing communication channel. Send the `request_id` of a failing sign-up
together with the matching log lines from the Identity Service. Postindustria
has no access to your infrastructure, so that correlation ID is the only way the
request can be traced. Zitadel's own operation is a product question, not a RAMP
one.

> This runbook assumes the provider is already running and the Identity Service is
> pointed at it. For setting it up, the client registration and first-boot verification,
> see [`DEPLOYMENT.md`](DEPLOYMENT.md) and [`CONFIGURATION.md`](CONFIGURATION.md).

---

## 1. Overview

This is where developers sign in before the Identity Service will create an agent for
them. It holds their accounts and passwords; the Identity Service holds neither.

**It is needed at two moments, and only two:**

| Moment | What happens without it |
|---|---|
| When a developer signs up | Sign-up fails. Nobody new can get an agent. |
| When the Identity Service **starts** | It exits. It checks discovery at boot and refuses to run without it. |

Everything else carries on. Agents that already exist keep working — they authenticate
with tokens the Identity Service issued and verifies itself, so a provider outage is
invisible to them.

**That difference is the thing to remember.** A running platform survives this being
down; a platform you are restarting does not. Bring the provider back before restarting
the Identity Service, and never schedule maintenance on both at once.

---

## 2. Monitoring

### 2.1 Health

```bash
curl -s https://login.example/.well-known/openid-configuration | head -c 120
# Expect: JSON whose "issuer" is exactly your hostname
```

That single check covers what RAMP depends on. If it answers with the right issuer, the
Identity Service can start and developers can sign in.

Zitadel publishes its own liveness and readiness endpoints; use whatever your platform
normally uses for them. Nothing in RAMP looks at them.

### 2.2 Logs

Zitadel's logs are its own. On the RAMP side, sign-in shows up in the Identity
Service's logs under `identity.oauthserver.*` — the full table is in
[`src/identity/RUNBOOK.md`](../../src/identity/RUNBOOK.md) §2.2. The ones that point
here:

| Event | Level | Means |
|---|---|---|
| `identity.oauthserver.callback.exchange` | ERROR | The provider returned something the Identity Service could not use. Usually the client secret. |
| `identity.oauthserver.callback.provision` | WARN or ERROR | Sign-in worked, but creating the agent afterwards failed. **Not a provider problem** — look at Vault and the database. WARN when a backend was simply unavailable, ERROR otherwise. |
| `identity.exit` with `oidc upstream:` | ERROR | The Identity Service could not reach the provider at start-up. |

**A redirect-address mismatch appears in neither log.** The provider refuses before it
ever redirects, so the Identity Service sees nothing at all. §3 covers it.

### 2.3 Alerts

**These are recommendations, not configured alerts.** Nothing here ships an alerting
rule.

| Signal | Severity | First action |
|---|---|---|
| Discovery unreachable, or the issuer changed | **Wake on-call** | No new sign-ups, and the Identity Service will not restart. §3. |
| `identity.exit` with `oidc upstream:` | **Wake on-call** | The Identity Service is down and cannot start until this is back. |
| `identity.oauthserver.callback.exchange` in large numbers | **Wake on-call** | Usually a rotated or mismatched client secret. §4. |
| Developers report being sent back with an error | Business hours | Almost always the redirect address. §3. |
| Zitadel database backup has not succeeded in 24 hours | Business hours | Every developer account lives there. §5. |

---

## 3. Troubleshooting

### 3.1 Symptom → cause → fix

| Symptom | Why | What to do |
|---|---|---|
| **Sign-in stops at the provider with a redirect error, nothing in the Identity Service's logs** | The address on the client does not exactly match `IDENTITY_AUTH_ISSUER` + `/callback` | Compare them character for character — a trailing slash and `http` for `https` are the usual causes. Fix it on the client ([`DEPLOYMENT.md`](DEPLOYMENT.md) §5). The logs are silent because the request never reached RAMP. |
| The Identity Service will not start, `err` contains `oidc upstream:` | It contacts the provider at boot and exits if it cannot | Confirm discovery answers **from inside that container**, not just from your workstation. Then restart. |
| Sign-in returns, but the Identity Service reports a failure exchanging the code | The client secret is wrong — usually rotated on one side only | Rotate deliberately and restart, §4. |
| Discovery reports an `issuer` you did not configure | The hostname is written into storage at first start | It cannot be edited. §3.2 below is the only path, and it costs every account. |
| Everything worked, then stopped after moving the hostname | Same cause | Same. |
| Sign-in works but no agent appears | The provider is fine; agent creation failed afterwards | Look for `identity.oauthserver.callback.provision` and check Vault — [`deploy/storage/vault/RUNBOOK.md`](../storage/vault/RUNBOOK.md) §3. |
| Zitadel will not boot after an upgrade | v4.x has a known crash during its own migrations, not yet fixed | Roll back to `v3.4.9`. §4.3. |
| Zitadel will not start and reports it cannot decrypt | Wrong or missing master key | Supply the correct one. There is no recovery without it. |

### 3.2 If the hostname really must change

There is no supported edit. The published issuer comes from what was stored at first
start, and the Identity Service refuses responses that do not match it.

The only route is a fresh instance with empty storage, which loses every developer
account — every developer signs up again and gets a **new agent identity**, so their
existing agents are left behind with no owner. Treat it as a migration with notice to
your developers, not as a configuration change.

The cheap way to avoid this is in [`DEPLOYMENT.md`](DEPLOYMENT.md) §3: check the
published issuer before anybody signs up.

### 3.3 Gotchas

- **A redirect mismatch is invisible on the RAMP side.** If a developer reports being
  sent back with an error and your logs are clean, this is it.
- **The Identity Service needs this only at start-up and at sign-up.** Do not chase a
  provider outage when running agents are failing — they do not use it.
- **Never restart the Identity Service while this is down.** It will not come back.
- **The hostname and the master key are permanent.** Neither can be changed after first
  start without losing the data.
- **A client secret cannot be read back.** Losing it means generating a new one.
- **The setup script and `init-steps.yaml` in this directory are for the automated
  test stack only.** They carry published passwords and a published master key.

### 3.4 A developer registers and the confirmation code never arrives

Zitadel sends the code and treats the account as unusable until it is entered, so this
is reported as "I signed up and nothing happened". Work through it in this order —
each step tells a Zitadel problem apart from a relay problem.

**1. Is a provider configured at all?** Sign in to the console as the admin user, open
Default settings → Notifications → SMTP provider. If it is missing or inactive on an
instance that was deployed with mail settings, the first-start configuration did not
take: fix the deployment and rebuild rather than configuring it by hand, or the next
rebuild loses the fix. Configuration is in [`CONFIGURATION.md`](CONFIGURATION.md) §3.

**2. Are the host, username and sender what you expect?** The password cannot be read
back. Compare the rest against what the deployment configured.

**3. Send a test message from that screen.** It reports the relay's own answer, which
is the fastest way to separate the two sides:

- Authentication rejected → wrong username or password, or a credential that was
  deactivated at the relay.
- Sender rejected → the relay does not allow that `FROM`. Amazon SES refuses any send
  whose sender falls outside the verified identity, and refuses it again if the
  credential's policy pins one exact address.
- Connection refused or timed out → wrong host, wrong port, or egress blocked. Check
  from inside the Zitadel container, not from your workstation.
- Accepted, but nothing arrives → the relay took it. Continue at the relay.

**4. On Amazon SES specifically**, three things reject mail after a clean apply:

```bash
# Is the sending identity verified, and is DKIM through?
aws sesv2 get-email-identity --region us-east-1 --email-identity <domain>

# Is the account still sandboxed? ProductionAccessEnabled tells you.
aws sesv2 get-account --region us-east-1

# What happened to what was accepted?
aws sesv2 get-account --region us-east-1 --query 'SendQuota'
```

In the sandbox, SES accepts the send and delivers only to recipients verified in the
same region — a registration to any other address disappears silently. Sandbox status,
identity verification, the SMTP endpoint and the derived SMTP password are all
per-region: mixing regions is the common cause of "the credential is right and it
still fails".

**5. Check the address the mail was sent to.** A code delivered to a mistyped address
is not a fault in any of the above.
---

## 4. Procedures

### 4.1 Routine operations

**Restart.** Costs nothing on the RAMP side: signed-in agents are unaffected, and only
sign-ups that are halfway through are interrupted. **Do not restart the Identity
Service while this is restarting** — it would not come back until this is answering.

**Manage developers.** Adding, disabling and removing developer accounts, password
policy, multi-factor, and corporate or social sign-in are all done here and need no
change on the RAMP side.

**Disabling a developer's account stops them signing in — it does not stop their
agent.** The agent authenticates with a token the Identity Service issued, and its key
lives in Vault. To stop the agent, revoke its key and remove its registered client:
[`src/identity/RUNBOOK.md`](../../src/identity/RUNBOOK.md) §4.2. Do both.

### 4.2 Rotating the client secret

The Identity Service reads the secret only at start-up, so there is a short period in
which the two disagree. Keep it short and do it in this order.

1. Generate a new secret on the client in the Zitadel console. **The old one stops
   working immediately** — Zitadel replaces rather than adds.
2. Write it where the Identity Service reads it:
   ```bash
   umask 077
   printf '%s' '<new secret>' > /secrets/oidc_client_secret
   ```
3. Restart the Identity Service.
   ```bash
   docker compose logs identity | tail -2
   # Expect: "identity listening". An identity.exit with "oidc upstream:" means
   # the provider was unreachable, not that the secret is wrong — a wrong secret
   # is not detected until a real sign-in.
   ```
4. **Do a real sign-in**, per [`DEPLOYMENT.md`](DEPLOYMENT.md) §7. Nothing before this
   step proves the new secret works.

Between steps 1 and 3, sign-ups fail. Existing agents are unaffected throughout.

**Changing the redirect address** works the same way: update `IDENTITY_AUTH_ISSUER`
on the Identity Service and the client's redirect address here **together**, then
restart and do a real sign-in. They are one setting in two places.

### 4.3 Upgrade and rollback

**Stay on `v3.4.9` unless you have tested otherwise.** v4.x has a known crash during
its own migrations, not yet fixed, so an upgrade can leave the instance unable to boot.

Before any upgrade:

1. Back up the database (§5) and confirm you have the master key.
2. Restore that backup into a throwaway instance and upgrade *that* first.

**Roll back** by starting the previous image against the same database — which works
only if the newer version has not already migrated the schema. That is exactly what the
v4 crash happens during, so the backup from step 1 is the real rollback path.

Take the Identity Service down before a risky upgrade, or leave it running and simply
do not restart it — it does not need the provider while it runs.

### 4.4 Rotating the SMTP password

The order matters. Zitadel holds one password at a time, and the relay stops accepting
the old one the moment it is removed — so removing it first means every registration in
that window fails silently, with no error anywhere in RAMP.

Rotate with two credentials live at once:

1. Create a **second** credential at the relay. Both are now valid. On Amazon SES this
   is a second access key on the same IAM user, which allows two.
2. Update the stored provider in Zitadel — console → Default settings → Notifications →
   SMTP provider, or the Admin API — to the new username and password. The environment
   variables are not involved: they are read only when the instance is first created
   ([`CONFIGURATION.md`](CONFIGURATION.md) §3).
3. Send a test message from that screen and confirm it arrives.
4. Update whatever renders the first-start configuration, so a future rebuild from empty
   storage comes up on the new credential rather than a deleted one.
5. Only now, deactivate the old credential at the relay. Deactivate before deleting —
   deactivating is reversible for a few minutes, deleting is not.

Do not do this by re-running infrastructure tooling that replaces the credential in one
step. That deletes the old password before Zitadel has the new one, which is the outage
this procedure exists to avoid.

---

## 5. Backup and recovery

Two things, and each is useless without the other:

| What | Where | If you lose it |
|---|---|---|
| Developer accounts | Zitadel's PostgreSQL database | Every developer signs up again — and gets a **new agent identity**, because the Identity Service ties an agent to the account that created it. Their existing agents are left behind with no owner. |
| The master key | Your secret manager | The database cannot be decrypted. Same outcome as losing the database, with the backup sitting there unreadable. |

Back up the database on your normal PostgreSQL schedule
([`deploy/storage/postgres/RUNBOOK.md`](../storage/postgres/RUNBOOK.md) §5 covers the
mechanics). Keep the master key somewhere separate — a backup containing both is a
backup where one stolen copy is enough.

**Test a restore.** Restore into a throwaway instance with the same master key and
confirm you can sign in. An untested backup of an unrecoverable store is not a backup.

Losing this is less severe than losing Vault — developers can sign up again, whereas a
lost agent key is gone for good — but the visible outcome is similar, because a new
account produces a new agent.

RAMP does not say how often you back up or how fast you must recover. You set them.

---

## 6. Limitations

- **The hostname cannot be changed after first start.** It is written into storage and
  published as the issuer.
- **The master key cannot be changed or recovered**, and everything stored depends on
  it.
- **A client secret cannot be read back**, only replaced.
- **Mail settings in the environment apply only at first start.** On an instance that
  already exists they are ignored, and the stored provider is edited instead — so the
  two can drift apart, and a rebuild from empty storage comes up on the environment's
  values, not the edited ones.
- **The Identity Service reads the secret only at start-up**, so rotating it needs a
  restart and a short window in which sign-ups fail.
- **The Identity Service will not start while this is unreachable**, even though it does
  not need it while running.
- **A pinned version.** v4.x is not usable yet because of a known crash at start-up,
  during its own migrations, that is not yet fixed.
- **No role or group mapping.** Anyone who can sign in can create an agent; whether that
  agent may spend is decided on the Exchange —
  [`src/exchange/RUNBOOK.md`](../../src/exchange/RUNBOOK.md) §4.2.
