# Buy a demo article and inspect its RAMP evidence chain

Use this guide to buy a paid article through the demo's MCP endpoint, capture the
transaction id it returns, and — if the stack operator grants you privileged
access — render the evidence chain for that transaction.

The two halves have different access models, and you may be given only the first:

- **Buying** needs the public MCP endpoint, a sign-in, a registered agent with
  money on it, and an article address. Nothing else.
- **Inspecting the evidence** needs SSH access to the deployment's VM as a named
  operator, from one of your own registered addresses, plus the Exchange's
  internal admin plane, the Broker database password, and permission to read
  CloudWatch logs. A buyer does not automatically hold any of that.

If you only have buyer access, sections 1 and 2 are your whole journey. Ask the
stack operator to run section 3 and show you the output.

## What the chain is meant to prove

`make ledger TX=<transaction-id>` prints what three independent parties recorded
about one licensed transaction, and re-verifies both signatures offline from the
bytes those records stored.

The claim it supports: **a chain that lines up across all three parties is
evidence precisely because no single party could have produced it alone.** The
Exchange holds the signed offer and the agent's acceptance. The Broker
independently recorded having offered that offer to that agent, before any
transaction existed. The edge worker recorded the delivery it authorized, and the
digest it computed over the URL it was presented matches the digest the Exchange
stored when it minted that URL. Nothing is re-derived: the tool verifies the
stored signature against the stored key over the stored bytes.

---

## 1. What the stack operator must give you

### To buy an article

| what | example shape |
|---|---|
| the MCP connector URL | `https://mcp.demo.<domain>/mcp` |
| how to sign in | a local user the operator created, or Google if configured |
| the article address to buy | `https://demo.<domain>/articles/philosophers/thales-of-miletus.txt` |
| funding | either a confirmation that your agent already holds money, or the operator's promise to credit it once you report your `billing_ref` |

### To inspect the evidence — privileged, and separate

| what | why |
|---|---|
| a checkout of this repository, at the revision the stack was deployed from | `make ledger` is a tool in this tree, not something the deployment serves |
| an open SSH tunnel to the VM, or the operator running section 3 for you | the admin plane and the database are on the VM's loopback interface only |
| your own entry in the deployment's `ssh_operators`, and a connection from one of the addresses it lists for you | each key is installed with an OpenSSH `from=` restriction holding only its own addresses, so being an operator is not enough on its own — you must also be at one of your own addresses |
| a resolved `RAMP_ADMIN_URL` | normally `http://127.0.0.1:8082` through the tunnel |
| a resolved `BROKER_DB_URL`, including the password | the Broker's routing record is row 2 of the chain |
| AWS credentials that can read CloudWatch Logs, and the exact log group name | rows 5 and 6 come from the edge worker's log lines |

**Before you share a screen.** `BROKER_DB_URL` carries the deployment's database
password. Set it before the call starts, not during it, and keep it out of any
terminal you project. The rendered chain itself is safe to show: the signed URL
is a live bearer capability until it expires, and the evidence contract withholds
it deliberately — the chain joins on its SHA-256 digest instead.

---

## 2. Buy the article

1. **Connect the assistant.** In an assistant that supports custom MCP
   connectors, add the connector URL the operator gave you. The assistant walks
   you through sign-in, and afterwards holds a token for an agent whose signing
   key the Identity Service custodies. Every tool call below is signed with that
   key on the agent's behalf.

2. **Register the agent.** Ask the assistant to register with the exchange, naming
   it — `ramp_register` takes the exchange's domain and the registration details
   that exchange asks for, which it publishes in its own `/.well-known/ramp.json`.
   `ramp_status` with the same domain works too if the agent is already
   registered. The reply carries the agent's `billing_ref`, a random handle the
   Exchange minted.

3. **Get the agent funded.** A fresh agent's balance is empty and the demo
   article is not free. Give the `billing_ref` to the stack operator, who credits
   that specific account. Ask them to confirm before you continue; a purchase
   against an empty account fails in a way that looks like a protocol error.

4. **Ask for the article by its address.** Discovery is by URL only, so ask for
   the address rather than a search:

   > Fetch https://demo.\<domain\>/articles/philosophers/thales-of-miletus.txt
   > through RAMP and quote what it says.

5. **Confirm the purchase really happened.** In the assistant's transcript you
   should see `ramp_discover` and then `ramp_execute`. There is no separate fetch
   step — the Identity Service fetches the content on the agent's behalf and
   returns the body inside the `ramp_execute` result. The answer quotes the
   article including its retrieval-proof markers, `RAMP-DEMO-CANARY-8FK3J2-0418`
   among them; the full marker list is in `deploy/fixtures/demo/CATALOG.md`. Those
   markers exist nowhere but the origin file, so quoting them proves the whole
   loop ran.

6. **Capture the transaction id.** `ramp_execute` returns one per item. Ask the
   assistant for the raw tool result rather than its summary — a summary usually
   drops the id, and it is the only input section 3 needs.

If step 4 or 5 fails, see [Purchase problems](#purchase-problems) below.

---

## 3. Render the evidence chain — privileged

This section needs everything in the privileged table above. If you were not
given it, hand the transaction id to the stack operator and ask them to run this.

### Open the tunnel

Both services are published on the VM's loopback interface only, so nothing
reaches them from outside without a tunnel. In its own terminal:

```bash
ssh -N ubuntu@<the VM address the operator gave you> \
    -L 8082:127.0.0.1:8082 \
    -L 5432:127.0.0.1:5432
```

`-N` means "forward ports, run no command", so this prints nothing and stays in
the foreground until Ctrl-C closes it. Add `-i <path-to-your-key>` if your key is
not one your SSH client offers by default.

Check it before going further, from a second terminal:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8082/
```

`404` is the answer you want: the request reached the admin plane and passed the
address allowlist, and that router simply has no handler on `/`. `403` means the
allowlist rejected you, which is the deployment's configuration rather than your
tunnel. A connection error means the tunnel is not up.

The stack operator, who holds the Terraform state, can build the same command
without being told the address — see
[Reaching the admin plane and the database over SSH](deploy-demo-aws.md) in the
deployment guide.

### Run it

From the repository root:

```bash
export RAMP_ADMIN_URL="http://127.0.0.1:8082"
export BROKER_DB_URL="postgres://ramp:<password>@127.0.0.1:5432/ramp?sslmode=disable"
export RAMP_EDGE_LOG_GROUP="/aws/lambda/us-east-1.ramp-demo-edge"

make ledger TX=7f3a1c2e-9b4d-4e51-a0c7-2d8e6f105b93
```

Those are real shapes, not invented ones. What varies between deployments:

| value | where the shape comes from |
|---|---|
| `127.0.0.1:8082` | the local end of your tunnel. 8082 is the Exchange admin listener's default port, so a tunnel that forwards it unchanged lands here |
| `ramp` / `ramp` | the database user and database name. Both are fixed by the stack, so only the password differs per deployment — ask the operator for it |
| `127.0.0.1:5432` | the local end of the same tunnel. The Broker and the Exchange share one database, so one forwarded port serves both legs |
| `sslmode=disable` | correct here, and only here: the connection is already inside the SSH tunnel |
| `us-east-1.` | a **prefix**, not the region you are reading. It names where the function was deployed. The logs land in the region that served the request |
| `ramp-demo-edge` | `<name_prefix>-edge`. `ramp-demo` is the default for the demo stack; a deployment that set `name_prefix` differently changes this half |

**Two of the three are optional, and the tool says what it lost.** Omit
`BROKER_DB_URL` and the chain renders without the Broker's routing decision
(row 2). Omit `RAMP_EDGE_LOG_GROUP` and it renders without the delivery record
(rows 5 and 6). Both cases still exit zero and mark the missing rows, so a
partial chain is a real option when the operator gives you only part of the
access — but read the marks, because a missing row looks the same whether the
source was never read or never written.

Run `go run ./src/broker/cmd/ramp-ledger -h` for the full flag set, including
`-broker-window` for the time window used to find the Broker's routing decision
and `-edge-regions` for the regions swept for the delivery record.

---

## 4. What a complete chain looks like

Scrubbed to placeholder hosts; the shape and every field are from a real run.

```
RAMP evidence chain
  transaction 00000000-0000-4000-8000-000000000000
  tenant      tenant-demo

PARTY                    STEP                      EVENT                                                            CORRELATOR                    CRYPTO
Exchange                 1. offer signed           issued and signed offer tenant-demo:https://publisher.example/…  offer=tenant-demo:https://…   EdDSA 10c3931264c43d7438…
Broker                   2. offer routed           offered tenant-demo:https://publisher.example/… among 1 candid…  req=00000000-0000-4000-8…     unsigned audit row
Agent agents.example     3. offer accepted         signed an acceptance as smoke-agent.agents.example               idem=tx-00000000000000000…    EdDSA 05f9c6b2f1b2827a71…
Exchange                 4. URL minted             minted a signed retrieval URL, expiring 2026-08-16T22:11:22Z     idem=tx-000000000000000…      sha256 fb00e26cd3ca527da…
Edge                     5. URL verified           verified the signature on GET /articles/… and authorized deli…   req=00000000-0000-4000-8…     sha256 fb00e26cd3ca527da…
                                                   very, served from eu-central-1
Edge                     6. origin fetch released  released the request to the CDN for the origin fetch (cdn-orig…  req=00000000-0000-4000-8…     —
Exchange                 7. reporting              PENDING, due 2026-08-17T22:06:22Z                                tx=00000000-0000-4000-8…      —

ASSERTIONS
  [v] Exchange offer signature re-verifies offline
        ed25519.Verify accepted 1218 canonical bytes against the stored Exchange key
  [v] Agent acceptance signature re-verifies offline
        ed25519.Verify accepted 296 canonical bytes against the stored agent key
  [v] Acceptance binds this exact agreement (all 4 signed members)
        offer_sig, requester_id, requester_domain and idempotency_key inside the signed bytes all match the row
  [v] Transaction-log key derives from the signed request key
  [v] Broker independently recorded offering this offer
  [v] Broker's agent and the signing agent are the same identity
  [v] Delivered URL is the URL the Exchange minted
        sha256 fb00e26cd3ca527dab291c5ddb613c7c7fba94052927adf34e178ad7b83f6c88 on both sides

7 of 7 checked assertions hold.
```

### The lines worth pointing at

**Rows 4 and 5 carry the same digest.** The Exchange stored it when it minted the
URL; the edge worker computed it over the URL it was actually presented. The last
assertion confirms full equality — not a shared prefix.

**Row 2 comes from a different party.** The Broker recorded having offered this
offer to this agent before any transaction existed, so it is an independent
witness rather than the Exchange corroborating itself.

**The third assertion is the one that turns two signatures into one agreement.**
Verifying both proves only that the Exchange signed some offer and the agent
signed some acceptance. Comparing all four members of the signed acceptance
payload against the row is what refuses a genuine acceptance spliced onto a
different offer, and — through the idempotency key — one acceptance reused across
two executes.

**Row 6 makes the strongest claim the record earns, and no more.** It has three
forms:

| row 6 says | when |
|---|---|
| origin fetch released | the worker never saw a response |
| origin response observed | the worker waited, but the status is missing or not a success |
| content served | the worker waited and recorded a success status |

On CloudFront — which is what this stack runs — the worker runs at the
viewer-request event: it verifies the signature, writes its record, and hands the
request back for the CDN to fetch the origin. Nothing in this chain observed an
origin response, so the row stays at the first form. That is why the sample above
shows it, and it is not a defect.

On the runtimes where the worker waits for the origin itself, the status decides
between the other two. `fetch()` resolves normally for 404 and 500, so a request
that reached the origin and got an error looks identical to a successful one
until you read the status — which is exactly why the row will not say "content
served" without it. Anything unreadable, missing or outside a successful range
falls to the weaker form: a drift may only ever weaken this row, never promote
it.

### Three marks, not two

`[v]` held. `[x]` ran and failed — the chain contradicting itself, which is what
the tool exists to surface. `[?]` could not be checked because a source was never
read. An operator with a closed tunnel must not see what an operator holding a
forged row sees, so the summary counts them apart.

---

## 5. Troubleshooting

### Purchase problems

| symptom | cause |
|---|---|
| Sign-in never completes | Identity Service or Zitadel. The operator reads their logs on the VM |
| `ramp_register` fails | The Exchange rejected the agent. The operator's seeding step may not have run |
| Execute fails on price or balance | The agent's account is empty, or the credit went to a different `billing_ref`. Report the exact `billing_ref` from `ramp_status` and ask the operator to re-check |
| Discovery returns nothing | The Broker does not know the Exchange, or the address is not in the demo catalog. This is a stack-owner problem — see the appendix |
| The answer summarizes rather than quotes | Ask again for the article text verbatim, and for the raw `ramp_execute` result. Without the raw result you have no transaction id |

### Evidence problems

**A missing source degrades to a stated absence, and the command still exits
zero.** The chain reports "not recorded" rather than failing, so judge a run by
confirming every row populates — not by confirming the command succeeded.

| symptom | cause |
|---|---|
| Row 2 absent | `BROKER_DB_URL` unset, the tunnel is down, or the routing decision falls outside the search window — widen it with `-broker-window` |
| Rows 5 and 6 absent, purchase made seconds ago | CloudWatch has not made the log line searchable yet. Wait and re-run the same command; the transaction id stays valid |
| Rows 5 and 6 absent, purchase made minutes ago | The request was served by a point of presence outside the swept regions. Name it with `-edge-regions`, or ask which regions hold the log group |
| Rows 5 and 6 absent after an edge deploy | Propagation. The serving location was still on the previous bundle and wrote no record |
| Row 7 shows `PENDING` | Usage has not been reported yet. That is a true statement about an open obligation, not a gap — report usage first if the demo needs `RECEIVED` |
| `403` from the admin plane | The allowlist rejected the source address, which is about the admin configuration and not the tunnel |
| `404` on the evidence route | The running Exchange image predates the evidence handler. No amount of configuration fixes this; the image has to be rebuilt and pushed |
| Connection refused on `RAMP_ADMIN_URL` | The tunnel is not up |

Rows 5 and 6 read the same record, so they are absent together or present
together. Only row 5 names the region, because that is where the sweep found the
record rather than something the worker wrote.

---

## Appendix: stack-owner preflight

These checks belong to whoever deployed the stack. A buyer should be told they
passed, not asked to run them.

Every operator script defaults to the staging stack, so `STACK_DIR` is not
optional — without it the scripts read a stack that was never deployed, which
surfaces as a Terraform provider error rather than anything mentioning the wrong
environment:

```bash
export STACK_DIR="$PWD/deploy/terraform/stacks/demo-aws"   # absolute path, from
                                                           # the repository root
```

**The public path.** The Broker must know the Exchange, and a discovery must
return offers. This has failed before, and it fails in a way that looks like an
agent problem rather than a seeding one, so check it rather than assuming:

```bash
deploy/terraform/scripts/smoke.sh
```

A passing smoke check proves the public purchase and delivery path: discovery
through the Broker, a licensed purchase from the Exchange, and a fetch the edge
verified. It proves nothing about the evidence half. It does not touch the admin
endpoint, does not open an SSH tunnel, does not reach Postgres from outside the
VM, does not exercise anyone's AWS permissions, and says nothing about whether
CloudWatch has indexed the edge's record yet. Each of those is checked below.

**The evidence half.** With the tunnel open, confirm the running Exchange image
actually carries the evidence handler:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
    "http://127.0.0.1:8082/ops/transaction-evidence?tx=not-a-uuid"
```

`400` is the answer you want — the route exists and rejected the malformed id.
`404` means the deployed image predates the handler. `403` means the allowlist
rejected your source address. Then check the database leg and the log leg the
same way, before a demo rather than during one: open `psql` against the forwarded
port, and confirm the edge log group exists in a region the distribution serves.

**The edge worker.** The delivery record rows 5 and 6 read is written by the
worker. A point of presence still running an older bundle serves the request
perfectly and records nothing, so the chain shows the delivery leg absent for a
reason that looks like a defect. After any edge deploy, allow the propagation
wait the deployment guide describes before generating the transaction you intend
to show.
