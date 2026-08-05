# RAMP publisher discovery documents — overview

Two documents tell the rest of the world who represents this publisher and which
keys it signs with. This folder holds a filled-in copy of each, so you can look
at what your deployment is serving and tell whether it is right.

Audience: the DevOps engineer deploying the Edge Worker. Words that may be new
are explained the first time they appear.

| Address | File here | What it is |
|---|---|---|
| `/.well-known/ramp.json` | [`ramp.json.example`](ramp.json.example) | The commercial document. An AI bot that gets a `403` reads it to learn who sells access to this content and where to negotiate. The Exchange reads it to learn which account gets paid, and who is allowed to add content on the publisher's behalf. |
| `/.well-known/http-message-signatures-directory` | [`http-message-signatures-directory.example`](http-message-signatures-directory.example) | The publisher's key directory: its own public signing keys as a JWK Set (a JSON list of public keys, RFC 7517). |

---

## These are reference copies, not files to upload

**Nothing here is deployed.** The Worker builds both documents in memory on the
first request it receives, from its environment variables, and serves that same
pair to every later request. There is no file to place on the origin web server
and no file to keep in sync.

The Worker answers both addresses **itself**, even when the origin already
publishes its own copies at the same addresses — the Worker replies and the
origin is never asked. That makes the Worker's configuration the only thing that
decides what the world sees, and it makes one route setting load-bearing: **the
Worker's routes must cover `/.well-known/*`.** A route that misses those paths
breaks bot negotiation quietly — the bot receives a `403` telling it where to
look, follows the pointer, and finds whatever the origin happens to serve, or
nothing. See [`../../src/edge/DEPLOYMENT.md`](../../src/edge/DEPLOYMENT.md) §6.1.

Use these files two ways. Before you deploy, read them next to your own variable
values — [`template-env.json`](template-env.json) holds the exact values that
produce the two files here, so you can compare input against input as well as
output against output. After you deploy, `curl` both addresses and compare — see
"Check what you are serving" below.

Three of the variables in `template-env.json` reach neither document.
`EXCHANGE_URL` only supplies a header on a bot denial, `EXCHANGE_WBA_URL` is the
address the Worker fetches the *Exchange's* keys from, and `ORIGIN_URL` is the
address of the backend the Worker forwards verified requests to. They are in the
file because the Worker will not serve without them, not because they are
published.

`ORIGIN_URL` is one of a pair: a deployment sets either it or `SAME_ZONE_ORIGIN`.
Set neither and the Worker answers an error to every request, article traffic
included. There is one exception — a deployment where the CDN in front fetches
the origin itself, where setting neither is correct. Choosing between the two is
explained in
[`../../src/edge/CONFIGURATION.md`](../../src/edge/CONFIGURATION.md) §3.1, and
the exception is described in
[`../../src/edge/README.md`](../../src/edge/README.md).

So the file holds every setting the Worker itself requires, plus the two optional
ones that fill in the documents in this folder, and you can read it as the
minimum list. Two further things are needed before traffic is served and neither
is a variable: the routes above, and the publisher's tenant set up on the
Exchange ([`../../src/edge/CONFIGURATION.md`](../../src/edge/CONFIGURATION.md)
§5).

Both files are validated against the canonical schemas in
[`../../internal/rampwellknown/schema/`](../../internal/rampwellknown/schema/)
on every test run. The same run also requests both addresses through the
Worker's own routes, using the values in `template-env.json`, and compares each
response body against the file here — so they cannot drift away from what the
code serves. The wire shapes come from the RAMP protocol module
`github.com/RAMP-Protocol/protocol`.

---

## Where each field comes from

Every field is produced by an environment variable. If you deploy with the
Terraform module in [`../terraform/modules/cloudflare-edge/`](../terraform/modules/cloudflare-edge/),
the third column is the input name to set. Full variable reference:
[`../../src/edge/CONFIGURATION.md`](../../src/edge/CONFIGURATION.md) §2.

### `ramp.json`

| Field | Worker variable | Terraform input |
|---|---|---|
| `ver` | none — the Worker writes the protocol version | — |
| `role` | none — always `ROLE_PUBLISHER` for a publisher deployment | — |
| `domain` | `PROVIDER` | `provider_domain` |
| `exchanges[].domain` | `EXCHANGES_JSON` | `exchanges_json` |
| `exchanges[].endpoint` | `EXCHANGES_JSON` | `exchanges_json` |
| `exchanges[].relationship` | none — always `PROVIDER_RELATIONSHIP_DIRECT` | — |
| `exchanges[].ext.resource_owner_id` | `EXCHANGES_JSON` | `exchanges_json` |
| `supported_profiles` | `EXCHANGES_JSON` — see the note below | `exchanges_json` |
| `catalog_contributors` | `CATALOG_CONTRIBUTORS_JSON` | `catalog_contributors_json` |

The Terraform input name is the lowercase form of the variable name in every row
but one: `PROVIDER` is set by `provider_domain`, because `provider` is a reserved
word in Terraform's language.

**`supported_profiles` moves.** You write it inside each entry of
`EXCHANGES_JSON`, and it comes out at the **top level** of the document, as the
combined list from every entry with duplicates removed. It does not appear on the
`exchanges[]` entries in the served document. The example file shows the result,
not the input. If no entry names a profile, the field is left out of the document
entirely rather than served as an empty list.

**`ext.resource_owner_id` is the account that gets paid, and it has no default.**
The Exchange reads it out of the document this Worker serves, looking at the
entry whose `domain` equals the Exchange's own name — an exact string match, with
no cleanup of spelling.

Confirm two values with your Exchange operator before you deploy: the exact name
the Exchange calls itself, and the payee id to declare. **Getting them wrong
fails in two different ways, and only one of them is visible.**

- **A wrong exchange name, or a missing `ext`, is refused.** No entry matches the
  Exchange's own name, so every attempt to add this publisher's content comes
  back with the reason `missing_resource_owner_id`. The content never enters the
  catalog and nothing about it can ever be sold, while the Worker starts cleanly
  and serves this document without complaint. You see it in the push rejections.
- **A wrong payee id is accepted.** The Exchange checks only that the value is
  not empty. It never checks the id against anything, so a typo is stored on the
  catalog entry and used as the payee when the content settles. The content
  enters the catalog, the content sells, and the money is attributed to an
  account your Exchange operator does not recognise. Nothing rejects it and
  nothing warns.

That is why the example file leaves the field reading
`<the payee id the Exchange operator assigns — fill in>` rather than something
that looks like a real id. **Deploy it unchanged and you sell content under that
literal string.** Replace it with the value your Exchange operator gives you, and
read it back once with the `curl` check below. See
[`../../src/edge/CONFIGURATION.md`](../../src/edge/CONFIGURATION.md) §3.5.

**`catalog_contributors` names other parties, not the publisher.** The publisher
is already allowed to add its own content: the Exchange first compares the caller
against this document's own `domain` field, and only then looks through
`catalog_contributors`. So a publisher that adds its own content needs no entry
here, and may leave `CATALOG_CONTRIBUTORS_JSON` unset. With the variable unset the
field is absent from the served document, not served as an empty list. List a
party here when it is someone else — an ingestion partner, a verification vendor,
an Exchange that enriches entries. The `relationship` value is free text
describing the arrangement.

One trap: the comparison is between **hosts**. Spelling differences are cleaned
up — a scheme prefix, capital letters, a trailing dot, an explicit `:443` all
compare equal — but `www.publisher.example` and `publisher.example` are two
different hosts, not two spellings of one. If content is added from a host other
than the one in `domain`, that other host needs an entry here.

### `http-message-signatures-directory`

| Field | Worker variable | Terraform input |
|---|---|---|
| `keys[]` | `WBA_KEYS_JSON` | `wba_keys_json` |
| `revocation_url` | `WBA_REVOCATION_URL` | `wba_revocation_url` — leave unset, see below |

Each key carries `kty`, `crv`, `use`, `alg`, `x`, `not_before` and `not_after`,
and all seven are required. **There is no `kid` field**, and adding one is a
defect: a key is named by its RFC 7638 thumbprint, computed from the key itself,
so a hand-written name has nothing to attach to.

If you use the module in
[`../terraform/modules/publisher-manifest/`](../terraform/modules/publisher-manifest/),
you do not write `exchanges_json` or `catalog_contributors_json` by hand — that
module builds both strings from an Exchange hostname, a payee id and a
contributor id.

---

## Making the signing keypair

The key in the example file is a placeholder. It has the right length and
alphabet for the format, and its 32 bytes are not a point on the Ed25519 curve,
so no signature can ever verify against it. Replace it.

**Produce the replacement with the commands below — do not invent one.** Nothing
between this file and the wire checks that `x` is a real public key. The Worker
checks the length and the alphabet, and so does the Exchange; neither asks
whether the value is a key anyone actually holds.

The danger is not that a made-up string is obviously wrong — it is that you
cannot tell by looking. Some 43-character strings decode to a real point on the
curve, and a few of those are points that **anybody can produce valid signatures
for**, without holding any private key. Publish one of those and this
publisher's key directory — the document the Exchange reads to decide who may
write to its catalog — is advertising a key any caller can sign with. Others
decode to a point nobody holds the private half of, in which case your own
pushes simply never verify. Neither outcome is visible in the served document.

**The private half never leaves your key store.** Do not put it in this
repository, in a Worker variable, in Terraform state, or in a `tfvars` file. The
Worker publishes public keys and holds no secrets at all.

Generate a keypair and read out the public half:

```bash
# 1. The keypair. Keep this file; it is the private half.
openssl genpkey -algorithm ed25519 -out publisher-signing-key.pem

# 2. The public half, in the form the `x` field wants.
openssl pkey -in publisher-signing-key.pem -pubout -outform DER \
  | tail -c 32 | openssl base64 -A | tr '+/' '-_' | tr -d '=' ; echo
# Prints 43 characters. That string is `x`.
```

The last 32 bytes of the DER public key are the key itself; the pipeline
re-encodes them as unpadded base64url, which is what RFC 8037 specifies for an
Ed25519 JWK.

Then set `WBA_KEYS_JSON` to a JSON list holding one key, using that `x` and a
validity window you choose:

```bash
WBA_KEYS_JSON='[{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","x":"<the 43 characters>","not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z"}]'
```

Both timestamps are required and both are placeholders in the example file. The
window is closed at the start and open at the end: a key is valid from
`not_before` inclusive until `not_after` exclusive. At `not_after` exactly, it is
already invalid.

---

## Two publisher setups, and why a `404` can be correct

Which one applies is a per-deployment decision. **The two example files show the
two setups combined**, so that every field is visible somewhere. Your deployment
drops the parts it does not use — each setup below names them.

**The publisher adds its own content.** It signs those requests with its own key,
and the Exchange learns that key by fetching this directory. The directory must
carry the key, so `WBA_KEYS_JSON` is set. No `catalog_contributors` entry is
needed, because the document's own `domain` field already authorizes the
publisher. *Drop from the example:* the `catalog_contributors` array in
`ramp.json.example`, and leave `CATALOG_CONTRIBUTORS_JSON` unset. Note that the
`publisher-manifest` Terraform module below cannot produce this shape: it requires
a contributor id and always renders one entry, so a deployment in this setup sets
`CATALOG_CONTRIBUTORS_JSON` by hand or not at all.

**Someone else adds content on the publisher's behalf.** That party is named in
`catalog_contributors`, and its key lives in **its own** directory on **its own**
domain, which the Exchange fetches from there. The publisher issues no keys at
all: `WBA_KEYS_JSON` stays unset and this address answers `404`. *Drop from the
example:* the whole of `http-message-signatures-directory.example` — there is no
key document to serve.

A deployment can also be both at once — the publisher signs its own pushes *and*
names a partner that pushes too. That is the shape the example pair shows. The
Terraform module in
[`../terraform/modules/publisher-manifest/`](../terraform/modules/publisher-manifest/)
renders the `ramp.json` half of it, always emitting a `catalog_contributors`
entry; the key directory is separate, and you set `wba_keys_json` yourself or
leave it unset.

**A `404` on the key directory is a correct configuration, not a fault.** The
directory publishes the publisher's *own* signing keys, and a publisher that
issues none has nothing to publish. It is unrelated to the keys the Worker uses
to check paid delivery addresses — those come from the *Exchange's* directory and
are never served here. See
[`../../src/edge/CONFIGURATION.md`](../../src/edge/CONFIGURATION.md) §3.4.

---

## Why there is no `revocation_url`, and what to use instead

The field exists in the format, and this deployment leaves it unset **because
nothing serves the document it would point at.** A key-revocation list is not
among the addresses the Worker answers
([`../../src/edge/CONFIGURATION.md`](../../src/edge/CONFIGURATION.md) §3.4), so an
advertised `revocation_url` would send every verifier to an address that returns
nothing.

Retire a key by **rotating** it instead:

1. Shorten the outgoing key's `not_after` to the moment you want it to stop
   being selectable.
2. Append the new key to `WBA_KEYS_JSON`.
3. Redeploy, then sign your next catalog push with the new key.

**All three steps are required, and step 3 is what finishes the job.** Step 1 on
its own does not stop the old key working for catalog pushes.

The Exchange does not read your list when it checks a signature. It keeps **one**
key pinned for this publisher and checks against that. It chooses the pinned key
— on first contact, and again after a signature stops matching — by taking the
first key in your list whose window covers that moment. Re-reads are rate-limited,
so a rotation can take a short while to be picked up.

Nothing re-reads your directory on a schedule. The Exchange re-reads it only after
a signature has already failed against the pinned key. So while the old key is
still pinned and someone is still signing with it, every push keeps verifying and
the shortened `not_after` is never looked at. The pin moves when a signature
fails — in practice, the first push you sign with the new key. That is step 3.

**If the old private key was compromised, this matters.** Whoever holds it can
keep adding catalog entries until the pin moves, and step 1 does not move the pin
on its own. Sign a push with the new key straight after you redeploy, and tell
your Exchange operator that the old key is compromised.

Two more consequences, and they pull in opposite directions:

- **Leave the outgoing key first and still inside its window, and the rotation
  never happens.** Every re-pin picks that same key again, so pushes signed with
  the new key keep being rejected. This is the case operators hit.
- **Reordering alone is not retirement.** It moves the pin, but the outgoing key
  is still published and still inside its window, so any verifier that resolves a
  key by its fingerprint rather than by a pin — which is how a signer's key is
  resolved on the other RAMP surfaces — still accepts it.

Step 1 settles both of those. It makes the outgoing key stop being selectable at
a time you choose, whatever order the list is in, and it is the only signal that
reaches a verifier resolving by fingerprint. With `revocation_url` unset there is
nothing else to withdraw a key with.

---

## Check what you are serving

These two checks are the ones for the discovery documents, and they live here.
The full post-deploy list is in
[`../../src/edge/DEPLOYMENT.md`](../../src/edge/DEPLOYMENT.md) §8, whose checks C
and D point back at this section for the detail below.

Replace `<host>` with the publisher hostname the Worker runs on.

**The commercial document.**

```bash
curl -s https://<host>/.well-known/ramp.json
# Expect: 200, and JSON with "role":"ROLE_PUBLISHER", your PROVIDER value as
#         "domain", and an "exchanges" entry carrying
#         "ext":{"resource_owner_id":"…"}.
```

Compare the whole document field by field against
[`ramp.json.example`](ramp.json.example). Two things to look at first:

- If `ext` is missing, this publisher's content cannot enter the catalog. Fix
  `EXCHANGES_JSON` before going further.
- If `resource_owner_id` is present but is not the exact value your Exchange
  operator gave you, nothing will complain and the content will sell under the
  wrong account. This `curl` is the only place that mistake is visible.

**The key directory.**

```bash
curl -s -D - https://<host>/.well-known/http-message-signatures-directory
# Expect, for a publisher that issues keys:
#   HTTP/2 200
#   content-type: application/jwk-set+json
#   a "keys" array whose entry has "kty":"OKP", "crv":"Ed25519", a 43-character
#   "x", and no "kid".
#
# Expect, for a publisher that issues no keys:
#   HTTP/2 404   — correct, see above.
```

**Read the `x` value in that output and check it against the one you put in
`WBA_KEYS_JSON`.** Do not decide from the status and the content type alone. Your
own web server may already publish a key document at this same address, and if
the Worker's routes do not cover `/.well-known/*` it is that document the world
receives — served with the same status and quite possibly the same content type,
so the response looks correct while the keys the world uses to authenticate this
publisher are not yours. The `x` value is the one part of the answer another
server cannot produce by accident. If it does not match, the routes are the first
thing to check
([`../../src/edge/DEPLOYMENT.md`](../../src/edge/DEPLOYMENT.md) §6.1).

Day-to-day operation is in
[`../../src/edge/RUNBOOK.md`](../../src/edge/RUNBOOK.md).
