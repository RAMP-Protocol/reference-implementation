# RAMP catalog feed v1

`catalog-feed-v1.schema.json` is a JSON Schema (Draft 2020-12) for **one line** of a RAMP
catalog feed — the JSON-Lines file a publisher supplies to get content into an Exchange.

## Why this exists

The feed is the only way content enters the catalog. There is no SQL write path and no
bulk-import endpoint: every resource arrives through the signed
`CatalogService.PushResources` RPC, driven by `src/exchange/cmd/ramp-ingest` over a feed
file.

```
feed.jsonl -> parse -> map to ramp.v1.ResourceEntry -> RFC 9421 sign -> PushResources -> catalog
```

That made the line format load-bearing and undocumented at the same time. This directory
is the specification, and the schema next to it lets a publisher check a feed before
pushing it — the ingester rejects an unknown field outright rather than ignoring it, so a
typo that a lenient parser would skip fails the whole file here.

## The format

A feed is [JSON Lines](https://jsonlines.org/): one JSON object per line. The file as a
whole is **not** a JSON document, which is why the schema describes a line and not a file.

- UTF-8, one resource per line, no envelope and no header line.
- Blank lines are skipped.
- A line must contain **exactly one** JSON object. Anything after the closing brace fails
  the line, so two objects on one line is an error rather than two records.
- Maximum line length is 16 MiB. A resource with many terms can exceed the usual 64 KiB
  scanner default, which is why the limit is raised.
- **Unknown fields are rejected**, not ignored. The line schema is closed.
- Errors name the 1-based line number.

A push is **all or nothing**. One bad line voids the entire file and nothing is persisted,
so a feed cannot land half-applied. The whole batch also travels as a single request with
a **1 MiB body cap**, which is the practical limit on how many resources one push carries.

A feed only ever **upserts**. There is no delete or tombstone: removing a resource from
the feed does not remove it from the catalog.

## Line schema

### Top level

Everything except `domain` and `path` is optional.

| Field | Type | Notes |
|---|---|---|
| `domain` | string | **Required.** Publisher domain. The Exchange derives the owning tenant from this server-side; a caller-supplied tenant that disagrees is rejected, never honored. |
| `path` | string | **Required.** Resource path including the leading slash. The catalog URI is `scheme://domain + path`. |
| `title` | string | Surfaces on the offer. |
| `license` | object | The governing license document, shared by every term on the line. See below. |
| `terms` | array | Declared licensing offers, at most 32. See below. |
| `content_id` | string | Stable publisher-side id. When present it is the upsert key. |
| `word_count` | int32 | Audit metadata. |
| `estimated_quantity` | int32 | Quantity in the metering unit. For text, roughly `word_count * 1.32`. |
| `content_hash` | string | Digest of the body. No format constraint — pass-through. |
| `hash_method` | string | Algorithm that produced `content_hash`. |
| `source` | string | How the entry was discovered. **Full uppercase enum name** — see "Enum spellings". |
| `provenance_source` | string | Free text, e.g. a CMS plugin name. |
| `provenance_timestamp` | string | RFC3339. When the metadata was collected. Becomes the offer's `data_as_of`. |
| `resource_mutability` | string | How volatile the resource is. **Full uppercase enum name.** Omitted defaults to `RESOURCE_MUTABILITY_STATIC`. |
| `ext` | object | Open extension object, carried through verbatim. Must be an object. |
| `ext_critical` | array of string | Names of `ext` keys a consumer must understand to use the offer safely. |
| `attestations` | array | Signed claims about the resource. See below. |

Two traps worth stating plainly:

- **A line with no `terms` is accepted** and stored, but it produces **no offer**, so the
  resource is invisible to agents. This is the most common reason a feed ingests cleanly
  and then nothing is discoverable.
- **`resource_mutability` is a typed top-level field.** A value placed inside `ext` is not
  read. Previews are the opposite case: there is no typed previews field, so previews ride
  inside `ext` under a `previews` key.

### `license`

| Field | Type | Notes |
|---|---|---|
| `id` | string | SPDX short-id such as `CC-BY-4.0`, or a publisher catalog doc-id. |
| `uri` | string | Canonical identity of the document (RFC 3986). Not URL-validated — non-URL schemes are legitimate. |
| `uri_digest` | string | `method:hexdigest`. **Required whenever `uri` is set.** |
| `name` | string | Human-readable name. |

`uri_digest` accepts only `sha256:`, `sha384:` and `sha512:` with a matching hex length.
Without a pinned digest the referenced document can be swapped after the offer is signed,
and a forgeable digest would defeat exactly the protection the field exists for — so md5
and sha1 are refused.

### `terms[]`

Each element becomes one license term. `semantics` and `pricing` are required.

| Field | Type | Notes |
|---|---|---|
| `semantics` | string | `enumerated` or `reference_only`. |
| `functions` | array of string | Permitted function tokens, e.g. `ai-input`, `ai-train`, `ai-index`, `search`. At most 64. |
| `prohibited_functions` | array of string | Prohibited function tokens. Must not intersect `functions`. |
| `user_types` | array of string | e.g. `academic`, `commercial_entity`. |
| `geos` | array of string | ISO 3166-1 alpha-2 codes, or one of `*`, `EU`, `EEA`. |
| `pricing` | object | **Required on every term.** |
| `quotas` | array | Usage caps. Not billing quantities. |
| `obligations` | array | Post-use requirements such as attribution. |
| `scopes` | array of string | Delegation scopes a requester must cover, e.g. `subscription:premium`. At most 64. |

Training, inference and retrieval are distinguished by **function token** — `ai-train` vs
`ai-input` vs `ai-index` — not by a separate field.

`scopes` is the **only** input to term selection. Metadata never changes which term or
price an agent is offered.

Under `reference_only` the license document is authoritative, and the machine fields
(`functions`, `quotas`, `obligations` and the rest) are **permitted** as an advisory
readable summary of that document. The publisher certifies the summary does not contradict
the document; nothing checks that at ingest. A `reference_only` term must carry
`license.uri`.

### `terms[].pricing`

| Field | Type | Notes |
|---|---|---|
| `model` | string | **Required.** `free`, `per_unit` or `flat`. |
| `rate` | string | Exact decimal **string**. See "Money is a string". |
| `unit` | string | Metering basis. **Required for `per_unit`.** Ignored for `free` and `flat`. |
| `currency` | string | ISO 4217, e.g. `EUR`. |

- `free` requires a zero rate: omit it, or give any value that reduces to zero such as
  `"0"` or `"0.00"`. A non-zero value is refused — an absent `pricing` block is not the
  same as free, and a free term is never inferred.
- `per_unit` requires both `unit` and an explicit non-empty `rate`.
- `flat` requires an explicit non-empty `rate` and takes no unit.

A subscription is not a pricing model. It is `model: "free"` plus `scopes`.

A bare `unit` must be a registered metering token — `accesses`, `tokens`, `fetches` and so
on. A `vendor:token` value is a deliberate custom unit and is not checked against the
registry.

### `terms[].quotas[]`

All three fields are required.

| Field | Type | Notes |
|---|---|---|
| `metric` | string | What is counted, e.g. `accesses`, `tokens`, `impressions`. |
| `limit` | integer | At least 1. A limit of zero would grant nothing. |
| `window` | string | `hourly`, `daily`, `monthly` or `total`. |

A bare `metric` must be a registered quota token; `vendor:token` is a custom metric and is
not registry-checked.

### `terms[].obligations[]`

| Field | Type | Notes |
|---|---|---|
| `kind` | string | **Required.** `attribution`, `contribution`, `share_alike`, `network_copyleft`, `notice`, `other`. |
| `trigger` | string | **Required.** `on_use`, `on_distribution`, `on_network_service`, `on_derivative`. |
| `scope_license` | string | SPDX short-id a derivative must carry. Required by `share_alike`. |
| `detail` | string | Human-readable specifics, e.g. the wording of a credit line. |

`trigger` really is required. Omitting it fails the line, even though it looks optional
next to `scope_license` and `detail`.

### `attestations[]`

Every field is optional. The ingester carries an attestation through without verifying its
signature.

| Field | Type | Notes |
|---|---|---|
| `verifier` | string | Domain of the attesting party. |
| `kid` | string | Key identifier — an RFC 7638 JWK thumbprint. |
| `attested_at` | string | RFC3339. |
| `uri` | string | The resource the claims are about. |
| `claims` | object | Asserted facts, e.g. `word_count`, `language`, `iab_categories`. Must be an object. |
| `signature` | string | Ed25519 signature over the other fields. |

## Example feed

`example.jsonl` in this directory is a complete, valid feed covering the whole field
surface. Its eight lines are, in order:

| Line | Shows |
|---|---|
| 1 | The minimum: a domain, a path, and one free term. Nothing else is required. |
| 2 | Two terms on one resource — free for academic and non-profit users, priced per access for commercial ones, with a daily quota. |
| 3 | Flat pricing with an attribution obligation. |
| 4 | An open license with two obligations, including `share_alike` carrying a `scope_license`. |
| 5 | A `reference_only` term gated behind a subscription scope. |
| 6 | Every metadata field at once — `content_id`, counts, hash, ingestion source, provenance, mutability, `ext` with previews, `ext_critical`, and an attestation. |
| 7 | A second publisher, per-second pricing, and a `vendor:`-namespaced custom quota metric. |
| 8 | A CMS-style record writing `semantics` and `pricing.model` in uppercase, which is accepted — see "Case sensitivity". |

Every line parses, maps to a `ResourceEntry`, and passes both protovalidate and term
validation with no vocabulary warnings. It is documentation, not a test fixture — nothing
runs against it, and the signature on line 6 is a placeholder that no one verifies.

Reformatted for reading, line 2 is:

```json
{
  "domain": "publisher.example",
  "path": "/article/how-photosynthesis-works",
  "title": "How Photosynthesis Works",
  "license": {
    "id": "pub-ai-2026",
    "uri": "https://publisher.example/licensing/ai",
    "uri_digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "name": "Publisher AI License"
  },
  "terms": [
    {
      "semantics": "enumerated",
      "functions": ["ai-input", "search"],
      "prohibited_functions": ["ai-train"],
      "user_types": ["academic"],
      "geos": ["DE", "EU"],
      "pricing": {"model": "free", "rate": "0", "currency": "EUR"}
    },
    {
      "semantics": "enumerated",
      "functions": ["ai-input"],
      "user_types": ["commercial_entity"],
      "geos": ["DE", "EU"],
      "pricing": {"model": "per_unit", "unit": "accesses", "rate": "0.02", "currency": "EUR"},
      "quotas": [{"metric": "accesses", "limit": 1000, "window": "daily"}]
    }
  ]
}
```

One resource offered two ways. Academic users in Germany and the EU may use it as model
input or in search at no charge, but may not train on it. Commercial users in the same
regions pay 0.02 EUR per access, capped at 1000 accesses a day. Training is refused in
both, because `ai-train` is prohibited in the first term and simply absent from the
permitted list in the second.

The agent picks the term it can honor and carries the compliance obligation. The Exchange
does not evaluate restrictions to decide what an agent may see — only `scopes` gates term
visibility.

## Money is a string

`pricing.rate` is an **exact decimal string, never a JSON number**. `{"rate": 0.02}` fails
the line; `{"rate": "0.02"}` passes.

Money is decimal on every RAMP surface to avoid binary rounding and to allow arbitrary
sub-cent precision such as `"0.0001234"`. The accepted form is non-negative, with no sign,
no exponent and no leading dot, up to 32 characters. Insignificant trailing zeros are
stripped on ingest, so `"0.050"` is stored as `"0.05"` and `"5.0"` as `"5"`.

## Enum spellings

The format mixes two spelling conventions. This is the least guessable thing about it, so
check it first when a value is refused.

**Lowercase short names** — `terms[].semantics`, `pricing.model`, `quotas[].window`,
`obligations[].kind`, `obligations[].trigger`:

```json
{"semantics": "enumerated", "pricing": {"model": "per_unit"}}
```

**Full uppercase proto enum names** — `source` and `resource_mutability`:

```json
{"source": "INGESTION_SOURCE_CMS_API", "resource_mutability": "RESOURCE_MUTABILITY_LIVE"}
```

For both of those, the `_UNSPECIFIED` sentinel is refused. Declaring
`RESOURCE_MUTABILITY_UNSPECIFIED` is an error; omitting the field is not, and defaults the
offer to `RESOURCE_MUTABILITY_STATIC`.

### Case sensitivity

The two groups above differ in more than spelling convention: **one is case-insensitive
and the other is not.** Getting this backwards is a common source of confusion, so the
split is worth stating field by field.

**Case-insensitive** — the value is lowercased before it is matched, and surrounding
whitespace is trimmed. `"ENUMERATED"`, `"Enumerated"` and `"enumerated"` all mean the same
thing:

- `terms[].semantics`
- `terms[].pricing.model`
- `terms[].quotas[].window`
- `terms[].obligations[].kind` and `terms[].obligations[].trigger`

**Case-normalized** — accepted in any case and rewritten to a canonical form, which is what
the Exchange stores and what appears on the offer. Aliases are resolved at the same time,
so `generative-ai` becomes `ai-input`:

- `terms[].functions` and `terms[].prohibited_functions` — lowercased
- `terms[].user_types` — lowercased
- `terms[].geos` — uppercased, so `de` is stored as `DE`

**Case-sensitive** — matched exactly, with no folding. A lowercase spelling is rejected:

- `source` and `resource_mutability` must be the full uppercase proto enum name.
- A **bare** `pricing.unit` or `quotas[].metric` must be lowercase. `"accesses"` is
  accepted and `"ACCESSES"` is refused, because the registered-token form is
  `[a-z0-9-]+`. A `vendor:namespaced` value is exempt and may mix case.

Emitting everything in the canonical form — lowercase short names, uppercase proto enum
names — sidesteps the distinction entirely, and is what a feed should aim for. The
tolerance exists so a publisher whose CMS emits `"FREE"` is not blocked; it is not an
invitation to mix styles.

## Identity and idempotency

The catalog row key is derived, not supplied:

- With `content_id`, the row is keyed on it. Two lines sharing a `content_id` collapse to
  **one** row, last write wins — including two lines in the same file.
- Without `content_id`, the row is keyed on the URI. Re-pushing the same `domain` + `path`
  updates the same row rather than creating a second one.

Either way a re-push is an update, so re-running a feed is safe.

A URI belongs to exactly one catalog row. Re-pushing the same resource updates that row in
place, but a *different* resource claiming a URI another row already owns is rejected —
otherwise it would shadow the incumbent's terms and signing identity. That applies within
a single file too: two lines with different `content_id` values but the same `domain` and
`path` collide.

## Where each rule is enforced

A rejection comes from one of three places. Knowing which one narrows the fix.

**1. Parse.** JSON well-formedness, exactly one object per line, no trailing content,
unknown fields, and field types — a string where an integer belongs. Reports the line
number.

**2. Map.** Value validation after a clean parse: enum name resolution, RFC3339
timestamps, the money form, `per_unit` needing a unit, `free` needing a zero rate, and the
requirement that `ext` and attestation `claims` are objects.

**3. Server**, at the `PushResources` RPC. Three groups:

- *Shape rules* — `reference_only` needing `license.uri`, `uri` needing `uri_digest`, at
  most one restriction per axis, quota limits of at least 1, `permitted` and `prohibited`
  not intersecting, `share_alike` needing a `scope_license`.
- *Registry membership* — an unregistered bare `pricing.unit` or `quotas[].metric` is a
  hard rejection. An unregistered bare **restriction** token is only a warning, returned in
  the response, because that vocabulary is open and forward-compatible.
- *Authorization and identity*. Each offending entry gets a machine-readable reason, and
  the failed push reports them as `uri (reason)` pairs:

| Reason | Meaning |
|---|---|
| `unknown_publisher_domain` | No tenant is registered for the line's `domain`. |
| `tenant_mismatch` | The caller-supplied tenant disagrees with the one derived from `domain`. |
| `caller_not_in_catalog_contributors` | The publisher's `/.well-known/ramp.json` does not authorize this caller to contribute. |
| `missing_resource_owner_id` | The manifest's entry for this Exchange carries no `resource_owner_id`, so there is no settlement payee. It is never inferred. |
| `invalid_license_terms` | A term failed validation. |
| `too_many_terms` | More than 32 terms on one entry. |
| `uri_owned_by_other_resource` | The URI already belongs to a different catalog row, or two entries in this push claim it under different keys. |
| `invalid_entry` | The entry would not convert for storage — a missing `domain` or `path`, or terms that will not marshal. |

Any one of these voids the whole push. The reasons name every offending entry at once, so
one round of fixes can address them all.

The schema in this directory covers layers 1 and 2 in full, plus the per-line shape rules
from layer 3.

## What the schema deliberately does not check

Each of these is a decision, not an oversight.

- **Vocabulary membership** for `functions`, `prohibited_functions`, `user_types`, `geos`,
  `pricing.unit` and `quotas[].metric`. Those registries are generated from options on the
  protocol's own enums, so restating the tokens here would create a second copy that drifts
  on the next protocol version. It would also misreport behavior, since an unregistered
  restriction token warns while an unregistered unit or metric rejects. The schema checks
  the token *form* — bare or `vendor:namespaced` — and leaves membership to the Exchange.
- **Stateful server gates** — tenant resolution, caller signature, contributor
  authorization, the resource-owner payee, URI ownership across tenants, and the
  all-or-nothing batch rule. These depend on Exchange state, not on the line.
- **`unit` on a `free` or `flat` term.** The ingester silently ignores it rather than
  refusing the line, so the schema permits it too. It has no effect.
- **Leading and trailing whitespace** around a case-insensitive enum value. The mapper
  trims it, so `" free "` is accepted by the ingester but refused by the schema. That is a
  deliberate disagreement in the safe direction: padding is a feed defect worth surfacing
  early, and removing it never changes what the value means.
- **Cross-line rules.** Each line validates alone; a `content_id` collision between two
  lines is legal input that collapses to one row.
- **`functions` and `prohibited_functions` not overlapping.** A token listed in both is
  rejected at the RPC boundary, but JSON Schema cannot compare two sibling arrays for a
  shared member, so this one is unreachable here rather than merely omitted. It is the only
  per-line rule in that category.

Everything else in the "Where each rule is enforced" list above **is** checked here, down
to the per-token length and character rules. A line this schema accepts can still be
refused for a registry-membership or a stateful reason, but not for a shape reason.

## Source

- Line format and parse rules: `src/exchange/internal/ingest/parser.go`.
- Value validation and enum spellings: `src/exchange/internal/ingest/mapper.go` and
  `src/exchange/internal/ingest/enum.go`.
- Server rules and rejection reasons: `src/exchange/internal/service/`.
- Message shapes, enum values, validation expressions and the token vocabularies:
  the `ramp.v1` protocol, published as the Go module
  `github.com/RAMP-Protocol/protocol`, pinned in the repository's root `go.mod`. Read the
  proto that module ships rather than citing the protocol from memory.
- Example feed: `example.jsonl` in this directory. Feeds that the test suite actually
  runs against live in `deploy/fixtures/publisher/` — `sample.jsonl` for the basic shape,
  and the corpus under `metadata/` for the extension fields and the rejection paths.

## Authority

`src/exchange/internal/ingest/parser.go` and its mapper **define** the format. This
document and the schema beside it are derived views of that code.

No automated check currently holds the three together. If the schema and the ingester
disagree, the ingester is right and the schema is a bug — report it rather than working
around it.

## Validating a feed

Any Draft 2020-12 validator works. The schema applies per line, so split the file first:

```bash
while IFS= read -r line; do
  [ -z "$line" ] && continue
  printf '%s\n' "$line" | your-json-schema-validator catalog-feed-v1.schema.json -
done < feed.jsonl
```

Run it against `example.jsonl` first. If that file fails, the problem is your validator
setup rather than your feed.

A clean pass means the line is well-formed and internally consistent. It does not mean the
push will be accepted — the tenant, contributor authorization and payee gates are checked
by the Exchange against its own state.
