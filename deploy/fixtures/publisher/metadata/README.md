# Resource-Metadata Round-Trip Corpus

Shared test corpus for the RAMP resource-metadata round-trip feature:
ingest-accept, then push → discover (+ transact).

This directory is the shared corpus of JSONL fixtures for the resource-metadata
round-trip feature. A subset is executed today: the ingest parse/map layer drives
these `.jsonl` files through production `ParseJSONL`/`MapRecords` in
`src/exchange/internal/transport/ingest_metadata_e2e_test.go`. Do not fork the
fixtures into a task; extend them here.

> **`expected_outcomes.json` is documentation-only.** The outcome matrix (here and
> in that file) records the *intended* per-line behaviour, but **no runner consumes
> it** — it is not an executed assertion. The Offer-projection guarantees it narrates
> — an explicit `resource_mutability` is honored and does **not** leak into `ext`, and
> an omitted value defaults to `RESOURCE_MUTABILITY_STATIC` — are the ones actually
> pinned, by the running integration test
> `src/exchange/internal/transport/catalog_metadata_integration_test.go`
> (`assertOfferMetadata` / `assertOfferNoMetadata`). Wiring a runner that executes the
> manifest is a separate follow-up.

## The feature under test

A publisher feeds the Exchange a JSONL file (one resource per line). The
pipeline is:

```
ParseJSONL (parser.go) → MapRecords (mapper.go) → PushEntries (push.go, through the SDK catalog client)
  → CatalogService.PushResources RPC → ramp.catalog
  → DiscoverResources RPC → buildOffer (discover.go) → signed Offer
```

Resource-metadata support makes **metadata** a first-class part of this round-trip.

### Extended feed-line schema (what these fixtures exercise)

**The full line format lives in `schemas/catalog-feed/v1/README.md`**, alongside a
machine-checkable JSON Schema. The field table that used to sit here is gone on purpose —
it was a partial second copy, and a partial copy is the thing that drifts.

What these fixtures exercise is the metadata extension surface: the optional top-level
fields beyond `domain`, `path`, `title`, `license` and `terms[]` — `content_id`,
`word_count`, `estimated_quantity`, `content_hash`, `hash_method`, `source`,
`provenance_source`, `provenance_timestamp`, `resource_mutability`, `ext`, `ext_critical`
and `attestations[]`. Their Offer-side projections are the subject of the scenario matrix
below.

### CRITICAL proto fact — `resource_mutability` is a typed field; `previews` still rides INSIDE `ext`

`ResourceEntry` carries a typed, optional `resource_mutability` field (proto
field 14). The feed supplies it as a **top-level** field (full enum NAME), and it
is authoritative — a value in `ext` is NOT read:

```json
"resource_mutability": "RESOURCE_MUTABILITY_STATIC",
"ext": {
  "previews": [ {"url":..,"media_type":..,"width":..,"height":..,"duration":..,"size":..} ],
  "...any other passthrough keys": ...
}
```

`ResourceEntry` still has **no** typed `previews` field, so previews rides inside
`ext` on the feed/ingest side (typed promotion is a separate follow-up).

On the **Offer** side:

- `resource_mutability` (typed) → `Offer.identity.resource_mutability` (enum);
  omitted → `RESOURCE_MUTABILITY_STATIC` (buildOffer default); an explicit
  `RESOURCE_MUTABILITY_UNSPECIFIED` is rejected at the mapper. It is a typed field
  and never appears in `Offer.ext`.
- `ext.previews[]` → `Offer.previews[]` (`Preview` messages), while the full `ext`
  (previews plus passthrough keys such as `editorial_desk`) is carried verbatim on
  `Offer.ext`.

### Enum value names (verified against the pinned proto)

Verified against the protocol module at the revision `go.mod` pins — read the pin there rather than from a version written into this page, which goes stale at the next re-pin. `resource_mutability` is a typed field on `ResourceEntry`, number 14, not an `ext` key.

- `ResourceMutability`: `RESOURCE_MUTABILITY_UNSPECIFIED | _STATIC | _DYNAMIC | _LIVE`
- `IngestionSource`: `INGESTION_SOURCE_UNSPECIFIED | _RAMP_SITEMAP | _RSL |
  _SITEMAP | _HTML_CRAWL | _CMS_API | _MANUAL | _CATALOG_API`

### The pricing/selection invariant (the whole point)

`selectTerms` (`src/exchange/internal/service/termselect.go`) filters terms by
**scopes ONLY**.
Metadata is **never** an input to term/price selection. The corpus proves this
two ways (see the entanglement cases below).

## Scenario matrix

Dimensions × cases. Every positive line reuses the `license` / `terms` / `pricing`
shapes from `../sample.jsonl`, so each line is otherwise-valid and the variable
under test is isolated.

| Dimension | File | case_id(s) | What it proves |
|---|---|---|---|
| Happy path (all fields) | `valid_full.jsonl` | `valid_full_all_fields` | Every metadata field surfaces on the Offer |
| Partial metadata | `valid_partial.jsonl` | `valid_partial_hash_only`, `valid_partial_provenance_only`, `valid_partial_ext_mutability_only` | Only the supplied fields appear; the rest are unset |
| Legacy / zero metadata | `legacy_no_metadata.jsonl` | `legacy_zero_metadata` | Today's shape still accepted; Offer metadata empty (NULL row unaffected) |
| IngestionSource enum coverage | `source_enum_variants.jsonl` | `source_ramp_sitemap` … `source_catalog_api` (7) | Every real `IngestionSource` value round-trips (incl. `INGESTION_SOURCE_CMS_API`) |
| Mutability (typed field) | `mutability_variants.jsonl` | `mutability_static`, `mutability_dynamic`, `mutability_live`, `mutability_absent` | top-level `resource_mutability` → `Offer.identity.resource_mutability`; omitted → STATIC (buildOffer default) |
| Previews via ext | `previews_variants.jsonl` | `previews_zero`, `previews_one_minimal`, `previews_many_full_dims` | 0/1/many previews; optional width/height/duration/size present and absent |
| Attestations | `attestations.jsonl` | `attestations_absent`, `attestations_one_selfattest`, `attestations_many_with_thirdparty` | absent / one / many; non-trivial nested claims proto-equal on the Offer |
| Provenance → data_as_of | `provenance.jsonl` | `provenance_present`, `provenance_absent` | `provenance_timestamp` present → `Offer.data_as_of` equals it; absent → unset |
| Content hash | `valid_partial.jsonl`, `attestations.jsonl`, `valid_full.jsonl` | `valid_partial_hash_only`, `attestations_absent`, `valid_full_all_fields` | `content_hash`+`hash_method` → `Offer.identity.*` |
| PARSE rejections | `reject_parse.jsonl` | `reject_unknown_key`, `reject_malformed_provenance_timestamp`, `reject_garbage_source`, `reject_ext_not_object`, `reject_attestation_claims_not_object`, `reject_trailing_garbage` | Each isolated reject; `DisallowUnknownFields` stays strict |
| MAPPER rejections (mutability) | `reject_map_mutability.jsonl` | `reject_mutability_unspecified`, `reject_mutability_unknown` | Explicit `UNSPECIFIED` and unknown enum name parse clean but fail `MapRecords`; nothing persisted |
| PUSH all-or-nothing | `reject_push_allornothing.jsonl` | `reject_push_allornothing_file` (+ 3 line cases) | One bad line voids the whole push; nothing persisted |
| **Pass-through baseline** | `passthrough_baseline.jsonl` | `passthrough_baseline_with_meta`, `passthrough_baseline_without_meta` | **Metadata inert to Select**: same term + price with and without metadata |
| **Multi-term + scope projection** | `multiterm_scope_projection.jsonl` | `multiterm_meta_premium_requester`, `multiterm_meta_default_requester` | **Same metadata regardless of which term scope selects**; only price differs |
| **Transact parity** | `transact_parity.jsonl` | `transact_parity_full_meta` | Offer signature re-verifies through ExecuteTransaction (buildOffer rebuilds identical metadata) |

## The entanglement / pass-through invariant (call-out)

Metadata MUST NOT change which term or price the Exchange selects. Two cases
carry this proof:

1. **`passthrough_baseline.jsonl`** — `passthrough_baseline_with_meta` vs
   `passthrough_baseline_without_meta`. Two resources with an **identical**
   `terms[]` block; one has full metadata, one has none. The `pairwise_assertion`
   in the manifest (`passthrough_invariant_select_inert`) asserts
   `offer.pricing` is equal and the selected term is proto-equal across the two.

2. **`multiterm_scope_projection.jsonl`** — the SAME line discovered by a
   `premium` requester (selects the 9.99 premium term) and a `default` requester
   (selects the 4.99 public term). The `pairwise_assertion`
   (`multiterm_metadata_invariant_across_scope`) asserts the metadata block is
   proto-equal across both offers while `selected_price_rate` differs — selection
   is driven by **scopes only**, metadata is along for the ride.

Every positive case additionally carries `offer.terms_unchanged: true` and
`offer.price_unchanged: true` as a per-line guard that adding its metadata
variant did not perturb the projected terms or price relative to the
metadata-free baseline shape.

## The transact-parity assertion (call-out)

`transact_parity.jsonl` → `transact_parity_full_meta` carries
`"transact_parity": true`. The push→discover→**ExecuteTransaction** e2e
must, for this line: discover the signed offer, call `ExecuteTransaction` with it,
and assert the signature re-verifies. The Exchange verifies the PRESENTED
offer's exact signed bytes (metadata included) at execute; if the discovery
path emits metadata that is dropped or reordered anywhere between signing and
presentation, the canonical signed bytes diverge and verification fails. This
case is the guard against that divergence.

## Consuming `expected_outcomes.json` from a Go integration test

> Not yet wired — this section is a **suggested** shape for a future runner; no
> code consumes the manifest today (see the documentation-only note at the top).

The manifest is a list of `files`, each with `cases[*]` keyed by
`{file, line_number, case_id, description}` and an `expected` block. Suggested
Go shape (illustrative — the e2e task owns the real types):

```go
type Expected struct {
    Parse json.RawMessage `json:"parse"` // "ok" | {reject,layer}
    Push  json.RawMessage `json:"push"`  // "accepted" | {rejected} | null
    Offer *OfferExpect    `json:"offer"` // nil => no offer expected
    TransactParity bool   `json:"transact_parity"`
}
type OfferExpect struct {
    IdentityContentHash      *string         `json:"identity_content_hash"`
    IdentityHashMethod       *string         `json:"identity_hash_method"`
    IdentityResourceMutability string        `json:"identity_resource_mutability"`
    Previews                 json.RawMessage `json:"previews"`      // int count | []Preview
    Attestations             json.RawMessage `json:"attestations"`  // int count | []Attestation
    Ext                      map[string]any  `json:"ext"`           // subset that MUST be present
    ExtCritical              []string        `json:"ext_critical"`
    DataAsOf                 *string         `json:"data_as_of"`    // nil => assert unset
    TermsUnchanged           bool            `json:"terms_unchanged"`
    PriceUnchanged           bool            `json:"price_unchanged"`
}
```

Assertion rules:

- A `*string` / `*X` field that is JSON `null` → assert the Offer field is
  **unset** (zero/nil). A field absent from the JSON `expected.offer` object →
  **do not assert** that field.
- `previews` / `attestations` accept EITHER an integer (assert count) OR an array
  (assert proto-equal element-wise, in order).
- `ext` is a **subset**: every listed key must be present and proto-equal; extra
  keys on the Offer are allowed.
- `pairwise_assertion` blocks (on `passthrough_baseline.jsonl` and
  `multiterm_scope_projection.jsonl`) are cross-line/cross-requester: resolve the
  two named `case_id`s' offers and assert the stated equalities.
- `file_level_expectation` (on `reject_push_allornothing.jsonl`) is asserted once
  per file: run the whole file through ingest, expect failure, then assert
  neither sibling resource is discoverable.

### Parse-vs-push reject layers

`reject_parse.jsonl` cases carry `expected.parse.layer` (`parser` | `mapper`)
naming where the reject lands once `Record` is extended:

- `parser` — Go `json.Decode` under `DisallowUnknownFields` (unknown key),
  typed-field decode (`ext`/`claims` not an object, RFC3339 `provenance_timestamp`),
  or the `dec.More()` trailing-content guard.
- `mapper` — `MapRecords` token/enum validation after a clean parse
  (e.g. unknown `source` enum spelling).

These layer assignments are the **recommended** design. If the implementer
chooses a different (but still single-reason)
rejection point for a given line — e.g. validating `source` at parse instead of
map — update that case's `layer` here so the corpus stays the source of truth.

## Open items for the team-lead (resolve before e2e consumes the corpus)

See the handoff summary; nothing blocks authoring, but two design choices the
implementer must pin (and reflect back into the manifest if they differ):

1. **`source` field representation** — typed as a validated enum at parse time,
   or a raw string validated at map time. The corpus assumes raw-string-at-parse
   + enum-validate-at-map (so `reject_garbage_source` is `layer: mapper`).
2. **`provenance_timestamp` representation** — decoded as `time.Time` (RFC3339)
   at parse (corpus assumption, `reject_malformed_provenance_timestamp` is
   `layer: parser`), or kept as a string and validated at map.
