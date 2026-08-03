# ADR-014 — Universal Licensing Core

**Status:** Accepted

---

## Overview

The Universal Licensing Core is RAMP's authoritative, cross-domain model for expressing licensing terms on any digital resource. A resource carries `repeated LicenseTerm terms`. This document defines the `LicenseTerm` shape and the messages it composes (`License`, `Restriction`, `Quota`, `Obligation`, `Pricing`), the vocabulary mechanism for the open string axes, how terms are projected onto offers, how an offer is rendered into the requester's declared extension profile (e.g. CoMP) at reply time, and the validation rules applied at ingest. The same shapes are used at ingestion (publisher → Exchange) and emission (Exchange → agent).

---

## The unit: `LicenseTerm`

A resource carries `repeated LicenseTerm terms`. One resource → many terms: a publisher may offer `crawl=free`, `RAG=$0.05/access`, and `training-data=$15/GB` as separate terms on the same URL. The same `LicenseTerm` shape is used at ingestion (publisher → Exchange) and emission (Exchange → agent). The Exchange selects the terms an agent is entitled to — by `resource_id`/URI and Biscuit scope (requester-attribute filtering is not applied — see *Requester-attribute filtering is not applied*) — and signs them as offers. There is no second "offer shape" and no field-stripping step.

```proto
message LicenseTerm {
  License               license      = 1;  // optional for ENUMERATED; required for REFERENCE_ONLY
  TermSemantics         semantics    = 2;  // required
  repeated Restriction  restrictions = 3;
  repeated Quota        quotas       = 4;
  repeated Obligation   obligations  = 5;
  Pricing               pricing      = 6;  // required for every term (ENUMERATED and REFERENCE_ONLY)
  repeated string       scopes       = 7;  // empty = public; AND-semantics; Biscuit-gated
  optional string       part_label   = 8;  // informational: human-readable name for this sub-part
}
```

Multiple terms on the same resource represent either **alternative license options** (dual-licensing: GPL vs commercial) or **use-type splits** (indexing priced differently from generative-AI use). Each surviving term produces one independent offer. An agent requesting content sees only the offers its scope entitles it to; it picks the one that matches its intent.

---

## License identity

```proto
message License {
  string          uri        = 1;  // canonical identity. RFC 3986; NEVER URL-validate.
  optional string id         = 2;  // stable short id: SPDX short-id, TollBit cuid, catalog doc-id
  optional string name       = 3;  // human label (licenseType, schema.org node name)
  optional bool   immutable  = 4;  // data-labels TDL: document at uri is versioned and will not change
  optional string uri_digest = 5;  // "method:hexdigest" pin of the doc at uri; REQUIRED whenever uri is present (any semantics, mutable or not)
}
```

`uri` is the canonical identity of the license document. It must never be validated as an HTTP URL — data-labels TDL identifiers use non-URL schemes, and strict URL validation would reject conformant TDLs. `id` is the stable short identifier (`GPL-3.0-only`, TollBit `cuid`) used by agents and the vocab linter for known-license lookup.

---

## Term semantics

```proto
enum TermSemantics {
  TERM_SEMANTICS_UNSPECIFIED    = 0;  // unset — rejected at ingest
  TERM_SEMANTICS_ENUMERATED     = 1;  // restrictions/quotas/obligations/pricing are authoritative on the wire
  TERM_SEMANTICS_REFERENCE_ONLY = 2;  // License.uri is authoritative; machine fields, if present, are an advisory summary
}
```

**ENUMERATED:** the machine-readable fields are authoritative. The publisher may also supply `License.uri` pointing to the full legal text; this is encouraged. The publisher certifies at submission that no enumerated value contradicts the referenced document. The agent gets machine terms as a faithful approximation and may use them without reading the license document.

**REFERENCE_ONLY:** `License.uri` governs the authoritative terms and MUST be present (non-empty). The machine fields — `restrictions`, `quotas`, `obligations` — are OPTIONAL and, when present, are an **advisory readable summary** of the referenced document (the document remains authoritative). They are validated and canonicalized exactly like an ENUMERATED term, so an agent may read the summary and decide without fetching the document — or rely on the document for full detail. The publisher certifies the summary does not contradict the document; that is an attestation, not a machine-checkable ingest rule. `Pricing`, however, is REQUIRED on every term regardless of semantics: an agent cannot act on a priceless term, so the machine-readable price is always stated even when the rest of the terms live in the referenced document. Whenever `License.uri` is present, `License.uri_digest` MUST also be present — a "method:hexdigest" pin of the referenced document — so the agent can verify the bytes it fetches; the `uri` could otherwise be swapped (by a MitM or the publisher) after the offer is signed. This holds for ENUMERATED terms that carry a `uri` too, not only REFERENCE_ONLY, and regardless of `immutable`. A pure data-labels TDL maps to `LicenseTerm{ license{uri, immutable:true, uri_digest}, semantics: REFERENCE_ONLY, pricing }`.

---

## Restrictions

```proto
message Restriction {
  RestrictionKind  kind       = 1;  // required
  repeated string  permitted  = 2;  // registry-governed tokens
  repeated string  prohibited = 3;
  bool             advisory   = 4;  // default false = BINDING (fail closed on any token the consumer can't evaluate); true = non-blocking
}

enum RestrictionKind {
  RESTRICTION_KIND_UNSPECIFIED = 0;  // unset — rejected at ingest
  RESTRICTION_KIND_FUNCTION    = 1;  // what the agent may do with the content
  RESTRICTION_KIND_GEOGRAPHY   = 2;  // where the agent may use it
  RESTRICTION_KIND_USER_TYPE   = 3;  // who may use it
  RESTRICTION_KIND_OTHER       = 4;  // escape hatch; linted and discouraged
}
```

**Invariants (enforced at ingest):**
- At most one `Restriction` per `kind` in a term. Two restrictions with the same `kind` are rejected.
- A `Restriction` must carry ≥ 1 `permitted` token, ≥ 1 `prohibited` token, or both. An empty restriction is rejected.
- `permitted ∩ prohibited` non-empty: rejected.
- **Fail-closed by default.** A restriction is BINDING unless `advisory = true`: a consumer that cannot evaluate any token in it (including an unknown vendor token) MUST fail closed and refuse the offer. Publishers set `advisory = true` only where silent non-compliance is acceptable; they leave it false (the default) for restrictions whose violation would constitute infringement (editorial-only, territory-limited, training-prohibited). A junk token in a binding restriction makes the content unsellable to any agent that does not recognize it.

### Vocabulary

The registered tokens are proto-native: the `(ramp.v1.vocab_enum)` entries on the `RestrictionKind` enum values in `ramp.proto` (module `github.com/RAMP-Protocol/protocol`) are the sole authored source. The token list is authored once, on the enum value.

**`FUNCTION` — seeded from RSL 1.0 (AI tokens) and established IP/copyright terms (other domains)**

| Token | Source | Meaning |
|---|---|---|
| `all` | RSL-1.0 | all uses; shorthand for permitting/prohibiting everything |
| `ai-all` | RSL-1.0 | all AI uses; covers ai-train + ai-input + ai-index + tts |
| `ai-train` | RSL-1.0 | ML/AI model training data (AIPREF alias: `train-ai`) |
| `ai-input` | RSL-1.0 | AI inference input: RAG, grounding, agent context, summarization (industry alias: `generative-ai`) |
| `ai-index` | RSL-1.0 | build an AI-powered retrieval index (vector embeddings, semantic search) |
| `search` | RSL-1.0 | traditional keyword search engine indexing |
| `crawl` | RSL-1.0 | fetch/download content to create a local copy (AIPREF alias: `scrape`) |
| `text-and-data-mining` | RSL-1.0 | automated text/data analysis; EU DSM Art. 4 (alias: `tdm`) |
| `tts` | IETF-AIPREF | text-to-speech synthesis |
| `commercial` | CC | any commercial application |
| `advertising` | IP-standard | use in advertising or promotional materials |
| `editorial` | IP-standard | editorial/journalistic use |
| `research` | RSL-1.0 | non-commercial academic/scientific research |
| `reproduce` | copyright-law | make copies (alias: `copy`) |
| `distribute` | copyright-law | distribute copies to third parties |
| `modify` | copyright-law | create derivative works (aliases: `adapt`, `derivative`) |
| `display` | IP-standard | publicly display on screen |
| `sync` | music-licensing | synchronize with audio-visual media (sync license) |
| `broadcast` | broadcasting-law | over-the-air or cable broadcast |
| `stream` | IP-standard | on-demand internet streaming |
| `print` | IP-standard | reproduce in print media |
| `manufacture` | patent-law | manufacture physical goods from the design |
| `sell` | patent-law | sell goods/services incorporating the licensed work |

Custom values: namespace prefix required (`vendor:token`). The linter warns on unregistered bare tokens.

**`GEOGRAPHY`** — ISO-3166-1 alpha-2 country codes (`US`, `DE`, `GB`) are implicitly valid. Special registry values: `*` (worldwide), `EU` (current EU member states), `EEA` (EU + NO/IS/LI).

**`USER_TYPE`** — `individual`, `academic`, `non_profit`, `news_publisher`, `broadcaster`, `commercial_entity`. Custom values namespaced.

---

## Quotas

```proto
message Quota {
  string          metric = 1;  // registry-governed; required
  int64           limit  = 2;  // required; value ≥ 1 (limit ≤ 0 rejected)
  QuotaWindow     window = 3;  // required
}

enum QuotaWindow {
  QUOTA_WINDOW_UNSPECIFIED = 0;  // unset — rejected at ingest
  QUOTA_WINDOW_HOURLY      = 1;
  QUOTA_WINDOW_DAILY       = 2;
  QUOTA_WINDOW_MONTHLY     = 3;
  QUOTA_WINDOW_TOTAL       = 4;  // lifetime / per-license-grant cap
}
```

Quotas express caps that gate license validity, not price. A cap of 10,000 units manufactured is a grant boundary; charging $0.50 per unit is a pricing matter. These are separate fields.

`limit ≤ 0` is rejected (`0` is the proto3 default for the non-optional `int64`, so an unset limit and a zero limit are indistinguishable and both invalid). Zero allowance is expressed as a `Restriction.prohibited` token, not a zero-cap quota. A present `Quota` must have `limit ≥ 1`.

**Registered metrics** (authored as `(ramp.v1.vocab)` on `Quota.metric`): `display-words`, `impressions`, `tokens`, `input-tokens`, `units-manufactured`, `accesses`, `copies`, `seats`. Custom metrics use namespace prefix.

---

## Obligations

```proto
message Obligation {
  ObligationKind    kind          = 1;  // required
  ObligationTrigger trigger       = 2;  // required
  optional string   scope_license = 3;  // required for SHARE_ALIKE; SPDX short-id or license URI
  optional string   detail        = 4;  // attribution string, notice file URI; OTHER without it → lint warning
}

enum ObligationKind {
  OBLIGATION_KIND_UNSPECIFIED      = 0;  // unset — rejected at ingest
  OBLIGATION_KIND_ATTRIBUTION      = 1;  // credit the author / source
  OBLIGATION_KIND_CONTRIBUTION     = 2;  // contribute back (open-contribution licenses)
  OBLIGATION_KIND_SHARE_ALIKE      = 3;  // distribute derivatives under the same / compatible license
  OBLIGATION_KIND_NETWORK_COPYLEFT = 4;  // AGPL-style: serving over a network triggers distribution obligations
  OBLIGATION_KIND_NOTICE           = 5;  // include a specific license notice file verbatim
  OBLIGATION_KIND_OTHER            = 6;  // escape hatch; linted and discouraged
}

enum ObligationTrigger {
  OBLIGATION_TRIGGER_UNSPECIFIED        = 0;  // unset — rejected at ingest
  OBLIGATION_TRIGGER_ON_USE             = 1;
  OBLIGATION_TRIGGER_ON_DISTRIBUTION    = 2;  // GPL
  OBLIGATION_TRIGGER_ON_NETWORK_SERVICE = 3;  // AGPL
  OBLIGATION_TRIGGER_ON_DERIVATIVE      = 4;  // CC-BY-SA share-alike on derivatives
}
```

`trigger` is load-bearing: GPL and AGPL differ only on this field (`ON_DISTRIBUTION` vs `ON_NETWORK_SERVICE`).

**`scope_license` on `SHARE_ALIKE`:** the license that any derivative of this content must be released under. This is a forward-looking constraint on the agent's derivative works, not an alternative license for the resource itself. For most copyleft licenses, `scope_license` equals the term's own `License.id` (GPL derivatives must be GPL). The field exists separately because some licenses allow derivatives under a broader compatible license (LGPL, MPL, EUPL). `scope_license` is required for `SHARE_ALIKE` and rejected if absent. Value: SPDX short-id preferred; arbitrary license URI accepted. The ingestion linter warns on unrecognized values; no SPDX-specific parsing at the proto level.

---

## Pricing

```proto
// Pricing is a SHARED message — it is also `Offer.pricing`, used by Broker
// ranking system-wide. Pricing has no notion of revenue share.
message Pricing {
  PricingModel    model                   = 1;  // required
  double          rate                    = 2;
  string          currency                = 3;  // ISO-4217, e.g. "USD"
  optional double unit_cost               = 4;  // pre-computed; used by Broker ranking
  optional int32  estimated_quantity      = 5;  // quantity in the metering unit
  optional int32  license_duration_months = 7;  // absent = perpetual
  optional string unit                    = 8;  // metering basis (vocabulary) — required iff model = PER_UNIT
  optional PricingMetering metering       = 9;  // absent = ONLINE
}

// PricingModel is the charging STRUCTURE only — a closed, small set. The
// open-ended metering basis ("per what") is NOT enumerated here; it lives in
// Pricing.unit as a registry-governed vocabulary (see below).
enum PricingModel {
  PRICING_MODEL_UNSPECIFIED = 0;  // unset — rejected at ingest (omission cannot default to FREE)
  PRICING_MODEL_FREE        = 1;  // no charge; rate must be 0
  PRICING_MODEL_PER_UNIT    = 2;  // rate per Pricing.unit; unit REQUIRED (registered token or vendor:custom)
  PRICING_MODEL_FLAT        = 3;  // one-time flat fee; rate is the total, no unit
}

// PricingMetering is the deliberate exception to the UNSPECIFIED-at-0 rule:
// it is OPTIONAL with a real default — absent = ONLINE — so 0 carries meaning
// and is never rejected.
enum PricingMetering {
  PRICING_METERING_ONLINE                = 0;  // default; Exchange gates delivery and observes every charge event
  PRICING_METERING_NONE                  = 1;  // no ongoing usage tracking; one-time sale
  PRICING_METERING_OFFLINE_SELF_REPORTED = 2;  // agent self-reports usage; Exchange audits (manufacturing royalties, etc.)
}
```

`Pricing` is required on **every** term, regardless of semantics (ENUMERATED and REFERENCE_ONLY alike). If there is no monetary charge, use `model: FREE` explicitly — absent `Pricing` is rejected.

`license_duration_months` expresses how long the license grant is valid after first access. Absent means perpetual.

Revenue distribution to a publisher's rightsholders (royalty splits, settlements) is outside the protocol scope. The agent settles a single price with the Exchange; internal distribution is Exchange-side billing RAMP never sees. There is no `REVENUE_SHARE` model — settlement happens off-protocol.

### Metering basis is a vocabulary

The "per what" of `PER_UNIT` pricing — per fetch, access, token, call, page, minute, record, stream, image, seat, sq-km, character — is open-ended and grows with every domain, so it is not enumerated in `PricingModel`. It is the same registry-governed vocabulary used for the other open axes (function, geography, user-type, `Quota.metric`). `Pricing.unit` stays a plain `string`; the registered tokens live in **field options on the `unit` field**, carried in the proto and read by buf tooling:

```proto
string unit = 8 [
  // Registry: the SOLE authored source of the registered bare tokens.
  // repeated custom option, FieldOptions extension 50001 (internal range
  // 50000–99999). The direct `repeated string` form is intentional — modern
  // protoc supports repeated custom options; do NOT wrap it in a message.
  (ramp.v1.vocab) = "fetches",  (ramp.v1.vocab) = "accesses", (ramp.v1.vocab) = "tokens",
  (ramp.v1.vocab) = "calls",    (ramp.v1.vocab) = "pages",    (ramp.v1.vocab) = "minutes",
  (ramp.v1.vocab) = "records",  (ramp.v1.vocab) = "streams",  (ramp.v1.vocab) = "images",
  (ramp.v1.vocab) = "seats",    (ramp.v1.vocab) = "units-manufactured",
  (ramp.v1.vocab) = "characters", (ramp.v1.vocab) = "bytes",  (ramp.v1.vocab) = "items",
  (ramp.v1.vocab) = "sq-km",
  // Structure only — NO token list here, so it cannot drift from the registry:
  // empty, OR a well-formed bare token, OR a vendor: namespaced token.
  (buf.validate.field).cel = {
    id: "pricing.unit.format"
    message: "unit must be empty, a lowercase-dashed token, or vendor:namespaced"
    expression: "this == '' || this.matches('^[a-z0-9-]+$') || this.matches('^[A-Za-z0-9._-]+:.+$')"
  }
];
```

`(ramp.v1.vocab)` is a custom `repeated string` extension on `google.protobuf.FieldOptions` (number `50001`), shared by the field axes `Pricing.unit` and `Quota.metric`; the enum-selected axes (function / geography / user-type) use the sibling `(ramp.v1.vocab_enum)` extension on `EnumValueOptions` (number `50002`). The token list is authored in exactly one place and serves three roles, with no duplication:

1. **The registry** — the option entries, and nothing else, list the tokens. Adding a token edits this list: an additive, non-breaking version bump; no message-shape change, no consumer breaks.
2. **The constants** — the `protoc-gen-rampvocab` buf plugin reads the options **structurally** off the descriptor (building a `dynamicpb` extension resolver from the `CodeGeneratorRequest` descriptors) and emits, into the normal `buf generate`, a typed string constant per token (`pricingunits.Accesses = "accesses"`), `All`, and `IsRegistered(string) bool`. Application code branches on these constants to make decisions, not merely to validate.
3. **Validation** splits by concern so the CEL never re-lists the tokens:
   - **Structure & cross-field** → `protovalidate`. The field CEL above (empty / bare-form / `vendor:namespaced`) plus message-level `(buf.validate.message).cel` on `Pricing` for `PER_UNIT ⇒ unit != ''` and `FREE ⇒ rate == 0`. The buf-maintained `protovalidate` runtime evaluates these via the Connect `validate` interceptor at the RPC boundary; code constructing a `Pricing`/`LicenseTerm` after the boundary calls `protovalidate.Validate()` explicitly.
   - **Registry membership** ("a bare token must be registered") → the generated `IsRegistered`, enforced at **ingest** (`PushResources`), single-sourced from the option list. Structure is universal; membership is checked where terms enter the system.

The constants and the membership check both derive from the option list and cannot drift, while the CEL stays a fixed structural rule. The same mechanism serves every open axis. Cross-unit cost comparison uses `unit_cost` (normalized) for Broker ranking.

---

## Scope-gating and offer projection

A `LicenseTerm` carries `repeated string scopes` — hierarchical capability tokens (`subscription:premium`, `dist:US`). The Exchange returns a term to an agent iff the agent's Biscuit authority covers **all** of the term's `scopes[]` (AND semantics). Empty `scopes[]` = public.

Scopes are hierarchical: a Biscuit carrying `dist:*` covers `dist:US`, `dist:CA`, etc. Publishers issue Biscuits with matching scopes (or `*`) to authorized agents.

A term the agent's scope does not cover is not returned — the agent never learns it exists. A publisher that wants upsell instead emits `OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT` (existence revealed, access denied).

**Selection.** The Exchange projects terms into offers by `resource_id`/URI and Biscuit scope coverage **only** (see *Requester-attribute filtering is not applied*). It does not filter terms by the requester's self-declared attributes (`user_type` / `geography` / `intended_use`). Restrictions ride on the returned offer; the agent self-selects the term whose restrictions it can honour, and enforcement happens downstream at `accept → report → reconcile`.

> **Scope-trust caveat (deferred verification).** Today `requester.scopes` is a self-declared wire field the Exchange **trusts without attestation** — scope coverage is an honest projection of intent, not yet an authorization boundary (an agent could claim any scope). Verifying scopes (entitlement-biscuit attenuation + WBA-bound identity) is deliberately deferred; when it lands, scopes are verified upstream and `licenseterm.Select` is unchanged. Until then, scope coverage MUST NOT be relied on as an access-control gate.

Each surviving term produces one offer, and that offer's `Offer.pricing` is simply that term's `Pricing` (the authoritative copy stays in `Offer.terms[].pricing`) — there is no separate "headline" price chosen among several terms. A resource with dual-licensed terms (GPL + commercial) produces two separate offers; the agent picks the one matching its intent and scope.

---

## Extension profiles and reply-time projection

The licensing model above is profile-agnostic: a resource carries `terms[]` and the Exchange stores them once. Domain extension profiles (CoMP `ramp-comp-v1`, news, academic, C2PA, …) are **render targets, not a second storage format.** RAMP's promise — "describe your resources in any format (RSL, sitemap, JSONL, CoMP); we present them in the profile the consumer understands" — is a normalize-on-ingest, render-on-reply pipeline. The Exchange never stores a profile rendering as its source of truth; it renders on demand from the normalized model.

**Who picks the profile.** The requester declares the profiles it can parse in `DiscoverResourcesRequest.supported_profiles` (`repeated string`; values match the Exchange's `WellKnownManifest.supported_profiles`). The agent declares the same set in `ResourceQuery.supported_profiles` and the Broker forwards it. The Exchange includes profile-specific `ext` fields in an Offer when the caller declares the matching profile, and MAY skip expensive profile-specific computation when it does not. **Absence of the field means "send all available metadata"** — the Exchange MUST NOT withhold base resource metadata solely because the caller omitted it.

**The projection axis — term-independent vs term-dependent.**
- *Term-independent* resource metadata (content hash, word count, language, mutability, previews, provenance) is intrinsic to the URI. It is harmonized and stored **at ingestion**, is 1:1 with the resource, and carries no per-term multiplicity. This is the `ResourceEntry.ext` / metadata round-trip persisted on the catalog and re-emitted on every offer.
- *Term-dependent* facts (pricing, permitted/prohibited functions, usage restrictions) are projected **at reply**, from the **single selected term the offer already embodies**. A CoMP "package" is therefore an **offer-level** artifact: one offer = one term = one CoMP package. The "N terms ⇒ N CoMP packages" multiplicity that has no representation at the resource level dissolves at the offer boundary, where selection has already chosen one term.

**The hot path stays mechanical.** Reply-time projection is a pure function `render(selected term, resource metadata, target profile)` — the same class of operation `buildOffer` already performs when it copies a term's `Pricing` onto `Offer.pricing`. There is no decision logic on the hot path. Where rendering cost matters, the projection is cached per `(term, profile)` at catalog-snapshot rebuild (the decode-once-at-rebuild pattern), so discovery selects a pre-rendered blob: the *decision* of which profile to emit stays request-keyed, the *cost* moves to rebuild.

**The term is authoritative; `ext` is advisory.** A publisher may put anything in `ext` at ingestion; the ingestion linter MAY warn that a key is not profile-conformant, but does not block (publisher-correctness). For any field an offer owns — pricing above all — the **term is the single source of truth and shadows `ext` at render**: the Exchange renders owned fields from the selected term and ignores a conflicting `ext` value. A publisher therefore should not state pricing (or other offer-owned facts) inside a CoMP `ext` payload; if it does, the rendered offer carries the term's value, not the `ext` value. Offer and profile rendering are coherent by construction, with no conflict-resolution branch on the hot path.

**Expressibility is per-profile, and some terms are irreducible.** Each profile expresses a subset of term-space. A construct with no representation in the requested profile — e.g. revenue-share, for which RAMP deliberately has no `Pricing` model (settlement is off-protocol; see *Pricing*) — is rendered as the closest expressible subset, flagged, or omitted from that profile's `ext`; it is never silently misrepresented. The authoritative `LicenseTerm` always rides on `Offer.terms[]` regardless of profile, so a consumer that does not understand a profile — or a term no profile can express — still receives the canonical term. The term-construct → profile-field mapping (with explicit unmappables) is maintained as a per-profile expressibility matrix alongside this document.

---

## Requester-attribute filtering is not applied

The Exchange excludes a term from discovery and pricing **only** by `resource_id` / URI and by **scope coverage** (Biscuit-backed, enforceable). It does **not** filter terms by matching the requester's **self-declared attributes** — `user_type`, `geography`, or `intended_use` → `Restriction{kind: FUNCTION}` — against the term's `Restriction`s. Requester-attribute restriction-matching is **not performed** (it was removed on 2026-06-15; see *Changelog*).

**Rationale.**
- **Unenforceable say-so.** A requester's `user_type` / `geography` / `intended_use` are self-declared and the Exchange never validates them. Filtering on an unverified claim is advisory at best — it bought no real enforcement, only the *appearance* of one.
- **Scope creep.** Restriction-axis matching pulled the Exchange toward being a general license-matching engine and forced a world-spanning canonical vocabulary to compare requester facets against term tokens. `ext` is for *additional* attributes, not basic filtering inputs. The Exchange's job is narrower: select transactable terms by `resource_id` + scope and sign them.
- **The restriction still rides on the offer.** `Restriction`s remain **first-class** on terms — validated, normalized, stored, and **returned on the offer** — so the **agent self-selects** the term whose restrictions it can honour. Removing the filter does not drop the data; it relocates the decision to the party that can actually act on it.
- **Enforcement moves downstream.** The real enforcement point is `accept → report → reconcile`: the agent accepts a term, reports usage against it, and the Exchange reconciles reported usage against the term's restrictions/quotas/obligations. That is where a verifiable contract exists.

**Consequences.**
- `licenseterm.Select` is **scope-only** (the single projection shared by discovery-signing and execute-verification, so offer signatures stay byte-identical). The requester-axis machinery (`requesterAxes`, `restrictionsSatisfied`, the `intended_use`→FUNCTION wiring) is deleted.
- Discovery returns **every** scope-covered term regardless of the requester's `user_type` / `geography` / `intended_use`. When several terms project, the headline `Offer.pricing` is the **first** projected term in publisher order — not the cheapest.
- Execute returns `NotFound` only for an unknown offer or an entry with no scope-covered priced term — **never** for a requester-attribute mismatch.
- The Broker no longer relays `user_type` / `geography` facets (they fed only the removed filter); `intended_use` continues to ride on the native `Requester.intended_use` field, but its FUNCTION-axis *consumption* in the Exchange is gone.
- **Stored-side restriction handling is untouched:** `Validate` / `Normalize` / vocab membership / `canonicalToken` + aliases still run at ingest, so restrictions on returned offers are canonical. An unregistered `Restriction` token is a **lint warning** (term accepted), decoupled from the `advisory` flag, never a hard-reject — under scope-only projection it can never gate access. (Pricing/Quota metering-token membership remains a hard-reject; that is unrelated to restriction membership.)

**Future revival.** If requester-attribute filtering is ever reintroduced, it MUST be expressed as **typed proto fields** on the request (not an `ext` map), with a defined verification story — not self-declared say-so. No proto change is made now; this is a deferred enhancement.

---

## Sub-parts and linked resources

Resource rows are keyed by full URI including fragment: `article.html`, `article.html#part1`, `image1.png` are separate rows. Sub-parts of the same origin URL share a common path prefix; the fragment or distinct path uniquely identifies each.

The Exchange returns a flat collection of resource entries, each with its own URI and `terms[]`. An agent that requests `article.html` may receive back a collection containing only sub-part entries — `article.html#text`, `article.html#image-1` — with no entry for `article.html` itself. This is valid: the publisher licensed only the parts, not the whole. Conversely, an entry for `article.html` alone means the whole document has uniform terms. The agent infers the relationship from the URI structure (shared prefix + fragment); no explicit parent-child nesting exists in the response.

`part_label` on a `LicenseTerm` carries a human-readable name for the sub-part (e.g., "Introduction", "Figure 3"); it is informational only and never used in filtering or projection.

**Images:** same publisher domain → separate resource row with its own terms; included in `linked_resources[]`. Different domain → the Exchange does not represent that publisher; the agent accesses images directly from the origin without RAMP mediation.

**Quotes from third parties:** not separately licensed resources unless the quote's source is also a RAMP publisher with its own resource record. Default: same license as the host resource, with an ATTRIBUTION obligation.

**Contradiction guarantee:** if a resource and its sub-parts are pushed in the same call, no sub-part may grant more permissions than the parent resource. The Exchange rejects the push if this invariant is violated.

---

## Vocabulary governance

Three axes carry genuinely open vocabulary: `Restriction.permitted/prohibited` (function / geography / user-type values), `Quota.metric`, and `Pricing.unit`. Governance follows the SPDX / IANA / schema.org pattern: visible and costly to abuse, not hard-blocked.

**Registry:** proto-native. The registered tokens are authored as buf custom options directly on the fields / enum values that use them — `(ramp.v1.vocab)` on `Quota.metric` and `Pricing.unit`, `(ramp.v1.vocab_enum)` on the `RestrictionKind` enum values — and nowhere else. The `protoc-gen-rampvocab` buf plugin reads these options structurally and emits a typed-constant package per axis (`functiontokens`, `geographytokens`, `usertypes`, `quotametrics`, `pricingunits`) with `IsRegistered`; constants, membership check, and validation all derive from the single authored list and cannot drift. Function values are seeded from RSL 1.0, geography from ISO-3166-1 (only the non-ISO specials `*`/`EU`/`EEA` are registered; alpha-2 codes are structural). Additions are pull requests that edit the option list — an additive version bump. RSL `training-data` and AIPREF `train-ai` are registered as aliases.

**Build-time linter (`make quality`, hard FAIL):** scans committed fixtures. An unregistered bare token in our own fixtures is a typo to fix or a registry PR to file.

**Ingestion-time linter (WARN, non-fatal):** runs after Gate 1 (caller signature) and Gate 2 (contributor authorization), per-entry. A publisher pushing `metric: "imprssions"` receives a warning: "unrecognized metric — did you mean `impressions`? register it or namespace it." Warnings are returned in `PushResourcesResponse.warnings[]`.

**Namespacing:** bare token = canonical registry (`generative-ai`); `vendor:token` = deliberate custom (`acme:proprietary-use`). The linter warns on unregistered bare tokens and passes namespaced tokens silently.

---

## Validation rules (normative)

Two classes of check: a **hard reject** is *validation* — a correct, transactable Offer cannot be made from the term; a **warning** is *lint* — the Offer is still makeable and the warning is advisory (returned in `PushResourcesResponse.warnings[]`; see [Lint warnings](#lint-warnings-non-fatal)). The table below is the hard-reject set.

The shape/structure rejects below are enforced by **`protovalidate` (proto CEL) at the RPC boundary**, per-term — not hand-rolled in the Exchange. `PushResources` is **all-or-nothing**: if *any* term in *any* entry fails a hard reject, the whole submission is rejected with `InvalidArgument` (the error names the offending entry + rule) and **nothing is persisted**. There is no partial acceptance — the publisher fixes and resubmits the whole set. (REFERENCE_ONLY no longer forbids machine fields — they are an advisory summary; see the Semantics section.)

| Condition | Action |
|---|---|
| Any required enum is `UNSPECIFIED` (`semantics`, a `Restriction.kind`, a `Quota.window`, an `Obligation.kind`, an `Obligation.trigger`, `Pricing.model`) | reject |
| `semantics = REFERENCE_ONLY` and `License.uri` absent or empty | reject |
| `License.uri` present (non-empty) and `License.uri_digest` absent or empty (any semantics, mutable or not) | reject |
| `semantics = ENUMERATED` and `License.uri` present | accept (encouraged) |
| `Pricing` absent (any semantics) | reject |
| `Pricing.rate > 0` and `Pricing.currency` empty | reject |
| `Pricing.model = FREE` and `Pricing.rate ≠ 0` | reject |
| `Pricing.model = PER_UNIT` and `Pricing.unit` empty | reject |
| Two `Restriction` messages with the same `kind` in one term | reject |
| `Restriction` with no `permitted` and no `prohibited` tokens | reject |
| `permitted ∩ prohibited` non-empty | reject |
| `Quota` present with `limit ≤ 0` (absent ≡ 0 for non-optional int64) | reject |
| `Obligation.kind = SHARE_ALIKE` and `scope_license` absent or empty | reject |
| Sub-part term grants more permissions than parent resource term | reject |

---

## Lint warnings (non-fatal)

Surfaced in `PushResourcesResponse.warnings[]`; the term is still **accepted** and an Offer is made. Lint flags likely mistakes, not protocol violations.

| Condition | Warning |
|---|---|
| Unregistered bare vocab token (`Restriction` per axis, `Quota.metric`, `Pricing.unit`) | unrecognized token — register or namespace |
| `Obligation.kind = OBLIGATION_KIND_OTHER` with empty `detail` | an `OTHER` obligation should describe itself |
| `Pricing.model = PER_UNIT` (or `FLAT`) with `rate = 0` | zero rate on a paid model — use `FREE` |
| `Pricing.model` ∈ {`FREE`, `FLAT`} with `Pricing.unit` set | `unit` is ignored unless model = `PER_UNIT` |
| Subscription term (`model = FREE` + `subscription:*` intent) with empty `scopes` | subscription term is not entitlement-gated |
| `Pricing.currency` present but not well-formed ISO-4217 | currency code unrecognized |

---

## RSL canonical mapping

The three RAMP axes are orthogonal and an RSL license can set them independently: **what** you may do (a `FUNCTION` restriction — `crawl`, `ai-train`, `ai-input`), **how** you are charged (`Pricing.model`), and **per what** (`Pricing.unit`, taken from RSL's own `unit` attribute — never implied by the payment type). The table below shows the *charging* mapping; the use-naming payment types (`crawl`/`training`/`inference`) ALSO imply the corresponding function token in a restriction. Attribution and contribution are obligations, not pricing models.

| RSL `<payment type>` | RAMP `Pricing` (unit from RSL's `unit` attr) | implied function |
|---|---|---|
| `crawl` | `PER_UNIT` (typical `unit: "fetches"`) | `crawl` |
| `purchase` | `FLAT` (one-time) or `PER_UNIT` (metered) | — |
| `subscription` | `FREE` + scope gate (`scopes: ["subscription:..."]`) | — |
| `free` | `FREE` | — |
| `training` | `PER_UNIT` (`unit` per RSL — `tokens`, `pages`, `fetches`; not fixed) | `ai-train` |
| `use` / `inference` | `PER_UNIT` (typical `unit: "tokens"`) | `ai-input` |
| `attribution` | `FREE` + `Obligation{kind: ATTRIBUTION, trigger: ON_USE}` | — |
| `contribution` | `FREE` + `Obligation{kind: CONTRIBUTION, trigger: ON_USE}` | — |

`FREE` pricing is explicit and required; the ingestion worker sets `model: FREE` for RSL `attribution` and `contribution` payment types — absent `Pricing` on an ENUMERATED term is rejected.

---

## License examples

These express real licenses in enumerated terms and validate that the proto shape holds across domains.

> For brevity, `License.uri_digest` is omitted from the examples below. In a real term, any `license` carrying a `uri` MUST also carry its `uri_digest` (see [Validation rules](#validation-rules-normative)).

### CC BY 4.0 — permissive, all domains
```json
{ "license": { "uri": "https://creativecommons.org/licenses/by/4.0/", "id": "CC-BY-4.0", "immutable": true },
  "semantics": "ENUMERATED",
  "pricing": { "model": "FREE" },
  "obligations": [{ "kind": "ATTRIBUTION", "trigger": "ON_USE" }] }
```

### CC BY-NC 4.0 — non-commercial
```json
{ "license": { "uri": "https://creativecommons.org/licenses/by-nc/4.0/", "id": "CC-BY-NC-4.0", "immutable": true },
  "semantics": "ENUMERATED",
  "pricing": { "model": "FREE" },
  "restrictions": [{ "kind": "FUNCTION", "prohibited": ["commercial"] }],
  "obligations": [{ "kind": "ATTRIBUTION", "trigger": "ON_USE" }] }
```

### GPL-3.0 — copyleft (datasets / code)
```json
{ "license": { "uri": "https://spdx.org/licenses/GPL-3.0-only.html", "id": "GPL-3.0-only", "immutable": true },
  "semantics": "ENUMERATED",
  "pricing": { "model": "FREE" },
  "obligations": [
    { "kind": "ATTRIBUTION", "trigger": "ON_DISTRIBUTION" },
    { "kind": "SHARE_ALIKE", "trigger": "ON_DISTRIBUTION", "scope_license": "GPL-3.0-only" }
  ] }
```

### AGPL-3.0 — differs from GPL only in trigger
```json
{ "license": { "uri": "https://spdx.org/licenses/AGPL-3.0-only.html", "id": "AGPL-3.0-only", "immutable": true },
  "semantics": "ENUMERATED",
  "pricing": { "model": "FREE" },
  "obligations": [
    { "kind": "ATTRIBUTION", "trigger": "ON_DISTRIBUTION" },
    { "kind": "SHARE_ALIKE", "trigger": "ON_NETWORK_SERVICE", "scope_license": "AGPL-3.0-only" }
  ] }
```

### CC BY-SA 4.0 — share-alike on derivatives
```json
{ "license": { "uri": "https://creativecommons.org/licenses/by-sa/4.0/", "id": "CC-BY-SA-4.0", "immutable": true },
  "semantics": "ENUMERATED",
  "pricing": { "model": "FREE" },
  "obligations": [
    { "kind": "ATTRIBUTION", "trigger": "ON_USE" },
    { "kind": "SHARE_ALIKE", "trigger": "ON_DERIVATIVE", "scope_license": "CC-BY-SA-4.0" }
  ] }
```

### All-rights-reserved with RSL AI licensing (two terms, web publishing)
```json
[
  { "semantics": "ENUMERATED",
    "restrictions": [{ "kind": "FUNCTION", "permitted": ["crawl", "search", "ai-index"] }],
    "pricing": { "model": "PER_UNIT", "unit": "fetches", "rate": 0.001, "currency": "USD" } },

  { "semantics": "ENUMERATED",
    "restrictions": [{ "kind": "FUNCTION", "permitted": ["ai-input"] }],
    "pricing": { "model": "PER_UNIT", "unit": "accesses", "rate": 0.05, "currency": "USD" },
    "obligations": [{ "kind": "ATTRIBUTION", "trigger": "ON_USE" }] }
]
```

### RSL attribution payment type (obligation-based, no monetary charge)
```json
{ "semantics": "ENUMERATED",
  "pricing": { "model": "FREE" },
  "obligations": [{ "kind": "ATTRIBUTION", "trigger": "ON_USE" }] }
```
`FREE` is explicit. Absent `Pricing` would mean "terms not specified" — not free.

### Music: commercial sync license, territory-restricted
```json
{ "license": { "uri": "https://publisher.example/sync-license-standard" },
  "semantics": "ENUMERATED",
  "restrictions": [
    { "kind": "FUNCTION", "permitted": ["sync", "reproduce"] },
    { "kind": "GEOGRAPHY", "permitted": ["US", "CA", "GB"] }
  ],
  "pricing": { "model": "FLAT", "rate": 500.00, "currency": "USD" } }
```

### CERN OHL-S v2 — open hardware copyleft (CAD)
```json
{ "license": { "uri": "https://ohwr.org/cern_ohl_s_v2.txt", "id": "CERN-OHL-S-2.0", "immutable": true },
  "semantics": "ENUMERATED",
  "pricing": { "model": "FREE" },
  "obligations": [
    { "kind": "ATTRIBUTION", "trigger": "ON_DISTRIBUTION" },
    { "kind": "SHARE_ALIKE", "trigger": "ON_DISTRIBUTION", "scope_license": "CERN-OHL-S-2.0" },
    { "kind": "NOTICE", "trigger": "ON_DISTRIBUTION",
      "detail": "https://ohwr.org/cern_ohl_s_v2_notice.txt" }
  ] }
```

### CAD: per-unit manufacturing license with volume cap
```json
{ "semantics": "ENUMERATED",
  "restrictions": [{ "kind": "FUNCTION", "permitted": ["manufacture", "sell"] }],
  "quotas": [{ "metric": "units-manufactured", "limit": 10000, "window": "TOTAL" }],
  "pricing": { "model": "PER_UNIT", "unit": "units-manufactured", "rate": 0.50, "currency": "USD",
               "metering": "OFFLINE_SELF_REPORTED" } }
```
The quota caps the license grant (10,000 total units). `PER_UNIT` with `unit: units-manufactured` charges per manufacturing right. `OFFLINE_SELF_REPORTED` because the Exchange cannot observe manufacturing events directly.

### Stock media: subscription royalty-free
```json
{ "semantics": "ENUMERATED",
  "scopes": ["subscription:premium"],
  "restrictions": [{ "kind": "FUNCTION", "permitted": ["display", "editorial"] }],
  "pricing": { "model": "FREE" } }
```

### Stock media: rights-managed editorial
```json
{ "semantics": "ENUMERATED",
  "restrictions": [
    { "kind": "FUNCTION",    "permitted": ["editorial"] },
    { "kind": "GEOGRAPHY",   "permitted": ["US", "CA"] },
    { "kind": "USER_TYPE",   "permitted": ["news_publisher"] }
  ],
  "pricing": { "model": "FLAT", "rate": 350.00, "currency": "USD" },
  "obligations": [{ "kind": "ATTRIBUTION", "trigger": "ON_USE" }] }
```

### AI training prohibition
```json
{ "semantics": "ENUMERATED",
  "restrictions": [{ "kind": "FUNCTION",
    "prohibited": ["ai-train", "ai-input", "ai-index", "text-and-data-mining"] }],
  "pricing": { "model": "FREE" } }
```

### Data-labels TDL (REFERENCE_ONLY)
```json
{ "license": { "uri": "https://tdl.example/dataset-license-v2", "immutable": true,
               "uri_digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" },
  "semantics": "REFERENCE_ONLY" }
```
All machine fields absent. "See the document." Not free, not denied.

### CC0 (public domain)
```json
{ "license": { "uri": "https://creativecommons.org/publicdomain/zero/1.0/", "id": "CC0-1.0", "immutable": true },
  "semantics": "ENUMERATED",
  "pricing": { "model": "FREE" } }
```

---

## Compatibility

- **data-labels TDL:** `LicenseTerm{ license{uri, immutable:true, uri_digest}, semantics: REFERENCE_ONLY, pricing }` round-trips losslessly. Absent enforceable fields (`restrictions`/`quotas`/`obligations`) mean "see the document" — never deny, never free; `Pricing` is always stated.
- **RSL 1.0:** `one <content> → many <license>` ≡ `terms[]`. RSL `<standard>/<custom>/<terms>` → `License.uri`. Permits/prohibits → `Restriction`. Payment types → §RSL canonical mapping.
- **TollBit:** rate options map to `terms[]` with `License{id: cuid, name: licenseType, uri: licensePath}`; no `ext` required.
- **IETF AIPREF / CAWG / TDMRep:** function tokens are registered as RSL aliases. Cloudflare `crawler-price` projects from a `PER_UNIT`/`unit: fetches` term.

---

## Changelog

This ADR is edited in place to describe the current design; the entries below record what changed and the prior state where it matters.

- **2026-06-18 — Extension profiles are reply-time projections (CoMP is a view).** Added *Extension profiles and reply-time projection*. Domain profiles (CoMP `ramp-comp-v1`, …) are rendered on reply from the normalized term model — keyed on `DiscoverResourcesRequest.supported_profiles`, cached per `(term, profile)` at snapshot rebuild — and are never stored as a source of truth. Term-independent resource metadata is harmonized at ingest; term-dependent facts are projected per-offer (one offer = one term = one CoMP package). The term shadows `ext` for offer-owned fields, so offer and profile rendering are coherent without a hot-path conflict branch. Unmappable constructs (e.g. revenue-share) are flagged/omitted per a per-profile expressibility matrix; the canonical `LicenseTerm` always rides on `Offer.terms[]`. *Before:* the JSONL/`ext` metadata round-trip shipped as pure pass-through, with no defined profile rendering and no stated rule for publisher `ext` that contradicts a term.
- **2026-06-15 — Selection is scope-only.** The Exchange selects terms into offers by `resource_id`/URI and Biscuit scope coverage only; recorded in *Requester-attribute filtering is not applied*. *Before:* selection also filtered terms by matching the requester's self-declared `user_type` / `geography` / `intended_use` against the term's `Restriction`s. Removed because those inputs are unverified say-so (advisory at best) and the matching pulled the Exchange toward being a general license-matching engine; restrictions still ride on the offer and the agent self-selects.
