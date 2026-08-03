# CoMP V1 JSON Schema

`comp-v1.schema.json` is a JSON Schema (Draft 2020-12) for the canonical CoMP V1
wire format — both the request-side `aisystem` document and the supply-side
`package` document.

## Why this exists

CoMP V1 ships as a **single Markdown specification** with no upstream
machine-readable schema (no `.proto`, no JSON Schema, no reference validator).
This schema is RAMP-authored, derived field-by-field from the spec's object
attribute tables and integer-coded "Lists". It serves two purposes:

1. **Conformance gate** — the machine-checked validator the CoMP
   conformance harness (`src/exchange/internal/comptest`) upgrades to. The render
   slices' emitted `ext.comp` Package can be validated against it directly.
2. **Upstream contribution** — the artifact proposed back to IAB Tech Lab
   to fill the missing machine-readable-schema gap.

## Source (cited)

- **Spec:** "Content Metadata Marketplace Supply Specification (MVP)"
  (`CoMP-1.0.md`, H1 title; initiative brand: Content Monetization Protocols).
- **Repo:** https://github.com/IABTechLab/CoMP/blob/main/CoMP-1.0.md
- **Commit:** `08c0181afe69030f7b5ffa2e1227b69e9d4e2db8` (`main`). CoMP V1
  finalized 2026-04-28.

## Shape

A CoMP document is an object carrying `aisystem` and/or `package` (at least one).
`$defs` model `AISystem`, `AISystemUse`, `Package`, `Scope`, `Text`, `Video`,
`Image`, `Audio`, `Retrieval`. Every canonical object sets
`additionalProperties: false` (no foreign keys at canonical paths); non-CoMP
extensions (e.g. RAMP fields) are permitted **only** under each object's open
nested `ext` object. Integer-coded Lists with a fixed value set (allowed-use,
price-type, content-scope, content-type, auth methods, delivery formats,
function/sub-function, publication status, creation source) are modeled as
`enum`s; open taxonomies (`cat`, `language`, `cattax`, `country`, `citation`,
`provenance`, `resdis`) are typed integers without an enum. Media `title` is
`string` or `string[]` (the canonical examples use both).

## Self-test

`src/exchange/internal/comptest/schema_test.go` proves the schema is correct: it
validates all sixteen canonical documents (the package and aisystem halves of the
eight worked examples, vendored under `deploy/fixtures/comp/canonical/`) and
rejects deliberately-broken documents.
