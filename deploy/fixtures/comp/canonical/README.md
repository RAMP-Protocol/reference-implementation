# Canonical CoMP V1 examples (conformance corpus)

Vendored supply-side **Package** documents from the eight worked examples in the
canonical CoMP V1 specification. These are the conformance oracle:
the CoMP rendering emitted under `Offer.ext.comp` must validate against the same
canonical Package shape these examples exhibit, proving a real CoMP consumer
would accept it.

## Source (cited)

- **Spec:** "Content Metadata Marketplace Supply Specification (MVP)" — the H1
  title of `CoMP-1.0.md` (initiative brand: Content Monetization Protocols).
- **Repo:** https://github.com/IABTechLab/CoMP/blob/main/CoMP-1.0.md
- **Commit:** `08c0181afe69030f7b5ffa2e1227b69e9d4e2db8` (`main`, last substantive
  update 2026-04-20, "Updated per Public Comment Feedback"). CoMP V1 finalized
  2026-04-28.
- **Format:** CoMP V1 ships as a single Markdown spec — there is **no upstream
  `.proto`, JSON Schema, or reference parser**. The eight worked examples + the
  object attribute tables are the only machine-checkable oracle that exists.

## What is vendored

`example-{1..8}-package.json` — each file is the **supply-side `package`** half
of the correspondingly-numbered worked example, copied verbatim (re-indented).
Each example in the spec is a request/response pair: a request-side `aisystem`
document and a supply-side `package` document. RAMP renders the **supply side**
(an Offer's CoMP projection is a Package), so only the package halves are
vendored as the conformance corpus. The request-side `aisystem` halves are out
of scope for supply-side rendering conformance.

| File | Example |
|------|---------|
| example-1-package.json | Example 1: Unauthorized Request |
| example-2-package.json | Example 2: Authorized Request |
| example-3-package.json | Example 3: Curated Selection of Multiple Asset Types |
| example-4-package.json | Example 4: Image Creation |
| example-5-package.json | Example 5: Podcast Full Feed Authorized |
| example-6-package.json | Example 6: Podcast Published After a Date |
| example-7-package.json | Example 7: Video Creation |
| example-8-package.json | Example 8: Agent Actions |

## Oracle / consumers

The Go conformance helper `src/exchange/internal/comptest` (`Validate`) encodes
the canonical supply-side object schema (Package/Scope/Text/Video/Image/Audio/
Retrieval, derived from the spec attribute tables) and validates a rendered
`ext.comp` Package against it: known keys only at canonical paths (RAMP extras
live solely under nested `ext` objects), canonical field types, and required
fields. Its self-test asserts every file here is accepted (proving the oracle is
correct) and that a deliberately-broken document is rejected.

When the RAMP-authored CoMP V1 JSON Schema lands, it drops in as
a machine-checked schema-validation gate behind the same `Validate` interface;
that schema is self-proven against these same eight examples.
