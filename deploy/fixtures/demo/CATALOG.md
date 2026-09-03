# RAMP Demo Catalog Manifest

This manifest describes the **demo catalog**. Every resource below is produced
from the three JSONL feeds in this directory (`philosophy.jsonl`, `music.jsonl`,
`sfx.jsonl`) via the real ingestion path (`ParseJSONL` → `mapRecord`, which
canonicalizes each term through the SDK's `helpers.NormalizeLicenseTerm` →
`CatalogService.PushResources`, where the Exchange runs the SDK's
`helpers.ValidateLicenseTerm`). All 22 records / 26 terms parse, map, and
validate with zero warnings and zero hard rejects against the registered RAMP
vocab pinned in `go.mod`.

The e2e suite does **not** read these feeds. It owns its own copy under
`tests/e2e/harness/fixtures/catalog/`, so the two sets are free to diverge: a
demo wants one currency and a tidy story, a test suite wants the awkward
combinations. Changing a price or a term here does not change any test
expectation.

Content files live under `deploy/content/demo/<publisher>/...` at paths that
match the `path` column below (the Phase-2 origin container serves that tree).

## Publishers

| Publisher | Domain | Content base | Records |
|-----------|--------|--------------|---------|
| Stoa Press | `demo.ramp-protocol.org` | `deploy/content/demo/stoa-press/articles/philosophers/` | 10 |
| Harmonia Records | `music.demo.ramp-protocol.org` | `deploy/content/demo/harmonia-records/{lyrics,tracks}/` | 6 |
| FoleyWorks | `sfx.demo.ramp-protocol.org` | `deploy/content/demo/foleyworks/sfx/` | 6 |

## Retrieval canary

`/articles/philosophers/thales-of-miletus.txt` embeds the retrieval-proof
canary the e2e/demo checks. The retrieved body MUST contain, verbatim:

- token `RAMP-DEMO-CANARY-8FK3J2-0418`
- Greek phrase `καῦμα διὰ ῥάμπης`
- marker `entry XI.47-bis`

Thales is deliberately a FLAT-priced (`9.99 EUR`) term with an attribution +
backlink obligation, so the canary path also exercises a priced fetch with an
obligation.

## Resource → terms (philosophy.jsonl · Stoa Press · `demo.ramp-protocol.org`)

| Domain | Path | Content-Type | #Terms | Terms summary |
|--------|------|--------------|--------|---------------|
| demo.ramp-protocol.org | /articles/philosophers/socrates.txt | text/plain | 1 | FREE; fn[ai-input+search]; PROHIBIT[ai-train]; user[academic]; geo[EU] |
| demo.ramp-protocol.org | /articles/philosophers/plato.txt | text/plain | 2 | (a) FREE; fn[ai-input+ai-index+search]; PROHIBIT[ai-train]; user[academic]; geo[EU,EEA] **\|\|** (b) PER_UNIT 0.03/accesses EUR; user[commercial_entity]; geo[EU]; quota 5000 accesses/daily; obl:attribution(on_use, backlink) |
| demo.ramp-protocol.org | /articles/philosophers/aristotle.txt | text/plain | 1 | FLAT 7.50 EUR; fn[ai-input+ai-index]; PROHIBIT[ai-train]; geo[EU]; obl:attribution(on_use, backlink) |
| demo.ramp-protocol.org | /articles/philosophers/epicurus.txt | text/plain | 1 | PER_UNIT 0.0001/characters EUR; fn[ai-input]; PROHIBIT[ai-train]; user[individual]; geo[US,GB] |
| demo.ramp-protocol.org | /articles/philosophers/heraclitus.txt | text/plain | 1 | FREE; fn[ai-input+search+research]; PROHIBIT[ai-train]; geo[EU] |
| demo.ramp-protocol.org | /articles/philosophers/parmenides.txt | text/plain | 1 | reference_only / subscription (scopes: subscription:premium); pricing free EUR; license uri required |
| demo.ramp-protocol.org | /articles/philosophers/democritus.txt | text/plain | 1 | FLAT 6.00 EUR; fn[ai-input+ai-index]; geo[GB]; obl:attribution(on_use) + obl:notice(on_distribution) |
| demo.ramp-protocol.org | /articles/philosophers/pythagoras.txt | text/plain | 1 | PER_UNIT 0.00002/tokens EUR; fn[ai-input+ai-index]; user[commercial_entity]; geo[GB,EU]; quota 2000000 tokens/daily; obl:contribution(on_use, royalty) |
| demo.ramp-protocol.org | /articles/philosophers/zeno-of-citium.txt | text/plain | 2 | (a) FREE; fn[ai-input+research+search]; PROHIBIT[ai-train]; user[academic]; geo[EU] **\|\|** (b) PER_UNIT 0.04/accesses EUR; user[commercial_entity]; geo[EU,US]; quota 10000 accesses/monthly |
| demo.ramp-protocol.org | /articles/philosophers/thales-of-miletus.txt | text/plain | 1 | **CANARY** · FLAT 9.99 EUR; fn[ai-input+ai-index+search]; PROHIBIT[ai-train]; geo[EU]; obl:attribution(on_use, backlink) |

## Resource → terms (music.jsonl · Harmonia Records · `music.demo.ramp-protocol.org`)

| Domain | Path | Content-Type | #Terms | Terms summary |
|--------|------|--------------|--------|---------------|
| music.demo.ramp-protocol.org | /lyrics/midnight-harbour.txt | text/plain | 2 | (a) FREE; fn[ai-input+search]; PROHIBIT[ai-train]; user[academic]; geo[EU,GB] **\|\|** (b) PER_UNIT 0.05/accesses EUR; fn[ai-input+ai-index+tts]; user[commercial_entity]; geo[EU,GB]; quota 2000 accesses/daily; obl:attribution(on_use, backlink) |
| music.demo.ramp-protocol.org | /lyrics/paper-satellites.txt | text/plain | 1 | FLAT 3.50 EUR; fn[ai-input+ai-index]; PROHIBIT[ai-train]; geo[US]; obl:attribution(on_use, backlink) |
| music.demo.ramp-protocol.org | /lyrics/ferrograph-blues.txt | text/plain | 1 | reference_only / subscription (scopes: subscription:catalog); pricing free EUR |
| music.demo.ramp-protocol.org | /tracks/aurora-drift.json | application/json | 1 | PER_UNIT 0.002/streams EUR; fn[ai-input+sync+stream]; PROHIBIT[ai-train]; user[commercial_entity]; geo[EU,US,GB]; quota 50000 accesses/monthly; obl:contribution(on_use, royalty) |
| music.demo.ramp-protocol.org | /tracks/copper-mile.json | application/json | 1 | FLAT 4.00 EUR; fn[ai-input+ai-index+sync]; user[non_profit]; geo[EU]; obl:notice(on_distribution) |
| music.demo.ramp-protocol.org | /tracks/static-garden.json | application/json | 1 | PER_UNIT 0.01/minutes EUR; fn[ai-input+stream+sync]; PROHIBIT[ai-train]; user[commercial_entity]; geo[GB]; quota 1000 accesses/daily |

## Resource → terms (sfx.jsonl · FoleyWorks · `sfx.demo.ramp-protocol.org`)

| Domain | Path | Content-Type | #Terms | Terms summary |
|--------|------|--------------|--------|---------------|
| sfx.demo.ramp-protocol.org | /sfx/rain-on-tin-roof.json | application/json | 1 | FREE; fn[ai-input+search]; PROHIBIT[ai-train]; user[individual]; geo[EU,US,GB]; obl:attribution(on_use, backlink) |
| sfx.demo.ramp-protocol.org | /sfx/wooden-door-creak.json | application/json | 1 | PER_UNIT 0.25/accesses EUR; fn[ai-input+sync+reproduce]; user[commercial_entity]; geo[EU,US,GB]; quota 500 accesses/daily; obl:contribution(on_distribution, royalty) |
| sfx.demo.ramp-protocol.org | /sfx/sci-fi-door-whoosh.json | application/json | 1 | FLAT 12.00 EUR; fn[ai-input+sync+modify+reproduce]; PROHIBIT[ai-train]; geo[EU,US,GB]; obl:attribution(on_use) |
| sfx.demo.ramp-protocol.org | /sfx/footsteps-gravel.json | application/json | 1 | reference_only / subscription (scopes: subscription:library); pricing free EUR |
| sfx.demo.ramp-protocol.org | /sfx/thunder-rumble.json | application/json | 2 | (a) FREE; fn[ai-input+search]; PROHIBIT[ai-train]; user[academic]; geo[EU] **\|\|** (b) PER_UNIT 0.15/accesses EUR; fn[ai-input+sync+reproduce]; user[commercial_entity]; geo[EU,GB]; quota 750 accesses/daily; obl:notice(on_distribution) |
| sfx.demo.ramp-protocol.org | /sfx/typewriter-keystroke.json | application/json | 1 | PER_UNIT 0.10/accesses EUR; fn[ai-input+sync+reproduce+modify]; user[commercial_entity]; geo[US]; quota 250 accesses/hourly |

## Variety matrix (coverage proof)

| Axis | Value | Resources that cover it |
|------|-------|-------------------------|
| Pricing | FREE | socrates, heraclitus, plato(a), zeno(a), midnight-harbour(a), rain-on-tin-roof, thunder-rumble(a) |
| Pricing | FLAT | aristotle, democritus, thales (canary), paper-satellites, copper-mile, sci-fi-door-whoosh |
| Pricing | PER_UNIT | epicurus, pythagoras, plato(b), zeno(b), aurora-drift, static-garden, midnight-harbour(b), wooden-door-creak, thunder-rumble(b), typewriter-keystroke |
| Pricing | reference_only / subscription | parmenides (subscription:premium), ferrograph-blues (subscription:catalog), footsteps-gravel (subscription:library) |
| Currency | EUR | socrates, plato, aristotle, heraclitus, parmenides, thales, copper-mile, footsteps-gravel, thunder-rumble(a) |
| Currency | EUR | epicurus, zeno(b), paper-satellites, ferrograph-blues, aurora-drift, rain-on-tin-roof, wooden-door-creak, sci-fi-door-whoosh, typewriter-keystroke |
| Currency | EUR | democritus, pythagoras, midnight-harbour, static-garden, thunder-rumble(b) |
| Restriction: geo | EU-only | socrates, aristotle, heraclitus, copper-mile, thunder-rumble(a), zeno(a) |
| Restriction: geo | US-only / US-incl | epicurus(US,GB), paper-satellites(US), typewriter-keystroke(US) |
| Restriction: geo | EEA | plato(a) (geo[EU,EEA]) |
| Restriction: user_type | academic | socrates, plato(a), zeno(a), midnight-harbour(a), thunder-rumble(a) |
| Restriction: user_type | commercial_entity | plato(b), pythagoras, zeno(b), midnight-harbour(b), aurora-drift, static-garden, wooden-door-creak, thunder-rumble(b), typewriter-keystroke |
| Restriction: user_type | individual | epicurus, rain-on-tin-roof |
| Restriction: user_type | non_profit | copper-mile |
| Function | ai-input | every enumerated term |
| Function | ai-index | plato, aristotle, democritus, pythagoras, zeno(b), midnight-harbour(b), copper-mile, paper-satellites |
| Function | search | socrates, plato(a), heraclitus, zeno(a), thales, midnight-harbour(a), rain-on-tin-roof, thunder-rumble(a) |
| Function | ai-train PROHIBITED | socrates, plato(a), aristotle, epicurus, heraclitus, zeno(a), thales, midnight-harbour(a), paper-satellites, aurora-drift, static-garden, rain-on-tin-roof, sci-fi-door-whoosh, thunder-rumble(a) |
| Function | synthesis/media (sync, stream, tts) | tts: midnight-harbour(b); sync: aurora-drift, copper-mile, static-garden, wooden-door-creak, sci-fi-door-whoosh, thunder-rumble(b), typewriter-keystroke; stream: aurora-drift, static-garden |
| Obligation | attribution (with backlink detail) | plato(b), aristotle, thales, midnight-harbour(b), paper-satellites, rain-on-tin-roof, sci-fi-door-whoosh, democritus |
| Obligation | reporting / royalty (contribution + notice) | contribution: pythagoras, aurora-drift, wooden-door-creak; notice: democritus, copper-mile, thunder-rumble(b) |
| Quota | daily access cap on PER_UNIT | plato(b), midnight-harbour(b), static-garden, wooden-door-creak, thunder-rumble(b) (also pythagoras tokens/daily) |
| Quota | other windows | monthly: zeno(b), aurora-drift; hourly: typewriter-keystroke |
| Multi-term resource (2+ terms) | academic-FREE + commercial-PER_UNIT | plato, zeno-of-citium, midnight-harbour, thunder-rumble |

## Registered-vocab note

Every `functions`, `user_types`, `geos`, pricing `model`/`unit`, quota
`metric`/`window`, and obligation `kind`/`trigger` token in the three feeds is
a registered canonical token in the pinned protocol module. There are **no
unregistered tokens** anywhere in the catalog — a clean run through the SDK's
`helpers.ValidateLicenseTerm`, the ingest-tier check the Exchange runs on every
pushed term, produced zero lint warnings and zero hard rejects across all 26
terms (`src/exchange/internal/ingest/demo_feeds_test.go` asserts this).

Subscription pricing is modeled as `reference_only` semantics with a
`subscription:*` scope and `free` pricing (the proto's closed pricing model set
is FREE/FLAT/PER_UNIT; "subscription" is a scope, not a pricing model).
