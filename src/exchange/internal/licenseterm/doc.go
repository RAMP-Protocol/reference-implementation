// Package licenseterm is the single home for all RAMP license-term validation,
// normalization and selection logic.
//
// It operates directly on the generated rampv1.LicenseTerm proto type: the term
// shape is never redefined locally, and term logic is never reimplemented at
// call sites. Handlers (e.g. CatalogService.PushResources, discovery) import
// this package rather than open-coding restriction/quota/obligation rules —
// mirroring the internal/rampwellknown extraction pattern.
//
// The public surface:
//   - Validate  — Pricing required on every term, REFERENCE_ONLY
//     requires a License uri; unknown-token warnings deferred.
//   - Normalize — alias resolution + token canonicalization,
//     run by the handler before Validate and before persist so the stored row
//     and the DiscoverResources→Offer.terms projection carry canonical tokens.
//   - Select    — scope coverage only (requester-attribute matching removed,
//     ADR-014 2026-06-15 amendment).
//
// Vocabulary is abstracted behind VocabProvider so this package can flag unknown
// tokens without owning the registry; the embedded registry loader is a
// separate follow-up.
package licenseterm
