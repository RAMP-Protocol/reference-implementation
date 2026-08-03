# ADR-019 — Proto-Defined Error and Response Contract

**Status:** Accepted

---

## Overview

ADR-014 made the *success* side of the protocol a single, SDK-validated, cross-language contract: typed `LicenseTerm` shapes, protovalidate CEL at the RPC boundary, the same bytes at ingestion and emission. This ADR is the *failure-and-response* completion of that model. It defines the complete error model — every failure mode and error-response shape, for every RPC — and standardizes the response envelope, so that errors and responses, like licensing, are a single language-agnostic contract validated by the SDK rather than re-expressed in each service and each language.

The proto change has landed first (the `protocol-unification` work in the `RAMP-Protocol/protocol` repo); this ADR records the decisions and the adoption obligations on the Exchange, Broker, and edge worker.

## The problem

The same failure was named in mutually incompatible ways across the system:

- the Exchange mapped domain failures through a hand-rolled Go `Kind` enum whose seven-mode entitlement family (`KindEntitlementMissing/Malformed/Expired/WrongBuyer`, `KindSubscriptionLapsed`, `KindEntitlementNotGranted`, `KindEntitlementStaleAttenuation`) all collapsed to `CodeUnauthenticated` on the wire — distinguishable only by a server-side tag;
- the Broker carried its own, separate `Kind` enum;
- the catalog-push path formatted ad-hoc reason strings ("caller not in catalog contributors", "tenant mismatch") into free text;
- the transaction-denial path persisted a database denial enum whose values did not match the proto `DenialReason`, and the proto `DenialReason` was never emitted on the wire;
- the edge worker had its own lowercase token union (`pop_expired`, `thumbprint_mismatch`, …) for verification failures.

The response *shapes* were typed but not standardized: failure signals lived in success bodies as `bool accepted` / `verified` flags and `rejection_reason` / `failure_reason` strings; the envelope (`ver`, `ext`, correlation ids) was inconsistent message to message; and two distinct concerns — request correlation and idempotency — were conflated under a generic `id` / `request_id`.

A client therefore could not rely on one validated, machine-readable contract for either errors or responses. The reason for a failure was expressed differently in Go, TypeScript, and Python, and the shapes lived in code, not the contract.

## Decision

### 1. Failure is a typed `ErrorDetail` on the transport error

The transport carries a coarse canonical code (gRPC / Connect `Code`) as the error *class*. A single `ErrorDetail` message — attached to the transport error's `details`, the same mechanism protovalidate uses for its violations — carries the precise, machine-readable *reason* plus structured context. Clients branch on the typed reason, never on a human string.

```proto
message ErrorDetail {
  string message = 1;                  // developer-facing, NON-authoritative
  string domain = 2;                   // e.g. "ramp.v1.ExchangeService" (ErrorInfo-compatible)
  map<string, string> metadata = 3;    // dynamic context (ids, limits, axes)
  oneof reason {
    TransactionDenial         transaction_denial          = 10;
    CatalogRejection          catalog_rejection           = 11;
    RegistrationFailure       registration_failure        = 12;
    DisputeFailure            dispute_failure             = 13;
    DomainVerificationFailure domain_verification_failure = 14;
    RetrievalAuthFailure      retrieval_auth_failure      = 15;
    UsageReportRejection      usage_report_rejection      = 16;
  }
}
```

Each per-domain detail wraps a typed reason enum (and any structured context). `TransactionDenial` reuses `DenialReason` (now extended with the entitlement family) plus `restriction_mismatches`; the others introduce `CatalogRejectionReason`, `RegistrationFailureReason`, `DisputeFailureReason`, `DomainVerificationFailureReason`, `RetrievalAuthFailureReason` (value-for-value from the edge `verify.ts` / `pop.ts` unions), and `UsageReportRejectionReason`. Reason fields carry `(buf.validate.field).enum = {defined_only: true, not_in: [0]}`, so an attached detail can never be `UNSPECIFIED`.

These per-domain reason enums are the single source of truth that the hand-rolled vocabularies collapse onto.

**Closed enums, not `google.rpc.ErrorInfo` strings.** Google uses an open `reason` string because its API surface is enormous and federated; ours is a handful of fully-controlled RPCs, and the entire goal is compile-time conformance across Go, TypeScript, and Python — which a closed enum delivers and a string would surrender. `ErrorDetail` keeps an ErrorInfo-compatible `domain` + `metadata` for generic tooling, but the authoritative reason is the enum. One carrier message (a `oneof`) is kept rather than attaching bare detail messages, so client code has exactly one type to look for.

### 2. A failed action is a transport error; a successful query stays in the body

The dividing rule (gRPC / AIP-193): a method that could not perform the requested *action* returns a non-OK code plus an `ErrorDetail`; a *query* that ran successfully returns its answer in the body, and "no results" is a successful answer.

- `DiscoverResources` stays a success with in-body `OfferGroup.absence_reason`.
- A denied *single* `ExecuteTransaction`, a rejected `ReportUsage`, a refused `DisputeTransaction` filing, and a failed domain verification become transport errors carrying the typed detail. The in-body `accepted` / `verified` flags and `rejection_reason` / `failure_reason` strings were removed.
- Batch transactions are the deliberate exception: a batch is a successful call whose per-item `TransactionResultItem` may carry a `denial_reason` in-body — exactly like discovery absence, because the partial results *are* the answer.

Success bodies now carry only the payload-when-it-worked.

### 3. One response envelope; correlation by transport header

Every RPC request and response carries `ver` at field 1; the external-contract messages carry `ext` / `ext_critical` so any of them is forward-extensible (trivial internal catalog-admin messages get `ver` only).

Correlation was removed from the proto entirely. The former `request_id` fields were dead code — no implementation read or wrote them. Correlation already flows the way signatures do, over the transport: an `X-Request-ID` header, minted and propagated by shared middleware in the Broker, Exchange, and edge, and bound to a request-scoped logger. By the same reasoning that put signatures on RFC 9421 (a value proxies, edge functions, and tracing systems read without parsing protobuf belongs on the transport), a correlation id has no place in the message body. Cross-system tracing, when added, rides on W3C Trace Context (`traceparent` / `tracestate`) headers.

### 4. Idempotency is an explicit, required `idempotency_key`

Idempotency is the mirror image of correlation: it is persisted, settlement-bound state the server *acts on* — the Exchange dedupes on it, stores it under a `UNIQUE` constraint, and threads it into the billing adapter so a replay cannot double-charge. By the rule that governs the wire format — what must outlive the HTTP exchange and survive a dispute stays a typed field — the idempotency key belongs in the body (this is where RAMP diverges from Stripe's header-based key: RAMP's is part of the signed, persisted, reconciled record).

The mutating requests carried this as a generic `id` (only `TransactionRequest.id` was actually deduped on; `UsageReport.id` was an unwired intention). It is renamed `idempotency_key` and made required (`min_len = 1`) on the state-mutating RPCs — `ExecuteTransaction`, `ReportUsage`, `DisputeTransaction` — naming the guarantee: the server MUST return the original result on replay. The request needs no separate own-id, because the durable identity of what it creates is the Exchange-assigned id in the response (`transaction_id`, `report_id`, `dispute_id`). Queries take no key; the naturally-idempotent catalog upsert/delete and onboarding calls are left out deliberately.

The field is declared in the contract **ahead of full enforcement**: the Exchange dedupes `ExecuteTransaction` today; `ReportUsage` and `DisputeTransaction` adopt the same check as the implementation catches up to the contract. The proto leads, the services follow.

## Consequences

Adoption obligations across the system (sequenced after the proto change):

- **Exchange.** Reduce the Go `Kind` type to mapping a domain failure to a transport code only; the reason it emits comes from the proto enum, attached as an `ErrorDetail` detail. The database denial enum stores the proto `DenialReason` — no parallel vocabulary. The transaction path emits the proto denial reason on the wire. Wire idempotency dedup for `ReportUsage` and `DisputeTransaction` (today only `ExecuteTransaction`), keyed on `idempotency_key`.
- **Broker.** Refusals use the proto vocabulary and an `ErrorDetail`, not free strings or an `ext`-smuggled error; the broker's `Kind` enum collapses to transport-code mapping.
- **Edge worker.** Replace the TypeScript token union with the generated `RetrievalAuthFailureReason` enum; signed-URL and proof-of-possession failures emit the proto reason.
- **All services.** Turn on response/detail validation so emitted messages — including `ErrorDetail` — are validated against the proto on the way out. Tests assert the typed proto reason per method's failure modes (success and failure paths), through the public RPC/route surface, never by string-matching.
- **Cross-language.** A conformance suite asserts the same canonical message (success and error) round-trips identically across the generated SDKs. (Python is not yet in `buf.gen.yaml`; if it remains a component, it is added, ideally as Pydantic, so no hand-rolled wire-shaped mirror is needed.)

These are tracked as separate implementation tickets; this ADR fixes the contract and the rationale.

## Rejected alternatives

- **`google.rpc.ErrorInfo` with an open string `reason`.** Re-imports the stringly-typed problem the whole effort removes; clients lose compile-time typing. Rejected in favor of closed per-domain enums (with `domain`/`metadata` kept for ErrorInfo compatibility).
- **No wrapper — attach bare detail messages to the transport error.** More idiomatic to `google.rpc`, but forces every client to scan for N detail types; the goal is uniform client code, so a single `ErrorDetail` carrier with a `oneof` was kept.
- **One flat mega-enum for all failure reasons.** Maximum uniformity, but couples every component to one enum and makes it a global merge point; per-domain enums under one carrier give the same uniformity with component independence.
- **Model denials/absence as transport errors uniformly (incl. discovery).** Conflates "the query answered, with no results" with "the action failed." Discovery absence and batch per-item denials stay in-body.
- **Keep correlation as a body `request_id`.** It was dead code and duplicates what the `X-Request-ID` header already does, visible to infrastructure without parsing protobuf.
- **Idempotency key as an HTTP header (Stripe-style).** RAMP's key is persisted, signed, and reconciled — it is business state, not a transport hint, so it stays a typed body field.

## Non-goals

- This ADR does not design the wire idempotency *store* (LRU sizing, DB UNIQUE backstop) — that is the Exchange's concern (see ADR-011's double-charge invariant).
- It does not add distributed tracing; it only states that correlation rides on `X-Request-ID` today and W3C Trace Context when tracing is introduced.
- It does not redesign the `DisputeStatus` lifecycle or the reconciliation model (ADR-011/012).
- It does not specify the Python SDK generation strategy beyond noting the mandate that components consume generated SDK types rather than hand-rolled mirrors.
- It does not change the success-side licensing contract (ADR-014).

## References

- ADR-014 — Universal Licensing Core (the success-side contract this completes).
- `RAMP-Protocol/protocol` — `ramp.proto`, the landed contract. The wire-shaping reasoning for the error model, success-body rule, correlation-by-header and idempotency lives with it.
- gRPC error model / Google AIP-193 (canonical codes + typed error details).
