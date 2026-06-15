# ADR-012 — Edge Delivery-Log Contract

**Status:** Accepted (2026-06-02)

---

## Context

The reconciliation procedure in ADR-011 requires three witnesses per transaction: the Exchange's signed-URL mint event, the Agent Usage Report, and a third witness that the Edge actually served bytes. The RAMP protocol defines the signed-URL shape, an optional `Offer.content_hash` qualified by `ResourceMutability`, and a `DomainVerificationRequest` flow for onboarding signing keys, but it does not define the third witness — there is no `DeliveryLog` or `FetchAcknowledgement` message in `ramp.proto`. The Edge is the only party that sees both the signed URL and the delivered bytes; this ADR pins the evidence the Edge must produce. The contract is scoped below the protocol layer so publishers who use CDN-native delivery can produce an equivalent witness without protocol churn.

---

## Decision

### D1 — Per-fetch signed delivery record

For every signed-URL fetch — successful or denied — the Edge emits exactly one **delivery record**, independently signed under the Edge's per-node Ed25519 key (D2). Records are not Merkle-chained (D5).

Schema:

```
record_id            ULID                  Edge-generated, monotonic per instance
record_timestamp     RFC3339 UTC ns        Edge wall clock at fetch processing
edge_node_id         string                Edge identity (D3)
edge_signing_kid     string                kid of the record-signing key (D2)
transaction_id       string (UUID)         From signed URL's txn_id parameter
signed_url_hash      hex(SHA-256)          Hash of full URL incl. query;
                                           matches transaction_events.signed_url_hash
agent_identity_hash  base64url             From URL's agent_id (RFC 7638 thumbprint)
url_expires          RFC3339               From URL's expires parameter
outcome              enum                  DELIVERY_OUTCOME_* (see below)
outcome_reason       enum, conditional     DELIVERY_REASON_*; required when outcome != DELIVERED_OK
http_status          int32                 Status returned to agent
bytes_sent           int64, conditional    Required when outcome=DELIVERED_OK
content_hash_observed string, optional     "method:hexdigest" of bytes streamed (D4)
content_hash_method  string, conditional   Required when content_hash_observed populated
rfc9421_signature_valid bool               DPoP/PoP check result
presented_agent_kid  string, optional      kid of key the agent presented
client_ip_hash       hex(SHA-256)          Salted hash; never the raw IP; salt rotates quarterly
user_agent           string, optional      Truncated to 256 bytes
record_signature     base64url             Ed25519 over JCS (RFC 8785) of preceding fields
```

Outcome enum (closed, exhaustive — ADR-008 D2 applies):

```
DELIVERY_OUTCOME_DELIVERED_OK         http_status=200, bytes_sent>0
DELIVERY_OUTCOME_DENIED_VERIFICATION  URL HMAC or Ed25519 sig failed (reason distinguishes)
DELIVERY_OUTCOME_DENIED_EXPIRED       URL past expires at fetch time
DELIVERY_OUTCOME_DENIED_BINDING       thumbprint(presented) != agent_id, or RFC 9421 failed
DELIVERY_OUTCOME_DENIED_REPLAY        Single-use enforcement refused second fetch
DELIVERY_OUTCOME_ORIGIN_ERROR         Origin error/timeout; no usable bytes
DELIVERY_OUTCOME_INTERNAL_ERROR       Edge runtime fault (ADR-008 D2)
```

A range request produces one record covering the served range. Streaming endpoints (`ResourceMutability=LIVE`) emit one record at stream open and optionally one at close; per-frame records are not required.

The reconciler enforces `UNIQUE(transaction_id, edge_node_id)`; duplicates route to ADR-011 D3 manual review.

### D2 — Per-Edge Ed25519 record-signing key, distinct from URL-signing keys

The Edge signs delivery records; the Exchange signs URLs. Two attestations, two keys:

| Role | Holder | Key | Operation |
|---|---|---|---|
| URL signing | Exchange (per-tenant) | RSA (CloudFront) or Ed25519 (Cloudflare/Fastly) | Mint by Exchange, verify at Edge |
| Record signing | Edge (per-node) | Ed25519 | Mint at Edge, verify at reconciler |

Sharing the key collapses both attestations into one self-referential signature, which is no stronger than an unsigned log.

Edge keys are published in the publisher's [`WellKnownManifest.public_keys`](/Users/konst/projects/RAMP-Protocol/protocol/proto/ramp/v1/ramp.proto:1748) at `https://{publisher-domain}/.well-known/ramp.json` using the existing `JsonWebKey` shape (kty=OKP, crv=Ed25519, kid, not_before/not_after). The reconciler resolves `edge_signing_kid` against this manifest. Key rotation and revocation reuse the existing `invalidation_url` machinery (ADR-003, ADR-009). A publisher operating multiple PoPs lists one `kid` per node; `not_before`/`not_after` windows enable independent per-node rotation.

### D3 — Edge onboarding reuses the ACME HTTP-01 domain-verification flow

Edge onboarding uses the protocol's existing [Provider Domain Verification flow](/Users/konst/projects/RAMP-Protocol/protocol/proto/ramp/v1/ramp.proto:2179) unchanged:

1. Operator generates an Ed25519 keypair.
2. Operator calls `RequestDomainVerification` with `domain={publisher-domain}`; Exchange returns a challenge token.
3. Edge serves `/.well-known/ramp-verify/{token}` from its `acmeTokens` map ([`src/edge/src/app.ts:32-37`](/Users/konst/projects/agentic-content-access/src/edge/src/app.ts) already implements this).
4. Operator calls `ConfirmDomainVerification` with `domain`, `token`, `signing_key=<pubkey>`, `cdn_type="edge-ed25519"` (distinct from `cloudfront`/`akamai`/`fastly`/`hmac` URL-signing types).
5. Exchange fetches the token from the publisher's domain; on success it registers the key under `WellKnownManifest.public_keys` with the kid in `DomainVerificationResult.key_id`.

The trust anchor is the publisher's domain; each per-node Ed25519 key is a leaf in the manifest. No certificate path; validity is the JWK's `not_before`/`not_after`. N nodes means N ceremonies.

### D4 — `Offer.content_hash` propagates opportunistically; reconciliation degrades gracefully

When `Offer.content_hash` is populated and `resource_mutability=RESOURCE_MUTABILITY_STATIC`: the Exchange embeds hash and method in the signed URL as `ch=<hexdigest>` and `chm=<method>` (covered by the URL HMAC). The Edge streams-hashes served bytes and populates `content_hash_observed`/`content_hash_method`. The reconciler compares announced vs observed and produces a per-transaction verdict; mismatch is disputable through the existing chain (`UsageReport → UsageReportResponse → DisputeRequest`).

When `Offer.content_hash` is absent or `resource_mutability=DYNAMIC`: no `ch` parameter; the Edge may still compute the hash for its own forensics but the reconciler does not compare. Witness collapses to "Edge served some bytes against `transaction_id`" — weaker than item-level integrity, stronger than no witness. `UsageReport.consumed_quantity` provides a non-cryptographic sanity check against `bytes_sent`.

When `resource_mutability=LIVE`: `content_hash` is inapplicable; the record carries cumulative `bytes_sent` only. This is the documented limit of cryptographic reconciliation for streams. **LIVE record-shape decisions are deferred** to the first LIVE-streaming publisher integration — including whether to introduce a distinct `DELIVERY_OUTCOME_STREAM_OPENED` outcome (evidence that the stream opened but cumulative bytes never landed in a close record) and whether close records carry runtime-computed cumulative bytes. The current publisher use cases are text + images; introducing those record-shape values now would produce schema entries with no producer (Edge) and no consumer (reconciler + dispute path are themselves deferred).

Publishers who announce `content_hash` get automatic dispute evidence; publishers who do not accept that disputes require subjective evidence.

### D5 — Per-record signatures; no Merkle chain in v1

Each record is independently signed; `record_signature` covers the JCS form of all fields. There is no `prev_record_hash` and no cross-record chain. Merkle linking defends against silent ordering attacks by the Edge operator; at v1 scale the Edge is operated by or for the publisher (D3's domain anchor), per-transaction uniqueness is reconciler-enforced, and missing-record detection comes from the ADR-011 three-way join. Chain machinery (durable tip cache, restart-vs-partition disambiguation, signed transition records) solves a problem v1 does not have.

### D6 — Local append-only JSONL polled by the Exchange reconciler

The Edge writes records to a per-UTC-day append-only JSONL file (one record per line) at a configurable mount point (default `/var/lib/ramp-edge/delivery-log/YYYY-MM-DD.jsonl`). The Edge fsync()s after each batch flush (default 50 records or 100 ms). The reconciler pulls every 60 s (configurable) via `GET /internal/delivery-log?since={record_id}`, which streams JSONL strictly after `record_id` up to 8 MB per call. The endpoint is authenticated by an RFC 9421 Ed25519 signature from the Exchange against the Edge's configured allowlist.

Local-file isolates the Edge's serving function from reconciler health: the Edge does not lose its primary function because the reconciler is slow or offline. Inline push would add a synchronous dependency to every fetch; a shared event stream (Kafka/NATS/Kinesis) adds a third operational service without solving any v1 problem.

On runtimes without writable local FS, the file lives in the platform-native equivalent (Workers KV one-key-per-day, S3 one-object-per-hour). v1 ships only Cloudflare Workers using Workers KV directly; the per-runtime abstraction is deferred.

### D7 — `EDGE_SIGNED_LOG` is the default witness mode; `CDN_ACCESS_LOG` is opt-in

`tenants.signing_scheme` gains a parallel `delivery_witness_mode` enum: `EDGE_SIGNED_LOG` (default; D1–D6), `CDN_ACCESS_LOG` (fallback), `BOTH` (high-assurance: Edge signs and CDN logs are independent witness). Operators opt down to `CDN_ACCESS_LOG` explicitly.

`CDN_ACCESS_LOG` fallback: the reconciler joins the Exchange transaction log to the CDN's standard access logs on `signed_url_hash`. CDN logs include URI, status, bytes, client IP, user-agent, and POP identity (CloudFront `x-edge-location`, Cloudflare `ColoCode`, Fastly `fastly.pop`). They do not include a response hash, a per-record signature, or any cross-record linkage. The fallback is weaker on three documented properties: no item-level integrity (no `content_hash_observed`), no per-record non-repudiation, no structural protection against CDN-side log omissions.

`CDN_ACCESS_LOG` is sufficient when the publisher accepts URL-level reconciliation, operates the CDN account directly, and accepts CDN log-delivery latency (CloudFront up to 24 h; Cloudflare Logpush minutes; Fastly streaming seconds) as the reconciliation cadence. It is insufficient for publishers under audit/regulatory regimes requiring per-fetch non-repudiation, for multi-CDN deployments, or for publishers who may need to dispute the CDN's own behavior.

### D8 — Retention: 90 days at the Edge, indefinite at the Exchange after reconciliation

The Edge retains records for at least 90 days rolling, matching the Exchange's `EVENT_SIGNED_URL_ISSUED` floor so cross-log joins are possible. After the reconciler acknowledges a record range, the Edge may prune older entries; the Exchange archives reconciled records to S3 Object Lock (compliance mode) under the same regime as the transaction log. `CDN_ACCESS_LOG` deployments inherit the CDN's retention policy — the ADR does not impose the 90-day floor because the publisher operates that policy.

### D9 — Implementation-level contract, not protocol-level

This ADR does not add a `DeliveryLog` message to `ramp.proto`. The protocol's reconciliation model names three witnesses without standardising the form of the first; multiple delivery topologies are protocol-compatible, and standardising one would exclude the `CDN_ACCESS_LOG` fallback. The Edge ↔ Exchange interface is internal to the Exchange operator's deployment. A future protocol-level `EdgeManifest` carrying delivery-log format declarations, so third-party Exchanges can read each other's reconciliation feeds, is a worthwhile RFC for a later version but is out of scope for v1.

---

## Out of scope

- **Stream-tier transport (Kafka/NATS/Kinesis)** — implementable when sustained > 1,000 records/sec per Edge node, > 100 MB/day per Edge node, or reconciler pull p95 > 30 s for two consecutive sweeps. Record format unchanged; only transport changes. Cutover via signed `TRANSITION_REASON_TRANSPORT_MIGRATION` sentinel.
- **Runtime-agnostic `DeliveryLogStore` TypeScript interface** (`append`/`range`/`flush`) with per-runtime adapters — defer until a second Edge runtime ships in production.
- **Merkle-linked log with `prev_record_hash`** — defer until tamper-evident ordering is a real threat-model requirement. Options at that point: roll our own (add `prev_record_hash`, signed `DELIVERY_OUTCOME_CHAIN_TRANSITION` records at startup/rekey/maintenance/adapter-upgrade/transport-migration, reconciler grace window for chain gaps); or adopt Sigstore Rekor / Trillian-Tessera as a transparency log.
- **Signed `DELIVERY_OUTCOME_CHAIN_TRANSITION` record format and reconciler grace-window policy** — deferred with the Merkle chain.
- **Reconciler chain-tip durable cache schema** (`edge_chain_tips` table) — deferred with the chain.
- **Operational rehearsal harness for the stream-tier cross-over** — deferred with the cross-over.

---

## Consequences

### Positive

- Three-way reconciliation has three witnesses. The third is a known schema, retention, signing key.
- Stolen-URL detection is deterministic: `DELIVERY_OUTCOME_DENIED_BINDING` rate on a `transaction_id` flags real leakage, not a hypothesis.
- `Offer.content_hash` becomes operationally valuable: D4 plumbs it from offer through URL through Edge to reconciler.
- Edge onboarding reuses `DomainVerificationRequest`, `WellKnownManifest.public_keys`, and `invalidation_url` — no new RPC, manifest field, or key-distribution surface.
- CDN-native deployments are supported with documented evidence weakening.
- v1 stays small: one append-only file, one polling endpoint, no chain, no multi-runtime adapter, no stream producer.

### Negative

- Operators of multi-PoP Edges manage one key per PoP with overlap rotation. Tractable via `not_before`/`not_after` but real operational surface.
- 60 s reconciler-pull cadence: a fresh fetch is invisible to the Exchange for up to 60 s. Edge-local rate-limiting on `DELIVERY_OUTCOME_DENIED_BINDING` covers the real-time anomaly case without waiting for the reconciler.
- No structural protection against record reordering or silent deletion at the Edge. Missing-record detection relies on the ADR-011 three-way join; higher-assurance deployments take the Merkle upgrade path.

### Rejected alternatives

- Sign records with the publisher's URL-signing key — conflates two attestations (D2).
- Push records inline to the Exchange — adds synchronous failure-domain coupling (D6).
- Standardise `DeliveryLog` in `ramp.proto` — excludes CDN-native fallback (D9).
- Trust CDN access logs as the primary witness — rejected as default, accepted as opt-in fallback (D7).
- Ship the Merkle chain in v1 — no active threat model justifies the operational complexity (D5).
- Ship the multi-runtime `DeliveryLogStore` abstraction in v1 — premature with one concrete adapter.

---

## References

- ADR-001 — three-layer auth.
- ADR-002 — entitlement-biscuit model.
- ADR-006 — broker intermediation.
- ADR-008 D2 — structured absence reasons.
- ADR-009 — identity boundary; per-Edge Ed25519 key onboarding.
- ADR-010 — publisher payout / inverse-posting policy.
- ADR-011 — three-way reconciliation procedure.
- [`ramp.proto`](/Users/konst/projects/RAMP-Protocol/protocol/proto/ramp/v1/ramp.proto) — `Offer.content_hash` (515), `ResourceMutability` (1082), `DomainVerificationRequest/Confirmation/Result` (2179+), `WellKnownManifest.public_keys` (1748), `JsonWebKey` (1697).
- [`src/edge/src/app.ts`](/Users/konst/projects/agentic-content-access/src/edge/src/app.ts), [`src/edge/src/verify.ts`](/Users/konst/projects/agentic-content-access/src/edge/src/verify.ts) — current Edge implementation; `/.well-known/ramp-verify/:token` handler at app.ts:32-37 is the primitive D3 reuses.
- [`src/exchange/internal/signing/signed_url.go`](/Users/konst/projects/agentic-content-access/src/exchange/internal/signing/signed_url.go) — URL signers; distinct from record signing per D2.
- Crosby & Wallach, "Efficient Data Structures for Tamper-Evident Logging", USENIX Security 2009 — Merkle-linked log reference.
- Sigstore Rekor; Trillian-Tessera — transparency-log alternatives for the Merkle upgrade path.
- AWS CloudFront standard logging; Cloudflare Logpush; Fastly streaming logs — D7 fallback field inventories.
