# RAMP Protocol Changelog

## v0.3.0 (2026-03-18) — Content Attestation + Dispute Resolution

Content integrity verification via cryptographic attestations, structured dispute resolution, publisher domain verification, and operational diagnostics.

### ContentAttestation (replaces ContentQuality)
- **ContentAttestation** message — signed claim envelope from a trusted party (publisher or verification vendor)
  - `verifier`: domain of the attesting party
  - `kid`: key ID from the verifier's JWKS
  - `attested_at`: timestamp of attestation
  - `uri`: content URI covered
  - `claims`: JSON claims (max 4KB) — `estimated_tokens`, `word_count`, `language`, `iab_categories`, `content_hash`, `hash_method`, plus vendor-specific claims
  - `signature`: Ed25519 over JCS-canonicalized (RFC 8785) representation
- Three verification levels:
  - **Level 0** (no attestations): identifiers only (DOI, IPTC GUID), nothing cryptographically verifiable; only CDN delivery failure is auto-disputable
  - **Level 1** (self-attested): publisher signs own claims with Ed25519; agent can independently verify content hash; CDN delivery failure + hash mismatch are auto-disputable
  - **Level 2** (third-party attested): independent verification vendor crawled and attested; agent trusts attestation without re-verifying hash; token count discrepancy is auto-disputable when corroborated by CDN response size
- `ramp-verifier.json` well-known endpoint — verifiers MUST publish keys and claims schema at `https://{verifier}/.well-known/ramp-verifier.json` (JWKS pattern)
- **Offer.attestations** (`repeated ContentAttestation`) replaces `ContentQuality`
- **CatalogEntryProto.attestations** — attestations at catalog level
- **ContentQuality message REMOVED** — subsumed by attestation claims; quality scores live in vendor-specific attestation claims, not as a protocol-level concept

### Dispute Resolution
- **DisputeStatus** enum (10 values): `UNSPECIFIED`, `FILED`, `AUTO_RESOLVED`, `EVIDENCE_NEEDED`, `UNDER_REVIEW`, `ESCALATED`, `RESOLVED`, `APPEALED`, `SETTLED`, `FINAL`
  - Three-tier resolution: Tier 1 automated (<1s), Tier 2 rule-based (<24h), Tier 3 pattern investigation (async)
  - Appeals: `RESOLVED` → `APPEALED` → re-enters `UNDER_REVIEW`
- **ResolutionType** enum (5 values): `UNSPECIFIED`, `CREDIT`, `REDELIVERY`, `REJECTED`, `INVESTIGATION`
- **DisputeRequest** message — agent signals content delivery problem
  - `transaction_id`, `billing_id`, `reason` (DisputeReason enum), `description`
  - `received_content_hash` + `received_hash_method` — evidence of what was actually received
  - `report_id` — MUST reference a filed UsageReport (dispute chain enforcement)
- **DisputeResponse** message — marketplace acknowledges and processes dispute
  - `dispute_id`, `rejection_reason`, `estimated_resolution`
  - `status` (DisputeStatus) — current lifecycle state
  - `resolution` (ResolutionType) — populated at terminal states
- **DisputeTransaction RPC** on MarketplaceService — `DisputeRequest` → `DisputeResponse`
- **Dispute chain**: `Offer` → `Transaction` (transaction_id) → `UsageReport` → `UsageReportResponse` (report_id) → `DisputeRequest` (transaction_id + report_id)
- **UsageReportResponse.report_id** — marketplace-assigned identifier enabling the dispute chain

### Domain Verification (Publisher Onboarding)
- **RequestDomainVerification RPC** — `DomainVerificationRequest` → `DomainVerificationChallenge`
- **ConfirmDomainVerification RPC** — `DomainVerificationConfirmation` → `DomainVerificationResult`
- ACME HTTP-01 style flow: request challenge → place token at `{domain}/.well-known/ramp-verify/{token}` → confirm → marketplace verifies
- Atomic key registration: signing key registered upon successful verification
- Double protection: marketplace also checks `parse.json` authorization

### Catalog Contributors
- **CatalogContributor** message — `domain` + `relationship` (e.g., "verifier", "marketplace")
- **PublisherManifest.catalog_contributors** — authorized third-party catalog pushers
- Prevents unauthorized parties from pushing fake attestations for publishers they don't represent

### Operational Diagnostics
- **OfferAbsenceReason** enum (7 values + UNSPECIFIED): `NOT_IN_CATALOG`, `CONTENT_BLOCKED`, `FUNCTION_PROHIBITED`, `GEO_RESTRICTED`, `USER_CATEGORY_PROHIBITED`, `TEMPORARILY_UNAVAILABLE`, `NOT_AUTHORIZED`
- **OfferGroup.absence_reason** — per-URI diagnostic when no offers available
- **RateLimitInfo** message — `limit`, `remaining`, `reset_at`, `window` (modeled after IETF RateLimit header fields)
- **SupplyResponse.rate_limit** — enables proactive throttling for Orchestrator fanout

### Breaking Changes from v0.2
- **ContentQuality removed** — use `Offer.attestations` with `ContentAttestation` claims instead
- **Offer.quality removed** — replaced by `Offer.attestations`

## v0.2.0 (2026-03-16) — Production-Ready Protocol

First complete protocol specification with full system design, threat model, and expert review.

### MarketplaceService RPCs
- `DiscoverSupply` — single and batch (multi-URI via OfferGroup)
- `ExecuteTransaction` — single and batch (TransactionItem/TransactionResultItem)
- `ReportUsage` — mandatory post-usage reporting

### CatalogService RPCs (for content intelligence providers)
- `PushContent` — signed, with provenance tracking
- `RemoveContent`
- `RefreshCatalog`

### Authentication
- Ed25519 at every boundary (RAMP Authentication Principle)
- Agent signs requests (Ed25519, key at `/.well-known/ramp-agent.json`)
- Orchestrator co-signs forwarded requests (Ed25519)
- Marketplace signs offers (Ed25519, key at `/marketplace/v1/keys`)
- Publisher authorizes Marketplaces via `parse.json`
- Signed URLs use HMAC-SHA256 (Marketplace↔CDN shared secret)
- `lid` is a public identifier, not a credential

### Offers and Pricing
- ContentQuality metadata (editorial_tier, quality_score, quality_scorer)
- ContentIdentity with layered verification (Level 0/1/2: none/SimHash/SHA-256)
- AccessRestrictions from RSL permits/prohibits
- IAB Content Taxonomy codes (iab_categories)
- 8 PricingModel values (per_article, per_token, per_crawl, subscription, free, attribution, contribution, training)
- Subscription offers (subscription_id, zero marginal cost)
- subscription_unit_value for ASC 606 cost attribution
- Mandatory marketplace_signature (Ed25519) on every Offer

### Transaction Security
- DenialReason enum (11 values) for structured denial vocabulary
- agent_identity_hash bound into signed URLs
- Idempotency via TransactionRequest.id
- Write-before-sign invariant (WAL)

### Discovery
- PublisherManifest at `/.well-known/parse.json`
- DiscoveryMethod enum (marketplace, search, recommendation, syndication) — v2 extension point
- IngestionSource enum (7 sources + catalog API)

### Reporting
- Mandatory UsageReport with required token_count
- ReportingObligation with window and required_fields
- Two independent metrics: compliance rate vs token accuracy

### Built on
- IAB Tech Lab CoMP v1.0 (all 9 objects mapped 1:1)
- RSL 1.0 (pricing, permits, prohibits mapped to RAMP)
- Protobuf + Connect (HTTP/JSON + gRPC dual protocol)

### Changes from v0.1 (IAB draft)
- Added transaction protocol (CoMP defines data model only, not transport)
- Added discovery mechanism (parse.json, edge function 403 redirect)
- Added content identity and cross-marketplace dedup
- Added pricing normalization (eCPT)
- Added mandatory usage reporting
- Added threat model with 30 attack vectors and countermeasures
- Added Ed25519 authentication principle
- Added subscription/direct deal transaction mode
- Added batch multi-URL queries
- Added content quality signals
- Added publisher audit API
