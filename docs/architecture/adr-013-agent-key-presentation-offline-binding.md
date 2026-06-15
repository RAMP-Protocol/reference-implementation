# ADR-013 — Agent-Key Presentation for Offline Delivery-URL Binding

**Status:** Accepted (2026-06-11); **D5 + D6.1 amended (2026-06-11)** — the binding principal is always the **Agent**, and enforcement defaults **ON wherever the edge is technically capable**. The relay-path conformance this requires (agent-signed `ExecuteTransaction`, multisig verification of all hop signatures, default-ON flip) is tracked in **RAMP-56**.

---

## Context

A signed delivery URL is a bearer token: anyone who obtains it before `expires` can fetch the bytes. This ADR specifies the proto's OPTIONAL "Retrieval-URL identity binding" (DPoP-style, RFC 9449 *in concept*): the Exchange binds the URL to the requesting agent's Ed25519 key by embedding the key's RFC 7638 JWK Thumbprint as the `agent_id` URL parameter (ADR-009 D5), and a capable delivery edge rejects fetches that cannot prove possession of that key — verified **fully offline, no JWKS fetch**.

The proto narrative (`proto/ramp/v1/ramp.proto`, "Retrieval-URL identity binding") fixes the *what*: "require the fetcher to present its public key and an RFC 9421 signature over the retrieval request, and check `thumbprint(presented key) == agent_identity_hash`." It does **not** fix the *how* — the wire carrier for the presented key is unspecified. The proto's only inline-JWK references are the well-known manifest key announcement (`WellKnownManifest.public_keys`, `JsonWebKey`), not the fetch request.

ADR-012 D1 already reserves the delivery-log fields that record the outcome of this check — `presented_agent_kid`, `rfc9421_signature_valid`, and outcome `DELIVERY_OUTCOME_DENIED_BINDING` ("`thumbprint(presented) != agent_id`, or RFC 9421 failed") — but it does not pin the verification's wire contract. This ADR pins it.

Two prior facts constrain the decision:

- **ADR-011** reconciles the edge delivery log against `transaction_log` by **thumbprint equality**. The URL therefore carries the *thumbprint* (`agent_id`), never the key; key-in-URL is ruled out.
- **Web Bot Auth is part of the v1 identity substrate.** Under WBA the agent's RFC 9421 signing `keyid` **is** its RFC 7638 thumbprint. The fetch reuses the WBA signer, so the GET signature carries the thumbprint as its `keyid` for free.

---

## Decision

### D1 — Raw public key in a dedicated header (Option 1, not inline JWK)

The fetcher presents its raw 32-byte Ed25519 public key, **base64url-no-pad**, in a dedicated header:

```
X-RAMP-Agent-Key: <base64url-nopad(32-byte raw Ed25519 public key)>
```

The alternative — embedding the key as an inline JWK inside the RFC 9421 `Signature-Input` — is **rejected**. RFC 9421 has no native parameter for inline key material (`keyid` is an opaque identifier, not a key); inlining a JWK overloads `keyid` or invents a custom parameter, is heavier on the wire (full JSON JWK vs 32 raw bytes), and widens the canonicalization surface that must stay byte-identical across Go + TS. A raw 32-byte key has zero parse ambiguity, and the edge reconstructs the canonical JWK from it deterministically to compute the thumbprint (D4). The DPoP-native inline-JWK home is the RFC 9449 proof JWT, a transport this project declined in favour of RFC 9421.

### D2 — RFC 9421 signature over the GET; covered components

The fetcher signs the GET with RFC 9421 (`Signature` / `Signature-Input` headers), reusing the existing `internal/httpsig` machinery. Covered components are the GET-appropriate subset of the existing service-to-service set:

- `@method`, `@target-uri`, plus the `created` / `expires` signature parameters.
- **Dropped from the service set:** `content-digest` (a GET has no body) and `authorization` (the signed URL *is* the credential and rides inside `@target-uri`).

`@target-uri` covers the full signed URL including the `agent_id`, `sig`, and `expires` query params, binding the proof to *this* URL. No `nonce`: single-use replay defence would require shared edge state, contradicting the offline/stateless edge; replay is bounded by the short `created`/`expires` window stacked on the URL's own TTL.

### D3 — WBA `keyid` coupling and the 3-way identity check

Because WBA sets `keyid == RFC 7638 thumbprint`, three values on the wire are the same thumbprint. The edge enforces all three equal, offline:

```
agent_id (URL param, Exchange-signed)
   ==  keyid (Signature-Input, agent-set)
   ==  thumbprint(presented key)   (edge-computed from X-RAMP-Agent-Key)
```

`thumbprint(presented key) == agent_id` is the **non-negotiable security property**: verifying the RFC 9421 signature against the presented key *without* it lets any actor present their own key plus a valid self-signature and fetch. `keyid == thumbprint` is the WBA consistency add-on — it costs nothing (the field already carries the thumbprint) and rejects a malformed or mismatched `keyid` early. The fetch signer is the WBA signer; this binding introduces no second signing path.

### D4 — One thumbprint helper, one encoding, four call-sites

A single RFC 7638 thumbprint helper — JSON `{"crv":"Ed25519","kty":"OKP","x":"<base64url-nopad(pubkey)>"}`, members lexicographically ordered, no whitespace, SHA-256, **base64url-no-pad** — is implemented once per language (Go + TS), byte-parity tested against shared fixtures, and reused at all four sites: the `agent_id` URL parameter, the `keyid`, the response `agent_identity_hash`, and the edge's `thumbprint(presented key)`. A divergence at any site rejects every bound fetch.

This supersedes the current Exchange behaviour, which is wrong twice: it emits the value as **hex** (`exchange_helpers.go`, `fmt.Sprintf("%x", …)`) and computes the wrong **value** (`SHA256(requester_id|tx_request_id)` at `exchange.go`) instead of the thumbprint. Both the encoding and the value are replaced.

### D5 — The Exchange binds to the Agent, always

The binding principal is **always the agent** — the key the agent holds and fetches with — never a relay. Two requirements follow:

1. **The agent signs its requests to the Broker, and the `ExecuteTransaction` that reaches the Exchange MUST carry the agent's RFC 9421 signature.** The agent never auto-delegates the execute to the Broker; it signs the execute it intends to make. A relay that re-originates `ExecuteTransaction` under its own identity (so the agent's signature is absent on the Exchange hop) is **non-conformant** — the bound URL would name the relay, which the agent cannot satisfy at fetch.

2. **On a multi-hop / relayed path (`MCP → Broker → Exchange`) the request is multisig, and the Exchange verifies every signature.** The Broker is a relay: it adds its own relay signature for hop integrity and audit but **preserves the agent's**, and it carries the Exchange reply back to the agent. The Exchange verifies **all** hop signatures, then binds `agent_id` — and records `transaction_log.agent_identity_hash` — to the **agent's** verified key (the `requester` principal), attesting the relay separately (`allow_broker_relay`, ADR-006). On the direct path the agent is the sole signer and this collapses to the obvious case.

The Exchange computes `agent_id` by **recomputing** the thumbprint from the agent's proven pubkey bytes (`requester.id → agentreg.LookupPublicKey`), never by echoing a caller-claimed `keyid`. The binding is to what was cryptographically proven *for the agent*, not to whichever key happened to terminate the transport hop.

### D6 — Enforcement is OPTIONAL; CloudFront-native falls back to bearer

Edge enforcement of the binding is OPTIONAL per proto. Code-capable edges (Cloudflare / Fastly / Lambda@Edge) enforce D1–D3. **CloudFront-native deployments cannot run the proof-of-possession check** and fall back to bearer security: short URL TTL + TLS only, no binding. This is consistent with the CloudFront-native signing constraint (RSA signed URLs, verified natively by the CDN). There is **no binding-parity requirement** — onboarding a CloudFront-native tenant does not require Lambda@Edge; the tenant accepts the weaker bearer posture explicitly, the same way ADR-012 D7 lets a tenant opt down to `CDN_ACCESS_LOG`.

#### D6.1 — Enforcement defaults ON where the edge is technically capable

Edge enforcement defaults **ON** wherever the edge can run the proof-of-possession check — Cloudflare / Fastly / Lambda@Edge. The bearer fallback (`RAMP_ENFORCE_BINDING=false`) applies **only** where the edge is technically incapable: CloudFront-native, which verifies RSA signed URLs inside the CDN and cannot execute the PoP path (D6). The rule is "default enforce; bearer only where you can't" — the same opt-down shape as ADR-012 D7's `CDN_ACCESS_LOG`.

**Implementation status (interim — see RAMP-56).** As shipped in the MR that introduces this ADR, the Exchange still binds `agent_id` to the proven *transport* caller, which on the relay path `MCP → Broker → Exchange` is the Broker's relay key — not the agent: the Broker re-originates and re-signs the `ExecuteTransaction` with its relay key (`src/broker/internal/xclient/signing_transport.go`), so the agent's signature is absent on the Exchange hop. On that interim a capable edge would reject legitimate agent fetches, so enforcement ships **OFF by default** until the D5 agent-binding lands. The **direct-agent** path (agent signs `ExecuteTransaction`, kid == requester.id) already satisfies D5 and is exercised with `RAMP_ENFORCE_BINDING=true` in the obligation / PoP e2e.

This **replaces** the prior "unsatisfiable on the relay path / deferred to Web Bot Auth" framing. The relay-path binding is not unsatisfiable: it requires the agent to sign the `ExecuteTransaction`, the Broker to relay it as multisig (preserving the agent's signature), and the Exchange to verify all hop signatures and bind to the agent (D5). That is a scoped change — agent-signed execute + multisig-aware verification + the default-ON flip — tracked in **RAMP-56**, not a WBA-era deferral.

---

## Out of scope

- **Inline-JWK / RFC 9449 DPoP-JWT transport** — rejected (D1); revisit only if an external RAMP edge/fetcher implementation pins a JWK-on-the-wire contract.
- **Nonce-based single-use replay defence at the edge** — requires shared edge state; deferred unless the short-TTL window proves insufficient. Single-use *delivery* enforcement is the separate `DELIVERY_OUTCOME_DENIED_REPLAY` concern (ADR-012 D1).
- **Proof-of-possession on the CloudFront-native path** — bearer fallback (D6); enforcing it would require Lambda@Edge and is a per-tenant deployment choice, not a v1 requirement.
- **Response-path / multi-hop *delivery* key binding** — the delivery edge binds a single fetch hop; chained delivery intermediaries are out of scope. (Request-path multi-hop *signature* verification — the agent + relay multisig the Exchange must verify before binding — is **in** scope per D5.)

---

## Consequences

### Positive

- The wire contract both ends must agree on is pinned and minimal: one header (`X-RAMP-Agent-Key`) plus the existing RFC 9421 headers. Lowest cross-language interop risk of the options considered.
- The binding is strictly stronger under WBA: `keyid == thumbprint` is enforced, not assumed, so a stolen URL replayed with a mismatched signing key is rejected on two independent checks.
- No second signing path: the MCP fetcher reuses the WBA signer it already runs for Exchange request signing.
- Corrects `agent_identity_hash`, previously wrong twice (wrong value `SHA256(requester_id|tx_request_id)`, hex-encoded): it is now the RFC 7638 thumbprint, base64url-no-pad, embedded in the URL rather than emitted inert.

### Negative

- A new RAMP-specific header (`X-RAMP-Agent-Key`) to document and version; not an existing standard.
- CloudFront-native tenants get a weaker delivery posture (bearer + TTL). Asymmetric capability across edge runtimes is accepted and documented (D6), not engineered away.
- The thumbprint helper is interop-critical: a byte-level divergence between the Go and TS implementations rejects every bound fetch. Mitigated by shared fixtures + byte-parity tests (D4).

### Rejected alternatives

- **Inline JWK in `Signature-Input`** — overloads `keyid`, heavier, wider canonicalization surface (D1).
- **RFC 9449 DPoP proof JWT** — a second signing format alongside the project's RFC 9421 stack; declined.
- **Key in the URL as a query parameter** — ruled out by ADR-011 (the URL carries the thumbprint for reconciliation, not the key).
- **Echo the caller-claimed `keyid` as the binding value** — binds to an unproven assertion (D5).
- **Require Lambda@Edge for CloudFront-native binding parity** — forces a paid edge tier on tenants who accept bearer security; rejected (D6).

---

## References

- ADR-006 — broker intermediation; the relay-trust model (`allow_broker_relay`) under which the Exchange attests the Broker as relay while binding to the agent (D5).
- ADR-009 D5 — identity boundary; `agent_identity_hash` = RFC 7638 thumbprint; `agent_id` URL parameter.
- RAMP-56 — follow-up: agent-signed `ExecuteTransaction` on the relay path, multisig verification of all hop signatures, and the edge enforcement default-ON flip (D5 / D6.1).
- ADR-011 — three-way reconciliation; join on thumbprint equality (why the URL carries the thumbprint, not the key).
- ADR-012 D1 — edge delivery-log fields `presented_agent_kid`, `rfc9421_signature_valid`, outcome `DELIVERY_OUTCOME_DENIED_BINDING`.
- `proto/ramp/v1/ramp.proto` — "Retrieval-URL identity binding" narrative; `agent_identity_hash` field; `WellKnownManifest.public_keys` / `JsonWebKey` (the manifest's inline-JWK use, distinct from the fetch).
- `internal/rampthumbprint/` (Go), `src/edge/src/thumbprint.ts` (TS), `src/mcp/.../thumbprint.py` (Python) — the single RFC 7638 thumbprint helper, byte-parity tested against shared fixtures (D4).
- `src/edge/src/verify.ts` — edge URL-signature verifier; `src/edge/src/pop.ts` — proof-of-possession path (D1–D3).
- `src/exchange/internal/signing/signed_url.go` — `Ed25519URLSigner` (embeds `agent_id`); `internal/httpsig` — RFC 9421 stack reused for the fetch signature.
- RFC 7638 (JWK Thumbprint), RFC 9421 (HTTP Message Signatures), RFC 9449 (DPoP — conceptual lineage, declined as transport), Web Bot Auth (HTTP Message Signatures directory).
