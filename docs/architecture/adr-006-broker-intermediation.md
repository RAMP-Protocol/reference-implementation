# ADR-006 — Broker Intermediation and Transparency Chain (`authorized_intermediaries`)

**Status:** Accepted (2026-04-23)
**Tracks:** broker intermediation.
**Depends on:**
- `docs/architecture/adr-005-biscuit-transport-canonical-binding.md` Part 3 — Pattern-2 attenuation-append as the sanctioned intermediation mechanism. ADR-006 specifies *who* is permitted to append.
- `docs/architecture/adr-004-protocol-layers.md` — intermediation authorization lives in the inner (biscuit) layer; ramp.json discovery lives in the outer (deployment) layer.
**Companion documents:**
- `docs/architecture/adr-002-entitlement-biscuit-model.md` — authority-block fact convention this ADR extends.
- `docs/architecture/adr-003-key-rotation-revocation.md` — intermediary pubkey rotation inherits the biscuit-layer mechanics.

---

## Context

ADR-005 Part 3 established that intermediaries append attenuation blocks to the biscuit chain rather than re-signing. Every hop becomes cryptographically visible. This is the mechanism; it does not, by itself, answer two questions a resource owner cares about:

1. **Is this intermediary authorized to represent me?** A biscuit chain with three attenuation blocks is fully verifiable, but verification only proves that each block was signed by some key. It does not prove those keys belong to intermediaries the resource owner agreed to do business with. An adversarial broker can insert itself in the chain, and Exchange has no authoritative source saying "this broker is legitimate" versus "this broker is shadow."

2. **How are brokers discovered in the first place?** An agent deciding which broker to route a query through needs a public list of brokers the content owner acknowledges. The authority-block facts are private per-contract data; they cannot serve as a discovery mechanism before a contract exists.

The two questions live at different layers:

- **Authorization** (who can cryptographically represent the resource owner on a specific contract) is an inner-layer concern; it must be expressible as a biscuit fact so Exchange can verify it without external API calls.
- **Discovery** (who does the resource owner publicly acknowledge as an intermediary) is an outer-layer concern; it lives in ramp.json alongside the list of authorized Exchanges.

Both are required to close the shadow-exchange / shadow-broker gap. Either alone leaves a bypass.

---

## Decision

### A. Authority-block fact — `authorized_intermediaries`

Every authority block MAY carry a Datalog fact listing the public keys of intermediaries authorized to append attenuation to this specific biscuit chain:

```
authorized_intermediaries([hex($pk_broker_A), hex($pk_broker_B), ...]);
```

When the fact is absent, the biscuit chain MUST contain no intermediary attenuation blocks beyond the mandatory per-request buyer attenuation. When the fact is present, every attenuation block signed by a key that is not the buyer's delegation key MUST be signed by a key in the `authorized_intermediaries` list.

**Gate G at Exchange** (forthcoming implementation):

1. Enumerate all attenuation blocks in the biscuit chain after the authority block.
2. The first attenuation block (mandatory per ADR-002) MUST be signed by the buyer's delegation key (Gate A.4 already enforces this).
3. Any subsequent attenuation blocks MUST be signed by a key listed in the authority's `authorized_intermediaries` fact.
4. Failure → `connect.CodePermissionDenied` with reason `unauthorized_intermediary`.

Gate G runs alongside Gates A–F. Concretely: Gate G uses the attenuation-chain structure; it is deterministic, biscuit-chain-local, no external fetch needed.

### B. ramp.json schema extension — `authorized_brokers`

Content-provider-published `ramp.json` gains an optional top-level array:

```json
{
  "exchanges": [ ... ],
  "authorized_brokers": [
    {
      "name": "Example Broker",
      "pubkey": "04abc...",
      "contact": "https://example-broker.com/contact",
      "jurisdictions": ["US", "EU"],
      "profiles": ["ramp-news-v1"]
    }
  ]
}
```

`authorized_brokers` entries are discovery signals only — Exchange does not consult ramp.json at authz time. Agents use the list to select brokers when initiating a RAMP request. Audit tooling uses the list to detect ramp.json/authority-block drift (a broker listed in ramp.json but absent from a specific contract's `authorized_intermediaries` is legitimate but not yet contracted-with; a broker absent from ramp.json but present in an authority block is a red flag worth surfacing).

The schema extension is optional and backward-compatible: ramp.json consumers that don't understand `authorized_brokers` ignore it; content owners that don't publish it signal "no authorized brokers" (equivalent to an empty list at the discovery layer).

### C. Second-order brokers

When Broker A, listed in an authority's `authorized_intermediaries`, wants to delegate to Sub-broker B, three options:

1. **Pre-authorization** (near-term, recommended): the content owner lists both A and B in `authorized_intermediaries` at mint time. B's key is carried directly in the authority block. Gate G accepts attenuations from either. Simple, deterministic.
2. **Broker-appended delegation** (future evolution): Broker A appends its own attenuation block containing a `delegates_to(hex($pk_B))` fact. Gate G extended to accept B's attenuation if there exists an authority-block `authorized_intermediaries` entry or a preceding attenuation-block `delegates_to` fact signed by an authorized intermediary. Requires recursive Datalog check; biscuit v2 supports this.
3. **Disallowed**: only direct intermediaries. Conservative. Rejected because it forces every contract renegotiation whenever a broker changes its downstream.

Near-term Gate G implements only option 1. Option 2 is documented as the evolution path once a real multi-hop broker scenario exists.

### D. Relationship to ADR-003 revocation

Intermediary pubkeys are included in the keyed revocation list pattern established by ADR-003:

- Each authorized intermediary publishes its own JWKS + revocation list URL.
- The authority block embeds the intermediary's pubkey directly; no JWKS fetch needed at authz time.
- For revocation: a compromised intermediary kid listed in a revocation list causes Gate C (keyed revocation) to reject any attenuation signed by that kid. Gate G and Gate C compose: Gate G says "this intermediary is authorized," Gate C says "but this specific key is revoked."

This means intermediary rotation is automatic once ADR-003's revocation mechanics apply to intermediary kids. Content owners don't need to re-issue authority blocks on routine intermediary key rotation; they need to re-issue only when the intermediary identity itself changes.

---

## Consequences

### Positive

- **Shadow brokers become cryptographically detectable.** A broker inserting itself between agent and Exchange would have to sign an attenuation block with a key not in `authorized_intermediaries`. Gate G catches this deterministically.
- **Discovery and authorization are cleanly separated.** ramp.json lists public intermediaries; authority block lists per-contract cryptographically-authorized intermediaries. Discovery can be adversarial without authz degrading; authz is resistant to stale discovery.
- **No new key hierarchy.** Intermediary pubkeys are embedded directly in authority blocks; no JWKS endpoint for intermediaries, no PKI setup.
- **Revocation inherits ADR-003.** Compromised intermediary kids flow through the same Gate C revocation mechanism the buyer and resource-owner kids use.
- **Audit tooling has a straightforward invariant.** For any request, the set of signers in the biscuit chain must be a subset of `{buyer_delegation_pubkey} ∪ authorized_intermediaries`. Drift is mechanically checkable.

### Negative

- **Authority-block size grows.** Each authorized intermediary adds ~32 bytes (Ed25519 pubkey). Ten intermediaries add ~320 bytes plus Datalog framing. Still well within reasonable biscuit sizes.
- **Intermediary onboarding requires content-owner action.** Adding a broker means reissuing authority blocks (via `renewal_url`) with the broker's pubkey added. This is correct behavior (content owner is the trust root) but slower than an entirely discovery-based scheme.
- **Second-order delegation is deferred.** Near-term Gate G doesn't support option 2 (broker-appended delegation). Multi-hop brokers need pre-authorization in authority. Acceptable near-term because multi-hop isn't a near-term deployment pattern.
- **ramp.json schema churn.** New top-level field; consumers that strictly validate unknown fields will reject (should not — ramp.json was designed for extension, see its top-level ext field). Minor.

---

## Rejected alternatives

### Broker authorization lives only in ramp.json

Rejected. ramp.json is a discovery artifact; Exchange has no cryptographic binding from ramp.json to a specific request. An adversary forging a ramp.json bypass (MitM, DNS hijack, stale cache) would pass authz. Cryptographic authorization requires the biscuit layer.

### Broker authorization lives only in authority block

Rejected. Without a discovery signal, agents have no way to select brokers before a contract exists. Every contract initiation would require out-of-band broker discovery. ramp.json extension closes this gap.

### Single fact covering both authorized intermediaries and authorized delegates (e.g. `trusted_keys`)

Rejected. The roles are semantically distinct — buyer's delegation key is mandatory and signs every request; intermediaries are optional and sign only when in the chain. Collapsing them into one list creates ambiguity for Gate A.4 ("this block MUST be signed by buyer_delegation_pubkey") and Gate G ("this block MUST be signed by an authorized intermediary"). Clear separation keeps the gates deterministic.

### Gate G as a check on ramp.json

Rejected. Exchange would have to fetch ramp.json on every authz decision, which adds an external HTTP dependency and a cache layer at the authz-hot path. Authority-block-native expression keeps Gate G self-contained, same pattern as Gates A/B/C/D/E/F.

### Allow unsigned "relay" brokers that don't append attenuation

Rejected. Without an attenuation block, the broker's participation in the chain is invisible. Shadow exchanges become indistinguishable from honest relays. Every intermediary hop MUST appear as a signed attenuation block; if the intermediary is "too lightweight" to sign, it shouldn't be in the trust path.

---

## Non-goals

- This ADR does not define the Broker's outbound attenuation contents. Mutating brokers (future: rewriting queries, consolidating offers) will specify their attenuation facts in a follow-up ADR.
- This ADR does not specify how ramp.json is served, cached, or refreshed. It defines the schema extension.
- This ADR does not commit to implementing Gate G before there's a real broker-append scenario. Until then, `authorized_intermediaries` remains an optional authority-block fact that is unenforced but permitted.
- This ADR does not specify cross-contract intermediary lists or industry-wide broker registries. Authority-block-local scope keeps the mechanism small.

---

## Implementation follow-up

Out of scope for this ADR atom, tracked separately:

- **Gate G implementation** — Exchange `policygate` extension, unit + integration tests.
- **Authority-block mint extension** — biscuit mint tool to accept and emit `authorized_intermediaries`.
- **ramp.json schema extension** — publish updated schema, lint rules, agent-side parser support.
- **Broker attenuation-append** — the actual code that makes a broker append an attenuation block (triggers Gate G to become real).

All deferred until a multi-hop broker scenario exists. For now, the protocol surface is pinned and clients can adopt the authority-block fact as an opt-in for shadow-exchange prevention.

---

## References

- ADR-002 — authority-block fact convention.
- ADR-003 — key rotation and revocation (applies to intermediary kids).
- ADR-004 — protocol layers (authorization inner-layer, discovery outer-layer).
- ADR-005 Part 3 — Pattern-2 attenuation-append mechanism this ADR governs.
