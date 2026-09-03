-- Append-once evidence store: the full signed offer + both-party signatures for
-- every successfully executed transaction item, keyed 1:1 by transaction_id.
--
-- transaction_log holds only thin references (offer_id, a signed-URL hash, an
-- agent-identity thumbprint) and its rows are UPDATEd when a usage report lands.
-- The two Ed25519 proofs that establish what was actually agreed -- the
-- Exchange's signature over the offer and the agent's acceptance signature -- are
-- verified on every execute and then dropped. This table captures them verbatim
-- so a third party can re-verify BOTH sides from a stored row alone, with no
-- access to the agent registry, the Exchange key file, or any live service:
--   * the Exchange signed this exact offer:
--       ed25519.Verify(exchange_signing_public_key, offer_canonical_bytes, offer_signature)
--   * the agent accepted this exact offer:
--       ed25519.Verify(agent_public_key, agent_acceptance_canonical_bytes, agent_acceptance_signature)
-- The acceptance payload's four inputs (offer_signature, requester_id,
-- requester_domain, request_idempotency_key) are stored too, so the stored bytes
-- can be independently rebuilt and audited rather than merely trusted.
-- Both verifying public keys are stored (not key ids) so re-verification survives
-- key rotation, which removes retired kids from the published JWKS.
--
-- SCOPE OF THE GUARANTEE. The signatures cover what was AGREED, not what was
-- DELIVERED. transaction_id, signed_url_full, request_id and created_at fall
-- outside both signatures -- they are this Exchange's own assertions about the
-- delivery, not counterparty-signed facts. A delivery witness is the edge
-- delivery log's job (ADR-012), reconciled per ADR-011.
--
-- COLUMN PROVENANCE. Every column is exactly one of:
--   signed         -- inside a verified signature; a tampered value denies the
--                     execute before this row is written
--   server-derived -- computed or held by this Exchange, never read from the wire
--   caller-asserted-- supplied by the caller and covered by NO signature
-- The signature_algorithm fields are deliberately server-derived, NOT echoed
-- from the wire: the canonical signing payload CLEARS signature and
-- signature_algorithm before canonicalising, so the wire labels are outside
-- signature coverage and a caller can set them to anything under an otherwise
-- valid signature. Both verification paths bottom out in ed25519.Verify, so the
-- Exchange's own constant is the true statement about what was checked. The
-- same normalization is applied to offer_json, so every column agrees.
-- request_id is the sole caller-asserted column; it is charset- and
-- length-validated at the middleware before it reaches here.
--
-- request_id PROVENANCE. The middleware accepts a conforming caller-supplied
-- X-Request-ID verbatim and mints a UUID otherwise. A minted UUID lies entirely
-- inside the accepted charset, so the two provenances are byte-indistinguishable
-- in the column alone -- yet request_id is the join key correlating an evidence
-- row outward against the edge delivery log (ADR-012) and the reconciliation
-- sweep (ADR-011). request_id_minted records which one this was, so a forensic
-- query can tell a server-derived correlation key from an attacker-influenceable
-- one. It is nullable and travels with request_id: an absent id has no
-- provenance to state, and a present one always has exactly one (constraint
-- below). There is deliberately NO default -- an append-once row states every
-- fact explicitly, and a defaulted provenance flag would silently assert a
-- provenance nobody established.
--
-- Both signatures are stored as lowercase-or-uppercase hex TEXT rather than
-- BYTEA: the verbatim wire form is what the counterparty sent, and a dispute
-- reads the same characters it can find in a request log. The CHECKs pin the
-- shape a 64-byte Ed25519 signature must have. They are deliberately
-- case-INSENSITIVE: agent_acceptance_signature arrives off the wire and hex
-- decoding accepts either case, so a lowercase-only constraint would reject an
-- acceptance that had already verified -- turning a valid execute into a write
-- failure. Every signature that decodes to 64 bytes is exactly 128 hex
-- characters, so neither CHECK can reject a verified signature.
--
-- Both *_canonical_bytes columns hold the verbatim RFC 8785 JCS of canonical
-- proto-JSON that each signature was computed over -- the offer with its
-- signature fields cleared, and the AgentAcceptancePayload. Protobuf-binary is
-- declared non-canonical by the protocol, so neither can be re-serialized for
-- verification; the bytes are stored as-signed.
--
-- Storing both, rather than re-deriving the acceptance payload from its four
-- stored inputs, is what makes re-verification independent of the canonicalization
-- RECIPE and not merely of the message schema. The field set of
-- AgentAcceptancePayload is fixed by the protocol, but the recipe is not: it has
-- already moved once, from deterministic protobuf to JCS over proto-JSON. A row
-- that stores only inputs re-verifies only for as long as the verifier's recipe
-- still matches the signer's, and a mismatch is indistinguishable from a forged
-- signature. A row that stores the signed bytes needs nothing but ed25519.Verify.
--
-- offer_json duplicates offer_canonical_bytes on purpose: JSONB is queryable and
-- human-auditable, BYTEA is neither. The canonical bytes remain the arbiter.
--
-- offer_id is the presented signed Offer.offer_id — an opaque per-offer UUID
-- minted at discovery, carrying no resource identity (resource identity lives
-- in transaction_log.resource_id; execute binds the offer to its catalog row
-- via the signed Identity.canonical_url). It always equals
-- transaction_log.offer_id and is duplicated here so an evidence row reads
-- standalone, without a join.
--
-- requester_id is the signed Requester.id VERBATIM — the bytes the agent put its
-- signature over, which is why the column keeps the signed field's name rather
-- than agent_id. What the row attests is what was signed, so this value is never
-- rewritten; that property is the point of an evidence table.
--
-- It NAMES the same agent as ramp.agents.agent_id and transaction_log.agent_id
-- but is not byte-equal to them. Those two hold the agent's canonical identity —
-- its directory host, scheme dropped and spelling folded (internal/agentid) —
-- while a signer is free to write that host any way it likes, and the deployed
-- identity service in fact signs "scheme://host". So the forensic join is:
--
--   agentid.FromDirectory(requester_id) = transaction_log.agent_id
--
-- and NOT a plain equality, which would silently return nothing for every row
-- whose signer spelled its directory as a URL. Stated here so the join does not
-- have to be rediscovered from source, and so a search for agent_id reaches this
-- table too. src/exchange/internal/transport has an integration test pinning the
-- relationship, so code and this comment cannot drift apart again.
--
-- request_idempotency_key is the REQUEST-level key the acceptance actually signs,
-- NOT the derived per-item key (reqKey:offer_id) that transaction_log stores.
--
-- requester_domain is bounded at the RFC 1035 maximum DNS name length. It is the
-- one caller-influenced value here that nothing upstream constrains -- the proto
-- validates only requester.type -- and this table has no deletion path, so an
-- unbounded value would be unbounded forever. The acceptance signature does not
-- mitigate: the agent signs the requester it chose, with its own key. The service
-- rejects an over-long domain before executing; this CHECK is the structural
-- backstop for a writer that skips that validation.
--
-- agent_discovery_url is the anchored well-known directory the agent's key was
-- pinned from. The registry overwrites an agent's key in place on rotation and
-- keeps no history, so without this the row proves "key K signed these terms"
-- but nothing about K ever having been this agent's key. With it -- plus
-- created_at on an append-once row -- the row additionally attests where and
-- when this Exchange obtained K. Empty when the agent carries no directory
-- anchor. Independent proof that the agent published K there needs archived
-- directory snapshots or an append-only key history; neither exists yet.
-- Note the deliberate asymmetry with ramp.agents.discovery_url, which is
-- NULLable: this column is NOT NULL and encodes absence as ''. An append-once
-- evidence row states a value for every column, so "the Exchange recorded no
-- directory for this key" is a fact it asserts rather than a gap it leaves. The
-- cost is that a forensic join across the two needs
-- `agents.discovery_url IS NULL` on one side and
-- `evidence.agent_discovery_url = ''` on the other.
--
-- Immutability: enforced by the BEFORE UPDATE/DELETE/TRUNCATE triggers below.
-- REVOKE is intentionally omitted -- every environment connects as the database
-- owner (the same identity that runs migrations), which bypasses table REVOKEs,
-- so REVOKE would be a no-op here; the trigger holds regardless of role. The
-- ultimate integrity guarantee is the persisted signatures plus three-way
-- reconciliation.
--
-- Retention: rows are meant to be kept for the same >= 13-month financial window
-- as transaction_log, and NO MECHANISM FOR REMOVING THEM EXISTS TODAY. State that
-- plainly rather than implying one: the triggers below refuse DELETE and TRUNCATE
-- unconditionally, this table is not partitioned (nothing in this schema is), and
-- the only statement that removes a row is DROP TABLE. Anything written here is
-- written for the lifetime of the database until that changes.
--
-- Partitioning THIS table alone, ahead of transaction_log, was considered and
-- rejected. A partitioned table's primary key must contain the partition key, so
-- keying by created_at would force PRIMARY KEY (transaction_id, created_at) and
-- give up the 1:1-by-transaction_id guarantee this table is built on -- a
-- partitioned table cannot carry a global UNIQUE (transaction_id) either. It
-- would also make an INSERT fail wherever no matching partition had been
-- provisioned, in every environment and every test fixture.
--
-- The retention mechanism therefore belongs to the partitioning work, which has
-- to cover transaction_log and ALL FOUR of its foreign-key children together:
-- reporting_obligations, report_tokens, transaction_reports, and this table.
-- ON DELETE RESTRICT is deliberate -- evidence must not vanish with its parent --
-- but note the FK action is not the operative constraint for a daily-partition
-- lifecycle: a partition is removed by DROP, which fires no row trigger and runs
-- no ON DELETE action, so the reference itself is what blocks. Whatever that work
-- chooses (composite-key FK or an application-level check) has to drop this
-- table's rows in the same sweep, and has to give the sweep a path past the
-- append-once triggers.

CREATE TABLE ramp.transaction_evidence (
    transaction_id                        TEXT PRIMARY KEY                    -- server-derived
        REFERENCES ramp.transaction_log (transaction_id) ON DELETE RESTRICT,
    tenant_id                             TEXT NOT NULL                       -- server-derived
        REFERENCES ramp.tenants (tenant_id) ON DELETE RESTRICT,

    -- Exchange side: the signed offer.
    offer_id                              TEXT  NOT NULL,               -- signed
    offer_json                            JSONB NOT NULL,               -- signed (algorithm label normalized)
    offer_canonical_bytes                 BYTEA NOT NULL,               -- signed: the verbatim JCS bytes
    offer_signature                       TEXT  NOT NULL               -- signed: Exchange Ed25519 signature (hex)
        CHECK (offer_signature ~ '^[0-9A-Fa-f]{128}$'),
    offer_signature_algorithm             TEXT  NOT NULL,               -- server-derived
    exchange_signing_public_key           BYTEA NOT NULL                -- server-derived
        CHECK (octet_length(exchange_signing_public_key) = 32),

    -- Agent side: the acceptance.
    agent_acceptance_signature            TEXT  NOT NULL               -- signed: agent Ed25519 signature (hex)
        CHECK (agent_acceptance_signature ~ '^[0-9A-Fa-f]{128}$'),
    agent_acceptance_canonical_bytes      BYTEA NOT NULL,               -- signed: the verbatim JCS bytes
    agent_acceptance_signature_algorithm  TEXT  NOT NULL,               -- server-derived
    requester_id                          TEXT  NOT NULL,               -- signed: acceptance-payload input
    requester_domain                      TEXT  NOT NULL               -- signed: acceptance-payload input
        CHECK (octet_length(requester_domain) <= 253),
    request_idempotency_key               TEXT  NOT NULL,               -- signed: acceptance-payload input
    agent_public_key                      BYTEA NOT NULL                -- server-derived: the registry-pinned key
        CHECK (octet_length(agent_public_key) = 32),
    agent_discovery_url                   TEXT  NOT NULL,               -- server-derived: where that key was pinned from

    -- Delivery + correlation. Covered by neither signature.
    signed_url_full                       TEXT  NOT NULL,               -- server-derived: full delivered URL
    request_id                            TEXT,                         -- caller-asserted, validated at the middleware
    request_id_minted                     BOOLEAN,                      -- server-derived: TRUE => minted, FALSE => taken from the caller
    created_at                            TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- server-derived

    -- The correlation id and its provenance travel together: an absent id has no
    -- provenance to state, and a present one always has exactly one.
    CONSTRAINT transaction_evidence_request_id_provenance
        CHECK ((request_id IS NULL) = (request_id_minted IS NULL))
);

CREATE INDEX transaction_evidence_tenant_idx  ON ramp.transaction_evidence (tenant_id, created_at DESC);
-- request_id is the outward join key (see the provenance note above), so it is
-- indexed the same way ramp.audit_log indexes its own. Without it the
-- reconciliation sweep the column exists to serve seq-scans an append-once,
-- never-pruned table. NULLs are not indexed by btree, which is what this wants:
-- a row with no correlation id joins to nothing.
CREATE INDEX transaction_evidence_request_idx ON ramp.transaction_evidence (request_id, created_at DESC);

-- Append-once enforcement (role-independent; see header note on REVOKE). One
-- function serves both triggers -- it only ever RAISEs, so it never returns.
CREATE FUNCTION ramp.prevent_evidence_mutation() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'ramp.transaction_evidence is append-once: % is prohibited', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_transaction_evidence_no_row_mutation
    BEFORE UPDATE OR DELETE ON ramp.transaction_evidence
    FOR EACH ROW EXECUTE FUNCTION ramp.prevent_evidence_mutation();

CREATE TRIGGER trg_transaction_evidence_no_truncate
    BEFORE TRUNCATE ON ramp.transaction_evidence
    FOR EACH STATEMENT EXECUTE FUNCTION ramp.prevent_evidence_mutation();
