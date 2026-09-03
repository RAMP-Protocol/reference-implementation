"""Shared Broker resolve helper for the E2E suites.

Signing a ``ramp.v1.BrokerService/Resolve`` request as the agent itself (with a
per-call nonce so the replay store never refuses a repeat) is needed by every
query-path suite. It lived near-verbatim in three test modules; this module is
its single home.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, cast

import httpx
from ramp_sdk import ProtocolVersion

from .constants import requester
from .stack_urls import StackURLs
from .relay import relay_execute
from .signing import USD_AGENT_KEY_PATH, sign_post


def _canonical_resolve_body(body: dict[str, object]) -> dict[str, object]:
    """Translate the suite's flat resolve dict into a canonical proto DiscoveryRequest.

    The merged Broker decodes ``ramp.v1.BrokerService/Resolve`` as a canonical
    proto-JSON ``DiscoveryRequest`` — ``requester.id`` is the self-act identity. After the
    Universal Licensing Core overhaul the requester is identity-only: the URIs
    ride on the message-level ``uris`` field and the intended use rides as a
    FUNCTION-axis ``acceptableRestrictions`` entry (see ``rampRequestToInput`` in
    ``src/broker/internal/transport/canonical.go``). The flat
    ``{agent_id, uri, intended_use, domain}`` shape every suite passes is mapped
    here; ``user_type`` / ``geography`` are no longer carried on the wire
    (ADR-014, 2026-06-15) and are dropped. A top-level ``nonce`` is preserved so
    the signed body stays unique for the replay store (the Broker's
    DiscardUnknown decoder ignores it).
    """
    # The pinned proto requires Requester.type != UNSPECIFIED on every message
    # carrying a Requester (enum not_in:[0]); the canonical DiscoveryRequest the
    # Broker decodes is no exception. Agent self-act → REQUESTER_TYPE_AGENT.
    requester_obj = requester(str(body["agent_id"]), cast(str | None, body.get("domain")))
    out: dict[str, object] = {
        "ver": ProtocolVersion,
        "id": f"rampreq-{uuid.uuid4().hex}",
        # Proto re-pin: DiscoveryRequest.idempotency_key now carries
        # min_len >= 1 (string.min_len). A resolve with an empty/absent key is
        # rejected at proto validation (400 invalid_argument) before reaching
        # the Broker — set a non-empty per-call key. Distinct from `id`
        # (correlation): idempotency_key is the dedup handle the proto requires.
        "idempotency_key": f"idem-{uuid.uuid4().hex}",
        "requester": requester_obj,
        "nonce": uuid.uuid4().hex,
    }
    # budget_minor → constraints.period_budget (major units), inverting the
    # Broker's amount*100 mapping (rampRequestToInput). Enforcement is gated on a
    # positive budget; the Broker meters spend per authenticated agent identity.
    budget_minor = body.get("budget_minor")
    if budget_minor is not None:
        out["constraints"] = {
            "period_budget": {
                # Money-as-string: Money.amount is a decimal STRING on
                # the wire (the canonical proto rejects a JSON number here).
                "amount": f"{int(str(budget_minor)) / 100:.2f}",
                "currency": str(body.get("currency", "USD")),
            }
        }
    # Multi-URI batch: a `uris` list rides straight onto the canonical
    # DiscoveryRequest.uris field, fanning the resolve across every named
    # publisher manifest. The single `uri` path (every legacy suite) maps to a
    # one-element list, so a single-uri request still yields exactly one group.
    if "uris" in body:
        out["uris"] = list(cast(list[object], body["uris"]))
    elif "uri" in body:
        out["uris"] = [body["uri"]]
    if body.get("intended_use") is not None:
        out["acceptable_restrictions"] = [
            {"axis": "RESTRICTION_KIND_FUNCTION", "values": [body["intended_use"]]}
        ]
    if body.get("query") is not None:
        out["query"] = body["query"]
    return out


def resolve(
    compose_stack: StackURLs,
    body: dict[str, object],
    *,
    key_path: Path | None = None,
) -> httpx.Response:
    """POST a signed ``ramp.v1.BrokerService/Resolve`` request as the agent itself.

    The Broker requires every signed ``/ramp.*`` call to carry a valid RFC 9421
    signature whose keyID equals the requester identity (``body['agent_id']``,
    mapped to canonical ``requester.id``) — self-act. The signing key MUST
    therefore match the ``agent_id`` in the body — the demo catalog denominates
    terms in different currencies, so the caller picks the buyer (EUR vs USD)
    whose balance currency matches the term and passes its key here.
    Defaults to the USD buyer (``agent-e2e``).

    Callers pass the suite's flat ``{agent_id, uri, intended_use, ...}`` dict;
    :func:`_canonical_resolve_body` maps it to the canonical proto-JSON
    ``DiscoveryRequest`` the merged Broker decodes. The per-call ``nonce`` keeps the
    signed body — hence the Content-Digest and the signature — unique, so the
    Broker's (keyID, signature) replay store never refuses a repeat resolve of
    the same {agent, uri}.
    """
    return sign_post(
        f"{compose_stack.broker}/ramp.v1.BrokerService/Resolve",
        body=_canonical_resolve_body(body),
        key_path=key_path or USD_AGENT_KEY_PATH,
        # Connect unary framing (ADR-019). Not a signed header, so it
        # rides as an extra header; the body stays the bare DiscoveryRequest message.
        extra_headers={"Connect-Protocol-Version": "1"},
    )


def _first_offer(discovery_payload: dict[str, Any]) -> dict[str, Any]:
    """Pluck the ranked winner from a discovery ``DiscoveryResponse``.

    Resolve is discovery-only: the winner is ``offer_groups[0].offers[0]`` —
    a full signed Offer, ranked winner-first — and NO ``retrieval_endpoint`` is
    minted (that is the execute phase). Reads the snake_case
    ``offer_groups``/``offers`` the Broker emits (``toDiscoveryResponse``): the
    wire is proto-JSON with proto field names, not the camelCase json_name alias.
    """
    groups = cast(list[dict[str, Any]], discovery_payload.get("offer_groups") or [])
    offers = [o for g in groups for o in cast(list[dict[str, Any]], g.get("offers") or [])]
    assert offers, f"Resolve returned no offers to execute: {discovery_payload!r}"
    return offers[0]


def execute_first_offer(
    compose_stack: StackURLs,
    body: dict[str, object],
    *,
    agent_id: str,
    domain: str,
    key_path: Path | None = None,
) -> httpx.Response:
    """Two-phase relay: Broker Resolve (discovery) then relay-execute.

    Phase 1 — Broker ``Resolve`` returns the ranked signed Offers in
    ``offer_groups`` (discovery-only, R7; no signed URL). Phase 2 — the agent
    reflects the winning Offer onto an ExecuteTransaction, signs an
    ``AgentAcceptance`` over it, and relays it through the Broker
    (``relay_execute``; agent sig1 + Broker sig2) to the Exchange, which mints
    the agent-bound ``retrieval_endpoint``. The same ``agent_id``/``key_path``
    drives both phases so sig1's keyID == the requester identity == the
    acceptance key. Under re-package the agent signs the Broker relay route only;
    the Broker derives the Exchange target from the signed ``offer.exchange`` and
    resolves it via that exchange's own well-known manifest, so no Exchange URL is
    supplied here.

    Returns the raw relay ``httpx.Response`` (the Exchange ``TransactionResponse``
    on success); callers own the status/body verdict.
    """
    discover_resp = resolve(compose_stack, body, key_path=key_path)
    assert discover_resp.status_code == httpx.codes.OK, (
        f"Broker Resolve must return 200 (precedes relay execute); "
        f"got {discover_resp.status_code}: {discover_resp.text[:512]}"
    )
    offer = _first_offer(cast(dict[str, Any], discover_resp.json()))
    return relay_execute(
        compose_stack.broker,
        offer,
        agent_id=agent_id,
        domain=domain,
        key_path=key_path or USD_AGENT_KEY_PATH,
    )
