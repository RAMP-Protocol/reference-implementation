"""Canonical Broker ``ramp.v1.BrokerService/Resolve`` response carriers for E2E.

Single source of truth for reading the canonical proto-JSON ``DiscoveryResponse``
the Broker returns on the Connect ``ramp.v1.BrokerService/Resolve`` endpoint.
The codec is emit-unpopulated ``protojson`` with proto field names, so the keys
are snake_case and a zero-valued scalar stays on the wire:

* the signed delivery URL rides on the top-level ``retrieval_endpoint`` field
  (the legacy top-level ``signed_url`` slot is gone). ADR-019: ``licensed`` is
  derived from its PRESENCE.
* the refusal cause rides on the typed ``absence_reason`` field
  (``OfferAbsenceReason``).
* the delivered price rides on the typed ``cost`` field (canonical ``Cost`` —
  ``amount`` = unit_cost × est_quantity, plus ``unit_cost`` and ``currency``).

ADR-019: the Broker's agent-facing ``DiscoveryResponse`` is PURELY the
canonical typed fields — it carries NO ``ramp.broker.*`` ext. Broker
selection/billing detail (winning offer id, budget/spend state, the evaluated
candidate list) lives only in the Broker's SelectionLog / budget service and is
never read off the wire. These carriers mirror the Go ``toDiscoveryResponse`` in
``src/broker/internal/transport/canonical.go`` — reading the same protojson the
Broker emits.
"""

from __future__ import annotations

from typing import Any


def licensed_of(payload: object) -> bool:
    """Return the Broker ``licensed`` signal.

    ADR-019: derived from the PRESENCE of the typed canonical
    ``retrieval_endpoint`` — the Broker sets it only on the licensed path and the
    emit-unpopulated codec omits it when unset — never from a ``ramp.broker.*``
    ext key.
    """
    return retrieval_endpoint_of(payload) is not None


def absence_reason_of(payload: object) -> str | None:
    """Return the typed refusal cause (``absence_reason`` OfferAbsenceReason), or None.

    None when licensed or for a non-dict payload.
    """
    if not isinstance(payload, dict):
        return None
    value = payload.get("absence_reason")
    return value if isinstance(value, str) and value else None


def retrieval_endpoint_of(payload: object) -> str | None:
    """Return the canonical signed URL (top-level ``retrieval_endpoint``), or None.

    Returns None for a non-dict payload or an absent/empty field — never raises.
    """
    if not isinstance(payload, dict):
        return None
    value = payload.get("retrieval_endpoint")
    return value if isinstance(value, str) and value else None


def first_item_of(payload: object) -> dict[str, Any] | None:
    """Return ``items[0]`` of an items-only ``TransactionResponse``, or None.

    An EXECUTE response is now an items[] envelope (a single
    offer is a 1-element batch), so the per-result fields (``retrieval_endpoint``,
    ``transaction_id``, ``cost``, ``denial_reason``) live in ``items[0]`` — not at
    the top level. Wrap an execute response with this helper, then apply the
    existing top-level carriers (:func:`retrieval_endpoint_of`, :func:`cost_of`,
    :func:`licensed_of`) to the returned item. The broker RESOLVE/discovery path
    keeps its top-level shape and does NOT use this. Returns None for a non-dict
    payload or an empty/absent ``items`` — never raises.
    """
    if not isinstance(payload, dict):
        return None
    items = payload.get("items")
    if not isinstance(items, list) or not items:
        return None
    first = items[0]
    return first if isinstance(first, dict) else None


def offer_exchanges_by_uri(payload: object) -> dict[str, set[str]]:
    """Map each ``OfferGroup.uri`` to the set of ``Offer.exchange`` values it carries.

    The S2 fan-out acceptance surface: a single broker ``Resolve`` over a batch
    returns one ``OfferGroup`` per requested URI (canonical proto-JSON
    ``offer_groups``/``uri``/``offers``/``exchange``), each group's offers stamped
    with the originating Exchange's domain (``offer.exchange``). A group with no
    offers (a typed-absence miss) maps to the empty set, so a negative leg can
    assert that a URI is present-but-absent. Returns an empty mapping for a
    non-dict payload — never raises.
    """
    if not isinstance(payload, dict):
        return {}
    groups = payload.get("offer_groups") or []
    out: dict[str, set[str]] = {}
    for group in groups if isinstance(groups, list) else []:
        if not isinstance(group, dict):
            continue
        uri = group.get("uri")
        if not isinstance(uri, str) or not uri:
            continue
        exchanges: set[str] = set()
        offers = group.get("offers") or []
        for offer in offers if isinstance(offers, list) else []:
            if not isinstance(offer, dict):
                continue
            value = offer.get("exchange")
            if isinstance(value, str) and value:
                exchanges.add(value)
        out[uri] = exchanges
    return out


def absence_reasons_by_uri(payload: object) -> dict[str, str]:
    """Map each ``OfferGroup.uri`` to its per-group ``absence_reason``, when set.

    A URI miss across every authorized exchange surfaces as a typed-absence
    group: ``offers`` empty and ``absence_reason`` carrying the ADR-008 D2
    ``OfferAbsenceReason`` (per-URI now, not per-response). Groups with offers
    (or no absence reason) are omitted. Returns an empty mapping for a non-dict
    payload — never raises.
    """
    if not isinstance(payload, dict):
        return {}
    groups = payload.get("offer_groups") or []
    out: dict[str, str] = {}
    for group in groups if isinstance(groups, list) else []:
        if not isinstance(group, dict):
            continue
        uri = group.get("uri")
        if not isinstance(uri, str) or not uri:
            continue
        reason = group.get("absence_reason")
        if isinstance(reason, str) and reason:
            out[uri] = reason
    return out


def cost_of(payload: object) -> dict[str, Any] | None:
    """Return the canonical delivered ``cost`` submessage, or None.

    The Cost message carries ``amount`` (unit_cost × est_quantity), ``unit_cost`` (the
    per-unit rate), and ``currency``. The Exchange always sets it on a delivered
    transaction (``buildTxResponse``) and the Broker forwards it verbatim
    (``toDiscoveryResponse``), so it is the agent-observable price — never a
    ``ramp.broker.*`` ext key. Returns None for a non-dict payload or an absent
    cost (e.g. a refusal).
    """
    if not isinstance(payload, dict):
        return None
    cost = payload.get("cost")
    return cost if isinstance(cost, dict) else None
