"""E2E: an agent's spend budget gates real content delivery, keyed on identity.

This suite tests the real agent scenario: an agent declares a spend budget
(``constraints.period_budget``) on a priced resolve. The Broker meters that
budget against the agent's **authenticated identity** — the signed
``Signature-Agent`` the Broker verifies before the guard runs — and refuses a
resolve whose cost would exceed it, *before* issuing any licence. The outcome is
observed through the **canonical** ``DiscoveryResponse`` an agent actually
consumes: a signed ``retrieval_endpoint`` (and ``transaction_id``) on success,
and their absence on refusal. No Broker-internal ``ext`` audit field is asserted
on — only the protocol-level delivery result.

The resource is the demo ``wooden-door-creak`` sound effect, whose sole term is
priced (PER_UNIT 0.25 USD), so a budget can actually be exceeded — unlike the
FREE-headline demo articles whose cost is always 0.

Three legs, pinning one axis — budget presence:

1. Within budget   → licensed: a signed URL is returned and fetches real bytes.
2. Over budget     → refused:  no signed URL, no transaction (budget enforced).
3. No budget set   → licensed: with no cap to meter against, the Broker skips the
   gate (``checkBudget`` short-circuits on a non-positive limit). The gate
   engages ONLY when the agent declares a positive budget.

Cross-resolve accumulation and cross-agent isolation are pinned by the Go
integration test ``TestResolve_BudgetAccumulatesPerAgent`` (a real Connect
round-trip on a deterministic clock) rather than end to end here, because a
shared-Redis e2e stack cannot reset the counter between legs.

Budgets are chosen to bracket the cost without depending on its exact value: a
1-minor budget is below any positive per-unit cost (→ refused); a very large
budget is above any plausible demo cost (→ licensed).
"""

from __future__ import annotations

from typing import Any, cast

import httpx

from .broker_client import resolve
from .conftest import StackURLs
from .edge_fetch import fetch_signed
from .relay import relay_execute
from .resolve_carriers import (
    absence_reason_of,
    cost_of,
    first_item_of,
    retrieval_endpoint_of,
)
from .seed import SeededFixture

# 1 minor (0.01 USD): below any positive per-unit cost → over budget.
_BUDGET_OVER = 1
# 10,000.00 USD: above any plausible demo cost → within budget.
_BUDGET_AMPLE = 1_000_000


def _resolve_priced(
    compose_stack: StackURLs,
    res: object,
    *,
    budget_minor: int | None,
) -> httpx.Response:
    """Discover the priced demo resource as its buyer, with an optional budget.

    R7: Broker Resolve is discovery-only AND it is where the budget PRE-FLIGHT
    gate lives — the Broker checks "can the agent afford the cheapest offer?" and
    refuses DISCOVERY (empty offer_groups + NOT_AUTHORIZED) when not, before any
    Offer is surfaced. So the budget GATE is observed here, on the discovery
    response; delivery (the signed URL) is a separate relay-execute phase below.
    Mirrors the demo resolve in ``test_full_path_terms`` (identity-only requester,
    no user_type/geography per ADR-014). The affordability pre-flight keys on the
    authenticated ``req.AgentID`` (see the module docstring); ``budget_minor`` is
    the only axis that varies across these legs (absent ⇒ the gate is skipped).
    """
    body: dict[str, object] = {
        "agent_id": res.buyer_agent_id,  # type: ignore[attr-defined]
        "uri": res.uri,  # type: ignore[attr-defined]
        "intended_use": "ai-input",
        "currency": "USD",
    }
    if budget_minor is not None:
        body["budget_minor"] = budget_minor
    return resolve(compose_stack, body, key_path=res.buyer_key_path)  # type: ignore[attr-defined]


def _first_offer_or_none(payload: dict[str, Any]) -> dict[str, Any] | None:
    """The winning discovered Offer (offerGroups[0].offers[0]), or None if refused.

    Non-empty offer_groups IS the discovery-licensed signal under R7; an empty
    discovery (the budget pre-flight refusal) yields None — there is nothing to
    execute.
    """
    groups = cast(list[dict[str, Any]], payload.get("offer_groups") or [])
    offers = [o for g in groups for o in cast(list[dict[str, Any]], g.get("offers") or [])]
    return offers[0] if offers else None


def _discovered(payload: dict[str, Any]) -> bool:
    """True when discovery surfaced at least one Offer (the licensed-discovery signal)."""
    return _first_offer_or_none(payload) is not None


def _deliver_priced(
    compose_stack: StackURLs,
    res: object,
    offer: dict[str, Any],
) -> httpx.Response:
    """Relay-execute a discovered priced Offer (agent sig1 over broker route + acceptance).

    The signed URL is minted on the EXECUTE (TransactionResponse). The priced demo
    resource is bought by its currency-matched buyer (USD). Under re-package the
    broker routes from the signed offer.exchange, so no Exchange URL is supplied.
    """
    return relay_execute(
        compose_stack.broker,
        offer,
        agent_id=res.buyer_agent_id,  # type: ignore[attr-defined]
        domain=res.domain,  # type: ignore[attr-defined]
        key_path=res.buyer_key_path,  # type: ignore[attr-defined]
    )


def test_within_budget_resolves_and_delivers_content(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """An ample budget → discovery passes the gate, relay-execute delivers."""
    res = seeded.priced_per_unit  # wooden-door-creak, PER_UNIT 0.25 USD
    # Phase 1 — discovery passes the budget pre-flight gate (ample budget).
    resp = _resolve_priced(compose_stack, res, budget_minor=_BUDGET_AMPLE)
    assert resp.status_code == httpx.codes.OK, resp.text
    discovery = resp.json()
    offer = _first_offer_or_none(discovery)
    assert offer is not None, f"ample budget must pass the gate and surface an offer: {discovery}"

    # Phase 2 — relay-execute the discovered Offer; the signed URL + delivered
    # price ride on the EXECUTE (TransactionResponse).
    exec_resp = _deliver_priced(compose_stack, res, offer)
    assert exec_resp.status_code == httpx.codes.OK, exec_resp.text
    # The EXECUTE response is an items[] envelope — read the
    # per-result fields (cost, retrievalEndpoint) from items[0]. The DISCOVERY
    # reads above (offerGroups/absenceReason) stay top-level (unchanged).
    payload = exec_resp.json()
    item = first_item_of(payload)
    assert item is not None, f"execute response carried no items[0]: {payload}"

    # ADR-019: the PAID-term price is the canonical typed per-item cost
    # (Exchange buildBatchResultItem). unitCost is the per-unit rate (stable;
    # amount = unitCost × est_quantity), so assert it equals the fixture term rate.
    # Money-as-string: Money.amount/unit_cost ride as decimal STRINGS on the wire
    # (FormatMoney: 0.25 → "0.25"); parse before comparing to the float fixture rate.
    cost = cost_of(item)
    assert cost is not None, payload
    assert float(cost["unit_cost"]) == seeded.priced_per_unit_rate, cost
    assert cost.get("currency") == "USD", cost

    signed_url = retrieval_endpoint_of(item)
    assert signed_url, payload
    content = fetch_signed(signed_url, compose_stack, timeout=15.0, key_path=res.buyer_key_path)
    assert content.text.strip(), content.text


def test_over_budget_is_refused_before_licensing(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """A budget below cost → refused AT DISCOVERY: no offer, NOT_AUTHORIZED.

    R7: the Broker meters the per-unit cost against the budget in the discovery
    PRE-FLIGHT gate and refuses before any Offer is surfaced. The refusal is
    observed on the discovery response itself: empty offer_groups (no offer to
    execute) and the typed NOT_AUTHORIZED absence_reason. There is nothing to
    relay-execute — the agent never reaches the delivery phase.
    """
    res = seeded.priced_per_unit
    resp = _resolve_priced(compose_stack, res, budget_minor=_BUDGET_OVER)
    assert resp.status_code == httpx.codes.OK, resp.text
    payload = resp.json()
    assert _discovered(payload) is False, f"over-budget must surface NO offer: {payload}"
    assert _first_offer_or_none(payload) is None, payload
    assert absence_reason_of(payload) == "OFFER_ABSENCE_REASON_NOT_AUTHORIZED", payload


# The Broker's cost guard is a per-agent accumulating cap keyed on the
# authenticated identity: each licensed resolve calls Budget.Record,
# so spend accumulates across an agent's resolves and a later resolve is refused
# once the cap is consumed. Cross-resolve accumulation and cross-agent isolation
# are pinned by the Go integration test TestResolve_BudgetAccumulatesPerAgent (a
# real Connect round-trip, deterministic clock) rather than end-to-end here,
# because a shared-Redis e2e stack cannot reset the counter between legs. The
# Exchange remains the authoritative biller at ExecuteTransaction (prepaid
# balance), covered separately:
#   - src/exchange/internal/transport/execute_integration_test.go
#     TestExecuteTransaction_BillingDenied: a drained balance ->
#     DENIAL_REASON_INSUFFICIENT_BALANCE (PermissionDenied).
#   - src/exchange/internal/transport/billing_ordering_integration_test.go:
#     the balance is debited per execute and restored on release.
# A broker-side CROSS-Exchange agent spend cap (recorded at relay-time, newly
# meaningful under R10 multi-Exchange) is a possible FUTURE feature, not the
# retired test's intent — it would be filed separately if the product wants it.


def test_no_budget_skips_the_gate(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """SAME priced resolve but NO budget declared → licensed (gate skipped).

    The budget pre-flight engages ONLY when the agent declares a positive
    period_budget (checkBudget short-circuits on a non-positive limit). With no
    budget to meter against, the priced resolve surfaces an offer and delivery
    succeeds. The only difference from
    :func:`test_over_budget_is_refused_before_licensing` is the absence of a
    declared budget; the outcome flipping from refused to licensed pins the
    declared budget as the sole cause of enforcement.
    """
    res = seeded.priced_per_unit
    # Phase 1 — no budget → the Broker skips the gate, so the resolve surfaces an
    # offer even for the priced resource.
    resp = _resolve_priced(compose_stack, res, budget_minor=None)
    assert resp.status_code == httpx.codes.OK, resp.text
    offer = _first_offer_or_none(resp.json())
    assert offer is not None, f"no budget must skip the gate and surface an offer: {resp.json()}"
    # Phase 2 — and delivery succeeds (nothing metered the priced request).
    exec_resp = _deliver_priced(compose_stack, res, offer)
    assert exec_resp.status_code == httpx.codes.OK, exec_resp.text
    exec_payload = exec_resp.json()
    item = first_item_of(exec_payload)
    assert item is not None, f"execute response carried no items[0]: {exec_payload}"
    assert retrieval_endpoint_of(item), exec_payload
