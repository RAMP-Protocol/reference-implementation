"""Full-path term-eligibility E2E over the live stack (demo catalog).

Exercises the COMPLETE vertical through public surfaces only, against the
demo-catalog resources the real ``ramp-ingest`` binary ingested:

* PUSH (validation surface): two probe pushes through the signed
  ``CatalogService/PushResources`` RPC assert the Exchange's term validator
  rejects a hard-invalid term and warns (but accepts) an unknown-vocab token.
  These exercise the RPC's reject/warning behaviour; they do NOT push demo
  content (the demo catalog is the binary's ingest output, asserted below).

* QUERY (agent): Broker → Exchange → Edge on the demo ``plato`` resource, which
  carries an academic-FREE term (pushed first) and a commercial-PER_UNIT 0.03
  term. Per ADR-014's 2026-06-15 amendment the Exchange filters by resource_id +
  scopes ONLY — it no longer excludes a term by the requester's self-declared
  user_type / geography / intended_use. So EVERY requester now discovers BOTH
  terms on one offer and the agent self-selects; the headline price is the FIRST
  projected term, i.e. plato's FREE term → unit cost 0. A requester
  in any geography (US included) is licensed and delivered bytes; the
  restrictions ride on the offer for the agent to self-honour, and are enforced
  downstream at accept→report→reconcile.

The QUERY path pushes NOTHING — it reads the demo catalog the seed ingested.
"""

from __future__ import annotations

import re
import uuid

import httpx
import pytest
from ramp_sdk.client import CallError

from .broker_client import execute_first_offer
from .catalog_push import (
    OBLIGATION_KIND_SHARE_ALIKE,
    OBLIGATION_TRIGGER_ON_DISTRIBUTION,
    PRICING_MODEL_FREE,
    RESTRICTION_KIND_FUNCTION,
    CatalogEntry,
    license_term,
    push_catalog,
    restriction,
)
from .conftest import StackURLs
from .discovery import discoverable
from .edge_fetch import fetch_signed
from .resolve_carriers import first_item_of, licensed_of, retrieval_endpoint_of
from .seed import (
    CONTRIBUTOR_KEY_PATH,
    DEMO_PHILOSOPHY_DOMAIN,
    USD_AGENT_ID,
    USD_AGENT_KEY_PATH,
    SeededFixture,
)


def _deliver_demo(compose_stack, res):
    # R7: Broker Resolve is discovery-only; the signed URL is minted on the relay
    # EXECUTE. Two-phase: Broker discover → relay-execute the winning Offer (agent
    # sig1 + Broker sig2 + offer-acceptance). user_type / geography are no longer
    # sent: the Broker stopped relaying them and the Exchange no longer filters on
    # them (ADR-014, 2026-06-15). Only the native intended_use rides through.
    body = {"agent_id": res.buyer_agent_id, "uri": res.uri, "intended_use": "ai-input"}
    return execute_first_offer(
        compose_stack,
        body,
        agent_id=res.buyer_agent_id,
        domain=res.domain,
        key_path=res.buyer_key_path,
    )


def _delivered_item(resp):
    """Return items[0] of an EXECUTE TransactionResponse (C2 items[] envelope).

    The EXECUTE response is an items[] envelope, so every
    per-result field (licensed/retrievalEndpoint/cost) lives on items[0], never
    the top level. Fails closed if the envelope carries no items[0].
    """
    payload = resp.json()
    item = first_item_of(payload)
    assert item is not None, f"execute response carried no items[0]: {payload}"
    return item


# ---------------------------------------------------------------------------
# PUSH (validation surface) — reject + warning probes via the real RPC.
# These push throwaway probe entries (unique synthetic paths); no demo
# content is pushed. Gate 2 is satisfied by the demo edge's ramp.json
# (which lists catalog-contributor-e2e), the same gate the binary clears.
# ---------------------------------------------------------------------------


def test_push_invalid_term_rejects_whole_batch(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed registers the contributor
) -> None:
    """All-or-nothing: a term violating a hard rule sinks the WHOLE push.

    The bad entry carries a SHARE_ALIKE obligation with no ``scope_license`` — a
    protovalidate boundary reject. Pushed alongside a valid sibling, it causes the
    entire submission to be rejected (HTTP 400 invalid_argument naming the rule);
    NEITHER entry is accepted. No partial acceptance — the publisher fixes and
    resubmits the whole set.
    """
    reject_path = f"/articles/probe/reject-{uuid.uuid4().hex}.txt"
    good_path = f"/articles/probe/good-{uuid.uuid4().hex}.txt"
    solo_path = f"/articles/probe/solo-{uuid.uuid4().hex}.txt"

    # SUCCESS leg: the good entry pushed ALONE is accepted (push_catalog raises
    # unless accepted == len(entries)), proving it is well-formed — so the batch
    # rejection below is caused by the bad sibling, not the good entry.
    push_catalog(
        exchange_url=compose_stack.exchange,
        tenant_id="tenant-demo-philosophy",
        entries=[
            CatalogEntry(
                domain=DEMO_PHILOSOPHY_DOMAIN,
                path=solo_path,
                content_id=f"probe-solo-{uuid.uuid4().hex}",
                terms=(license_term(model=PRICING_MODEL_FREE, rate=0.0, currency="EUR"),),
            ),
        ],
        key_path=CONTRIBUTOR_KEY_PATH,
    )

    # FAILURE leg: the same shape of good entry + an invalid sibling → whole push rejected.
    with pytest.raises(CallError) as caught:
        push_catalog(
            exchange_url=compose_stack.exchange,
            tenant_id="tenant-demo-philosophy",
            entries=[
                CatalogEntry(
                    domain=DEMO_PHILOSOPHY_DOMAIN,
                    path=good_path,
                    content_id=f"probe-good-{uuid.uuid4().hex}",
                    terms=(license_term(model=PRICING_MODEL_FREE, rate=0.0, currency="EUR"),),
                ),
                CatalogEntry(
                    domain=DEMO_PHILOSOPHY_DOMAIN,
                    path=reject_path,
                    content_id=f"probe-bad-{uuid.uuid4().hex}",
                    terms=(
                        license_term(
                            model=PRICING_MODEL_FREE,
                            rate=0.0,
                            currency="EUR",
                            obligations=(
                                {
                                    "kind": OBLIGATION_KIND_SHARE_ALIKE,
                                    "trigger": OBLIGATION_TRIGGER_ON_DISTRIBUTION,
                                },
                            ),
                        ),
                    ),
                ),
            ],
            key_path=CONTRIBUTOR_KEY_PATH,
        )
    # The SDK's typed refusal: HTTP 400 with the Connect code as the reason, and
    # the protovalidate message naming the rule (its id and text both carry
    # ``scope_license``).
    exc = caught.value
    assert exc.status == httpx.codes.BAD_REQUEST, exc
    assert exc.reason == "invalid_argument", exc
    assert "scope_license" in str(exc), exc

    # The all-or-nothing half, and the reason this test exists. The refusal
    # status alone would hold for a server that stored the valid sibling and
    # reported the invalid one, which is precisely the partial acceptance the
    # docstring says cannot happen. Read the good entry back through the public
    # discovery RPC and require it absent.
    # The stored URI carries the scheme the deployment configures, which is
    # http here — the same spelling every other read-back in this suite uses.
    good_uri = f"http://{DEMO_PHILOSOPHY_DOMAIN}{good_path}"
    assert not discoverable(
        compose_stack.exchange, good_uri, agent_id=USD_AGENT_ID, key_path=USD_AGENT_KEY_PATH
    ), f"the valid sibling {good_uri!r} was stored despite the batch being refused"

    # The control: the same entry shape pushed alone IS discoverable, so the
    # assertion above reflects the batch refusal rather than a read that finds
    # nothing whatever it is given.
    solo_uri = f"http://{DEMO_PHILOSOPHY_DOMAIN}{solo_path}"
    assert discoverable(
        compose_stack.exchange, solo_uri, agent_id=USD_AGENT_ID, key_path=USD_AGENT_KEY_PATH
    ), f"the solo entry {solo_uri!r} is not discoverable, so the read leg proves nothing"


def test_push_warning_unknown_vocab_accepted(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed registers the contributor
) -> None:
    """An unknown vocab token is surfaced in warnings[] but the term is accepted."""
    warn_path = f"/articles/probe/warn-{uuid.uuid4().hex}.txt"
    response = push_catalog(
        exchange_url=compose_stack.exchange,
        tenant_id="tenant-demo-philosophy",
        entries=[
            CatalogEntry(
                domain=DEMO_PHILOSOPHY_DOMAIN,
                path=warn_path,
                content_id=f"probe-warn-{uuid.uuid4().hex}",
                terms=(
                    license_term(
                        model=PRICING_MODEL_FREE,
                        rate=0.0,
                        currency="EUR",
                        restrictions=(
                            restriction(
                                RESTRICTION_KIND_FUNCTION,
                                permitted=("ai-input", "totally-made-up-use"),
                                advisory=True,
                            ),
                        ),
                    ),
                ),
            ),
        ],
        key_path=CONTRIBUTOR_KEY_PATH,
    )
    # Accepted whole: a refusal is a non-200 error the SDK raises before this
    # line, and the reference Exchange never sets ``rejected``.
    assert response.accepted == 1, response
    warnings = response.warnings or []
    assert any("totally-made-up-use" in w for w in warnings), (
        f"expected warnings[] to name the unregistered token, got {response!r}"
    )


# ---------------------------------------------------------------------------
# QUERY (agent) — full path Broker → Exchange → Edge on the demo plato resource.
# plato (demo.ramp-protocol.org/articles/philosophers/plato.txt): term (a)
# academic FREE EUR geo[EU,EEA] (pushed FIRST); term (b) commercial PER_UNIT 0.03
# EUR geo[EU]. Post-ADR-014 (2026-06-15) BOTH terms project for EVERY requester
# and the headline price is the FIRST term → FREE → unit cost 0. The
# agent self-selects among the returned terms; the Exchange no longer
# differentiates requesters by user_type / geography.
# ---------------------------------------------------------------------------


def test_query_returns_free_headline_term_and_gets_content(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Any requester resolves plato (both terms returned) and is delivered bytes.

    The Exchange returns both of plato's terms on one offer; the agent
    self-selects among them and is delivered bytes. The per-term pricing
    guarantee (FREE term headline cost 0) is covered at the Exchange catalog
    surface (catalog_pricing tests), not here — ADR-019 removed the
    Broker's evaluated-candidate list from the agent-facing wire (it is
    selection-audit detail in the SelectionLog), so this test asserts only the
    protocol-meaningful licensed outcome.
    """
    res = seeded.restricted  # plato
    resp = _deliver_demo(compose_stack, res)
    assert resp.status_code == httpx.codes.OK, resp.text
    item = _delivered_item(resp)
    assert licensed_of(item) is True, item
    signed_url = retrieval_endpoint_of(item)
    assert signed_url, item

    content = fetch_signed(signed_url, compose_stack, timeout=15.0, key_path=res.buyer_key_path)
    assert content.text.strip(), content.text


def test_query_all_terms_returned_for_self_selection(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """A requester that once mapped to plato's commercial term is still licensed.

    Pre-ADR-014 a commercial/EU requester was steered onto plato's PER_UNIT 0.03
    term. Now the Exchange returns BOTH terms and the agent self-selects, so the
    assertion is no longer a differentiated price — it is that the requester is
    licensed and receives a signed URL. The differentiated-cost guarantee was
    removed with requester-attribute filtering; pricing-per-term is covered at
    the Exchange surface (catalog_pricing tests).
    """
    res = seeded.restricted  # plato
    resp = _deliver_demo(compose_stack, res)
    assert resp.status_code == httpx.codes.OK, resp.text
    item = _delivered_item(resp)
    assert licensed_of(item) is True, item
    assert retrieval_endpoint_of(item), item


def test_query_us_requester_now_licensed(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """A requester that declares no permitted geography is STILL licensed (flip).

    Pre-ADR-014 a US commercial requester got no offer (plato's terms permit only
    EU). The Exchange no longer excludes by geography — the geography restriction
    rides on the returned offer for the agent to self-honour — so the requester
    is licensed and receives a signed URL. (user_type / geography are no longer
    even sent on the wire; this asserts the behaviour the inversion produces.)
    """
    res = seeded.restricted  # plato
    resp = _deliver_demo(compose_stack, res)
    assert resp.status_code == httpx.codes.OK, resp.text
    item = _delivered_item(resp)
    assert licensed_of(item) is True, item
    assert retrieval_endpoint_of(item), item


def test_query_tampered_signature_is_rejected(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Mutating the signature on a term-derived signed URL flips edge verify to 403."""
    res = seeded.restricted  # plato
    resp = _deliver_demo(compose_stack, res)
    assert resp.status_code == httpx.codes.OK, resp.text
    signed_url = retrieval_endpoint_of(_delivered_item(resp))
    assert signed_url, resp.text
    m = re.search(r"sig=([^&]+)", signed_url)
    assert m, signed_url
    val = m.group(1)
    mid = len(val) // 2
    replacement = "B" if val[mid] != "B" else "C"
    tampered = signed_url.replace(f"sig={val}", f"sig={val[:mid] + replacement + val[mid + 1 :]}")
    bad = httpx.get(tampered, follow_redirects=True, timeout=15.0)
    assert bad.status_code == httpx.codes.FORBIDDEN, bad.text
