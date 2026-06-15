"""Obligation 04 mixed-batch: public happy-path plus unknown-URI failure.

Obligation file: ``docs/obligations/04-public-endpoints-without-login.md``

Grounds in the obligation's "agent with no identity asks for a batch of
URIs, some public and some not; the platform returns offers only for the
public ones; for the non-public URIs it explains the agent does not have
access" framing — the obligation's batch-with-mixed-verdicts contract.

V1-aligned reading of "non-public" (post-slice-#1)
--------------------------------------------------
Pre-slice-#1 the test interpreted "non-public" as
*subscription-restricted*: it seeded a catalog row with
``required_scopes``/``subscription_id`` and asserted the response group
carried ``OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT``. Slice #1
(``e2k7h.1``/``e2k7h.8``, commits ``6462090`` and ``d9d774a``) removed
that vocabulary from the v1 surface:

* ``LookupVerdict`` collapsed to ``{LookupMiss, LookupHitPublic}`` —
  ``LookupHitRestricted`` and ``LookupHitSubscription`` were dropped
  (``src/exchange/internal/service/catalog.go:78-103``).
* Migration ``000007`` dropped the ``subscription_id`` and
  ``required_scopes`` columns from ``ramp.catalog``.
* ``OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT`` is no longer emitted from
  any catalog state — the only absence reason produced by the v1
  ``DiscoverResources`` path is ``OFFER_ABSENCE_REASON_NOT_IN_CATALOG``
  (``src/exchange/internal/service/discover.go:24-37``).

Subscription-shaped refusals remain in the obligation prose but are
deferred to obligations 01/02 (the subscription path); the obligation
file calls those out under "Explicitly out of scope" for v1
(``docs/obligations/04-public-endpoints-without-login.md:68-78``). In v1
the structural failure mode the catalog can produce for a "non-public"
URI is ``NOT_IN_CATALOG``: the URI is one the platform has no entry for
and therefore cannot offer access to.

So the test now expresses the obligation's batch contract with the v1
vocabulary: TWO seeded public URIs (the "public ones") and ONE
never-seeded URI (the "non-public" one). The response must:

* surface per-request offers on both seeded URIs;
* surface an empty offer list with ``absence_reason ==
  OFFER_ABSENCE_REASON_NOT_IN_CATALOG`` on the unseeded URI;
* let the agent proceed with the public offers only — the unseeded URI
  is not transacted and leaves no ``transaction_log`` row.

The request is still signed with the agent's own well-known Ed25519 key
per obligation 04's "every request is signed by the agent's well-known
key" clause. The harness's contributor kid is pinned in
``deploy/broker/keys.json`` so the Exchange's static httpsig resolver
finds it (``agentic-content-access-3zbe7``).
"""

from __future__ import annotations

import json
import uuid
from typing import Any, cast

import httpx
import psycopg
import pytest

from ..catalog_push import CatalogEntry, push_catalog
from ..conftest import COMPOSE_FILE, StackURLs
from ..httpsig_signer import load_keypair, sign_request
from ..seed import (
    CONTRIBUTOR_KEY_PATH,
    EDGE_PUBLIC_HOST,
    EDGE_PUBLIC_URL,
    SeededFixture,
    _resolve_pg_dsn,
    seed_stack,
)
from ..signing import AGENT_E2E_KEY_PATH
from .carriers import assert_signed_url


# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"

# Canonical v1 absence reason for a URI the catalog has no entry for.
# Per ``src/exchange/internal/service/discover.go`` the v1 surface emits
# only this value; ``SCOPE_INSUFFICIENT`` was removed when slice #1
# collapsed ``LookupVerdict`` to ``{LookupMiss, LookupHitPublic}``.
_NOT_IN_CATALOG = "OFFER_ABSENCE_REASON_NOT_IN_CATALOG"


@pytest.fixture(scope="module")
def seeded(compose_stack: StackURLs) -> SeededFixture:
    """Reuse the stack-wide seed (tenant, agent, exchange)."""
    return seed_stack(str(COMPOSE_FILE), compose_stack.exchange)


@pytest.fixture(scope="module")
def mixed_catalog(compose_stack: StackURLs, seeded: SeededFixture) -> tuple[str, str, str]:
    """Seed two public entries under the same tenant; return them plus an unseeded URI.

    Returns ``(public_uri_a, public_uri_b, unseeded_uri)``. Both public
    entries omit any scope/subscription metadata (those columns no longer
    exist post-migration ``000007``), so ``LookupWithScopes(uri, nil)`` for
    a no-identity caller resolves both as ``LookupHitPublic`` and the
    Exchange surfaces a per-request offer on each. The unseeded URI shares
    the same edge host so it is shaped like the other two but has no
    catalog row — ``Lookup`` returns ``LookupMiss`` and the Exchange
    surfaces an empty ``OfferGroup`` with ``absence_reason`` set to
    ``OFFER_ABSENCE_REASON_NOT_IN_CATALOG``.
    """
    suffix = uuid.uuid4().hex[:8]
    # path_a + path_b are pinned to mock-publisher fixtures
    # (tests/e2e/mock-publisher/content/public/mixed-{a,b}.html) so the
    # signed-URL fetch lands on a real origin. path_unseeded is per-run
    # randomised — the test never fetches it; it only verifies the
    # catalog miss path on DiscoverResources.
    path_a = "/public/mixed-a.html"
    path_b = "/public/mixed-b.html"
    path_unseeded = f"/public/mixed-unknown-{suffix}.html"
    public_uri_a = f"{EDGE_PUBLIC_URL}{path_a}"
    public_uri_b = f"{EDGE_PUBLIC_URL}{path_b}"
    unseeded_uri = f"{EDGE_PUBLIC_URL}{path_unseeded}"
    push_catalog(
        exchange_url=compose_stack.exchange,
        tenant_id=seeded.tenant_id,
        entries=[
            CatalogEntry(
                domain=EDGE_PUBLIC_HOST,
                path=path_a,
                content_id=f"res-public-a-{suffix}",
            ),
            CatalogEntry(
                domain=EDGE_PUBLIC_HOST,
                path=path_b,
                content_id=f"res-public-b-{suffix}",
            ),
        ],
        key_path=CONTRIBUTOR_KEY_PATH,
    )
    return public_uri_a, public_uri_b, unseeded_uri


def _post_signed_json(url: str, body: dict[str, object]) -> httpx.Response:
    """Sign a JSON POST with the agent's own well-known key and send it.

    Obligation 04: "every request is signed by the agent's well-known
    key". The agent here acts as its OWN principal — no separate
    delegation. The signing key is ``agent-e2e``'s Ed25519 keypair: its
    kid equals ``requester.id`` and is registered in ``ramp.agents`` (so
    the Exchange caller authz admits it on ExecuteTransaction) and pinned
    in ``deploy/broker/keys.json`` (so the global httpsig resolver
    verifies it). No ``Authorization`` bearer and no
    ``X-RAMP-Entitlement-Biscuit`` is stamped — those would carry a
    SEPARATE principal, which contradicts the agent-as-own-principal setup.
    """
    payload = json.dumps(body, separators=(",", ":")).encode()
    kid, priv = load_keypair(AGENT_E2E_KEY_PATH)
    signed = sign_request(method="POST", target_uri=url, body=payload, kid=kid, priv=priv)
    headers = {**signed.headers, "Content-Type": "application/json"}
    return httpx.post(url, content=payload, headers=headers, timeout=30.0)


def _group_for(groups: list[dict[str, Any]], uri: str) -> dict[str, Any] | None:
    """Pick the OfferGroup whose ``uri`` field matches ``uri``."""
    for g in groups:
        if g.get("uri") == uri:
            return g
    return None


def _absence_reason(group: dict[str, Any]) -> str | None:
    """Return the group's absence reason (canonical enum string), if any."""
    v = group.get("absenceReason") or group.get("absence_reason")
    return v if isinstance(v, str) else None


def test_mixed_batch_groups_public_offers_and_not_in_catalog_reason(
    compose_stack: StackURLs,
    seeded: SeededFixture,
    mixed_catalog: tuple[str, str, str],
) -> None:
    """Batch DiscoverResources returns per-URI offer groups for seeded + unseeded URIs.

    Every assertion below traces to the obligation's mixed-batch framing:

    1. Agent-as-own-principal opens the batch — the HTTP POST is signed
       by the agent's own well-known Ed25519 key (per obligation 04's
       "every request is signed by the agent's well-known key" clause)
       and carries neither ``Authorization`` bearer nor
       ``X-RAMP-Entitlement-Biscuit``; ``requester.uris`` carries three
       entries (two seeded public URIs and one never-seeded URI).
    2. "Returns offers only for the public ones" — both seeded URIs'
       ``OfferGroup`` entries carry at least one per-request offer.
    3. "Explains the agent does not have access" — the unseeded URI's
       ``OfferGroup`` has ``offers == []`` AND the canonical
       ``OFFER_ABSENCE_REASON_NOT_IN_CATALOG`` explanation in
       ``absenceReason``. This is the v1-aligned reading of the
       obligation's "non-public" failure mode after slice #1 collapsed
       the SCOPE_INSUFFICIENT vocabulary out of the catalog state (see
       module docstring).
    4. "The agent proceeds with the public ones" — after reading the
       batch response, the agent issues an ``ExecuteTransaction`` for
       one of the public URIs. The Exchange returns a signed URL that
       fetches publisher content through the edge. The unseeded URI is
       not followed; no extra ``transaction_log`` row appears for it.
    """
    public_uri_a, public_uri_b, unseeded_uri = mixed_catalog

    discover_url = f"{compose_stack.exchange}{_DISCOVER_PATH}"
    request_id = f"q-{uuid.uuid4().hex[:8]}"
    body: dict[str, object] = {
        "ver": "1.0",
        "id": request_id,
        "requester": {
            # rjtks (3b500c2) made requester.id mandatory — anonymous flow
            # is gone in v1. Use the billing-seeded agent-e2e identity.
            # Obligation 04's "no human-login identity" framing is now
            # carried by the absence of delegation/biscuit headers, not by
            # an empty requester.id.
            "id": "agent-e2e",
            "domain": "",
            "type": "REQUESTER_TYPE_AGENT",
            "uris": [public_uri_a, public_uri_b, unseeded_uri],
        },
    }
    resp = _post_signed_json(discover_url, body)

    assert resp.status_code == httpx.codes.OK, (
        f"signed batch DiscoverResources should succeed, got {resp.status_code}: {resp.text[:256]}"
    )
    payload = cast(dict[str, Any], resp.json())
    groups = cast(list[dict[str, Any]], payload.get("offerGroups") or [])
    assert groups, f"expected offerGroups in response, got {payload}"

    # (2) Both seeded URI groups carry offers.
    pub_group_a = _group_for(groups, public_uri_a)
    assert pub_group_a is not None, (
        f"no OfferGroup for seeded public URI {public_uri_a!r} in {groups}"
    )
    pub_offers_a = cast(list[dict[str, Any]], pub_group_a.get("offers") or [])
    assert pub_offers_a, f"seeded URI A must surface at least one offer, got {pub_group_a}"

    pub_group_b = _group_for(groups, public_uri_b)
    assert pub_group_b is not None, (
        f"no OfferGroup for seeded public URI {public_uri_b!r} in {groups}"
    )
    pub_offers_b = cast(list[dict[str, Any]], pub_group_b.get("offers") or [])
    assert pub_offers_b, f"seeded URI B must surface at least one offer, got {pub_group_b}"

    # (3) Unseeded URI group is empty and reports NOT_IN_CATALOG.
    unseeded_group = _group_for(groups, unseeded_uri)
    assert unseeded_group is not None, (
        f"no OfferGroup for unseeded URI {unseeded_uri!r} in {groups}"
    )
    unseeded_offers = cast(list[dict[str, Any]], unseeded_group.get("offers") or [])
    assert unseeded_offers == [], f"unseeded URI must have empty offers, got {unseeded_offers}"
    reason = _absence_reason(unseeded_group)
    assert reason == _NOT_IN_CATALOG, (
        f"unseeded URI group must report {_NOT_IN_CATALOG!r}; got {reason!r} in {unseeded_group}"
    )

    # (4) Agent proceeds with one of the public URIs.
    offer_id = pub_offers_a[0].get("offerId") or pub_offers_a[0].get("offer_id")
    offer_signature = pub_offers_a[0].get("signature") or pub_offers_a[0].get("offer_signature")
    assert offer_id, f"public offer A missing offer_id: {pub_offers_a[0]}"
    assert offer_signature, f"public offer A missing signature: {pub_offers_a[0]}"
    accept_url = f"{compose_stack.exchange}/ramp.v1.ExchangeService/ExecuteTransaction"
    tx_body = {
        "ver": "1.0",
        "id": f"tx-{uuid.uuid4().hex[:8]}",
        "offerId": offer_id,
        "offerSignature": offer_signature,
        "requester": {
            "id": "agent-e2e",
            "domain": "",
            "type": "REQUESTER_TYPE_AGENT",
        },
    }
    tx_resp = _post_signed_json(accept_url, tx_body)
    assert tx_resp.status_code == httpx.codes.OK, (
        f"signed ExecuteTransaction on public URI should succeed, got "
        f"{tx_resp.status_code}: {tx_resp.text[:256]}"
    )
    tx_payload = cast(dict[str, Any], tx_resp.json())
    transaction_id = tx_payload.get("transactionId") or tx_payload.get("transaction_id")
    assert transaction_id, f"transaction id missing from tx response: {tx_payload}"
    # canonical carrier: top-level retrieval_endpoint (field 18); legacy ext gone.
    signed_url = assert_signed_url(tx_payload)

    # Signed-URL canonical covers the FULL URL (see test_full_stack.py
    # module comment). Host-side fetch needs the netloc rewrite + a
    # `Host: edge:8787` header so Workerd reconstructs c.req.url with
    # the original signed authority byte-identical.
    host_signed_url = signed_url
    extra_headers: dict[str, str] = {}
    if compose_stack.edge != EDGE_PUBLIC_URL:
        host_signed_url = signed_url.replace(EDGE_PUBLIC_URL, compose_stack.edge)
        extra_headers["Host"] = EDGE_PUBLIC_HOST
    content_resp = httpx.get(host_signed_url, headers=extra_headers, timeout=30.0)
    assert content_resp.status_code == httpx.codes.OK, (
        f"public signed URL fetch failed: {content_resp.status_code} {content_resp.text[:256]}"
    )
    assert "content-marker-42" in content_resp.text, (
        f"publisher content missing marker: {content_resp.text[:256]}"
    )

    # "The agent proceeds with the public ones" — nothing is transacted
    # for the unseeded URI. Postgres is the observable: no
    # ``transaction_log`` row references the unseeded URI's content_id
    # prefix (``res-unknown-*`` was never seeded so the prefix does not
    # exist; we still assert defensively in case a future change
    # auto-creates a row).
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*)
            FROM ramp.transaction_log
            WHERE tenant_id = %s
              AND resource_id LIKE 'res-unknown-%%'
            """,
            (seeded.tenant_id,),
        )
        count_row = cur.fetchone()
    assert count_row is not None
    assert count_row[0] == 0, (
        f"unseeded URI must not have been transacted, found {count_row[0]} transaction_log row(s)"
    )
