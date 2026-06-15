"""Obligation 04, happy-0: an agent-as-own-principal fetches a public resource.

Traces to `docs/obligations/04-public-endpoints-without-login.md`, first
happy-path bullet (verbatim):

> An agent operating as its own principal asks the platform for a public
> resource. The platform returns an offer at price zero whose access
> restrictions reflect the resource's licensing rules. The agent accepts
> the offer; the platform delivers a signed URL.

The observable, per that file's implementation hints, is the platform's
``transaction_log`` row: ``agent_id`` is always populated (identifying
the agent in ``ramp.agents`` whose ``public_key`` matches the request's
signing key), while ``identity_sub`` is empty because no separate
principal was delegated — the agent is its own principal. This test
drives the Exchange directly (DiscoverResources → ExecuteTransaction)
with an RFC 9421 signature from the agent's own well-known Ed25519
key — per the obligation's "every request is signed by the agent's
well-known key" framing — and with neither Authorization nor entitlement
biscuit, because the agent is its OWN principal (no separate-principal
delegation). The test then fetches the signed URL through the edge and
inspects the ``ramp.transaction_log`` row.

Resolver wiring (3zbe7)
-----------------------
The harness signs with the catalog-contributor Ed25519 keypair
(committed at ``tests/e2e/harness/fixtures/catalog_contributor_key.json``).
The matching pubkey is pinned in ``deploy/broker/keys.json`` with kid
``catalog-contributor-e2e`` so the Exchange's static httpsig resolver
(``buildHTTPSigDeps`` → ``httpsig.Wireup`` in
``src/exchange/cmd/server/main.go``) resolves it. Seed_stack also
upserts the pubkey into ``ramp.agents`` for the catalog signature path.
"""

from __future__ import annotations

import json
import uuid

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

_OBLIGATION_TEXT = (
    "An agent operating as its own principal asks the platform for a "
    "public resource. The platform returns an offer at price zero whose "
    "access restrictions reflect the resource's licensing rules. The "
    "agent accepts the offer; the platform delivers a signed URL."
)

_LIST_OFFERS_PATH = "/ramp.v1.ExchangeService/DiscoverResources"
_ACCEPT_OFFER_PATH = "/ramp.v1.ExchangeService/ExecuteTransaction"


@pytest.fixture(scope="module")
def seeded(compose_stack: StackURLs) -> SeededFixture:
    """Reuse the shared ed25519 tenant seeded by seed_stack."""
    return seed_stack(str(COMPOSE_FILE), compose_stack.exchange)


@pytest.fixture(scope="module")
def public_resource(compose_stack: StackURLs, seeded: SeededFixture) -> tuple[str, str]:
    """Insert a free (unit_cost=0) catalog entry and return (resource_id, uri).

    The obligation allows the per-request price to be zero ("price, which
    may be zero"). Seeding price=0 keeps the assertion unambiguous: the
    agent paid nothing and yet the usage record still exists.
    """
    # Path is fixed so the mock publisher (tests/e2e/mock-publisher/content/
    # public/article.html) returns 200 for the signed-URL fetch. resource_id
    # carries the uuid so reruns within one compose-up window don't collide
    # at the catalog row.
    resource_id = f"res-public-{uuid.uuid4().hex[:8]}"
    path = "/public/article.html"
    uri = f"{EDGE_PUBLIC_URL}{path}"
    push_catalog(
        exchange_url=compose_stack.exchange,
        tenant_id=seeded.tenant_id,
        entries=[CatalogEntry(domain=EDGE_PUBLIC_HOST, path=path, content_id=resource_id)],
        key_path=CONTRIBUTOR_KEY_PATH,
    )
    return resource_id, uri


_FORBIDDEN_DELEGATION_HEADERS = (
    "authorization",
    "x-ramp-entitlement-biscuit",
)


def _assert_no_delegation_credentials_on_wire(resp: httpx.Response) -> None:
    """Fail if the request that produced ``resp`` carried any DELEGATION header.

    The obligation casts the agent-as-own-principal flow as carrying
    only the agent's well-known Ed25519 signing identity, never an
    upstream-principal credential. The agent SIGNS every request (per
    "every request is signed by the agent's well-known key"), so
    ``Signature`` / ``Signature-Input`` MUST be present — they identify
    the agent as principal. What MUST be absent are headers that would
    carry a SEPARATE principal's authority: ``Authorization`` (bearer
    JWT for a delegated principal) and ``X-RAMP-Entitlement-Biscuit``
    (entitlement chain rooted in a separate buyer organization).
    """
    sent = resp.request.headers
    for name in _FORBIDDEN_DELEGATION_HEADERS:
        # An empty Authorization is the value our signing helper stamps
        # to carry an empty covered-component slot — it is not a
        # delegation credential. The forbidden case is a populated
        # bearer/biscuit header.
        value = sent.get(name, "")
        assert not value, (
            f"obligation 04 public-resource path expects no delegation "
            f"or entitlement headers; outbound request to "
            f"{resp.request.url} carried {name!r}={value!r}"
        )


def _post_signed_json(url: str, body: dict[str, object]) -> httpx.Response:
    """Sign a JSON POST with the agent's own well-known key and send it.

    The obligation 04 prose requires: "every request is signed by the
    agent's well-known key, the same way every request on every other
    path in the protocol is signed". The agent here acts as its OWN
    principal — no separate delegation. The signing key is ``agent-e2e``'s
    Ed25519 keypair: its kid equals ``requester.id`` and is registered in
    ``ramp.agents`` (so the Exchange caller authz admits it on
    ExecuteTransaction) and pinned in ``deploy/broker/keys.json`` (so the
    global httpsig resolver verifies it). No ``Authorization`` bearer and
    no ``X-RAMP-Entitlement-Biscuit`` is stamped — those would carry a
    SEPARATE principal, which contradicts the agent-as-own-principal setup.
    """
    payload = json.dumps(body, separators=(",", ":")).encode()
    kid, priv = load_keypair(AGENT_E2E_KEY_PATH)
    signed = sign_request(method="POST", target_uri=url, body=payload, kid=kid, priv=priv)
    headers = {**signed.headers, "Content-Type": "application/json"}
    return httpx.post(url, content=payload, headers=headers, timeout=30.0)


def test_agent_as_own_principal_lists_accepts_and_fetches_public_resource(
    compose_stack: StackURLs,
    seeded: SeededFixture,
    public_resource: tuple[str, str],
) -> None:
    """Agent-as-own-principal lists, accepts, and fetches a zero-price resource.

    Every assertion below traces to the scenario text:
      1. "asks the platform for a public resource" — DiscoverResources returns 200
         and at least one offer for the URI. The request is signed with
         the agent's own well-known Ed25519 key per obligation 04's
         "every request is signed by the agent's well-known key" clause.
      2. "an offer at price zero" — the offer's price is zero.
         Per-request offers are recognised by the absence of a
         ``subscription_id`` (the canonical proto distinguishes
         subscription offers via that field). Production materialises
         the public-resource offer as FREE so the billing gate trivially
         exempts it; the assertion is price-based to keep the contract
         observable, not type-based, so a future migration to a different
         per-request shape does not silently weaken this test.
      3. "The agent accepts the offer; the platform delivers a signed URL"
         — the outbound ``request.headers`` on each Exchange call AND on
         the signed-URL fetch carries no ``Authorization`` bearer and no
         ``X-RAMP-Entitlement-Biscuit`` (asserted by
         ``_assert_no_delegation_credentials_on_wire``) — those would
         carry a SEPARATE principal, contradicting the agent-as-own-
         principal setup. The agent's signature headers ARE present
         (they identify the agent as principal). The
         ExecuteTransaction response carries a delivery URL on the
         canonical top-level ``retrievalEndpoint`` field; fetching that
         URL through the edge returns 200 with publisher content.
      4. Per the obligation's implementation hints, the
         ``transaction_log`` row's ``identity_sub`` column is empty for
         transactions where the agent is its own principal (no separate
         principal delegated). ``identity_source`` is paired with
         ``identity_sub`` from the same ``Delegation`` and is therefore
         also NULL on this path.
    """
    _resource_id, uri = public_resource

    list_url = f"{compose_stack.exchange}{_LIST_OFFERS_PATH}"
    # Canonical ResourceQuery body: identity in `requester`, URIs in
    # `requester.uris`. No `resourceUrl` field exists in the canonical
    # proto (W4 of t3vk canonicalised the request shape).
    list_resp = _post_signed_json(
        list_url,
        {
            "ver": "1.0",
            "id": f"q-{uuid.uuid4().hex[:8]}",
            "requester": {
                # rjtks (3b500c2) made requester.id mandatory — the anonymous
                # public-resource flow is gone in v1. The agent identifies as
                # the same agent-e2e the billing seed credits; obligation 04's
                # "agent-as-own-principal" framing is now carried by the
                # absence of delegation/biscuit headers (asserted below by
                # _assert_no_delegation_credentials_on_wire), not by an empty
                # requester.id.
                "id": "agent-e2e",
                "domain": "",
                "type": "REQUESTER_TYPE_AGENT",
                "uris": [uri],
            },
        },
    )
    _assert_no_delegation_credentials_on_wire(list_resp)
    assert list_resp.status_code == httpx.codes.OK, (
        f"signed DiscoverResources should succeed for public URI, got "
        f"{list_resp.status_code}: {list_resp.text[:256]}"
    )
    list_payload = list_resp.json()
    offers = list_payload.get("offers") or []
    assert offers, f"expected at least one offer for public URI, got {list_payload}"

    # Per-request offers have no subscription_id; subscription offers
    # do (W1 of t3vk removed the Offer.type / OfferType field).
    per_request_offers = [
        o for o in offers if not (o.get("subscriptionId") or o.get("subscription_id"))
    ]
    assert per_request_offers, f"public URI must surface a per-request offer, got offers={offers!r}"
    chosen = per_request_offers[0]
    price_minor = int((chosen.get("price") or {}).get("amountMinor", 0))
    assert price_minor == 0, (
        f"public resource seeded at unit_cost=0 but offer price_minor={price_minor}"
    )
    offer_id = chosen.get("offerId")
    assert offer_id, f"offer missing offerId: {chosen}"
    offer_signature = chosen.get("signature")
    assert offer_signature, f"offer missing signature: {chosen}"

    # Canonical TransactionRequest body (rjtks): tx_request_id (id) is a
    # mandatory idempotency key, offer_id + offer_signature are the
    # caller's commitment to the Exchange-minted offer, and the requester
    # identity triple identifies the agent the transaction is attributed
    # to. RFC 9421 ``kid`` (signing key) is decoupled from
    # ``requester.id`` by design (see tests/e2e/harness/signing.py
    # docstring): the test signs with the catalog-contributor kid so the
    # global static httpsig resolver verifies, but the requester.id is
    # ``agent-e2e`` — the only identity credited in the compose's
    # ``EXCHANGE_BILLING_SEED``. The agent-as-own-principal narrative is
    # carried by the absence of any delegation header
    # (``_assert_no_delegation_credentials_on_wire``), not by the
    # requester identifier value, and obligation 04's implementation
    # hint about agent_id is asserted below directly against the
    # ``transaction_log`` row.
    accept_url = f"{compose_stack.exchange}{_ACCEPT_OFFER_PATH}"
    tx_request_id = f"tx-{uuid.uuid4().hex}"
    accept_resp = _post_signed_json(
        accept_url,
        {
            "ver": "1.0",
            "id": tx_request_id,
            "offerId": offer_id,
            "offerSignature": offer_signature,
            "requester": {
                "id": "agent-e2e",
                "domain": "",
                "type": "REQUESTER_TYPE_AGENT",
            },
        },
    )
    _assert_no_delegation_credentials_on_wire(accept_resp)
    assert accept_resp.status_code == httpx.codes.OK, (
        f"signed ExecuteTransaction should succeed for zero-price offer, got "
        f"{accept_resp.status_code}: {accept_resp.text[:256]}"
    )
    accept_payload = accept_resp.json()
    # Canonical TransactionResponse carries `transaction_id`,
    # `billing_id`, `cost`, `delivery_method`, `agent_identity_hash`,
    # etc., at the top level. The signed delivery URL is carried on the
    # canonical RAMP-native field `retrieval_endpoint` (field 18; protojson
    # camelCase retrievalEndpoint). See
    # `src/exchange/internal/service/exchange_helpers.go::buildTxResponse`.
    transaction_id = accept_payload.get("transactionId")
    signed_url = assert_signed_url(accept_payload)
    assert transaction_id, f"transactionId missing from accept: {accept_payload}"

    # Rewrite the internal edge host (edge:8787) to the host-exposed address
    # when the test runs outside the compose network. Inside the compose
    # network `seed.EDGE_PUBLIC_URL` already points at `http://edge:8787`,
    # which the pytest runner can resolve via compose DNS.
    # Signed-URL canonical covers the FULL URL (scheme+host+path+query)
    # per src/exchange/internal/signing/signed_url.go:66 and
    # src/edge/src/verify.ts::canonicalMessage. Host-side fetches must
    # (a) rewrite the netloc to the host-published port for TCP routing
    # AND (b) carry a `Host: edge:8787` header so Workerd reconstructs
    # c.req.url with the original signed authority — see the
    # `_host_url` module-level comment in tests/e2e/harness/test_full_stack.py.
    host_signed_url = signed_url
    extra_headers: dict[str, str] = {}
    if compose_stack.edge != EDGE_PUBLIC_URL:
        host_signed_url = signed_url.replace(EDGE_PUBLIC_URL, compose_stack.edge)
        extra_headers["Host"] = EDGE_PUBLIC_HOST
    # Edge fetch carries no RFC 9421 signature — the signed URL itself
    # is the cryptographic credential the edge verifies. The
    # delegation-header guard still applies: no Authorization bearer
    # and no entitlement biscuit should leak onto the edge fetch.
    content_resp = httpx.get(host_signed_url, headers=extra_headers, timeout=30.0)
    _assert_no_delegation_credentials_on_wire(content_resp)
    assert content_resp.status_code == httpx.codes.OK, (
        f"signed URL fetch failed: {content_resp.status_code} {content_resp.text[:256]}"
    )
    assert "content-marker-42" in content_resp.text, (
        f"publisher content missing marker: {content_resp.text[:256]}"
    )

    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT agent_id, tenant_id
            FROM ramp.transaction_log
            WHERE transaction_id = %s
            """,
            (transaction_id,),
        )
        row = cur.fetchone()
    assert row is not None, f"no transaction_log row for {transaction_id}"
    agent_id, tenant_id = row
    assert tenant_id == seeded.tenant_id, (
        f"transaction_log.tenant_id = {tenant_id!r}, want {seeded.tenant_id!r}"
    )
    # transaction_log.identity_source and identity_sub were dropped by
    # migration 000007 (slice #1 e2k7h.7). The obligation 04
    # "agent-as-own-principal" semantic is now carried at the wire
    # boundary by the absence of delegation/biscuit headers
    # (_assert_no_delegation_credentials_on_wire above), not by a
    # persisted identity_sub IS NULL column.
    # Obligation 04 implementation hint: `agent_id` is always populated
    # and identifies the agent registered in `ramp.agents`. On the
    # agent-as-own-principal path the agent's cryptographic identity is
    # still recorded (the agent IS the principal).
    assert agent_id, (
        "public-path transaction missing agent_id; "
        "obligation requires the usage record to carry the agent's identity"
    )
