"""E2E: three REAL exchanges with SEPARATE catalog DBs + distinct identities (S1).

Core invariant under test
--------------------------------------------------------
The 3-exchange e2e topology gives each publisher its OWN exchange instance, with
its OWN catalog database and its OWN Ed25519 offer-signing identity:

* exchange-a (DB ``ramp``)   serves the PHILOSOPHY catalog; its offers carry
  ``offer.exchange == "exchange:8081"``.
* exchange-b (DB ``ramp_b``) serves the MUSIC catalog;      ``"exchange-b:8081"``.
* exchange-c (DB ``ramp_c``) serves the SFX catalog;        ``"exchange-c:8081"``.

Two properties prove the topology:

1. **Per-exchange catalog ISOLATION + identity.** A music URI discovered DIRECTLY
   against exchange-b returns an offer stamped with exchange-b's domain; a sfx URI
   on exchange-c returns exchange-c's domain; a philosophy URI on exchange-a
   returns exchange-a's domain. Because each exchange's DiscoverResources serves
   its OWN catalog DB (a global, un-tenant-filtered ListAll — catalog.go:373), the
   cross-catalog absence is the isolation signal: a music URI is ABSENT from
   exchange-a's catalog (no offers), and a philosophy URI is ABSENT from
   exchange-b's catalog. Separate DBs are what make that absence real — a shared DB
   would leak every catalog onto every exchange.

2. **Distinct signing identity.** The three exchanges' ``/.well-known/ramp.json``
   serve DISTINCT Ed25519 public keys (each minted from its own keypair by the
   rsa-keygen one-shot), so an offer signed by one exchange cannot be verified
   against another's manifest.

This file owns the DIRECT per-exchange isolation leg, the broker fan-out
legs, and the batch lifecycle capstone that replaced the retired
MCP-shim-driven sibling: the Python shim is gone (the MCP surface is the Go
adapter), so those legs are driven through the Broker/Exchange directly. The
shared per-exchange constants and black-box ledger readers live in
``_multi_exchange_common``.

Round-trip honesty: each discover leg is a full protocol round-trip on that
exchange's ``ExchangeService/DiscoverResources`` RPC (signed httpsig →
resolveCaller against THAT exchange's own ``ramp.agents`` DB → catalog trie
lookup). The well-known leg is a plain GET of the public manifest each exchange
serves. No DB short-circuit, no internal-state read.

RED on the single-exchange stack: ``compose_stack`` exposes no ``exchange_b`` /
``exchange_c`` URLs (and the stack has no exchange-b/c services), so the test
cannot even resolve its fixtures — the multi-exchange topology must be built for
it to collect and pass.
"""

from __future__ import annotations

import uuid
from typing import Any, cast

import httpx
import pytest

from . import broker_client
from ._multi_exchange_common import (
    _MUSIC_URI,
    _PHILOSOPHY_URI,
    _EXCHANGE_DOMAIN_TO_DB,
    _SFX_URI,
    _transaction_log_agent,
    _usage_record,
)
from .conftest import StackURLs
from .exchanges import (
    EXCHANGE_A_DOMAIN,
    EXCHANGE_B_DOMAIN,
    EXCHANGE_C_DOMAIN,
    exchange_url,
    recipient_of,
)
from .connect_errors import assert_refused
from .discovery import discover_body
from .reporting import REPORT_USAGE_PATH, report_body
from .constants import WBA_DIRECTORY_PATH
from .obligations.flow import discover_first_offer
from .edge_fetch import fetch_signed
from .relay import relay_execute_batch
from .resolve_carriers import (
    absence_reasons_by_uri,
    offer_exchanges_by_uri,
    retrieval_endpoint_of,
)
from .seed import (
    DEMO_MUSIC_DOMAIN,
    DEMO_PHILOSOPHY_DOMAIN,
    DEMO_SFX_DOMAIN,
    USD_AGENT_ID,
    SeededFixture,
)
from .signing import USD_AGENT_KEY_PATH, sign_post

pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"

# A string from the REAL body of each URI's content (deploy/content/demo/...), so
# the delivery leg can assert the licensed bytes actually arrived. Status 200 alone
# does not distinguish real delivery from an edge error-stub or a wrong-route body,
# both of which answer 200 — see edge_fetch.fetch_signed.
_URI_TO_MARKER = {
    _PHILOSOPHY_URI: "Socrates",
    _MUSIC_URI: "Paper Satellites",
    _SFX_URI: "Rain on Tin Roof",
}


def _offer_exchange(offer: dict[str, object]) -> str | None:
    """Read the canonical ``Offer.exchange`` (proto3-JSON camelCase ``exchange``)."""
    value = offer.get("exchange")
    return value if isinstance(value, str) and value else None


def _discover_uris(url: str, uri: str) -> set[str]:
    """Return the URIs the exchange at ``url`` carries an OFFER for, for one ``uri``.

    A full DiscoverResources protocol round-trip on that exchange's RPC. An empty
    ``offers`` list (the URI is not in THAT exchange's catalog DB) yields the empty
    set — the absence-of-side-effect signal the isolation legs assert on.

    The query names the exchange it is going to. Getting that wrong is refused
    outright rather than answered with an empty catalog, so the isolation legs
    below would read a refusal as "not in this exchange's catalog" if the
    addressing were sloppy.
    """
    resp = sign_post(
        f"{url}{_DISCOVER_PATH}",
        body=discover_body(agent_id=USD_AGENT_ID, uris=[uri], exchange=recipient_of(url)),
        key_path=USD_AGENT_KEY_PATH,
    )
    assert resp.status_code == httpx.codes.OK, resp.text
    offers = cast(list[dict[str, Any]], resp.json().get("offers") or [])
    return {uri} if offers else set()


def _wellknown_offer_key(exchange_url: str) -> str:
    """Return the distinguishing Ed25519 public-key material from an exchange's WBA directory.

    After the WBA split identity keys live in the pure WBA directory
    (``/.well-known/http-message-signatures-directory``) as inline JWKs whose ``x``
    is the base64url raw Ed25519 public key — the keyless ramp.json overlay carries
    none. The ``x`` byte string is the identity fingerprint compared across exchanges.
    """
    doc = httpx.get(f"{exchange_url}{WBA_DIRECTORY_PATH}", timeout=5.0).json()
    keys = doc.get("keys") or []
    assert keys, f"exchange WBA directory serves no keys: {doc!r}"
    x = keys[0].get("x")
    assert isinstance(x, str) and x, f"exchange WBA key has no x: {keys[0]!r}"
    return x


def test_three_exchanges_isolated_catalogs(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests each catalog into its DB
) -> None:
    """Each publisher resolves on its OWN exchange (distinct identity) and nowhere else.

    (a) music URI → exchange-b's domain; (b) sfx URI → exchange-c's domain;
    (c) philosophy URI → exchange-a's domain; (d) the 3 well-known manifests serve
    DISTINCT offer keys; PLUS cross-catalog absence (separate DBs).
    """
    # (a) music URI resolves on exchange-b, stamped with exchange-b's identity.
    music_offer = discover_first_offer(
        compose_stack.exchange_b,
        uri=_MUSIC_URI,
        agent_id=USD_AGENT_ID,
        domain=DEMO_MUSIC_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )
    assert _offer_exchange(music_offer) == EXCHANGE_B_DOMAIN, music_offer

    # (b) sfx URI resolves on exchange-c, stamped with exchange-c's identity.
    sfx_offer = discover_first_offer(
        compose_stack.exchange_c,
        uri=_SFX_URI,
        agent_id=USD_AGENT_ID,
        domain=DEMO_SFX_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )
    assert _offer_exchange(sfx_offer) == EXCHANGE_C_DOMAIN, sfx_offer

    # (c) philosophy URI resolves on exchange-a, stamped with exchange-a's identity.
    philo_offer = discover_first_offer(
        compose_stack.exchange,
        uri=_PHILOSOPHY_URI,
        agent_id=USD_AGENT_ID,
        domain=DEMO_PHILOSOPHY_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )
    assert _offer_exchange(philo_offer) == EXCHANGE_A_DOMAIN, philo_offer

    # Catalog ISOLATION (separate DBs): a music URI is ABSENT from exchange-a's
    # catalog, and a philosophy URI is ABSENT from exchange-b's catalog. A shared
    # DB would leak both catalogs onto both exchanges (global ListAll).
    assert _discover_uris(compose_stack.exchange, _MUSIC_URI) == set(), (
        "music URI leaked into exchange-a's catalog — DBs are not isolated"
    )
    assert _discover_uris(compose_stack.exchange_b, _PHILOSOPHY_URI) == set(), (
        "philosophy URI leaked into exchange-b's catalog — DBs are not isolated"
    )

    # (d) the three exchanges serve DISTINCT offer-signing keys.
    key_a = _wellknown_offer_key(compose_stack.exchange)
    key_b = _wellknown_offer_key(compose_stack.exchange_b)
    key_c = _wellknown_offer_key(compose_stack.exchange_c)
    assert len({key_a, key_b, key_c}) == 3, (
        f"exchanges must serve distinct offer keys; got a={key_a!r} b={key_b!r} c={key_c!r}"
    )


def test_broker_fans_out_batch_across_exchanges(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests each catalog into its DB
) -> None:
    """ONE broker Resolve over a 3-publisher batch returns a per-URI offer_group routed
    to the correct exchange, plus a typed-absence group for an uncatalogued URI.

    PROTOCOL round-trip (distinct from S1's DIRECT per-exchange legs): the agent
    signs ONE ``BrokerService/Resolve`` over ``uris=[philosophy, music, sfx, miss]``;
    the Broker probes each URI's publisher ``/.well-known/ramp.json``, unions the
    named exchanges ({a, b, c}), queries each with the full batch, and MERGES the
    per-URI ``OfferGroup``s the exchanges return — keyed on ``OfferGroup.uri``.

    Positive legs (Doctrine #9 full-surface): each publisher's URI comes back in
    its OWN group whose offer carries that exchange's ``offer.exchange``
    (``exchange:8081`` / ``exchange-b:8081`` / ``exchange-c:8081``) — proving the
    fan-out routed each URI to the manifest-authorized exchange and nowhere else.

    Negative leg (Doctrine #10): a philosophy-domain URI absent from every
    authorized exchange's catalog comes back as a present-but-empty group carrying
    a typed ``absenceReason`` (NOT_IN_CATALOG) — the per-URI absence the merge must
    surface, NOT a dropped/silent miss.
    """
    miss_uri = (
        f"http://{DEMO_PHILOSOPHY_DOMAIN}/articles/philosophers/nonexistent-{uuid.uuid4().hex}.txt"
    )
    resp = broker_client.resolve(
        compose_stack,
        body={
            "agent_id": USD_AGENT_ID,
            "uris": [_PHILOSOPHY_URI, _MUSIC_URI, _SFX_URI, miss_uri],
        },
        key_path=USD_AGENT_KEY_PATH,
    )
    assert resp.status_code == httpx.codes.OK, resp.text
    payload = cast(dict[str, Any], resp.json())

    by_uri = offer_exchanges_by_uri(payload)
    # Each requested URI gets its OWN offer_group keyed on the requested uri.
    assert by_uri.get(_PHILOSOPHY_URI) == {EXCHANGE_A_DOMAIN}, payload
    assert by_uri.get(_MUSIC_URI) == {EXCHANGE_B_DOMAIN}, payload
    assert by_uri.get(_SFX_URI) == {EXCHANGE_C_DOMAIN}, payload

    # Negative leg: the uncatalogued philosophy URI is PRESENT as a typed-absence
    # group (empty offers + NOT_IN_CATALOG), not silently dropped.
    assert by_uri.get(miss_uri) == set(), payload
    assert absence_reasons_by_uri(payload).get(miss_uri) == (
        "OFFER_ABSENCE_REASON_NOT_IN_CATALOG"
    ), payload


# A single SHARED requester profile drives the batch (requester is request-scoped
# in a batch TransactionRequest). individual/US satisfies all three discovered
# offers' projection; each is FREE or affordable for the USD buyer (the FREE-EUR
# philosophy offer authorizes under the zero-charge billing short-circuit), so the
# whole 3-exchange batch executes and every item comes back with its own signed
# retrieval endpoint. (The NON-ATOMIC partial-failure path — one exchange denying
# while others succeed — is pinned at the broker integration layer by
# TestExchangeRelay_BatchPartialFailure.)
_BATCH_REQUESTER_DOMAIN = DEMO_MUSIC_DOMAIN


def test_broker_batch_execute_fans_out_across_three_exchanges(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests each catalog into its DB
) -> None:
    """ONE broker batch ExecuteTransaction over offers spanning all 3 exchanges returns
    a per-item retrieval endpoint for every item, in original order (S4 fan-out + merge).

    PROTOCOL round-trip: the agent discovers one offer on EACH exchange
    (music on exchange-b, sfx on exchange-c, philosophy on exchange-a), reflects
    all three onto ONE ``TransactionRequest.items[]`` with per-item acceptances over
    the SHARED requester + idempotency_key, sig1-signs the whole batch body over the
    Broker relay route, and POSTs ONCE to ``/broker/v1/exchange/execute``. The broker
    groups the items by each item's signed ``offer.exchange``, fans out one
    broker-signed sub-request per DISTINCT exchange, and MERGES the per-exchange
    ``items[]`` back in ORIGINAL order.

    Doctrine #9 (full-surface): each of the three items comes back with its OWN
    signed ``retrievalEndpoint`` — proving every item was routed to and executed on
    its correct exchange and the per-exchange results were merged in original order.
    The derived per-item key (idempotency_key+":"+offer_id) keeps the three items
    from collapsing onto one transaction under the shared request idempotency_key. A
    sizing sanity assert pins the inbound 3-exchange batch body comfortably under the
    broker's 64 KiB pre-auth bound.
    """
    # Discover one offer per exchange under the SHARED requester domain.
    music_offer = discover_first_offer(
        compose_stack.exchange_b,
        uri=_MUSIC_URI,
        agent_id=USD_AGENT_ID,
        domain=_BATCH_REQUESTER_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )
    sfx_offer = discover_first_offer(
        compose_stack.exchange_c,
        uri=_SFX_URI,
        agent_id=USD_AGENT_ID,
        domain=_BATCH_REQUESTER_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )
    philo_offer = discover_first_offer(
        compose_stack.exchange,
        uri=_PHILOSOPHY_URI,
        agent_id=USD_AGENT_ID,
        domain=_BATCH_REQUESTER_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )

    # ONE batch relay over all three (original order: music, sfx, philosophy).
    resp, payload = relay_execute_batch(
        compose_stack.broker,
        [music_offer, sfx_offer, philo_offer],
        agent_id=USD_AGENT_ID,
        domain=_BATCH_REQUESTER_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )
    assert resp.status_code == httpx.codes.OK, (
        f"batch relay should succeed at the request level (non-atomic); "
        f"got {resp.status_code}: {resp.text[:512]}"
    )
    # Sizing sanity: a realistic 3-exchange batch body stays well under 64 KiB.
    assert len(payload) < 64 * 1024, (
        f"batch body {len(payload)} B exceeds the 64 KiB pre-auth bound"
    )

    body = cast(dict[str, Any], resp.json())
    items = cast(list[dict[str, Any]], body.get("items") or [])
    assert len(items) == 3, f"merged batch must return 3 items in original order, got {body}"

    by_offer = {it.get("offer_id"): it for it in items}
    music_id = music_offer.get("offer_id")
    sfx_id = sfx_offer.get("offer_id")
    philo_id = philo_offer.get("offer_id")

    # Every item (one per exchange) carries its OWN signed retrieval endpoint.
    for label, offer_id in (("music", music_id), ("sfx", sfx_id), ("philosophy", philo_id)):
        item = by_offer.get(offer_id)
        assert item is not None, f"no result item for {label} offer {offer_id!r} in {body}"
        endpoint = item.get("retrieval_endpoint")
        assert endpoint, f"{label} item missing retrieval_endpoint: {item}"
        assert not (item.get("denial_reason")), f"{label} item unexpectedly denied: {item}"

    # The three items resolved to three DISTINCT transactions (the derived per-item
    # key did not collapse them onto one under the shared request idempotency_key).
    tx_ids = {it.get("transaction_id") for it in items}
    assert len(tx_ids) == 3, f"expected 3 distinct transaction_ids, got {tx_ids}"

    # Original item order is preserved across the fan-out + merge.
    assert [it.get("offer_id") for it in items] == [music_id, sfx_id, philo_id], (
        f"merged items[] must preserve original order, got {[it.get('offer_id') for it in items]}"
    )


def _report_usage(compose_stack: StackURLs, issuer_domain: str, item: dict[str, Any]) -> str:
    """Sign a ReportUsage for item to its issuing exchange; return the report_id.

    Reports go DIRECTLY to the issuing exchange, never the broker. ``issuer_domain``
    is the offer's own ``exchange`` value: it both selects the URL to post to —
    the harness's in-network stand-in for the well-known endpoint resolution the
    MCP adapter does in production — and travels in the body as the recipient.
    consumed quantity is 0: the demo terms carry no reporting estimate, and the
    validator strict-rejects a positive quantity against a zero-estimate
    obligation.
    """
    # The report is addressed to the exchange that ISSUED the offer, which is the
    # same exchange the URL below resolves to. Naming a different one is refused
    # before any obligation is looked up.
    body = report_body(
        exchange=issuer_domain,
        transaction_id=str(item.get("transaction_id") or ""),
        agent_id=USD_AGENT_ID,
        domain=_BATCH_REQUESTER_DOMAIN,
        billing_id=str(item.get("billing_id") or ""),
    )
    resp = sign_post(
        f"{exchange_url(compose_stack, issuer_domain)}{REPORT_USAGE_PATH}",
        body=body,
        key_path=USD_AGENT_KEY_PATH,
    )
    assert resp.status_code == httpx.codes.OK, (
        f"ReportUsage to {issuer_domain} refused: {resp.status_code} {resp.text[:512]}"
    )
    report_id = resp.json().get("report_id")
    assert report_id, f"ReportUsage to {issuer_domain} returned no report_id: {resp.text}"
    return str(report_id)


def test_full_multi_exchange_batch_lifecycle(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests each catalog into its DB
) -> None:
    """HEADLINE capstone: ONE narrative drives the whole multi-exchange batch
    lifecycle over the real stack and asserts every leg end to end.

    An agent discovers an offer on each of three exchanges, licenses all three in
    ONE batch relay, fetches the delivered content from each publisher's edge, and
    reports usage to each issuing exchange — and each exchange records it in its
    OWN database, with the transaction ABSENT from the other two (topology
    isolation). Every leg is a real protocol round-trip driven the way an agent
    drives it: signed Broker/Exchange calls over HTTP, no shim, no re-implemented
    tool bodies; the one documented black-box exception is the per-DB ledger read
    (out of RAMP's protocol scope).

    This replaces the former MCP-shim-driven S6/S7 pair. The MCP tool surface
    itself is covered by the Go integration suite (src/identity/internal/mcp); the
    behavioural invariants those e2e tests asserted — per-exchange fan-out, content
    delivery, usage recorded per DB, cross-DB isolation — are preserved here,
    driven through the Broker/Exchange directly. The ed25519 edges enforce
    delivery-URL binding, so each content fetch presents the key the transaction
    was executed with; the CloudFront-RSA leg carries no ``agent_id=`` and needs
    none.
    """
    # ---- Leg 1: DISCOVER one offer on each of the 3 exchanges. --------------
    philo_offer = discover_first_offer(
        compose_stack.exchange,
        uri=_PHILOSOPHY_URI,
        agent_id=USD_AGENT_ID,
        domain=_BATCH_REQUESTER_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )
    music_offer = discover_first_offer(
        compose_stack.exchange_b,
        uri=_MUSIC_URI,
        agent_id=USD_AGENT_ID,
        domain=_BATCH_REQUESTER_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )
    sfx_offer = discover_first_offer(
        compose_stack.exchange_c,
        uri=_SFX_URI,
        agent_id=USD_AGENT_ID,
        domain=_BATCH_REQUESTER_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )
    chosen = [philo_offer, music_offer, sfx_offer]
    # Each offer's URI is known from the discover that produced it. Carrying the
    # mapping forward is what lets the delivery leg assert that the bytes for THAT
    # resource came back, rather than only that something answered 200.
    uri_by_offer = {
        philo_offer.get("offer_id"): _PHILOSOPHY_URI,
        music_offer.get("offer_id"): _MUSIC_URI,
        sfx_offer.get("offer_id"): _SFX_URI,
    }
    assert {_offer_exchange(o) for o in chosen} == {
        EXCHANGE_A_DOMAIN,
        EXCHANGE_B_DOMAIN,
        EXCHANGE_C_DOMAIN,
    }, "the 3 chosen offers must route to 3 distinct exchanges"

    # ---- Leg 2: PURCHASE all three in ONE batch (broker fans out per exchange).
    resp, _ = relay_execute_batch(
        compose_stack.broker,
        chosen,
        agent_id=USD_AGENT_ID,
        domain=_BATCH_REQUESTER_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )
    assert resp.status_code == httpx.codes.OK, (
        f"batch relay should succeed at the request level; "
        f"got {resp.status_code}: {resp.text[:512]}"
    )
    items = cast(list[dict[str, Any]], resp.json().get("items") or [])
    assert len(items) == 3, f"merged batch must return 3 items, got {resp.json()}"

    # Distinct transactions — the shared idempotency_key did not collapse them.
    tx_ids = {it.get("transaction_id") for it in items}
    assert len(tx_ids) == 3, f"expected 3 distinct transaction_ids, got {tx_ids}"

    exchange_by_offer = {o.get("offer_id"): _offer_exchange(o) for o in chosen}

    for item in items:
        offer_id = item.get("offer_id")
        exchange = exchange_by_offer[offer_id]
        assert exchange is not None, f"result item {offer_id!r} has no known exchange: {item}"
        own_db = _EXCHANGE_DOMAIN_TO_DB[exchange]
        tx_id = str(item.get("transaction_id") or "")
        assert not item.get("denial_reason"), (
            f"item for {offer_id} on {exchange} unexpectedly denied: {item}"
        )

        # ---- Leg 3: CONTENT DELIVERED — fetch the signed URL from its edge. --
        signed_url = retrieval_endpoint_of(item)
        assert signed_url, f"item for {offer_id} carried no retrieval_endpoint: {item}"
        # The marker is what makes this a DELIVERY assertion: an edge error-stub or
        # a wrong-route body also answers 200, so status alone would pass for both.
        # The key is presented for whichever of these legs is agent-bound — the two
        # ed25519 edges enforce the binding, and fetch_signed skips the proof for
        # the CloudFront-RSA leg, whose URL carries no agent_id to bind to.
        fetch_signed(
            str(signed_url),
            compose_stack,
            expect_marker=_URI_TO_MARKER[uri_by_offer[offer_id]],
            key_path=USD_AGENT_KEY_PATH,
        )

        # ---- Leg 4a: REPORT usage to the issuing exchange. ------------------
        report_id = _report_usage(compose_stack, exchange, item)

        # ---- Leg 4b: the exchange RECORDED the report in its OWN db. --------
        issued, outcome = _usage_record(own_db, tx_id)
        assert issued == report_id, (
            f"exchange {exchange} (db {own_db}) recorded issued_report_id {issued!r}, "
            f"want the report_id it returned {report_id!r}"
        )
        assert outcome == "VALIDATED", (
            f"exchange {exchange} recorded a non-VALIDATED outcome {outcome!r}"
        )

        # ---- Leg 4c: topology isolation — the tx is in its OWN db only. -----
        own_agent = _transaction_log_agent(own_db, tx_id)
        assert own_agent == USD_AGENT_ID, (
            f"exchange {exchange} (db {own_db}) must record transaction {tx_id!r} "
            f"under agent {USD_AGENT_ID!r}; got {own_agent!r}"
        )
        for other_exchange, other_db in _EXCHANGE_DOMAIN_TO_DB.items():
            if other_db == own_db:
                continue
            leaked = _transaction_log_agent(other_db, tx_id)
            assert leaked is None, (
                f"transaction {tx_id!r} (exchange {exchange}) leaked into "
                f"{other_exchange} (db {other_db}) — DBs are not isolated"
            )


def test_cross_agent_usage_report_refused_no_ledger_side_effect(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed registers buyers per-DB
) -> None:
    """A usage report for a transaction that does not exist on an exchange is refused
    and leaves NO ledger side effect (Doctrine #10 negative leg; mirrors test_04).

    The agent signs (with its own registered key) a ReportUsage to exchange-b's
    resolved endpoint for a fabricated transaction_id. resolveCaller admits the
    signature (the key is registered in ramp_b) but no obligation exists for the
    transaction, so the Exchange refuses with a non-2xx code AND writes no obligation
    row. This proves the report path does not invent state to make an unclaimed
    report succeed.
    """
    phantom_tx = f"tx-phantom-{uuid.uuid4().hex}"
    report_url = f"{compose_stack.exchange_b}{REPORT_USAGE_PATH}"

    resp = sign_post(
        report_url,
        body=report_body(
            exchange=recipient_of(report_url),
            transaction_id=phantom_tx,
            agent_id=USD_AGENT_ID,
        ),
        key_path=USD_AGENT_KEY_PATH,
    )
    # The refusal must be the one this test is named for: no obligation holds
    # this transaction, which the service layer answers with not_found. A
    # status-only assertion passes on any 4xx, including the wire-validation
    # refusal this test was changed to stop producing — it would keep passing
    # while proving that protovalidate works.
    assert_refused(resp, {"not_found"}, f"report for phantom transaction {phantom_tx}")
    # No ledger side effect: no obligation row was invented for the phantom tx.
    issued, outcome = _usage_record("ramp_b", phantom_tx)
    assert issued is None and outcome is None, (
        f"phantom report left a ledger side effect: issued={issued!r} outcome={outcome!r}"
    )
