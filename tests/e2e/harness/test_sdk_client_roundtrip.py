"""The SDK's own RAMP client, driven against the running stack.

Every other suite here builds a RAMP body by hand, signs it with
``signing.sign_post`` and posts it to a path constant. That proves the services;
it says nothing about the client the SDK now ships, which is what an external
integrator will actually hold. This suite drives that client and nothing else.

Five properties, and each one fails in a way that is easy to mistake for a
broken stack:

1. **Offers arrive verified, not rejected — from every Exchange.** Verification
   is fail-closed and the default resolver resolves nothing, so a client wired
   without keys rejects every offer with a reason. An Exchange whose directory
   cannot be read is simply absent from the key map, and only ITS offers are
   then rejected, so the property is driven over one URI per Exchange and every
   rejection list is asserted empty. Against a single URI, losing two of the
   three directories changed nothing that was checked.
2. **A usage report reaches the Exchange that issued the offer**, at the origin
   that Exchange advertises for itself — never an address from configuration.
   The reporting client below is built against a DIFFERENT Exchange on purpose;
   see ``test_sdk_client_walks_the_paid_path``.
3. **A signed delivery URL is followed, the agent key is presented, and bytes
   come back.**
4. **A refusal carries its decoded ErrorDetail** — the failing domain and a
   developer message — read out of the Connect error's ``details[]`` block.
   Whether that block's lowerCamelCase spelling is read correctly is a separate
   property, pinned by ``test_the_sdk_reads_a_camelcase_error_detail`` because
   nothing this deployment refuses can show it; see that test.
5. **Nothing on any leg is refused as non-canonical wire naming.** The client
   refuses a lowerCamelCase response body outright, at every depth and with no
   opt-out, so a single listener on the path that forgot the snake_case codec
   would surface here as a refused call.

Two tests below need none of that. ``test_the_sdk_reads_a_camelcase_error_detail``
drives the error-detail reader over a payload written inline, and
``test_the_signer_sends_every_covered_header`` reads what the signing transport
emits. Both are about the client alone, so they declare the stack-isolation mode
that skips the per-test cleanup chain.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from typing import Any, TypeVar

import pytest
from ramp_sdk.client import NOT_CANONICAL_WIRE_NAMING, CallError, CallErrorKind
from ramp_sdk.core import DiscoveryResult, OfferGroupResult, VerifiedOffer, Verifier
from ramp_sdk.errordetail import error_detail_from
from ramp_sdk.multisig_parse import parse_multisig_signature_input
from ramp_sdk.sync import BrokerClient, Client

from ._multi_exchange_common import (
    _EXCHANGE_DOMAIN_TO_DB,
    _MUSIC_URI,
    _PHILOSOPHY_URI,
    _SFX_URI,
    _usage_record,
)
from .conftest import StackURLs
from .exchanges import EXCHANGE_A_DOMAIN, EXCHANGE_B_DOMAIN, EXCHANGE_C_DOMAIN
from .httpsig_signer import load_keypair, signing_transport
from .reporting import report_body
from .sdk_client import offer_verifier, sdk_broker_client, sdk_exchange_client
from .seed import (
    DEMO_PHILOSOPHY_DOMAIN,
    USD_AGENT_ID,
    SeededFixture,
)
from .signing import AGENT_E2E_KEY_PATH, USD_AGENT_KEY_PATH

# epicurus: PER_UNIT 0.0001/characters USD — a PAID resource, deliberately. The
# report path needs an obligation to record, and the philosophy URI the
# multi-exchange suites share (socrates) is FREE.
_RESOURCE_URI = f"http://{DEMO_PHILOSOPHY_DOMAIN}/articles/philosophers/epicurus.txt"

#: One discoverable URI per Exchange, and which Exchange publishes it.
#:
#: Reused from the multi-exchange suites rather than respelled here, so a fourth
#: publisher is added in one place. These three are what make the all-exchange
#: property falsifiable: each is served by exactly one Exchange, so a directory
#: this client cannot read shows up as that Exchange's own URI coming back
#: rejected instead of verified.
_URI_OWNERS = {
    _PHILOSOPHY_URI: EXCHANGE_A_DOMAIN,
    _MUSIC_URI: EXCHANGE_B_DOMAIN,
    _SFX_URI: EXCHANGE_C_DOMAIN,
}

#: The stable grouping key every ExchangeService fault stamps on its ErrorDetail.
_EXCHANGE_SERVICE_DOMAIN = "ramp.v1.ExchangeService"

pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")


_T = TypeVar("_T")
#: Any SDK client face this suite builds; both carry close().
_C = TypeVar("_C", BrokerClient, Client)


def _call(fn: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
    """Run one client call, naming the one refusal that means the stack is misconfigured.

    A non-canonical-wire-naming refusal is not this suite's subject and reads as an
    unrelated failure wherever it surfaces, so it is turned into a sentence that
    says which mount to look at. Everything else travels as itself.
    """
    try:
        return fn(*args, **kwargs)
    except CallError as exc:
        if exc.reason_of() == NOT_CANONICAL_WIRE_NAMING:
            pytest.fail(
                f"refused as {NOT_CANONICAL_WIRE_NAMING}: a listener on this path served "
                f"the camelCase json_name alias instead of snake_case proto-JSON. Check "
                f"that its mount registers the canonical codec."
            )
        raise


@pytest.fixture(scope="module")
def verifier(compose_stack: StackURLs) -> Verifier:  # noqa: ARG001 — the stack must be up to fetch
    """The offer-key verifier every client in this module shares.

    Built once per module, not once per test. It reads all three Exchanges' Web
    Bot Auth directories over HTTP at a ten-second timeout, and three tests
    building it separately paid that three times for one identical answer.

    Module scope is safe because a Web Bot Auth directory is per-Exchange
    CONFIGURATION, not per-test state: the cleanup chain between tests does not
    touch it, so a verifier built for the first test is still correct for the
    last.

    The domains come from the URI-ownership map, which is the same list this
    module already uses to say which Exchange serves what. Reading them off the
    database-topology map instead named the right three by coincidence: this
    fixture opens no database, and coupling it to that map would make a change in
    the storage layout look like a change in who signs offers.
    """
    return offer_verifier(list(_URI_OWNERS.values()))


@dataclass
class _ClientFactory:
    """Builds this suite's SDK clients and closes every one it hands out.

    Every client here wants the same agent identity, key and verifier, and the
    only thing that varies is which Exchange it addresses. Written out per test
    that was four near-identical constructions and four try/finally blocks — one
    of which opened AFTER a second client was built, so a failure to build the
    second leaked the first for the rest of the session.
    """

    stack: StackURLs
    verifier: Verifier
    closing: ExitStack

    def broker(self) -> BrokerClient:
        """The Broker's discovery client."""
        return self._owned(
            sdk_broker_client(
                self.stack, self.verifier, agent_id=USD_AGENT_ID, key_path=USD_AGENT_KEY_PATH
            )
        )

    def exchange(self, domain: str) -> Client:
        """The client for one Exchange, addressed at the URL this stack reaches it on."""
        return self._owned(
            sdk_exchange_client(
                self.stack,
                domain,
                self.verifier,
                agent_id=USD_AGENT_ID,
                key_path=USD_AGENT_KEY_PATH,
            )
        )

    def _owned(self, client: _C) -> _C:
        """Register the close before the caller can raise between build and use."""
        self.closing.callback(client.close)
        return client


@pytest.fixture
def clients(compose_stack: StackURLs, verifier: Verifier) -> Iterator[_ClientFactory]:
    """A client factory whose teardown closes everything it built.

    The ExitStack registers each close at construction, so a client is owned from
    the moment it exists rather than from the moment a try block opens.
    """
    with ExitStack() as closing:
        yield _ClientFactory(stack=compose_stack, verifier=verifier, closing=closing)


def _only_verified_offer(group: OfferGroupResult, leg: str) -> VerifiedOffer:
    """The single verified offer in one group, refusing a partial success.

    Reports what was rejected and why, because a fail-closed rejection is the
    shape a mis-wired key resolver takes and it is otherwise indistinguishable
    from an Exchange that offered nothing. An EMPTY rejected list is asserted as
    well: a result carrying one verified offer beside a rejected one is a key
    resolver that reached some Exchange and not another, and reading index 0 and
    moving on would call that a pass.
    """
    # A verified or rejected offer wraps the offer as the canonical snake_case
    # proto-JSON object it arrived as, not a parsed model, so it is read by key.
    rejected = [(r.offer.get("offer_id"), r.reason) for r in group.result.rejected]
    assert group.result.verified, (
        f"{leg} verified no offers for {group.uri}: rejected={rejected} "
        f"absence_reason={group.absence_reason}. A rejection here usually means the "
        f"offer-key resolver never reached the Exchange's Web Bot Auth directory."
    )
    assert not rejected, (
        f"{leg} rejected {rejected} for {group.uri} alongside what it verified. "
        f"Every offer here is signed by an Exchange this verifier holds a key for, so a "
        f"rejection means one directory was not read."
    )
    return group.result.verified[0]


def _one_group_per_uri(
    result: DiscoveryResult, wanted: Iterable[str], leg: str
) -> dict[str, OfferGroupResult]:
    """Index a discovery result by URI, refusing anything but one group each."""
    by_uri: dict[str, OfferGroupResult] = {}
    for group in result.groups:
        assert group.uri not in by_uri, f"{leg} returned two groups for {group.uri}"
        by_uri[group.uri] = group
    assert set(by_uri) == set(wanted), (
        f"{leg} answered for {sorted(by_uri)}, asked about {sorted(wanted)}"
    )
    return by_uri


def test_broker_resolve_verifies_an_offer_from_every_exchange(
    clients: _ClientFactory,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests the demo catalog
) -> None:
    """Property 1, over one URI owned by each of the three Exchanges.

    Driving a single URI could not prove what property 1 claims. Each of these is
    published by exactly one Exchange, so verifying all three is what shows the
    key resolver reached EACH Exchange's Web Bot Auth directory and picked the
    right key for each.

    That distinction is not theoretical. An exchange the resolver cannot read is
    simply absent from the key map — the prefetch is deliberately built that way,
    so one unreachable directory leaves the others working — and the Verifier
    then rejects that exchange's offers fail-closed. Against one URI seeded on
    one Exchange, losing either of the other two directories changed nothing that
    was asserted.

    The offers here are FREE or flat-priced, which does not weaken the check: the
    Exchange signs every offer it issues, priced or not, so each one is verified
    against the issuer's published key exactly as a paid one would be.
    """
    result = _call(clients.broker().resolve, {"uris": list(_URI_OWNERS)})
    by_uri = _one_group_per_uri(result, _URI_OWNERS, "broker resolve")
    for uri, owner in _URI_OWNERS.items():
        offer = _only_verified_offer(by_uri[uri], f"broker resolve for {uri}")
        assert offer.offer.get("exchange") == owner, (
            f"{uri} came back verified but stamped with "
            f"{offer.offer.get('exchange')!r}, want {owner!r} — the offer was checked "
            f"against a key belonging to a different Exchange than the one that issued it"
        )


def test_sdk_client_walks_the_paid_path(
    clients: _ClientFactory,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests the demo catalog
) -> None:
    """Properties 1, 2 and 3: discover, buy, fetch, report — and prove where the report went.

    The report is sent through a client built against a DIFFERENT Exchange than
    the one that issued the offer, and the ``exchange`` it names is read off the
    verified offer rather than written from a constant. That is what makes
    property 2 falsifiable. A usage report is routed from the signed
    ``Offer.exchange`` through that Exchange's own manifest, never from
    configuration; while the client's base URL and the issuer are the same
    origin, a regression to configuration lands in the same place and nothing
    here would notice.

    Where it landed is then read from the issuing Exchange's OWN database, and
    from the other two to show it is absent there. The ledger has no protocol
    read surface by design, so that read is the documented black-box exception
    the multi-exchange suites already take.
    """
    discovered = _call(clients.broker().resolve, {"uris": [_RESOURCE_URI]})
    by_uri = _one_group_per_uri(discovered, [_RESOURCE_URI], "broker resolve")
    offer = _only_verified_offer(by_uri[_RESOURCE_URI], "broker resolve")
    issuer = offer.offer.get("exchange")
    assert issuer, f"the verified offer names no exchange: {offer.offer}"

    # Execute addresses the Exchange directly, so this client MUST be the issuer.
    buyer = clients.exchange(issuer)
    # Reporting routes off the signed offer, so this one deliberately is not.
    not_the_issuer = EXCHANGE_C_DOMAIN if issuer != EXCHANGE_C_DOMAIN else EXCHANGE_A_DOMAIN
    reporter = clients.exchange(not_the_issuer)

    purchased = _call(buyer.execute, offer)
    # Indexed only after the envelope is known to carry an item. Reading [0]
    # first turns an empty envelope into an IndexError, which says nothing about
    # what went wrong, instead of the assertion written for exactly that case.
    assert purchased.items, f"execute answered an envelope with no items: {purchased}"
    item = purchased.items[0]
    assert item.retrieval_endpoint, f"execute minted no delivery URL: {purchased}"

    # Property 3: the delivery leg presents the agent key and returns bytes.
    content = _call(buyer.fetch, item.retrieval_endpoint)
    assert content.body, "the delivery URL returned an empty body"

    reported = _call(
        reporter.report_usage,
        report_body(
            exchange=issuer,
            transaction_id=item.transaction_id,
            agent_id=USD_AGENT_ID,
            domain=DEMO_PHILOSOPHY_DOMAIN,
            # The Exchange minted this at execute and checks the report
            # against it, so a report that omits it is refused as a
            # billing_id mismatch rather than recorded.
            billing_id=item.billing_id,
            # consumed_quantity is left at its default 0. The epicurus term
            # carries no estimate, so the obligation records zero, and the
            # validator strict-rejects any positive quantity against a
            # zero-estimate obligation. What this test proves is WHERE the
            # report landed; the quantity is incidental to that.
        ),
    )

    assert reported.report_id, (
        f"the usage report answered no report_id, so nothing shows it was recorded: {reported}"
    )

    # Property 2, the observable half: the ISSUER recorded it, and nobody else.
    issued, outcome = _usage_record(_EXCHANGE_DOMAIN_TO_DB[issuer], item.transaction_id)
    assert issued == reported.report_id, (
        f"{issuer} recorded issued_report_id {issued!r}, want the client's "
        f"{reported.report_id!r} — the report did not land at the issuing Exchange"
    )
    assert outcome == "VALIDATED", f"{issuer} recorded outcome {outcome!r}, want VALIDATED"
    for domain, db in _EXCHANGE_DOMAIN_TO_DB.items():
        if domain == issuer:
            continue
        leaked, _ = _usage_record(db, item.transaction_id)
        assert leaked is None, (
            f"{domain} (db {db}) also holds a record for {item.transaction_id} — "
            f"the report reached an Exchange that did not issue the offer"
        )


def test_a_refusal_carries_its_decoded_error_detail(
    clients: _ClientFactory,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests the demo catalog
) -> None:
    """Property 4: a report for a transaction nobody holds carries a decoded detail.

    The Exchange attaches an ErrorDetail to the Connect error and this client
    decodes it out of the ``details[]`` block. The assertion is on that object's
    CONTENT. Asserting ``reason_of()`` would prove nothing — it falls back to the
    failure class when the peer named no reason, and no class is empty, so it
    cannot be falsy. Asserting only that ``exc.detail`` is not None proves little
    more, for the reason below.

    This path carries NO typed reason. The Exchange routes a ReportUsage fault
    through its shared reasonless envelope, which stamps domain and message and
    nothing else; the per-domain usage-report rejection reason is a later step in
    that service. Every field it does carry is a single word, so the proto name
    and the lowerCamelCase json_name alias are the same string, and this test
    cannot tell the SDK's alias rewrite from a reader that never had one. That
    property is pinned by ``test_the_sdk_reads_a_camelcase_error_detail`` below.
    """
    client = clients.exchange(EXCHANGE_A_DOMAIN)
    with pytest.raises(CallError) as caught:
        _call(
            client.report_usage,
            report_body(
                exchange=EXCHANGE_A_DOMAIN,
                transaction_id="tx-nobody-holds-this-one",
                agent_id=USD_AGENT_ID,
                domain=DEMO_PHILOSOPHY_DOMAIN,
            ),
        )

    exc = caught.value
    assert exc.kind is CallErrorKind.REFUSED, f"refused with kind {exc.kind}, want REFUSED"
    assert exc.detail is not None, (
        "the refusal carried no decoded ErrorDetail. The Exchange states the cause in "
        "the Connect error's details[] block; reading it is the whole point of decoding "
        "that block."
    )
    assert exc.detail.domain == _EXCHANGE_SERVICE_DOMAIN, (
        f"the detail attributes the fault to {exc.detail.domain!r}, want "
        f"{_EXCHANGE_SERVICE_DOMAIN!r} — every ExchangeService fault stamps the service "
        f"it came from, so a caller can group failures without parsing prose"
    )
    assert exc.detail.message, (
        f"the detail carries no developer message: {exc.detail!r}. It is not "
        f"authoritative and a caller must not branch on it, but an empty one leaves "
        f"whoever reads the log with nothing at all."
    )


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_the_sdk_reads_a_camelcase_error_detail() -> None:
    """The client decodes the lowerCamelCase ``details[]`` block, keys and all.

    Connect renders an error detail's ``debug`` projection with its own codec at
    default options, so that one payload arrives lowerCamelCase however the
    server's response codec is configured. The generated model declares proto
    names only. Until this SDK revision both the TypeScript and Python readers
    parsed the block with a snake-only schema and lost every multi-word key,
    reporting no reason at all for a refusal the peer had named precisely.

    The payload here is CONSTRUCTED, not captured, and that is not a shortcut.
    Nothing this deployment refuses carries a multi-word key: the Exchange routes
    every reachable fault through its reasonless envelope (domain and message
    only), the one typed-denial path never reaches the transport because a
    business denial is answered in-body at 200 as a per-item reason, and the
    Broker stamps no reason either. So there is no refusal to capture, and this
    drives the reader against the shape the protocol defines instead.

    ``transaction_denial`` is the choice because it is a reason block the reader
    MUST rewrite: drop the rewrite and the model refuses "transactionDenial" as an
    alias, the reader catches that and answers "no detail", and the first
    assertion below fails.
    """
    detail = error_detail_from(
        {
            "code": "permission_denied",
            "message": "denied",
            "details": [
                {
                    "type": "ramp.v1.ErrorDetail",
                    "debug": {
                        "message": "billing denied",
                        "domain": _EXCHANGE_SERVICE_DOMAIN,
                        "transactionDenial": {"reason": "DENIAL_REASON_INSUFFICIENT_BALANCE"},
                    },
                }
            ],
        }
    )
    assert detail is not None, (
        "the reader answered 'no detail' for a well-formed lowerCamelCase block, so a "
        "refusal the peer named precisely reads back as unexplained"
    )
    assert detail.transaction_denial is not None, (
        f"the reason block was dropped: {detail!r}. Its key is the only multi-word one "
        f"in the payload, which is exactly what a snake-only reader loses."
    )
    assert detail.transaction_denial.reason.value == "DENIAL_REASON_INSUFFICIENT_BALANCE"


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_the_signer_sends_every_covered_header() -> None:
    """Every name the signature base binds arrives on the request under that name.

    The RAMP covered set binds ``authorization`` and ``signature-agent``
    unconditionally, empty values included, so a later injection cannot ride an
    existing signature. A verifier rebuilds the base from the headers that
    ARRIVED and cannot tell an empty field from an absent one, so a value bound
    and not sent is not bound at all -- it is a refusal.

    That is not hypothetical. Both ports shipped for a while binding the two and
    sending neither, and every signed call this suite makes was answered
    ``header "authorization" missing from request``. The three tests above carried
    strict-xfail markers naming it. The markers are gone because the SDK is fixed;
    this is what watches the property in their place, so the same regression at a
    later pin is caught here rather than as four unexplained refusals.

    Reads the signer's own output, so it needs no stack and no network. The
    ``@``-prefixed covered names are derived components (the method, the target
    URI) rather than header fields, and are excluded.
    """
    _, priv = load_keypair(AGENT_E2E_KEY_PATH)
    signed = signing_transport("https://agent.example", priv).sign_outbound(
        method="POST",
        url="http://exchange.example/ramp.v1.ExchangeService/DiscoverResources",
        body=b"{}",
        authorization="",
    )

    members = parse_multisig_signature_input([signed.headers["signature-input"]])
    assert members, f"Signature-Input did not parse: {signed.headers['signature-input']!r}"
    covered = {name for name in members[0].covered_names if not name.startswith("@")}
    assert "authorization" in covered, (
        "the covered set no longer binds authorization. Dropping it is not a fix for "
        "the header never being sent -- it removes the binding that stops a bearer "
        "token being swapped under an existing signature."
    )
    missing = covered - set(signed.headers)
    assert not missing, (
        f"the signer bound {sorted(missing)} into the signature base and put nothing "
        f"on the wire under {'that name' if len(missing) == 1 else 'those names'}. "
        f"A conformant verifier rebuilds the base from what arrived and refuses. "
        f"Emitted: {sorted(signed.headers)}"
    )
