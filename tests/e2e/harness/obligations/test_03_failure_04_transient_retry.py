"""Obligation 03, failure-4: transient unreachability followed by a retry.

Obligation file: ``docs/obligations/03-browse-offers-without-committing.md``.

Scenario (verbatim — the sole failure-mode bullet):

> The platform is unreachable. The agent's browse call returns a
> transient failure. Retrying later succeeds.

The obligation's own "Why it matters" / "Implementation hints" sections
frame browse as a cheap, read-only planning call. The key property under
test here is therefore two-fold:

1. When the browse call cannot reach the platform, the agent sees a
   transport-level transient failure (an ``httpx.ConnectError`` — a TCP
   connect refused on an unused loopback port). It is NOT a 4xx/5xx with
   an offer list; the call never lands on the Exchange at all. This is
   what "unreachable" means, and it is distinct from the
   obligation-03 failure-3 scenario ("buyer not entitled") which DOES
   land at the Exchange and returns a structured empty-offer response.
2. Retrying against the healthy Exchange (the real compose endpoint)
   immediately succeeds — the same ``DiscoverResources`` call returns a
   structured offer list with the seeded SUBSCRIPTION offer.

Read-only guarantee (implementation hint): browse must not write a
``ramp.transaction_log`` row no matter whether the call failed or
succeeded. Both attempts above are asserted against the log.

Tenant isolation: this test owns ``tenant-e2e-ob03-transient`` /
``tenant-e2e-ob03-transient.local`` so it cannot collide with other
obligation tests running in parallel against the same compose stack.
The unreachable endpoint is ``http://127.0.0.1:19999`` — a deliberately
unused loopback port. The test does NOT stop/start any compose service,
so other parallel executors are not disturbed.

Production status:

Both halves of this scenario are exercised end-to-end on the current
build. The first attempt (transport-level ``ConnectError`` against an
unused loopback port) is basic ``httpx`` behavior and has always
worked. The second attempt (a retry against the healthy Exchange that
"succeeds") works because the wave-2 exchange-behavior gates landed
the agent-direct browse path:

* ``da2a5e3`` — wave-2 exchange behavior gates relaxed the global
  RFC 9421 httpsig middleware: ``exchangeGlobalSigRequestPredicate``
  in ``src/exchange/cmd/server/main.go`` now passes through any
  ``/ramp.*`` POST that lacks a ``Signature-Input`` header (agent-direct
  DiscoverResources / ExecuteTransaction / Report / DiscoverResources /
  ExecuteTransaction). Service-layer authorization takes over from
  there.
* ``25e51f7`` — it84 OfferType-on-Offer merge added the ``Offer.type``
  proto field plus the LookupHitSubscription scope-gated relax that
  this scenario's seeded SUBSCRIPTION offer rides on.
* ``e91039e`` — ADR-008 D3 sweep enforced strict mode on every
  ``pytest.mark.xfail`` under ``tests/``; this audit-and-flip task is
  the resulting forced-surfacing of the now-honest xpass.

Service-layer caller-identity policy (now lives in
``src/exchange/internal/service/discover.go`` — the legacy
``offers.go`` was removed in W1 of t3vk) is: "Browse is read-only and
supports three caller classes — anonymous (no JWT, no biscuit),
biscuit-only, JWT-bearer. Empty ``claims.Sub`` is therefore not a
rejection condition here." So unsigned / unauthenticated browse calls
reach the handler, return a structured ``DiscoverResources`` response,
and the seeded offer surfaces in the response body — exactly what the
obligation's "retrying later succeeds" semantic requires.

AUDIT NOTE (P2.03, beads agentic-content-access-y61v):

(a) The fixture INSERT into ``ramp.offers`` targets a table that was
    DROPPED by src/exchange/internal/db/migrations/
    000006_drop_ye6f9_schema.up.sql (W1 of t3vk). The seed path cannot
    run on the current schema; ``DiscoverResources`` reads from
    ``ramp.catalog``.
(b) The request body ``{"resourceUrl": resource_uri}`` is NOT a
    canonical ``ResourceQuery`` field. The canonical request carries
    the URI list under ``requester.uris`` (github.com/RAMP-Protocol/protocol/ramp/v1/ramp.proto,
    message Requester, field 5).
(c) References to ``OfferType`` in the module docstring above
    (the ``25e51f7`` cite) describe a field that was REMOVED in W1
    of t3vk; subscription offers are now identified by non-empty
    ``subscription_id`` only.

The verbatim obligation prose in the docstring's "Scenario" section
matches obligation-03's failure-mode bullet 2 (lines 35-36 of
``docs/obligations/03-browse-offers-without-committing.md``). The
scenario itself is IN SCOPE for obligation-03. P3 should migrate the
fixture onto ``ramp.catalog``, replace ``resourceUrl`` with
``requester.uris``, and clean up the OfferType reference. No xfail
marker is in place; the test will fail at seed time today.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import httpx
import psycopg
import pytest

from ..catalog_push import CatalogEntry, load_public_key_bytes, push_catalog
from ..conftest import COMPOSE_FILE, StackURLs
from ..seed import (
    CONTRIBUTOR_KEY_PATH,
    SeededFixture,
    _resolve_pg_dsn,
    _upsert_agent,
    _upsert_catalog_contributor,
    _upsert_exchange,
    _upsert_tenant_ed25519,
    seed_stack,
)
from ..signing import sign_post


# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_LIST_OFFERS_PATH = "/ramp.v1.ExchangeService/DiscoverResources"

_TENANT_ID = "tenant-e2e-ob03-transient"
_TENANT_DOMAIN = f"{_TENANT_ID}.local"
_AGENT_ID = "agent-e2e-ob03-transient"
_EXCHANGE_ID = "mp-e2e-ob03-transient"
_EXCHANGE_DOMAIN = "exchange.e2e.local"

_PUBLISHER_SLUG = "edge:8787"
_RESOURCE_PATH_PREFIX = "/premium/ob03-transient-"

# A deliberately unused loopback port. ``httpx`` attempting a POST here
# resolves 127.0.0.1, opens a TCP connection, and gets ECONNREFUSED —
# the transport-level "platform unreachable" the obligation describes.
# Using a loopback unused-port is side-effect-free: no other executor's
# compose services are touched, and no DNS is required.
_UNREACHABLE_URL = "http://127.0.0.1:19999"


@pytest.fixture(scope="module")
def seeded(compose_stack: StackURLs) -> SeededFixture:
    """Run the shared seed_stack to materialize the contributor key.

    ``seed_stack`` is idempotent: it generates the contributor keypair on
    first call (no-op if it already exists) and upserts the shared
    ``tenant-e2e`` rows. Depending on it here means this test can run in
    isolation — without relying on another test to have prepared the
    catalog-contributor fixture first.
    """
    return seed_stack(str(COMPOSE_FILE), compose_stack.exchange)


@pytest.fixture(scope="module")
def transient_seed(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — dependency: contributor key + shared tenant
) -> Iterator[tuple[str, str]]:
    """Seed tenant + catalog entry. The retry path asserts the row surfaces.

    Yields ``(resource_uri, offer_id)``. Post-t3vk, the legacy
    ``ramp.offers`` table was dropped; the discover path reads catalog
    rows directly. The catalog row's ``resource_id`` IS the canonical
    ``offer_id`` surfaced by DiscoverResources
    (discover.go::buildOffer:OfferId = entry.ResourceID), so we yield
    ``content_id`` as the offer_id the retry assertion looks for.

    The fixture is module-scoped so the tenant + catalog rows survive
    the two sequential attempts.
    """
    suffix = uuid.uuid4().hex[:8]
    path = f"{_RESOURCE_PATH_PREFIX}{suffix}.html"
    resource_uri = f"http://{_PUBLISHER_SLUG}{path}"
    content_id = f"res-ob03-transient-{suffix}"

    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    _upsert_tenant_ed25519(dsn, tenant_id=_TENANT_ID, domain=_TENANT_DOMAIN)
    _upsert_agent(dsn, agent_id=_AGENT_ID)
    _upsert_catalog_contributor(dsn, pubkey_bytes=load_public_key_bytes(CONTRIBUTOR_KEY_PATH))
    push_catalog(
        exchange_url=compose_stack.exchange,
        tenant_id=_TENANT_ID,
        entries=[
            CatalogEntry(domain=_PUBLISHER_SLUG, path=path, content_id=content_id),
        ],
        key_path=CONTRIBUTOR_KEY_PATH,
    )
    _upsert_exchange(dsn, exchange_id=_EXCHANGE_ID, domain=_EXCHANGE_DOMAIN)

    try:
        yield resource_uri, content_id
    finally:
        # ramp.offers no longer exists; tenant teardown elsewhere handles
        # catalog row removal.
        pass


def _count_transaction_rows(dsn: str) -> int:
    """Return transaction_log rows for this tenant + agent pair.

    Obligation 03's read-only guarantee: browse must NOT write a ledger
    row whether the call succeeded or failed. Counting by
    (tenant_id, agent_id) is sufficient — no other test uses this
    tenant-unique pair.
    """
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*) FROM ramp.transaction_log
            WHERE tenant_id = %s AND agent_id = %s
            """,
            (_TENANT_ID, _AGENT_ID),
        )
        row = cur.fetchone()
        return int(row[0]) if row else 0


def test_unreachable_browse_raises_transient_then_retry_succeeds(
    compose_stack: StackURLs,
    transient_seed: tuple[str, str],
) -> None:
    """Unreachable first attempt raises a transient error; retry succeeds.

    Assertions trace directly to the obligation's failure-mode bullet:

    (1) "The platform is unreachable" — POST to the unused loopback port
        19999 raises ``httpx.ConnectError`` (transport-level refused
        connection). A 4xx/5xx response would mean the call reached the
        platform, which is not what "unreachable" means in the
        obligation text.
    (2) "The agent's browse call returns a transient failure" — the
        error is a connect-time transport exception, NOT a Connect-RPC
        or Exchange domain error surfaced in a response body.
    (3) "Retrying later succeeds" — the same ``DiscoverResources`` request sent
        to the real Exchange (compose_stack.exchange) returns a 2xx with
        a structured JSON payload. The exact contents depend on the
        platform's current gating posture (RFC 9421 signing, JWT
        claims); the obligation only requires that the retry "succeeds"
        — i.e. the call lands on the platform and produces a structured
        response instead of a transport-level failure. We further assert
        that the seeded offer surfaces in the response body when the
        call is structurally successful, which is the obligation's
        "returns all applicable offers" semantic on the browse path.
    (4) Implementation hint — browse is read-only: no transaction_log
        row is written by either attempt. This is asserted before and
        after both attempts.
    """
    resource_uri, offer_id = transient_seed
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))

    # (4a) Read-only precondition — the log starts empty for this pair.
    rows_before = _count_transaction_rows(dsn)
    assert rows_before == 0, (
        f"precondition violated: transaction_log rows for "
        f"tenant={_TENANT_ID} agent={_AGENT_ID} before the test = "
        f"{rows_before}; expected 0 — the tenant pair is owned by this "
        f"test and must start clean"
    )

    # Canonical ResourceQuery shape — URIs ride on requester.uris[].
    # The legacy "resourceUrl" body was dropped post-t3vk and is silently
    # discarded by the Connect-Go JSON codec (DiscardUnknown=true).
    # requester.id is mandatory post-rjtks; the test signer's kid is the
    # transport-layer identity, requester.id is the service-layer agent.
    body = {
        "requester": {
            "id": _AGENT_ID,
            "domain": _TENANT_DOMAIN,
            "uris": [resource_uri],
        },
    }

    # (1)+(2) Unreachable attempt. A POST to an unused loopback port
    # must raise a connect-level transient failure BEFORE any response
    # headers or body are exchanged. ``httpx.ConnectError`` is the
    # specific subclass httpx raises when TCP connect fails (ECONNREFUSED
    # here, since nothing listens on :19999). A broader
    # ``httpx.TransportError`` match would also admit timeouts, read
    # errors, and TLS failures — the obligation's "unreachable" semantic
    # is strictly narrower, so we require ConnectError.
    #
    # We deliberately use a plain httpx.post for the unreachable attempt:
    # the TCP connection refused fires BEFORE any signing/verification
    # logic runs, so a signed POST would behave identically. The plain
    # call keeps the diagnostic surface minimal — the ConnectError
    # observed is precisely the obligation's "unreachable" symptom.
    with pytest.raises(httpx.ConnectError) as excinfo:
        httpx.post(f"{_UNREACHABLE_URL}{_LIST_OFFERS_PATH}", json=body, timeout=5.0)
    assert excinfo.value is not None, (
        "expected httpx.ConnectError to be raised, got no exception info"
    )

    # (4b) Still read-only after the unreachable attempt — the call
    # never reached the platform, but we assert explicitly in case a
    # future shim pre-writes a speculative row.
    rows_after_unreachable = _count_transaction_rows(dsn)
    assert rows_after_unreachable == 0, (
        f"read-only violated after unreachable attempt: transaction_log "
        f"rows for tenant={_TENANT_ID} agent={_AGENT_ID} = "
        f"{rows_after_unreachable}; expected 0 — browse is read-only "
        f"and the unreachable attempt did not land on the platform at all"
    )

    # (3) Retry against the healthy Exchange. The request is signed with
    # the test signer key per post-1rnxh's universal signing requirement;
    # only the destination URL changes from the unreachable attempt, which
    # is what "retrying later" means once the platform is reachable again.
    # We expect a structured HTTP response (2xx JSON), not a transport-
    # level exception.
    retry_resp = sign_post(f"{compose_stack.exchange}{_LIST_OFFERS_PATH}", body=body)
    assert retry_resp.status_code == httpx.codes.OK, (
        f"retry against the healthy Exchange must succeed, got "
        f"{retry_resp.status_code}: {retry_resp.text[:512]}"
    )
    retry_payload = retry_resp.json()
    assert isinstance(retry_payload, dict), (
        f"retry body must be a JSON object, got type "
        f"{type(retry_payload).__name__}: {retry_resp.text[:256]}"
    )

    # The obligation text for the broader browse contract says the
    # platform "returns all applicable offers" on success. The retry
    # path is what "succeeds" means here, so the seeded offer_id must
    # surface in the response body.
    offers = retry_payload.get("offers") or []
    offer_ids = {o.get("offerId") for o in offers if isinstance(o, dict)}
    assert offer_id in offer_ids, (
        f"retry against healthy Exchange must surface the seeded offer "
        f"{offer_id!r}; got offer_ids={sorted(oid for oid in offer_ids if oid)} "
        f"payload={retry_payload!r}"
    )

    # (4c) Still read-only after a successful browse retry — the
    # implementation hint is explicit: "browse is a read-only operation.
    # No ledger row is written."
    rows_after_retry = _count_transaction_rows(dsn)
    assert rows_after_retry == 0, (
        f"read-only violated after successful retry: transaction_log rows "
        f"for tenant={_TENANT_ID} agent={_AGENT_ID} = {rows_after_retry}; "
        f"expected 0 — browse is read-only and must not write a "
        f"transaction_log row even on success"
    )
