"""Obligation 00 happy-path #2: the agent fetches the URL; content is delivered.

Scenario (verbatim, third happy-path bullet):

> The agent fetches the URL. The resource owner's content is delivered
> as the response body.

Driven against the demo ``epicurus`` resource (PER_UNIT USD) as the USD demo
buyer through the FULL two-phase Broker-relay chain:
the agent discovers via the Broker ``Resolve``, relay-executes the winning Offer
(agent sig1 + Broker sig2 + offer-acceptance) through
``POST /broker/v1/exchange/execute`` to the Exchange (which returns the
agent-bound signed URL on the canonical ``retrievalEndpoint`` field), then issues
a plain HTTP GET against that signed URL. The demo domain resolves to its
Cloudflare edge, which verifies the ed25519 signature (PoP) and proxies to the
publisher origin — the body is delivered.

This previously carried a strict xfail for a wire-format gap that is now
closed (the signed URL rides on the canonical ``retrievalEndpoint`` and the
demo edges deliver content end-to-end), so it asserts the obligation strictly.
"""

from __future__ import annotations

from typing import Any, cast

import httpx
import pytest

from ..broker_client import execute_first_offer
from ..conftest import StackURLs
from ..edge_fetch import fetch_signed
from ..resolve_carriers import first_item_of, retrieval_endpoint_of
from ..seed import DEMO_PHILOSOPHY_DOMAIN, USD_AGENT_ID, SeededFixture
from ..signing import USD_AGENT_KEY_PATH

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "The agent fetches the URL. The resource owner's content is delivered as the response body."
)

_RESOURCE_URI = f"http://{DEMO_PHILOSOPHY_DOMAIN}/articles/philosophers/epicurus.txt"


def test_agent_fetches_signed_url_and_receives_publisher_content(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests the demo catalog
) -> None:
    """Two-phase relay → Edge PoP fetch returns the demo publisher's bytes."""
    resp = execute_first_offer(
        compose_stack,
        {"agent_id": USD_AGENT_ID, "uri": _RESOURCE_URI, "domain": DEMO_PHILOSOPHY_DOMAIN},
        agent_id=USD_AGENT_ID,
        domain=DEMO_PHILOSOPHY_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )
    assert resp.status_code == httpx.codes.OK, (
        f"two-phase relay execute should succeed; got {resp.status_code}: {resp.text[:512]}"
    )
    # The EXECUTE response is an items[] envelope — read the
    # per-result fields from items[0], never the top level.
    accept_payload = cast(dict[str, Any], resp.json())
    item = first_item_of(accept_payload)
    assert item is not None, f"relay response carried no items[0]: {accept_payload}"
    signed_url = retrieval_endpoint_of(item)
    assert signed_url, (
        f"signed URL missing from relay items[0] (retrievalEndpoint): {accept_payload}"
    )

    # Fetch the signed URL via the shared content-delivery seam: asserts 200 and
    # the ACTUAL delivered article (not merely non-empty) — a 200 edge error-stub
    # or wrong-route body must fail. "Epicurus" is the title/subject of
    # deploy/content/demo/stoa-press/.../epicurus.txt.
    # The accept-minted URL is bound to the executing agent — fetch with PoP.
    fetch_signed(
        signed_url,
        compose_stack,
        expect_marker="Epicurus",
        timeout=15.0,
        key_path=USD_AGENT_KEY_PATH,
    )
