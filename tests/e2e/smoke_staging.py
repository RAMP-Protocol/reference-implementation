"""Staging smoke proof: discover -> execute -> signed URL -> edge -> origin.

Env-parameterized smoke driver for the Terraform staging stack
(deploy/terraform/stacks/staging-aws). NOT a pytest module — a standalone
script run against a live, already-seeded staging deployment
(seed-staging.sh), normally via deploy/terraform/scripts/smoke.sh:

    RAMP_STAGING_EXCHANGE_URL=https://exchange.<domain> \
    RAMP_STAGING_BROKER_URL=https://broker.<domain> \
    RAMP_STAGING_PUBLISHER=demo.<domain> \
    RAMP_STAGING_AGENT_ID=agent-staging \
    RAMP_STAGING_AGENT_KEY=deploy/terraform/stacks/staging-aws/keys/agent-key.json \
    uv run --project tests/e2e python tests/e2e/smoke_staging.py

What it proves, end to end, over the real public surface (HTTPS, Cloudflare
DNS, the deployed edge worker):

1. Licensed discovery: Broker Resolve for a demo resource (socrates) returns
   a non-empty offer group — ingest + discovery work. Resolve is
   DISCOVERY-ONLY: it carries ranked signed Offers, never a signed URL.
2. Two-phase delivery for the canary: the winning Offer is relay-EXECUTED
   through the Broker (agent acceptance + broker relay signatures) and the
   Exchange mints the agent-bound signed retrievalEndpoint on the
   TransactionResponse item. A bare fetch of that URL (no proof of
   possession) is expected to DELIVER the origin body by default, matching an
   edge deployed with ramp_enforce_binding = "false"; set
   RAMP_STAGING_ENFORCE_BINDING=true for an edge that enforces binding, where
   the bare fetch must instead be REFUSED (403). Fetching WITH
   proof-of-possession headers (harness.edge_fetch.fetch_signed) delivers the
   origin body containing RAMP-DEMO-CANARY-8FK3J2-0418 — mint -> edge verify
   (signature + agent binding) -> origin round trip.

Both legs traverse the full deployed stack: agent-signed calls -> Broker ->
Exchange -> signed URL -> edge worker -> Caddy -> origin container. Nothing
reads or writes staging state directly — seeding is seed-staging.sh's job.

Scope note: the staging stack deploys the Exchange with the tigerbeetle
billing adapter, but this script asserts nothing about billing — it proves
the licensing/delivery path only.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tests" / "e2e"))

from harness.broker_client import execute_first_offer, resolve  # noqa: E402
from harness.stack_urls import StackURLs  # noqa: E402
from harness.edge_fetch import fetch_signed  # noqa: E402
from harness.resolve_carriers import (  # noqa: E402
    first_item_of,
    offer_exchanges_by_uri,
    retrieval_endpoint_of,
)

CANARY_MARKER = "RAMP-DEMO-CANARY-8FK3J2-0418"


def _require_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        msg = f"missing required env var: {name}"
        raise SystemExit(msg)
    return value


def _payload_of(resp: httpx.Response, leg: str) -> object:
    """Parse a response, failing with a readable diagnostic on non-200.

    During bring-up a down service answers with an HTML/text error page;
    parsing that as JSON would crash with a raw traceback instead of telling
    the operator which leg failed and what came back.
    """
    if resp.status_code != httpx.codes.OK:
        print(f"  {leg}: status={resp.status_code} body={resp.text[:500]}")
        msg = f"{leg} returned status {resp.status_code}"
        raise SystemExit(msg)
    return resp.json()


def _bare_fetch_binding_leg(signed: str, *, enforce: bool) -> None:
    """Fetch the agent-bound signed URL WITHOUT proof of possession.

    The staging stack always mints agent-bound URLs, so a URL without the
    agent_id binding is itself a failure regardless of edge enforcement.

    The expected outcome depends on how the edge under test is deployed:

    - enforce=True (the production posture): the edge must REFUSE the bare
      fetch (403). This is the proof that binding is actually enforced, not
      merely that the happy path works.
    - enforce=False (edge deployed with ramp_enforce_binding = "false"): the
      signed URL alone is sufficient, so the bare fetch must DELIVER the origin
      body (200 + canary marker).
    """
    if "agent_id=" not in signed:
        print(f"  retrievalEndpoint={signed}")
        msg = "signed URL carries no agent binding — staging must mint agent-bound URLs"
        raise SystemExit(msg)
    bare = httpx.get(signed, follow_redirects=True, timeout=30.0)
    if enforce:
        if bare.status_code != httpx.codes.FORBIDDEN:
            print(f"  bare fetch: status={bare.status_code} body={bare.text[:200]}")
            msg = "edge accepted an agent-bound URL without proof of possession"
            raise SystemExit(msg)
        print("  bare fetch refused (403) — agent binding enforced")
        return
    if bare.status_code != httpx.codes.OK or CANARY_MARKER not in bare.text:
        print(f"  bare fetch: status={bare.status_code} body={bare.text[:200]}")
        msg = "edge did not deliver the signed URL with binding enforcement off"
        raise SystemExit(msg)
    print("  bare fetch delivered (200) — agent binding not enforced")


def main() -> None:
    exchange_url = _require_env("RAMP_STAGING_EXCHANGE_URL")
    broker_url = _require_env("RAMP_STAGING_BROKER_URL")
    publisher = _require_env("RAMP_STAGING_PUBLISHER")
    agent_id = _require_env("RAMP_STAGING_AGENT_ID")
    agent_key = Path(_require_env("RAMP_STAGING_AGENT_KEY"))
    if not agent_key.is_file():
        msg = f"agent key not found: {agent_key}"
        raise SystemExit(msg)

    # Whether the edge under test enforces agent-key proof-of-possession.
    # Defaults to False, matching the staging edge deployed with
    # ramp_enforce_binding = "false": the bare-fetch leg then expects delivery
    # (200). Set RAMP_STAGING_ENFORCE_BINDING=true for an edge that enforces
    # binding, where the bare fetch is refused (403). Only the exact string
    # "true" enables the enforcement expectation.
    enforce_binding = os.environ.get("RAMP_STAGING_ENFORCE_BINDING", "false") == "true"

    # Only the exchange and broker URLs are consumed by the harness helpers
    # used here (fetch_signed follows the signed URL's own hostname over real
    # DNS, so no edge field is read). The empty strings satisfy the tuple
    # shape on purpose: if a future helper reads one of them, it fails fast
    # on an invalid URL rather than silently hitting the wrong endpoint.
    stack = StackURLs(
        exchange=exchange_url,
        exchange_b="",
        exchange_c="",
        broker=broker_url,
        edge="",
        aws_edge="",
        fastly_edge="",
        identity="",
        zitadel="",
    )

    print("== item 1: licensed discovery for socrates ==")
    socrates = f"https://{publisher}/articles/philosophers/socrates.txt"
    resp = resolve(
        stack,
        {"agent_id": agent_id, "uri": socrates, "intended_use": "ai-input"},
        key_path=agent_key,
    )
    payload = _payload_of(resp, "socrates resolve")
    # Resolve is discovery-only: a licensed discovery is a NON-EMPTY offer
    # group for the requested uri (never a retrievalEndpoint — that is minted
    # at execute time).
    offers_by_uri = offer_exchanges_by_uri(payload)
    if not offers_by_uri.get(socrates):
        print(f"  body={resp.text}")
        msg = "socrates discovery returned no offers (empty offer group)"
        raise SystemExit(msg)
    print(f"  offers from exchange(s): {sorted(offers_by_uri[socrates])}")

    print("== item 2: execute canary offer -> signed URL -> edge fetch ==")
    canary = f"https://{publisher}/articles/philosophers/thales-of-miletus.txt"
    # Two-phase mint: Broker Resolve (discovery) then relay-execute the
    # winning Offer; the Exchange mints the agent-bound signed URL on the
    # TransactionResponse items[0].
    resp = execute_first_offer(
        stack,
        {"agent_id": agent_id, "uri": canary, "intended_use": "ai-input"},
        agent_id=agent_id,
        domain=publisher,
        key_path=agent_key,
    )
    payload = _payload_of(resp, "canary execute")
    item = first_item_of(payload)
    if item is None:
        print(f"  body={resp.text}")
        msg = "canary execute response carried no items[0]"
        raise SystemExit(msg)
    signed = retrieval_endpoint_of(item)
    print(f"  retrievalEndpoint={signed}")
    if not signed:
        print(f"  body={resp.text}")
        msg = "canary execute returned no retrievalEndpoint"
        raise SystemExit(msg)

    # Binding leg first: fetch the agent-bound URL WITHOUT proof of possession.
    # The expected outcome (refused vs delivered) tracks how the edge under
    # test is deployed — see RAMP_STAGING_ENFORCE_BINDING above.
    _bare_fetch_binding_leg(signed, enforce=enforce_binding)

    # Happy path: real DNS, real TLS — the signed URL's hostname IS the
    # deployed edge worker's route. fetch_signed merges the PoP headers
    # (X-RAMP-Agent-Key + RFC 9421 GET signature) and asserts 200 + marker.
    try:
        content = fetch_signed(signed, stack, expect_marker=CANARY_MARKER, key_path=agent_key)
    except AssertionError as err:
        # Deliberate: fetch_signed asserts internally (it is harness code);
        # converting to SystemExit turns a traceback into a readable smoke
        # failure. The explicit re-check below keeps the proof valid even
        # under `python -O`, where those asserts vanish.
        msg = f"edge delivery failed: {err}"
        raise SystemExit(msg) from err
    # Re-checked explicitly: fetch_signed's internal asserts vanish under
    # `python -O`, and this is the proof the smoke exists for.
    if content.status_code != httpx.codes.OK or CANARY_MARKER not in content.text:
        print(f"  edge fetch: status={content.status_code} body={content.text[:200]}")
        msg = "edge delivery did not return the canary body"
        raise SystemExit(msg)
    print(f"  CANARY FOUND: {CANARY_MARKER}")
    print("\nSTAGING SMOKE PASSED")


if __name__ == "__main__":
    main()
