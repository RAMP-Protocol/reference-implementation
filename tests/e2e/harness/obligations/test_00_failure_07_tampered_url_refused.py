"""Obligation 00 — failure 07: tampered signed URL is refused at delivery.

Obligation file: ``docs/obligations/00-access-a-paid-resource.md``.

Scenario (verbatim — fourth failure-mode bullet):

> The URL delivered after acceptance is tampered with by the caller.
> The content is not served; the caller sees the delivery refused.

This test drives the scenario through the MCP shim's public surface
(``ramp_mcp_shim.broker.BrokerClient``) imported in-process — the team
lead's non-negotiable instruction. The flow:

1. Acceptance — call ``BrokerClient.resolve(...)`` against the seeded
   happy-path resource (``seeded.resource_uri``). The Broker's
   ``/broker/v1/resolve`` returns ``licensed=true`` plus an
   Exchange-minted Ed25519-signed URL pointing at the edge worker.
   This is the "URL delivered after acceptance" — the
   commitment surface that hands an agent a fetch URL is the same
   commitment the obligation refers to (``test_full_stack.py`` exercises
   the same shape via the same Broker call).
2. Tamper — flip a single character inside the ``sig=`` query parameter
   of the returned URL. The replacement character is forced to differ
   from the original within the base64url alphabet so the new sig is
   syntactically valid but cryptographically wrong; the edge's
   signature verification is what we want to trip, not its parser.
3. Refusal — call ``BrokerClient.fetch_content(tampered_url)``. The
   shim's content fetch raises ``BrokerError`` for any
   ``status_code >= 400``; the edge worker returns ``HTTP 403`` for a
   tampered Ed25519 signature
   (``src/edge/src/`` worker → ``crypto.subtle.verify`` failure path).

What the test asserts (each bullet traces to the scenario text):

* "the URL delivered after acceptance ..." — the Broker resolve call
  succeeds (HTTP 200, ``licensed=true``, ``signed_url`` non-empty). The
  prerequisite acceptance happens; the agent receives a real URL.
* "tampered with by the caller" — the test mutates one base64url byte
  inside ``sig=`` so the URL the caller GETs is provably not the one
  the platform issued (the original ``sig`` value is captured for the
  failure-message diagnostic).
* "the content is not served" — the fetch must NOT return the
  publisher's canary string ``content-marker-42``. ``BrokerClient.
  fetch_content`` raises ``BrokerError`` long before any body could be
  inspected, but if an implementation regression ever switched to
  returning a partial body the marker assertion is a defense-in-depth
  catch.
* "the caller sees the delivery refused" — ``BrokerError`` is raised
  AND its message carries ``403`` (the edge's verbatim verdict), so the
  refusal is observable and specific. We do not accept a 5xx, a
  connection error, or a silent empty 200 — those are not refusals.

Why this is NOT xfail:

The existing regression guard at
``tests/e2e/harness/test_full_stack.py::test_tampered_signature_is_rejected``
already proves the edge worker rejects tampered Ed25519 sigs with 403
against the same Broker-issued signed URL shape. This obligation test
drives the same path through the MCP shim's public surface — the
behavior is in production today, so we assert it strictly. If the edge
ever regressed (signature check bypass, key-id confusion, parser
permissiveness), this test fails loudly with the obligation bullet in
the failure message.

P2.00 audit note (pizh, against canonical proto at ramp.proto):

* This test exercises the BROKER public surface (``BrokerClient.resolve``
  and ``BrokerClient.fetch_content``). The resolve hop is now canonical —
  the Broker speaks ``RAMPRequest`` → ``RAMPResponse`` (proto-JSON), so the
  signed URL is read off the canonical ``retrieval_endpoint`` field. The
  obligation file (00) §"Status (R1 demo)" notes that "Failure mode 4 (URL
  tampering) is satisfied by Edge / CloudFront on the demo's AWS deployment.
  A tampered URL fails CloudFront's RSA signature check before reaching the
  origin; the caller sees an HTTP 403 from the edge. The refusal is delivered
  by the edge, not by Exchange's ``DenialReason`` vocabulary; both are valid
  refusals from the obligation's perspective." The canonical proto path ends
  at signed-URL issuance; the fetch+refusal step lives at the edge, which is
  intentionally outside the canonical proto.
* ``_OBLIGATION_TEXT`` quotes the obligation 00 fourth failure-mode
  bullet verbatim (``docs/obligations/00-access-a-paid-resource.md``).
"""

from __future__ import annotations

import asyncio
import re
import uuid
from typing import Any, cast

import httpx
import pytest

from ..conftest import COMPOSE_FILE, StackURLs
from ..seed import EDGE_PUBLIC_URL, SeededFixture, seed_stack
from ..relay import relay_execute


# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "The URL delivered after acceptance is tampered with by the caller. "
    "The content is not served; the caller sees the delivery refused."
)

_PUBLISHER_CANARY = "content-marker-42"
_BASE64URL_ALPHABET_FALLBACK = "B"
_BASE64URL_ALPHABET_FALLBACK_ALT = "C"


@pytest.fixture(scope="module")
def seeded(compose_stack: StackURLs) -> SeededFixture:
    """Reuse the session-wide stack seed (catalog row + tenant + agent).

    Module-scoped (not session) so the fixture re-runs cleanly when this
    file is invoked alone, but does no destructive setup beyond what
    ``seed_stack`` does idempotently.
    """
    return seed_stack(str(COMPOSE_FILE), compose_stack.exchange)


def _import_broker_client() -> type:
    """Import ``BrokerClient`` from the in-tree MCP shim.

    The runner image installs ``ramp_mcp_shim`` as an editable dep
    (see ``tests/e2e/Dockerfile``), so the import works inside the
    compose network without sys.path mangling. Host runs need the same
    fall-through that ``test_full_stack.py::test_mcp_ramp_fetch_returns_content``
    uses, so we replicate it here for parity with that test.
    """
    try:
        from ramp_mcp_shim.broker import BrokerClient
    except ModuleNotFoundError:  # pragma: no cover — host fallback
        import sys
        from pathlib import Path

        repo_root = Path(COMPOSE_FILE).resolve().parent
        mcp_src = repo_root / "src" / "mcp" / "src"
        if str(mcp_src) not in sys.path:
            sys.path.insert(0, str(mcp_src))
        from ramp_mcp_shim.broker import BrokerClient
    return BrokerClient


def _tamper_sig(signed_url: str) -> tuple[str, str]:
    """Return ``(tampered_url, original_sig)`` after flipping a byte in ``sig=``.

    The Ed25519-signed URL the Exchange mints carries the signature in a
    ``sig=<base64url>`` query parameter (see
    ``src/exchange/internal/signing/`` and the verifier under
    ``src/edge/``). Mutating the middle byte of that parameter — within
    the base64url alphabet — keeps the URL syntactically valid so the
    edge's parser cannot 400 us; only signature verification can refuse,
    which is the gate the obligation requires.

    Returning the original ``sig`` lets the test's failure message
    distinguish "tamper did not change the URL" (impossible by
    construction, but worth diagnosing) from "edge accepted the
    tampered URL" (the regression we exist to catch).
    """
    sig_match = re.search(r"sig=([^&]+)", signed_url)
    assert sig_match is not None, (
        f"signed URL has no sig= query param — cannot exercise the tamper path: {signed_url}"
    )
    sig_val = sig_match.group(1)
    # Empty / one-char sig would mean the issuer is broken; failing
    # loudly is the correct response.
    assert len(sig_val) >= 2, f"sig= value too short to mutate ({sig_val!r}) in {signed_url}"
    mid = len(sig_val) // 2
    replacement = (
        _BASE64URL_ALPHABET_FALLBACK
        if sig_val[mid] != _BASE64URL_ALPHABET_FALLBACK
        else _BASE64URL_ALPHABET_FALLBACK_ALT
    )
    tampered_sig = sig_val[:mid] + replacement + sig_val[mid + 1 :]
    assert tampered_sig != sig_val, f"tamper produced the same sig — flip is a no-op: {sig_val!r}"
    tampered_url = signed_url.replace(f"sig={sig_val}", f"sig={tampered_sig}")
    return tampered_url, sig_val


def _rewrite_for_host(signed_url: str, edge_url: str) -> str:
    """Rewrite the in-network edge host to the host-side mapped port.

    Inside the compose network ``edge:8787`` resolves natively; from
    the host (where pytest runs without ``RAMP_E2E_IN_NETWORK=1``) it
    does not. Mirrors the rewrite at
    ``test_00_happy_02_fetch_content.py:290`` to keep both run modes
    working with one test.
    """
    if edge_url == EDGE_PUBLIC_URL:
        return signed_url
    return signed_url.replace(EDGE_PUBLIC_URL, edge_url)


def _execute_via_relay(
    broker_url: str,
    agent_id: str,
    exchange_endpoint: str,
    offer_id: str,
    offer_signature: str,
) -> str:
    """Execute transaction via Broker relay and return signed URL.

    RAMP-56 two-phase flow: agent signs with Exchange URL (final destination),
    POSTs to Broker relay endpoint. Broker preserves agent sig1 and appends
    broker sig2 (multisig). Exchange verifies both signatures and returns
    signed URL.
    """
    resp = relay_execute(
        broker_url=broker_url,
        exchange_endpoint=exchange_endpoint,
        agent_id=agent_id,
        offer_id=offer_id,
        offer_signature=offer_signature,
    )
    assert resp.status_code == httpx.codes.OK, (
        f"ExecuteTransaction via relay failed: {resp.status_code}: {resp.text[:256]}"
    )
    tx_payload = cast(dict[str, Any], resp.json())
    signed_url = cast(str, tx_payload.get("retrievalEndpoint"))
    assert signed_url, f"ExecuteTransaction response missing retrievalEndpoint: {tx_payload}"
    return signed_url


def test_tampered_signed_url_refused_no_content_served(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Tampered Ed25519-signed URL is refused; the publisher payload never leaks.

    Drives the obligation through the MCP shim's public ``BrokerClient``
    surface in-process per the team-lead spec.

    Assertion trace:

    1. "URL delivered after acceptance" — ``BrokerClient.resolve`` for
       the seeded happy-path resource returns ``licensed=true`` and a
       non-empty ``signed_url``.
    2. "tampered with by the caller" — middle byte inside ``sig=`` is
       flipped within the base64url alphabet; the new URL is
       syntactically identical except for the cryptographic signature.
    3. "the content is not served" — the fetch must raise
       ``BrokerError`` (the shim's mapping of HTTP >= 400) AND no
       publisher-canary string surfaces.
    4. "the caller sees the delivery refused" — the raised error
       carries the edge's HTTP 403 verdict, so the refusal is
       specific (not a generic connection failure, not a silent 200).
    """
    broker_client_cls = _import_broker_client()

    # Late import keeps the module-level import surface stable when a
    # test runner discovers the file but skips it (e.g., RAMP_E2E_SKIP).
    from ramp_mcp_shim.broker import BrokerError
    from ramp_mcp_shim.models import RampRequest, Requester

    async def run() -> None:
        client = broker_client_cls(compose_stack.broker)

        # (1a) Discovery — Broker.resolve returns offers without executing.
        # A unique intended_use keeps the signed body distinct so the Broker's
        # (keyID, signature) replay store does not refuse this resolve as a
        # duplicate of another test's identical {agent, uri} within the window.
        resp = await client.resolve(
            RampRequest(
                id=f"rampreq-{uuid.uuid4().hex}",
                requester=Requester(
                    id=seeded.agent_id,
                    uris=[seeded.resource_uri],
                    intended_use=[f"e2e-{uuid.uuid4().hex}"],
                ),
            ),
        )
        assert resp.licensed is True, (
            f"prerequisite for the obligation — the agent must first "
            f"receive a 'URL delivered after acceptance' — was not met: "
            f"licensed={resp.licensed!r}, error={resp.error!r}, "
            f"resp={resp!r}"
        )

        # (1b) Extract offers from two-phase response
        offers = resp.ext.get("ramp.broker.offers", []) if resp.ext else []
        assert offers, (
            f"Broker.resolve returned licensed=true but no offers; "
            f"obligation 00 failure-7 cannot be exercised: {resp!r}"
        )
        offer = offers[0]
        offer_id = cast(str, offer.get("offer_id"))
        offer_signature = cast(str, offer.get("signature"))
        exchange_endpoint = cast(str, offer.get("exchange_endpoint"))
        assert offer_id and offer_signature and exchange_endpoint, (
            f"offer missing required fields: {offer!r}"
        )

        # (1c) Execute — agent signs with Exchange URL, POSTs to Broker relay.
        # This is the "URL delivered after acceptance" — the signed URL the
        # platform returns after transaction execution.
        signed_url = _execute_via_relay(
            compose_stack.broker,
            seeded.agent_id,
            exchange_endpoint,
            offer_id,
            offer_signature,
        )

        # (2) Tamper — flip a sig byte. The edge's parser stays happy;
        # only the cryptographic verify can refuse.
        tampered_url, original_sig = _tamper_sig(signed_url)
        host_tampered_url = _rewrite_for_host(tampered_url, compose_stack.edge)

        # (3, 4) Fetch the tampered URL via the shim's public surface.
        # Per ``BrokerClient.fetch_content`` (src/mcp/src/ramp_mcp_shim/
        # broker.py:81), any ``status_code >= 400`` raises BrokerError —
        # the shim's contract for "the delivery refused".
        with pytest.raises(BrokerError) as excinfo:
            await client.fetch_content(host_tampered_url)

        message = str(excinfo.value)
        assert "403" in message, (
            f"obligation 00 failure-7: {_OBLIGATION_TEXT} — a generic "
            f"connection failure or 5xx is not a refusal. BrokerError "
            f"did not carry the edge's HTTP 403 verdict: {message!r}; "
            f"original sig={original_sig!r}; "
            f"tampered url={host_tampered_url!r}"
        )
        assert _PUBLISHER_CANARY not in message, (
            f"obligation 00 failure-7: {_OBLIGATION_TEXT} — BrokerError "
            f"unexpectedly carries the publisher canary "
            f"{_PUBLISHER_CANARY!r}: content was served despite "
            f"signature tamper: {message!r}"
        )

    asyncio.run(run())
