"""Shared edge-fetch helper for the E2E suites (Phase 2b).

Under Phase 2b every demo publisher domain resolves in-network to its edge on
port 80 via a docker-compose network alias, so a broker-returned signed URL
(``http://demo.ramp-protocol.org/...``) is fetched DIRECTLY — no netloc rewrite,
no Host override (both are forbidden). This helper is therefore a pass-through
in the in-network runner; it exists as a single seam so suites do not each
reimplement the (now trivial) fetch-target resolution.
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx

from .stack_urls import StackURLs
from .signing import build_pop_headers


def edge_fetch_target(signed: str, compose_stack: StackURLs) -> tuple[str, dict[str, str]]:
    """Return ``(url, headers)`` to fetch a broker-returned signed URL.

    In-network (the runner) the demo domain resolves to its edge on port 80, so
    the signed URL is fetched verbatim with no extra headers. Host runs (no
    ``RAMP_E2E_IN_NETWORK``) cannot resolve the demo domains without /etc/hosts
    entries; the suites' primary execution mode is in-network.
    """
    del compose_stack  # in-network: the demo domain resolves natively
    if os.environ.get("RAMP_E2E_IN_NETWORK") == "1":
        return signed, {}
    # Host fallback: the demo domains do not resolve off the compose network.
    # Returning the URL unchanged lets a host run surface a clear DNS error
    # rather than silently rewriting to the wrong authority (the Host-override
    # trick is forbidden). Run the suite in-network (`make test-e2e`).
    return signed, {}


def fetch_signed(
    signed: str,
    compose_stack: StackURLs,
    *,
    expect_marker: str | None = None,
    timeout: float = 30.0,
    key_path: Path | None = None,
) -> httpx.Response:
    """Fetch a broker-returned signed URL via the edge; assert 200 (+ optional marker).

    The single home for the happy-path content-delivery idiom: resolve the
    fetch target via :func:`edge_fetch_target`, GET it (following redirects),
    assert HTTP 200, and — when ``expect_marker`` is given — assert the marker
    appears in the body (a 200 edge error-stub or a wrong-route body must fail).
    Returns the response so callers can make further assertions.

    ADR-013: a relay-minted ed25519 URL is BOUND to the executing
    agent's thumbprint (the ``agent_id=`` query param). When ``key_path`` is set
    AND the URL carries ``agent_id=``, proof-of-possession headers
    (X-RAMP-Agent-Key + an RFC 9421 GET signature over @method + @target-uri,
    signed with that agent key) are merged into the request before the GET. The
    ed25519 edges enforce the 3-way identity (agent_id == keyid ==
    thumbprint(presented key)); the key MUST be the SAME agent key the Exchange
    bound the URL to at execute time. Without it an agent-bound URL is refused
    403 (``missing_agent_key``). AWS CloudFront-RSA URLs carry no binding (no
    ``agent_id=``) and need no key — the guard skips PoP for them.

    Negative-path fetches that assert a non-200 outcome (e.g. a tampered-URL
    403) keep their bespoke ``httpx.get`` — they are not content delivery.
    """
    url, headers = edge_fetch_target(signed, compose_stack)
    if key_path is not None and "agent_id=" in url:
        headers = {**headers, **build_pop_headers(url=url, key_path=key_path)}
    resp = httpx.get(url, headers=headers, follow_redirects=True, timeout=timeout)
    assert resp.status_code == httpx.codes.OK, (
        f"signed URL fetch must return 200, got {resp.status_code}: {resp.text[:256]}"
    )
    if expect_marker is not None:
        assert expect_marker in resp.text, (
            f"delivered body missing expected marker {expect_marker!r}: {resp.text[:256]}"
        )
    return resp
