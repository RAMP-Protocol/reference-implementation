"""Host-side rewriting of compose-internal edge hosts in signed URLs.

Compose-internal hosts (``edge:8787`` etc.) appear inside the signed URLs the
Broker returns. When the tests run from the host (``RAMP_E2E_IN_NETWORK``
unset), those DNS names do not resolve; :func:`host_url` rewrites the netloc to
the host-published port reported by ``compose_stack`` so the TCP connection can
land on the edge container.

Signature contract (verified 2026-05-20)
------------------------------------------------------
- Exchange-side: ``src/exchange/internal/signing/signed_url.go:66`` builds the
  canonical as ``GET\\n<full URL minus sig>`` — scheme + host + path + query.
- Edge-side: ``src/edge/src/verify.ts:122-126`` mirrors that exactly via
  ``canonicalMessage(url)``, where ``url`` is parsed from ``c.req.url``
  (``app.ts:58``).

So the canonical payload covers the FULL URL, NOT just path+query. A bare
netloc rewrite for host-side fetch produces an HTTP request whose Host header
reflects the host-published port (e.g. ``127.0.0.1:58009``), which means
Workerd reconstructs ``c.req.url`` with that authority and the signature check
fails with ``signature_mismatch``.

Callers that ACTUALLY FETCH the rewritten URL through the edge must therefore
also stamp a ``Host:`` header matching the original signed netloc (e.g.
``edge:8787``) — see
``tests/e2e/harness/obligations/test_00_happy_03_usage_record_paid_access.py``
for the canonical pattern (post-a9esw.4). :func:`host_url` rewrites the URL
only; callers carry the Host header themselves.
"""

from __future__ import annotations

from .stack_urls import StackURLs

_COMPOSE_INTERNAL_EDGE_HOSTS: tuple[tuple[str, str], ...] = (
    ("http://edge:8787", "edge"),
    ("http://aws-edge:8788", "aws_edge"),
    ("http://fastly-edge:7676", "fastly_edge"),
)


def host_url(signed: str, compose_stack: StackURLs) -> str:
    """Rewrite a broker-returned signed URL's netloc for host-side fetch.

    Returns the rewritten URL only. Callers that fetch this URL through the
    edge's signature verifier MUST also pass a ``Host`` header equal to the
    original signed netloc (e.g. ``edge:8787``); the signature canonical covers
    the full URL — see the module docstring above.
    """
    for compose_host, attr in _COMPOSE_INTERNAL_EDGE_HOSTS:
        if compose_host in signed:
            return signed.replace(compose_host, getattr(compose_stack, attr))
    return signed


__all__ = ["host_url"]
