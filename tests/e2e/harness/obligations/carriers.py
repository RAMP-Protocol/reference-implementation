"""Canonical signed-URL carrier helpers for obligation e2e tests.

Single source of truth for reading ``TransactionResponse.retrieval_endpoint``
(field 18; protojson camelCase ``retrievalEndpoint``, snake fallback for any
UseProtoNames config) and asserting the legacy ``ext['signed_url']`` carrier is
gone after the move to the canonical field. The Go side consolidated on
``extractSignedURL``; this is its Python sibling.
"""

from __future__ import annotations


def retrieval_endpoint_of(payload: object) -> str | None:
    """Return the canonical signed URL from a TransactionResponse payload, or None.

    Reads the top-level ``retrievalEndpoint`` (protojson camelCase) with a
    ``retrieval_endpoint`` snake fallback. Returns None for a non-dict payload or
    an absent/empty field — never raises.
    """
    if not isinstance(payload, dict):
        return None
    value = payload.get("retrievalEndpoint") or payload.get("retrieval_endpoint")
    if isinstance(value, str) and value:
        return value
    return None


def assert_signed_url(payload: object) -> str:
    """Assert the canonical URL is present and the legacy carrier is gone; return it.

    Happy-path obligation contract: the response MUST carry a non-empty top-level
    ``retrievalEndpoint`` and MUST NOT carry the legacy ``ext['signed_url']`` slot
    (removed when the URL moved to the canonical field). Returns the non-empty
    signed URL for the caller to fetch.
    """
    url = retrieval_endpoint_of(payload)
    assert url, f"signed URL missing from response (canonical retrievalEndpoint): {payload!r}"
    ext = payload.get("ext") if isinstance(payload, dict) else None
    assert not (isinstance(ext, dict) and ext.get("signed_url")), (
        f"legacy ext['signed_url'] must no longer be populated: {payload!r}"
    )
    return url
