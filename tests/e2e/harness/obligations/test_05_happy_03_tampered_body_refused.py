"""Obligation 05 — happy 03: a tampered body is refused.

Verbatim scenario (fourth happy-path bullet):

> The agent presents a request whose body bytes do not match the
> Content-Digest the signature commits to. The platform refuses the
> request and says the body has been tampered (digest mismatch).

This test signs the request body ``A`` and then sends body ``B`` —
the digest header still commits to ``A`` but the wire payload is
``B``. The verifier's ``verifyContentDigest`` at
``internal/httpsig/httpsig.go:262-285`` (called from
``internal/httpsig/verifier.go:125``) MUST detect the mismatch and
refuse with ``ErrDigestMismatch``.

Assertions:

1. The platform refuses (non-2xx OR error body).
2. The refusal reason names the digest mismatch (one of
   ``{digest, mismatch, tampered, content-digest, body}``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from ..conftest import StackURLs
from ..httpsig_signer import load_keypair, sign_request
from ..seed import CONTRIBUTOR_KEY_PATH

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "The agent presents a request whose body bytes do not match the "
    "Content-Digest the signature commits to. The platform refuses "
    "the request and says the body has been tampered (digest "
    "mismatch)."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"

_DIGEST_TOKENS: tuple[str, ...] = (
    "digest",
    "mismatch",
    "tampered",
    "content-digest",
    "body",
)


def _flatten_strings(obj: object, out: list[str]) -> None:
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _flatten_strings(v, out)
    elif isinstance(obj, list):
        for item in obj:
            _flatten_strings(item, out)


def _refusal_haystack(resp: httpx.Response) -> str:
    candidates: list[str] = [resp.text]
    try:
        payload = resp.json()
    except json.JSONDecodeError:
        return " ".join(candidates).lower()
    _flatten_strings(payload, candidates)
    return " ".join(candidates).lower()


def _parse_payload(resp: httpx.Response) -> dict[str, Any] | None:
    try:
        payload = resp.json()
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


@pytest.mark.skipif(
    not Path(CONTRIBUTOR_KEY_PATH).is_file(),
    reason=(
        "catalog-contributor key fixture not present at "
        f"{CONTRIBUTOR_KEY_PATH}; the test must sign with a "
        "registered kid so the digest-mismatch gate is the layer "
        "under test (not the resolver)"
    ),
)
def test_tampered_body_is_refused_with_digest_mismatch(
    compose_stack: StackURLs,
) -> None:
    """Body bytes that don't match Content-Digest are refused.

    Every assertion below traces directly to obligation-05 happy-03:

    1. ``the platform refuses`` — non-2xx OR error body.
    2. ``says the body has been tampered`` — the refusal reason names
       the digest mismatch with a token from the DIGEST bucket.
    """
    # Sign body A — the digest header commits to A's bytes.
    body_a_obj = {"requester": {}, "uris": ["http://edge:8787/premium/article-a.html"]}
    body_a = json.dumps(body_a_obj, separators=(",", ":")).encode()

    # The wire payload is body B — different URI, different bytes,
    # different SHA-256. The signature still commits to body A.
    body_b_obj = {"requester": {}, "uris": ["http://edge:8787/premium/article-b.html"]}
    body_b = json.dumps(body_b_obj, separators=(",", ":")).encode()
    assert body_a != body_b, "pre-condition: tampered body must differ from signed body"

    kid, priv = load_keypair(CONTRIBUTOR_KEY_PATH)
    url = f"{compose_stack.exchange}{_DISCOVER_PATH}"
    signed = sign_request(method="POST", target_uri=url, body=body_a, kid=kid, priv=priv)
    headers = {**signed.headers, "Content-Type": "application/json"}

    # Send body B with the signature that committed to body A.
    resp = httpx.post(url, content=body_b, headers=headers, timeout=30.0)

    # (1) The platform refuses.
    payload = _parse_payload(resp)
    is_non_2xx = not (200 <= resp.status_code < 300)
    served_offers = bool(payload and payload.get("offers"))
    assert is_non_2xx or not served_offers, (
        f"expected a refusal for a body that does not match the signed "
        f"Content-Digest; got {resp.status_code} payload={payload!r} "
        f"body={resp.text[:512]}"
    )

    # (2) The refusal reason names the digest mismatch specifically.
    haystack = _refusal_haystack(resp)
    hit_digest = next((t for t in _DIGEST_TOKENS if t in haystack), None)
    assert hit_digest is not None, (
        f"refusal must name the digest mismatch — expected one of "
        f"{list(_DIGEST_TOKENS)}; got nothing in body={resp.text[:512]} "
        f"payload={payload!r}"
    )
