"""Obligation 05 — happy 01: a signature from an unknown signer is refused.

Verbatim scenario (second happy-path bullet):

> The agent presents a signature whose keyid is not advertised in any
> known /.well-known/ramp.json. The platform refuses the request and
> says the signer is unknown.

The test forges a syntactically valid RFC 9421 signature with a
freshly-generated Ed25519 keypair whose ``kid`` is NOT registered in
any agent's hosted ``ramp.json``. The signature itself is well-formed
— the platform must refuse at the **resolver** layer because it
cannot find a public key for the named ``kid``, not at the parser
layer. This is the load-bearing observable: the refusal must
distinguish "I cannot find your key" from "I do not understand your
signature bytes".

Assertions:

1. The platform refuses (non-2xx OR error body).
2. The refusal reason names the unknown signer (one of ``{unknown,
   unrecognized, not registered, no such key}`` combined with one of
   ``{kid, keyid, key, signer, agent}``).
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from ..conftest import StackURLs
from ..httpsig_signer import generate_random_keypair, sign_request

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "The agent presents a signature whose keyid is not advertised in "
    "any known /.well-known/ramp.json. The platform refuses the "
    "request and says the signer is unknown."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"

_UNKNOWN_TOKENS: tuple[str, ...] = (
    "unknown",
    "unrecognized",
    "not registered",
    "no such",
)
_KEY_TOKENS: tuple[str, ...] = ("kid", "keyid", "key", "signer", "agent")


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


def test_unknown_signer_is_refused_with_specific_reason(
    compose_stack: StackURLs,
) -> None:
    """A well-formed signature from an unregistered key is refused at the resolver.

    Every assertion below traces directly to obligation-05 happy-01:

    1. ``the platform refuses`` — non-2xx OR error body.
    2. ``says the signer is unknown`` — the refusal reason names the
       unknown signer with a two-category match
       (unknown-ness × key-naming).
    """
    body_obj = {"requester": {}, "uris": ["http://edge:8787/premium/any.html"]}
    body = json.dumps(body_obj, separators=(",", ":")).encode()

    kid, priv = generate_random_keypair("ghost-agent-not-in-any-ramp-json")
    url = f"{compose_stack.exchange}{_DISCOVER_PATH}"
    signed = sign_request(method="POST", target_uri=url, body=body, kid=kid, priv=priv)
    headers = {**signed.headers, "Content-Type": "application/json"}

    resp = httpx.post(url, content=body, headers=headers, timeout=30.0)

    # (1) The platform refuses.
    payload = _parse_payload(resp)
    is_non_2xx = not (200 <= resp.status_code < 300)
    served_offers = bool(payload and payload.get("offers"))
    assert is_non_2xx or not served_offers, (
        f"expected a refusal for a signature from an unregistered kid; "
        f"got {resp.status_code} payload={payload!r} body={resp.text[:512]}"
    )

    # (2) The refusal reason names the unknown signer specifically.
    haystack = _refusal_haystack(resp)
    hit_unknown = next((t for t in _UNKNOWN_TOKENS if t in haystack), None)
    hit_key = next((t for t in _KEY_TOKENS if t in haystack), None)
    assert hit_unknown is not None and hit_key is not None, (
        f"refusal must name the unknown signer — expected one of "
        f"{list(_UNKNOWN_TOKENS)} AND one of {list(_KEY_TOKENS)}; "
        f"got unknown={hit_unknown!r} key={hit_key!r} "
        f"body={resp.text[:512]} payload={payload!r}"
    )
