"""Obligation 05 — happy 02: an expired or future-dated signature is refused.

Verbatim scenario (third happy-path bullet):

> The agent presents a signature whose ``created`` parameter is too
> far in the future, or whose ``expires`` parameter is in the past.
> The platform refuses the request and says the signature is expired
> (or future-dated beyond skew).

This module covers BOTH halves of the timestamp-window contract:

- :func:`test_expired_signature_is_refused_with_specific_reason`
  constructs a signature whose ``created`` is far in the past and
  whose ``expires`` is also in the past — the classic stale-token
  shape, and the input the verifier's ``ErrExpired`` is meant to
  refuse.
- :func:`test_future_created_signature_is_refused_with_specific_reason`
  constructs a signature whose ``created`` is beyond the future-skew
  window (currently ``maxFutureSkew = 300s``) — the input the
  verifier's ``ErrFutureCreated`` is meant to refuse.

Both halves run through ``enforceCreatedExpires`` at
``internal/httpsig/verifier.go:185-200``.

Assertions (per test):

1. The platform refuses (non-2xx OR error body).
2. The refusal reason names the timestamp-window violation (one of
   ``{expired, expir, stale, expires, future, created}``).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from ramp_sdk import ProtocolVersion

from ..conftest import StackURLs
from ..httpsig_signer import load_keypair, sign_request
from ..seed import CONTRIBUTOR_KEY_PATH

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "The agent presents a signature whose created parameter is too "
    "far in the future, or whose expires parameter is in the past. "
    "The platform refuses the request and says the signature is "
    "expired (or future-dated beyond skew)."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"

_EXPIRED_TOKENS: tuple[str, ...] = (
    "expired",
    "expir",
    "stale",
    "expires",
)

# Future-created vocabulary covers the future-skew half. Matches the
# wrapped wording from ErrFutureCreated at
# internal/httpsig/verifier.go:46-48 + the literal 'created' param.
_FUTURE_CREATED_TOKENS: tuple[str, ...] = (
    "future",
    "created",
    "skew",
    "ahead",
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
        f"{CONTRIBUTOR_KEY_PATH}; this test signs with a registered "
        "kid so the resolver path is not the gate under test — the "
        "fixture is required to isolate the expires/created gate"
    ),
)
def test_expired_signature_is_refused_with_specific_reason(
    compose_stack: StackURLs,
) -> None:
    """A signature whose expires is in the past is refused as expired.

    Every assertion below traces directly to obligation-05 happy-02:

    1. ``the platform refuses`` — non-2xx OR error body.
    2. ``says the signature is expired`` — the refusal reason names
       the expired signature (token from the EXPIRED bucket).
    """
    body_obj = {
        "ver": ProtocolVersion,
        "requester": {},
        "uris": ["http://edge:8787/premium/any.html"],
    }
    body = json.dumps(body_obj, separators=(",", ":")).encode()

    kid, priv = load_keypair(CONTRIBUTOR_KEY_PATH)
    url = f"{compose_stack.exchange}{_DISCOVER_PATH}"
    now = int(time.time())
    # created = 10 minutes ago, expires = 5 minutes ago. Past the
    # 5-minute future-skew window AND past the expires gate, so the
    # signature is unambiguously stale.
    signed = sign_request(
        method="POST",
        target_uri=url,
        body=body,
        kid=kid,
        priv=priv,
        created=now - 600,
        expires=now - 300,
    )
    headers = {**signed.headers, "Content-Type": "application/json"}

    resp = httpx.post(url, content=body, headers=headers, timeout=30.0)

    # (1) The platform refuses.
    payload = _parse_payload(resp)
    is_non_2xx = not (200 <= resp.status_code < 300)
    served_offers = bool(payload and payload.get("offers"))
    assert is_non_2xx or not served_offers, (
        f"expected a refusal for an expired signature; "
        f"got {resp.status_code} payload={payload!r} body={resp.text[:512]}"
    )

    # (2) The refusal reason names the expired signature specifically.
    haystack = _refusal_haystack(resp)
    hit_expired = next((t for t in _EXPIRED_TOKENS if t in haystack), None)
    assert hit_expired is not None, (
        f"refusal must name the expired signature — expected one of "
        f"{list(_EXPIRED_TOKENS)}; got nothing in body={resp.text[:512]} "
        f"payload={payload!r}"
    )


@pytest.mark.skipif(
    not Path(CONTRIBUTOR_KEY_PATH).is_file(),
    reason=(
        "catalog-contributor key fixture not present at "
        f"{CONTRIBUTOR_KEY_PATH}; this test signs with a registered "
        "kid so the resolver path is not the gate under test — the "
        "fixture is required to isolate the created/skew gate"
    ),
)
def test_future_created_signature_is_refused_with_specific_reason(
    compose_stack: StackURLs,
) -> None:
    """A signature whose ``created`` is beyond the future-skew window is refused.

    Every assertion below traces directly to obligation-05 happy-02's
    future-dated half:

    1. ``the platform refuses`` — non-2xx OR error body.
    2. ``says the signature is ... future-dated beyond skew`` — the
       refusal reason names the future-created violation (token from
       the EXPIRED ∪ FUTURE-CREATED buckets, since both halves share
       a timestamp-window vocabulary).
    """
    body_obj = {
        "ver": ProtocolVersion,
        "requester": {},
        "uris": ["http://edge:8787/premium/any.html"],
    }
    body = json.dumps(body_obj, separators=(",", ":")).encode()

    kid, priv = load_keypair(CONTRIBUTOR_KEY_PATH)
    url = f"{compose_stack.exchange}{_DISCOVER_PATH}"
    now = int(time.time())
    # maxFutureSkew at internal/httpsig/verifier.go:59 is 300s. Push
    # created beyond that window (now + maxSkew + 60s) so it is
    # unambiguously future-dated; expires is set further ahead so the
    # only timestamp gate that can fire is ErrFutureCreated.
    signed = sign_request(
        method="POST",
        target_uri=url,
        body=body,
        kid=kid,
        priv=priv,
        created=now + 360,
        expires=now + 660,
    )
    headers = {**signed.headers, "Content-Type": "application/json"}

    resp = httpx.post(url, content=body, headers=headers, timeout=30.0)

    # (1) The platform refuses.
    payload = _parse_payload(resp)
    is_non_2xx = not (200 <= resp.status_code < 300)
    served_offers = bool(payload and payload.get("offers"))
    assert is_non_2xx or not served_offers, (
        f"expected a refusal for a future-created signature beyond skew; "
        f"got {resp.status_code} payload={payload!r} body={resp.text[:512]}"
    )

    # (2) The refusal reason names the timestamp-window violation.
    haystack = _refusal_haystack(resp)
    combined_tokens = _EXPIRED_TOKENS + _FUTURE_CREATED_TOKENS
    hit = next((t for t in combined_tokens if t in haystack), None)
    assert hit is not None, (
        f"refusal must name the future-created violation — expected one "
        f"of {list(combined_tokens)}; got nothing in body={resp.text[:512]} "
        f"payload={payload!r}"
    )
