"""Obligation 05 — happy 04: a replayed signature is refused.

Verbatim scenario (``docs/obligations/05-system-refuses-when-authority-is-bad.md``,
fifth happy-path bullet):

> The agent presents a request that re-uses an exact (keyid,
> signature) pair the platform has already accepted within the replay
> window. The platform refuses the request and says the signature was
> replayed.

Production has a replay surface: the middleware passes verified
``(keyID, Signature)`` pairs to a ``ReplayStore.SeenOrAdd`` at
``internal/httpsig/interceptor.go:132-138`` with the 5-minute
``ReplayTTL`` window. A duplicate within the window returns
``ErrReplayed``. The wireup at ``internal/httpsig/wireup.go`` selects
between a Redis-backed store (production) and an in-memory store
(tests).

The test signs once, sends twice — same bytes, same headers — and
asserts that the second call is refused with a replay-specific reason.

Assertions:

1. The platform refuses the SECOND call (non-2xx OR error body); the
   first call's outcome is not part of the contract (it may succeed,
   it may be refused at a different layer).
2. The refusal reason names the replay (one of ``{replay, replayed,
   already, duplicate, seen}``).
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
    "The agent presents a request that re-uses an exact (keyid, "
    "signature) pair the platform has already accepted within the "
    "replay window. The platform refuses the request and says the "
    "signature was replayed."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"

_REPLAY_TOKENS: tuple[str, ...] = (
    "replay",
    "replayed",
    "already",
    "duplicate",
    "seen",
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
        f"{CONTRIBUTOR_KEY_PATH}; replay enforcement only fires after "
        "the first call's signature verifies, so the test must sign "
        "with a registered kid"
    ),
)
def test_replayed_signature_is_refused_with_specific_reason(
    compose_stack: StackURLs,
) -> None:
    """The second call with the same (kid, signature) is refused as replay.

    Every assertion below traces directly to obligation-05 happy-04:

    1. ``the platform refuses`` the SECOND call — non-2xx OR error
       body. The first call's outcome is not asserted: it may legally
       succeed or be refused for unrelated reasons (e.g. the resource
       is not in the catalog); the contract under test is "the EXACT
       SAME (keyid, signature) pair is not accepted twice".
    2. ``says the signature was replayed`` — the refusal reason names
       the replay with a token from the REPLAY bucket.
    """
    body_obj = {"requester": {"uris": ["http://edge:8787/premium/replay.html"]}}
    body = json.dumps(body_obj, separators=(",", ":")).encode()

    kid, priv = load_keypair(CONTRIBUTOR_KEY_PATH)
    url = f"{compose_stack.exchange}{_DISCOVER_PATH}"
    signed = sign_request(method="POST", target_uri=url, body=body, kid=kid, priv=priv)
    headers = {**signed.headers, "Content-Type": "application/json"}

    # First call — outcome unconstrained.
    _ = httpx.post(url, content=body, headers=headers, timeout=30.0)

    # Second call — same body, same headers, same signature bytes.
    # The platform must detect the replay.
    resp = httpx.post(url, content=body, headers=headers, timeout=30.0)

    # (1) The second call is refused.
    payload = _parse_payload(resp)
    is_non_2xx = not (200 <= resp.status_code < 300)
    served_offers = bool(payload and payload.get("offers"))
    assert is_non_2xx or not served_offers, (
        f"expected a refusal for a replayed (kid, signature) pair on "
        f"the second call; got {resp.status_code} payload={payload!r} "
        f"body={resp.text[:512]}"
    )

    # (2) The refusal reason names the replay specifically.
    haystack = _refusal_haystack(resp)
    hit_replay = next((t for t in _REPLAY_TOKENS if t in haystack), None)
    assert hit_replay is not None, (
        f"refusal must name the replay — expected one of "
        f"{list(_REPLAY_TOKENS)}; got nothing in body={resp.text[:512]} "
        f"payload={payload!r}"
    )
