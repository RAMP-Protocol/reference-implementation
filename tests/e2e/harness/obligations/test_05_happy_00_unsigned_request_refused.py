"""Obligation 05 — happy 00: an unsigned request is refused.

Verbatim scenario (``docs/obligations/05-system-refuses-when-authority-is-bad.md``,
first happy-path bullet — for obligation 05 the "happy path" IS the
refusal, because refusal is the product):

> The agent presents a /ramp.v1.* request with no Signature or
> Signature-Input headers (and the path is one where v1 expects a
> signature). The platform refuses the request and says the signature
> is missing or unsigned.

The test drives a canonical-RPC POST against the Exchange with NO
``Signature`` and NO ``Signature-Input`` headers, then asserts:

1. The platform refuses (non-2xx OR error body — never a 200-with-
   offers).
2. The refusal reason names the missing signature (one of
   ``{missing, absent, unsigned, signature-input, signature, signed}``).
   Together with the canonical Connect ``code: unauthenticated`` body
   the httpsig middleware writes, the refusal is specific enough that
   a buyer operator can tell "I forgot to sign" apart from "I signed
   wrong".

Production status (post-A10, as of 2026-05-19)
----------------------------------------------

The Exchange's RFC 9421 middleware lives at
``internal/httpsig/interceptor.go``. The predicate
``exchangeGlobalSigRequestPredicate`` at
``src/exchange/cmd/server/main.go:225-234`` currently verifies a
``/ramp.v1.*`` request only when a ``Signature-Input`` header is
already present. A wholly-unsigned ``/ramp.v1.*`` call is allowed
through to the handler; the service layer then runs its own gates
(billing, scope, anonymous-execute relaxation). The unsigned call
therefore reaches the canonical-error path inside the handler, not
the httpsig 401. That meets the obligation's "platform refuses"
clause (refusal IS produced) but only conditionally meets
"specifically names missing signature".

The post-A10 desired behaviour is for the predicate to require the
header on the v1 paths the obligation cares about — at which point
the refusal is the httpsig 401 with
``ErrMissingSignatureInput`` / ``ErrMissingSignature`` in the
message. Until that is wired, the test is marked
``xfail(strict=True)`` with the production-gap citation; once the
predicate flips it becomes a regression guard.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from ..conftest import StackURLs

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "The agent presents a /ramp.v1.* request with no Signature or "
    "Signature-Input headers (and the path is one where v1 expects a "
    "signature). The platform refuses the request and says the "
    "signature is missing or unsigned."
)

_PRODUCTION_GAP = (
    "exchangeGlobalSigRequestPredicate at "
    "src/exchange/cmd/server/main.go:225-234 verifies /ramp.v1.* only "
    "when Signature-Input is present. A wholly-unsigned /ramp.v1.* "
    "DiscoverResources POST passes the predicate and reaches the "
    "handler unverified; the resulting refusal — when one is produced "
    "— comes from the service layer (billing/scope/anonymous-execute), "
    "not from httpsig. Until the predicate is tightened to require the "
    "header on the v1 paths this obligation covers (httpsig.Middleware "
    "emits a Connect-Unauthenticated body whose message contains "
    "'missing Signature-Input' / 'missing Signature' verbatim), the "
    "refusal does not specifically name the missing signature."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"

# Two-category token gate. Either category alone is insufficient:
# 'missing' on its own could match a missing scope or a missing
# resource; the conjunction with a signature-naming token is what
# makes the refusal specific to "you didn't sign me".
_MISSING_TOKENS: tuple[str, ...] = ("missing", "absent", "unsigned", "no signature")
_SIG_TOKENS: tuple[str, ...] = (
    "signature",
    "signature-input",
    "signed",
    "rfc 9421",
    "httpsig",
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


def test_unsigned_canonical_rpc_is_refused_with_signature_specific_reason(
    compose_stack: StackURLs,
) -> None:
    """An unsigned DiscoverResources call is refused, naming the missing signature.

    Every assertion below traces directly to obligation-05 happy-00:

    1. ``the platform refuses`` — non-2xx OR an error surface in the
       body (a 200 with an offer list would be a defect, the request
       was unauthenticated).
    2. ``says the signature is missing or unsigned`` — the refusal
       reason matches a missing-ness token AND a signature-naming
       token, so a buyer operator can tell this apart from a missing-
       scope refusal or a missing-resource refusal.
    """
    body = {"requester": {"uris": ["http://edge:8787/premium/any.html"]}}
    url = f"{compose_stack.exchange}{_DISCOVER_PATH}"
    # No Signature-Input, no Signature, no Content-Digest, no
    # Authorization. This is the "unsigned request" input.
    resp = httpx.post(url, json=body, timeout=30.0)

    # (1) The platform refuses.
    payload = _parse_payload(resp)
    is_non_2xx = not (200 <= resp.status_code < 300)
    served_offers = bool(payload and payload.get("offers"))
    assert is_non_2xx or not served_offers, (
        f"expected a refusal for an unsigned /ramp.v1.* call; "
        f"got {resp.status_code} payload={payload!r} body={resp.text[:512]}"
    )

    # (2) The refusal reason names the missing signature specifically.
    haystack = _refusal_haystack(resp)
    hit_missing = next((t for t in _MISSING_TOKENS if t in haystack), None)
    hit_sig = next((t for t in _SIG_TOKENS if t in haystack), None)
    assert hit_missing is not None and hit_sig is not None, (
        f"refusal must name the missing signature — expected one of "
        f"{list(_MISSING_TOKENS)} AND one of {list(_SIG_TOKENS)}; "
        f"got missing={hit_missing!r} sig={hit_sig!r} "
        f"body={resp.text[:512]} payload={payload!r}"
    )
