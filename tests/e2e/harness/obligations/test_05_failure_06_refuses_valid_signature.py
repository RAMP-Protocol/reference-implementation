"""Obligation 05 — failure 06: platform refuses a valid signature (DEFECT guard).

Verbatim scenario (second failure-mode bullet):

> The platform refuses a valid signature. This is a defect and must
> be caught before release. The refusal reason told to the agent
> must not leak internal details that a bad actor could use to craft
> a signature that would pass.

This test is a **regression guard for the false-positive direction**.
A correctly-implemented RFC 9421 verifier accepts a well-formed
signature from a registered ``kid`` whose ``created``/``expires``
window is current and whose ``Content-Digest`` matches the body.

The test signs a ``DiscoverResources`` POST with the registered
catalog-contributor keypair (a kid whose key its own well-known host
serves, so the verifier resolves it via per-agent discovery) and
asserts the response is NOT a Connect-Unauthenticated 401 carrying
any of the known httpsig refusal tokens.

A 401 with one of those tokens against a request the obligation
considers valid would be the precise defect this guard catches.

Note. The test does not assert a 200 — the request may legitimately
return 4xx/5xx for reasons unrelated to the signature (e.g. the
target URL is not in the catalog, the requester has no billing
arrangement). The contract under test is narrow: a valid signature
must not be refused AS A SIGNATURE failure. Status-code distinction
plus the absence of httpsig-vocabulary in the refusal body together
make that observable.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from ramp_sdk import ProtocolVersion

from ..conftest import StackURLs
from ..httpsig_signer import load_keypair, sign_request
from ..seed import CONTRIBUTOR_KEY_PATH

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "The platform refuses a valid signature. This is a defect and must be caught before release."
)

_PRODUCTION_GAP = (
    "DEFECT-GUARD — this test should pass against ANY correctly-"
    "behaving build. A regression in internal/httpsig/verifier.go "
    "(wrong covered-component set, incorrect base canonicalization, "
    "broken resolver lookup) would cause a valid signature to be "
    "refused with httpsig vocabulary in the body — at which point "
    "this test fails loudly. Not xfail."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"

# Vocabulary the httpsig middleware uses on the refusal path. A
# correctly-behaving build MUST NOT emit any of these in response to
# a valid signature.
_HTTPSIG_REFUSAL_TOKENS: tuple[str, ...] = (
    "httpsig",
    "signature verification failed",
    "missing signature",
    "missing signature-input",
    "unknown keyid",
    "digest mismatch",
    "missing required covered component",
    "signature expired",
    "signature replayed",
    "signature created in the future",
    "unsupported alg",
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


@pytest.mark.skipif(
    not Path(CONTRIBUTOR_KEY_PATH).is_file(),
    reason=(
        "catalog-contributor key fixture not present at "
        f"{CONTRIBUTOR_KEY_PATH}; this test signs a valid request and "
        "asserts it isn't refused at the signature layer — without "
        "the key it cannot construct the valid signature under test"
    ),
)
def test_valid_signature_is_not_refused_at_signature_layer(
    compose_stack: StackURLs,
) -> None:
    """A valid signature must not produce an httpsig-vocabulary refusal.

    Assertions:

    1. The Connect-Go transport does not return a 401 with the
       httpsig-middleware's wrapped error message. (4xx for other
       reasons is fine; 5xx is also fine — neither would be a
       signature-layer false positive.)
    2. The response body does not contain any token from
       :data:`_HTTPSIG_REFUSAL_TOKENS`. This is the strict observable
       — even a 200 with one of those tokens leaked into a structured
       field would be a defect, though the practical case is a 401
       whose body names the spurious httpsig failure.
    """
    body_obj = {
        "ver": ProtocolVersion,
        "requester": {},
        "uris": ["http://edge:8787/premium/regression-guard-valid.html"],
    }
    body = json.dumps(body_obj, separators=(",", ":")).encode()

    kid, priv = load_keypair(CONTRIBUTOR_KEY_PATH)
    url = f"{compose_stack.exchange}{_DISCOVER_PATH}"
    signed = sign_request(method="POST", target_uri=url, body=body, kid=kid, priv=priv)
    headers = {**signed.headers, "Content-Type": "application/json"}

    resp = httpx.post(url, content=body, headers=headers, timeout=30.0)

    haystack = _refusal_haystack(resp)
    spurious = [t for t in _HTTPSIG_REFUSAL_TOKENS if t in haystack]
    assert not spurious, (
        f"DEFECT — Exchange refused a valid signature at the signature "
        f"layer (httpsig refusal tokens present: {spurious}). Status: "
        f"{resp.status_code}. Body (truncated): {resp.text[:512]}. The "
        f"obligation requires that a valid signature MUST NOT trigger a "
        f"signature-layer refusal; other layers (billing, catalog, "
        f"scope) may still legitimately refuse, but their refusal "
        f"vocabularies must not collide with the httpsig vocabulary."
    )
