"""Obligation 05 — happy 05: a covered-header mismatch is refused.

Verbatim scenario (sixth-bullet covered-headers clause from the "What this is" enumeration):

> One or more of the covered headers the signature names is absent
> or differs from the value the verifier sees.

And from the implementation-hints section:

> ``ErrMissingRequiredComponent`` — covered-header mismatch (one of
> the required components — ``@method``, ``@target-uri``,
> ``content-digest``, ``authorization`` — was not committed to).

This test constructs a syntactically valid RFC 9421 signature whose
``Signature-Input`` covered-components list deliberately OMITS one of
the platform's required components (``authorization``). The signature
itself verifies cleanly against the canonical base the signer
constructed, but the verifier's ``enforceRequiredComponents`` at
``internal/httpsig/verifier.go:155-166`` MUST refuse with
``ErrMissingRequiredComponent`` because the covered set is missing a
required member.

Assertions:

1. The platform refuses (non-2xx OR error body).
2. The refusal reason names the covered-component mismatch (one of
   ``{required, component, covered, missing, authorization}``).
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ramp_sdk import ProtocolVersion

from ..conftest import StackURLs
from ..httpsig_signer import load_keypair
from ..seed import CONTRIBUTOR_KEY_PATH

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "One or more of the covered headers the signature names is absent "
    "or differs from the value the verifier sees. The platform refuses "
    "with a covered-component-missing reason."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"

# The vocabulary the refusal MUST draw from. Drawn from the wrapped
# error wording in internal/httpsig/verifier.go:155-166 + the missing
# component name itself.
_COVERED_MISMATCH_TOKENS: tuple[str, ...] = (
    "required",
    "component",
    "covered",
    "missing",
    "authorization",
)


def _sign_without_authorization(
    *,
    method: str,
    target_uri: str,
    body: bytes,
    kid: str,
    priv: Ed25519PrivateKey,
) -> dict[str, str]:
    """Build a RFC 9421 signature whose covered list omits ``authorization``.

    This deliberately diverges from the production signer in
    :mod:`httpsig_signer` (which always includes the full required
    set) — the divergence is the point. The verifier's
    ``enforceRequiredComponents`` MUST refuse this construction with
    ``ErrMissingRequiredComponent: authorization``.
    """
    now = int(time.time())
    created = now
    expires = now + 30

    digest_header = "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"
    # Covered list deliberately omits "authorization" — a required component.
    covered = ("@method", "@target-uri", "content-digest")
    covered_list = " ".join(f'"{c}"' for c in covered)
    sig_params = f'({covered_list});keyid="{kid}";alg="ed25519";created={created};expires={expires}'
    base_lines = [
        f'"@method": {method.upper()}',
        f'"@target-uri": {target_uri}',
        f'"content-digest": {digest_header}',
        f'"@signature-params": {sig_params}',
    ]
    base = "\n".join(base_lines)
    sig = priv.sign(base.encode())
    sig_b64 = base64.b64encode(sig).decode()
    return {
        "Content-Digest": digest_header,
        "Authorization": "",
        "Signature-Input": f"sig1={sig_params}",
        "Signature": f"sig1=:{sig_b64}:",
    }


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
        f"{CONTRIBUTOR_KEY_PATH}; the test must sign with a registered "
        "kid so the covered-components gate is the layer under test "
        "(not the resolver gate)"
    ),
)
def test_covered_header_mismatch_is_refused_with_specific_reason(
    compose_stack: StackURLs,
) -> None:
    """A signature whose covered list omits ``authorization`` is refused.

    Every assertion below traces directly to obligation-05's
    covered-headers clause:

    1. ``the platform refuses`` — non-2xx OR error body.
    2. The refusal reason names the covered-component mismatch
       (a token from the COVERED_MISMATCH bucket).
    """
    body_obj = {
        "ver": ProtocolVersion,
        "requester": {},
        "uris": ["http://edge:8787/premium/covered-mismatch.html"],
    }
    body = json.dumps(body_obj, separators=(",", ":")).encode()

    kid, priv = load_keypair(CONTRIBUTOR_KEY_PATH)
    url = f"{compose_stack.exchange}{_DISCOVER_PATH}"
    sig_headers = _sign_without_authorization(
        method="POST", target_uri=url, body=body, kid=kid, priv=priv
    )
    headers = {**sig_headers, "Content-Type": "application/json"}

    resp = httpx.post(url, content=body, headers=headers, timeout=30.0)

    # (1) The platform refuses.
    payload = _parse_payload(resp)
    is_non_2xx = not (200 <= resp.status_code < 300)
    served_offers = bool(payload and payload.get("offers"))
    assert is_non_2xx or not served_offers, (
        f"expected a refusal for a signature whose covered list omits a "
        f"required component (authorization); got {resp.status_code} "
        f"payload={payload!r} body={resp.text[:512]}"
    )

    # (2) The refusal reason names the covered-component mismatch.
    haystack = _refusal_haystack(resp)
    hit = next((t for t in _COVERED_MISMATCH_TOKENS if t in haystack), None)
    assert hit is not None, (
        f"refusal must name the covered-component mismatch — expected "
        f"one of {list(_COVERED_MISMATCH_TOKENS)}; got nothing in "
        f"body={resp.text[:512]} payload={payload!r}"
    )
