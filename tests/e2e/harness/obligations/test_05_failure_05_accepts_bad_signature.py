"""Obligation 05 — failure 05: platform accepts a bad signature (DEFECT guard).

Verbatim scenario (first failure-mode bullet):

> The platform accepts a bad signature. This is a defect and must be
> caught before release.

This test is a **regression guard for the negation**. The platform
must NEVER accept any of the five "bad signature" shapes the
obligation enumerates in its happy-path section:

1. ``unsigned`` — no ``Signature`` / ``Signature-Input`` headers.
2. ``unknown-signer`` — well-formed signature whose ``kid`` is not
   registered.
3. ``expired`` — well-formed signature whose ``expires`` is in the
   past.
4. ``tampered-body`` — well-formed signature whose ``Content-Digest``
   does not match the wire body.
5. ``replay`` — exact ``(keyid, signature)`` pair the platform has
   already accepted within the replay window.

For each variant the test issues a POST against the canonical RPC
surface (``DiscoverResources``) and asserts the response is NOT a
``200`` with a populated ``offers`` list. A populated offers list on
a request the obligation says must be refused is the precise defect
the platform must never ship.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from ramp_sdk import ProtocolVersion

from ..conftest import StackURLs
from ..httpsig_signer import (
    generate_random_keypair,
    load_keypair,
    sign_request,
)
from ..seed import CONTRIBUTOR_KEY_PATH

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "The platform accepts a bad signature. This is a defect and must be caught before release."
)

_PRODUCTION_GAP = (
    "DEFECT-GUARD — this test should pass against ANY correctly-"
    "behaving build. A regression that wires a bypass into "
    "exchangeGlobalSigRequestPredicate at "
    "src/exchange/cmd/server/main.go:225-234 OR removes the verifier "
    "checks in internal/httpsig/verifier.go would cause one or more "
    "variants to start returning a populated offers list — at which "
    "point this test fails loudly. It is not xfail."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"


@dataclass(frozen=True)
class _BadSignatureVariant:
    """One concrete "bad signature" shape the platform must refuse."""

    name: str
    description: str
    # Headers to stamp on the request. The bad-signature variant
    # constructs these so the request is well-formed at the HTTP layer
    # but bad at the signature layer.
    headers: dict[str, str]
    # Body bytes sent on the wire.
    body: bytes


def _build_variants(*, exchange_url: str) -> list[_BadSignatureVariant]:
    """Assemble the five bad-signature variants."""
    variants: list[_BadSignatureVariant] = []
    body_obj = {
        "ver": ProtocolVersion,
        "requester": {},
        "uris": ["http://edge:8787/premium/regression-guard.html"],
    }
    body = json.dumps(body_obj, separators=(",", ":")).encode()
    url = f"{exchange_url}{_DISCOVER_PATH}"

    # (a) Unsigned — no headers at all.
    variants.append(
        _BadSignatureVariant(
            name="unsigned",
            description="no Signature / Signature-Input headers at all",
            headers={"Content-Type": "application/json"},
            body=body,
        )
    )

    # (b) Unknown signer — well-formed signature from an unregistered kid.
    ghost_kid, ghost_priv = generate_random_keypair("ghost-bad-sig-defect-guard")
    ghost_signed = sign_request(
        method="POST", target_uri=url, body=body, kid=ghost_kid, priv=ghost_priv
    )
    variants.append(
        _BadSignatureVariant(
            name="unknown-signer",
            description="well-formed sig with kid not in any ramp.json",
            headers={**ghost_signed.headers, "Content-Type": "application/json"},
            body=body,
        )
    )

    # (c) Expired — only meaningful if we have a registered kid; otherwise
    # the resolver rejects before the timestamp gate. The fixture is gated
    # at use-site with a skipif on the calling test.
    if Path(CONTRIBUTOR_KEY_PATH).is_file():
        kid, priv = load_keypair(CONTRIBUTOR_KEY_PATH)
        now = int(time.time())
        expired_signed = sign_request(
            method="POST",
            target_uri=url,
            body=body,
            kid=kid,
            priv=priv,
            created=now - 600,
            expires=now - 300,
        )
        variants.append(
            _BadSignatureVariant(
                name="expired",
                description="well-formed sig whose expires is in the past",
                headers={**expired_signed.headers, "Content-Type": "application/json"},
                body=body,
            )
        )

        # (d) Tampered body — sign body A, send body B.
        body_b_obj = {
            "ver": ProtocolVersion,
            "requester": {},
            "uris": ["http://edge:8787/premium/different.html"],
        }
        body_b = json.dumps(body_b_obj, separators=(",", ":")).encode()
        signed_a = sign_request(method="POST", target_uri=url, body=body, kid=kid, priv=priv)
        variants.append(
            _BadSignatureVariant(
                name="tampered-body",
                description="body bytes do not match signed Content-Digest",
                headers={**signed_a.headers, "Content-Type": "application/json"},
                body=body_b,
            )
        )

        # (e) Replay — exact (kid, signature) pair previously accepted
        # inside the replay window. The variant carries headers from a
        # signed request; the test driver issues a priming first call
        # before the under-test second call so the second call is the
        # replay the platform must refuse.
        replay_body_obj = {
            "ver": ProtocolVersion,
            "requester": {},
            "uris": ["http://edge:8787/premium/replay-defect.html"],
        }
        replay_body = json.dumps(replay_body_obj, separators=(",", ":")).encode()
        replay_signed = sign_request(
            method="POST", target_uri=url, body=replay_body, kid=kid, priv=priv
        )
        variants.append(
            _BadSignatureVariant(
                name="replay",
                description=(
                    "exact (keyid, signature) pair already accepted within "
                    "the replay window — driver issues a priming call first"
                ),
                headers={**replay_signed.headers, "Content-Type": "application/json"},
                body=replay_body,
            )
        )

    return variants


def _refusal_verdict(resp: httpx.Response) -> tuple[bool, str]:
    """Return (refused, why) — the obligation-faithful contract.

    A positive refusal is one of:
      * 4xx, OR
      * 2xx with an empty/absent ``offers`` list, OR
      * 2xx with an ``error`` / ``error_message`` / ``error_code``
        field populated.

    A 2xx with a populated ``offers`` list — even a single offer —
    means the platform accepted a bad signature, which is the exact
    defect this guard fails on.
    """
    if 400 <= resp.status_code < 500:
        return True, f"HTTP {resp.status_code}"
    if resp.status_code >= 500:
        return False, f"HTTP {resp.status_code} server error — not a refusal"
    try:
        payload = resp.json()
    except json.JSONDecodeError:
        return False, f"HTTP {resp.status_code} non-JSON body — ambiguous"
    if not isinstance(payload, dict):
        return False, f"HTTP {resp.status_code} non-dict body — ambiguous"
    if not payload.get("offers"):
        return True, "empty offers"
    for key in ("error", "error_message", "error_code"):
        if payload.get(key):
            return True, f"{key}={payload[key]!r}"
    return False, (
        f"HTTP {resp.status_code} with populated offers — defect: offers={payload.get('offers')!r}"
    )


@pytest.mark.parametrize(
    "variant_name",
    [
        "unsigned",
        "unknown-signer",
        "expired",
        "tampered-body",
        "replay",
    ],
)
def test_platform_refuses_every_bad_signature_variant(
    compose_stack: StackURLs,
    variant_name: str,
) -> None:
    """Every bad-signature variant is refused on DiscoverResources.

    A single variant slipping through fails the test with the variant
    name and the response body — exactly the defect surface obligation
    05 demands be regression-guarded.
    """
    variants = {v.name: v for v in _build_variants(exchange_url=compose_stack.exchange)}
    if variant_name not in variants:
        pytest.skip(
            f"variant {variant_name!r} requires the catalog-contributor key "
            f"fixture at {CONTRIBUTOR_KEY_PATH}, which is not present"
        )
    variant = variants[variant_name]

    url = f"{compose_stack.exchange}{_DISCOVER_PATH}"

    # The replay variant requires a priming first call so the
    # (keyid, signature) pair is registered in the replay store;
    # the under-test POST is the SECOND call with identical headers
    # and body, which the platform must refuse with ErrReplayed.
    if variant.name == "replay":
        _ = httpx.post(url, content=variant.body, headers=variant.headers, timeout=30.0)

    resp = httpx.post(url, content=variant.body, headers=variant.headers, timeout=30.0)
    refused, why = _refusal_verdict(resp)
    assert refused, (
        f"DEFECT — Exchange DiscoverResources did NOT refuse a bad "
        f"signature (variant={variant.name!r}: {variant.description}). "
        f"Verdict: {why}. Obligation 05 requires refusal — a 200 with "
        f"a populated offers list against a bad-signature request is "
        f"exactly the defect this guard exists to catch. Response body "
        f"(truncated): {resp.text[:512]}"
    )
