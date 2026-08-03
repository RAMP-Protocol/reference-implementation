"""Obligation 05 — failure 07: refusal reasons are distinct per cause.

Verbatim scenario (third failure-mode bullet):

> The platform refuses but cannot explain why. This is a defect; the
> refusal reason must be specific enough for a buyer operator to fix
> the problem at their end.

Cross-cutting implementation hint from the same obligation:

> each failure case must be reproducible as an automated test, and
> each must produce a distinct, machine-readable refusal reason so
> operator tooling can triage. A single generic "unauthenticated"
> outcome for all of these is a defect.

This test is the regression guard for the *collapsed refusals* defect.
It exercises all five obligation-05 bad-signature scenarios inline
and asserts each refusal reason carries a distinct category token.
If every refusal collapses to the same generic string
(``unauthenticated`` standing alone is the exact defect), the test
captures exactly that collapse as its failure mode.

Assertions:

1. Every refusal reason is non-empty after whitespace strip — the
   "refuses but cannot explain why" defect in its most literal form.
2. No refusal reason is ONLY a generic token (one of
   ``{unauthorized, denied, unauthenticated, bad request}`` standing
   alone is forbidden).
3. Each refusal carries at least one category token distinguishing
   it from the other four — unsigned vs unknown-signer vs expired
   vs tampered-body vs replay each draw from their own
   vocabulary bucket.
4. The set of matched category tokens across the five calls has
   size ≥ 3 — a floor (realistically 5) that still catches the
   all-refusals-collapse-to-one-message defect.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
import pytest

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
    "The platform refuses but cannot explain why. This is a defect; "
    "the refusal reason must be specific enough for a buyer operator "
    "to fix the problem at their end. Each failure case must produce "
    "a distinct, machine-readable refusal reason so operator tooling "
    "can triage. A single generic outcome for all of these is a defect."
)

_PRODUCTION_GAP = (
    "internal/httpsig/verifier.go + interceptor.go define distinct "
    "sentinel errors (ErrMissingSignatureInput, ErrUnknownKey, "
    "ErrExpired, ErrDigestMismatch, ErrReplayed) that map to distinct "
    "wrapped error-message strings in the Connect-Unauthenticated "
    "body. The token vocabulary this test matches against is drawn "
    "directly from those error strings. The refusal is reachable when "
    "the predicate at src/exchange/cmd/server/main.go:225-234 admits "
    "signed v1 calls; the 'unsigned' scenario additionally requires "
    "the predicate to be tightened to require a signature on the v1 "
    "paths under test (see test_05_happy_00 _PRODUCTION_GAP). The "
    "'replay' scenario requires a priming first call inside the test "
    "so the (keyid, signature) pair is in the replay store before the "
    "under-test second call (interceptor.go:132-138)."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"

# Generic refusal tokens that, standing alone as the entire reason,
# fail the specificity contract. Matched after case-folding and
# whitespace-stripping.
_GENERIC_ONLY_REASONS: frozenset[str] = frozenset(
    {"bad request", "unauthorized", "denied", "unauthenticated"}
)

# Per-scenario category buckets. Each tuple is the vocabulary a
# specific refusal for that scenario MUST draw from.
_UNSIGNED_TOKENS: tuple[str, ...] = (
    "missing signature",
    "signature-input",
    "unsigned",
    "no signature",
    "absent",
)
_UNKNOWN_SIGNER_TOKENS: tuple[str, ...] = (
    "unknown",
    "unrecognized",
    "not registered",
    "no such",
)
_EXPIRED_TOKENS: tuple[str, ...] = (
    "expired",
    "expir",
    "stale",
    "future",
)
_TAMPERED_BODY_TOKENS: tuple[str, ...] = (
    "digest",
    "mismatch",
    "tampered",
    "content-digest",
)
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


def _extract_reason(resp: httpx.Response) -> str:
    """Return the canonical refusal-reason string for specificity checks."""
    try:
        payload = resp.json()
    except json.JSONDecodeError:
        return resp.text.strip()
    if isinstance(payload, dict):
        for key in ("message", "reason", "detail", "error"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return resp.text.strip()


def _first_token_hit(haystack: str, tokens: tuple[str, ...]) -> str | None:
    for token in tokens:
        if token in haystack:
            return token
    return None


def _build_unsigned(*, body: bytes) -> dict[str, str]:
    return {"Content-Type": "application/json"}


def _build_unknown_signer(*, body: bytes, url: str) -> dict[str, str]:
    kid, priv = generate_random_keypair("ghost-distinct-defect-guard")
    signed = sign_request(method="POST", target_uri=url, body=body, kid=kid, priv=priv)
    return {**signed.headers, "Content-Type": "application/json"}


def _build_expired(*, body: bytes, url: str) -> dict[str, str]:
    kid, priv = load_keypair(CONTRIBUTOR_KEY_PATH)
    now = int(time.time())
    signed = sign_request(
        method="POST",
        target_uri=url,
        body=body,
        kid=kid,
        priv=priv,
        created=now - 600,
        expires=now - 300,
    )
    return {**signed.headers, "Content-Type": "application/json"}


def _build_tampered(*, signed_body: bytes, url: str) -> dict[str, str]:
    kid, priv = load_keypair(CONTRIBUTOR_KEY_PATH)
    signed = sign_request(method="POST", target_uri=url, body=signed_body, kid=kid, priv=priv)
    return {**signed.headers, "Content-Type": "application/json"}


def _build_replay_headers(*, body: bytes, url: str) -> dict[str, str]:
    """Build signed headers used twice — second call is the replay under test.

    Caller must issue a priming first call against ``url`` with these
    headers and body BEFORE the under-test second call so the
    (keyid, signature) pair is in the replay store.
    """
    kid, priv = load_keypair(CONTRIBUTOR_KEY_PATH)
    signed = sign_request(method="POST", target_uri=url, body=body, kid=kid, priv=priv)
    return {**signed.headers, "Content-Type": "application/json"}


@pytest.mark.skipif(
    not Path(CONTRIBUTOR_KEY_PATH).is_file(),
    reason=(
        "catalog-contributor key fixture not present at "
        f"{CONTRIBUTOR_KEY_PATH}; the expired/tampered/garbage-sig "
        "scenarios all need a registered kid to isolate their gates "
        "from the resolver gate"
    ),
)
def test_five_bad_signature_refusals_are_specific_and_distinct(
    compose_stack: StackURLs,
) -> None:
    """All five v1 bad-signature refusals are non-empty, non-generic, and distinct."""
    body_obj = {"requester": {}, "uris": ["http://edge:8787/premium/distinct-defect-guard.html"]}
    body = json.dumps(body_obj, separators=(",", ":")).encode()
    body_b_obj = {"requester": {}, "uris": ["http://edge:8787/premium/tampered.html"]}
    body_b = json.dumps(body_b_obj, separators=(",", ":")).encode()
    replay_body_obj = {"requester": {}, "uris": ["http://edge:8787/premium/replay-distinct.html"]}
    replay_body = json.dumps(replay_body_obj, separators=(",", ":")).encode()
    url = f"{compose_stack.exchange}{_DISCOVER_PATH}"

    # Scenario 1: unsigned
    resp_unsigned = httpx.post(url, content=body, headers=_build_unsigned(body=body), timeout=30.0)

    # Scenario 2: unknown signer
    resp_unknown = httpx.post(
        url, content=body, headers=_build_unknown_signer(body=body, url=url), timeout=30.0
    )

    # Scenario 3: expired
    resp_expired = httpx.post(
        url, content=body, headers=_build_expired(body=body, url=url), timeout=30.0
    )

    # Scenario 4: tampered body — sign body but send body_b.
    resp_tampered = httpx.post(
        url, content=body_b, headers=_build_tampered(signed_body=body, url=url), timeout=30.0
    )

    # Scenario 5: replay — prime the (keyid, signature) pair with a
    # first call, then issue the under-test second call with identical
    # headers and body. The second call's refusal must name the replay.
    replay_headers = _build_replay_headers(body=replay_body, url=url)
    _ = httpx.post(url, content=replay_body, headers=replay_headers, timeout=30.0)
    resp_replay = httpx.post(url, content=replay_body, headers=replay_headers, timeout=30.0)

    scenarios: list[tuple[str, httpx.Response, tuple[str, ...]]] = [
        ("unsigned", resp_unsigned, _UNSIGNED_TOKENS),
        ("unknown-signer", resp_unknown, _UNKNOWN_SIGNER_TOKENS),
        ("expired", resp_expired, _EXPIRED_TOKENS),
        ("tampered-body", resp_tampered, _TAMPERED_BODY_TOKENS),
        ("replay", resp_replay, _REPLAY_TOKENS),
    ]

    # (1) Every reason is non-empty after whitespace strip.
    for scenario, resp, _tokens in scenarios:
        reason = _extract_reason(resp)
        assert reason, (
            f"{scenario}: refusal reason is empty after whitespace strip "
            f"(status={resp.status_code}, body={resp.text[:512]!r})"
        )

    # (2) No reason is *only* a generic token.
    for scenario, resp, _tokens in scenarios:
        reason = _extract_reason(resp)
        normalized = reason.casefold().strip(".: ")
        assert normalized not in _GENERIC_ONLY_REASONS, (
            f"{scenario}: refusal reason is only a generic token "
            f"({normalized!r}) — body={resp.text[:512]!r}"
        )

    # (3) Each scenario surfaces at least one token from its own bucket.
    per_scenario_hits: dict[str, str] = {}
    missing_hits: list[str] = []
    for scenario, resp, tokens in scenarios:
        haystack = _refusal_haystack(resp)
        hit = _first_token_hit(haystack, tokens)
        if hit is None:
            missing_hits.append(
                f"{scenario}: no token from {list(tokens)} in body={resp.text[:512]!r}"
            )
        else:
            per_scenario_hits[scenario] = hit
    assert not missing_hits, (
        "refusal reasons are not specific enough to triage — "
        "obligation requires a distinct, machine-readable refusal "
        "per mode: " + "; ".join(missing_hits)
    )

    # (4) The set of category tokens matched across the five calls has size ≥ 3.
    distinct_tokens = set(per_scenario_hits.values())
    assert len(distinct_tokens) >= 3, (
        f"only {len(distinct_tokens)} distinct category token(s) "
        f"across five bad-signature scenarios ({sorted(distinct_tokens)}); "
        f"obligation implementation hint: 'a single generic outcome "
        f"for all of these is a defect'. Per-scenario hits: "
        f"{per_scenario_hits!r}"
    )
