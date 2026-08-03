"""Shared discover -> accept flow for the obligation happy-path tests.

De-duplicates the DiscoverResources + ExecuteTransaction request bodies and the
"first offer / assert signature" extraction that the standard USD/``sign_post``
happy-path obligation tests repeat near-verbatim.

Scope note (premise correction): the requester's self-declared facets
(``domain`` / ``userType`` / ``geography``) are KEPT on the DiscoverResources
path. Per ADR-014 the Exchange does scope-only *projection* (it does not filter
terms by these facets), but the facets are still legitimately carried on the
wire to the Exchange — only the Broker-resolve canonical ``DiscoveryRequest`` dropped
them. So this shared builder preserves them.

Bespoke flows that do NOT use this helper, by design: the obligation-04 public-
resource tests (EUR agent, their own ``_post_signed_json`` + per-response
delegation-credential assertions + per-request-offer filtering) and the
obligation-05 signature negatives.
"""

from __future__ import annotations

import copy
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import httpx

from ramp_sdk.core import sign_offer_acceptance_jcs
from ..httpsig_signer import load_keypair
from ..signing import AGENT_E2E_KEY_PATH, sign_post

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"
_EXECUTE_PATH = "/ramp.v1.ExchangeService/ExecuteTransaction"


def discover_first_offer(
    exchange_url: str,
    *,
    uri: str,
    agent_id: str,
    domain: str,
    key_path: Path | None = None,
    user_type: str = "individual",
    geography: str = "US",
) -> dict[str, Any]:
    """DiscoverResources for ``uri`` as ``agent_id``; return the first offer.

    Asserts HTTP 200 and a non-empty ``offers`` list (DiscoverResources must
    precede ExecuteTransaction). ``key_path`` selects the signing identity
    (default: the generic test signer); pass the agent's key to sign AS the
    requester. The requester facets are carried as-is (Exchange-path facets).
    """
    resp = sign_post(
        f"{exchange_url}{_DISCOVER_PATH}",
        body={
            "id": f"q-{uuid.uuid4().hex}",
            "requester": {
                "id": agent_id,
                "domain": domain,
                # The pinned proto requires Requester.type != UNSPECIFIED on
                # EVERY message carrying a Requester (enum not_in:[0]),
                # ResourceQuery included — not just ExecuteTransaction.
                "type": "REQUESTER_TYPE_AGENT",
                "user_type": user_type,
                "geography": geography,
            },
            "uris": [uri],
        },
        key_path=key_path,
    )
    assert resp.status_code == httpx.codes.OK, (
        f"DiscoverResources must return 200 (precedes ExecuteTransaction); "
        f"got {resp.status_code}: {resp.text[:512]}"
    )
    offers = cast(list[dict[str, Any]], resp.json().get("offers") or [])
    assert offers, f"DiscoverResources returned no offers for {uri!r}"
    return offers[0]


@dataclass(frozen=True)
class AcceptResult:
    """Outcome of :func:`accept_offer` — the response, its parsed body, and the
    client-generated transaction request id the caller can assert echoed back."""

    response: httpx.Response
    payload: dict[str, Any]
    transaction_id: str


def execute_offer(
    exchange_url: str,
    offer: dict[str, Any],
    *,
    agent_id: str,
    domain: str,
    key_path: Path | None = None,
    mutate: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[httpx.Response, str]:
    """POST ExecuteTransaction REFLECTING the discovered ``offer`` verbatim.

    The tightened proto removed ``offer_signature`` and now
    requires the full signed Offer on ``TransactionRequest.offer`` (XOR
    ``items``); the Exchange verifies ``offer.signature`` over the exact
    presented bytes. So the request re-presents the WHOLE discovered offer dict
    (camelCase wire shape) reflected exactly as received from discovery — the
    only contract that still verifies. ``idempotencyKey`` and
    ``requester.type`` are set (the proto now requires them).

    ``mutate`` (negative-path hook) receives a DEEP COPY of the offer and may
    edit any field in place BEFORE signing+sending; the genuine Exchange
    ``signature`` (over the ORIGINAL bytes) then no longer covers the presented
    bytes, so the Exchange rejects with SIGNATURE_INVALID. The deep copy keeps
    the caller's offer object pristine for reuse.

    Agent acceptance: ``agent_acceptance`` is REQUIRED at execute even on this
    agent-direct path. The acceptance is detached-signed over the PRESENTED
    offer's ``signature`` (which the price/expiry ``mutate`` hooks leave intact)
    + requester + idempotency_key, so the acceptance presence/verify gate passes
    and the Exchange proceeds to the offer-signature verify — the rejection the
    tampered-offer negatives assert remains SIGNATURE_INVALID, not a missing-
    acceptance refusal.

    The signing ``key_path`` MUST match ``agent_id`` (the Exchange's caller
    authz requires keyID == requester.id on ExecuteTransaction, and the agent
    acceptance binds to that same key).

    Returns ``(response, tx_request_id)`` WITHOUT asserting status — callers
    (positive vs negative) own the verdict.
    """
    presented = copy.deepcopy(offer)
    if mutate is not None:
        mutate(presented)
    offer_signature = presented.get("signature")
    assert offer_signature, f"discovered offer carries no signature: {offer!r}"
    tx_request_id = f"tx-{uuid.uuid4().hex}"
    _, priv = load_keypair(key_path or AGENT_E2E_KEY_PATH)
    acceptance_sig, acceptance_alg = sign_offer_acceptance_jcs(
        seed=priv.private_bytes_raw(),
        offer_sig=str(offer_signature),
        requester_id=agent_id,
        requester_domain=domain,
        idempotency_key=tx_request_id,
    )
    # A single offer rides the items[] envelope (NO top-level
    # offer/agentAcceptance) — the same 1-element-batch wire shape the agent-direct
    # path now shares with the broker relay. The per-item acceptance still signs
    # over the PRESENTED offer.signature + requester + shared idempotency_key.
    resp = sign_post(
        f"{exchange_url}{_EXECUTE_PATH}",
        body={
            "ver": "1.0",
            "idempotency_key": tx_request_id,
            "requester": {
                "id": agent_id,
                "domain": domain,
                "type": "REQUESTER_TYPE_AGENT",
            },
            "items": [
                {
                    "offer": presented,
                    "agent_acceptance": {
                        "signature": acceptance_sig,
                        "signature_algorithm": acceptance_alg,
                    },
                }
            ],
        },
        key_path=key_path,
    )
    return resp, tx_request_id


def accept_offer(
    exchange_url: str,
    offer: dict[str, Any],
    *,
    agent_id: str,
    domain: str,
    key_path: Path | None = None,
) -> AcceptResult:
    """ExecuteTransaction accepting ``offer`` as ``agent_id``; assert 200.

    Reflects the FULL discovered offer on ``TransactionRequest.offer``;
    the ``offer`` must carry a non-empty Exchange ``signature``. The signing
    ``key_path`` MUST match ``agent_id`` (the Exchange's caller authz requires
    keyID == requester.id on ExecuteTransaction).
    """
    resp, tx_request_id = execute_offer(
        exchange_url, offer, agent_id=agent_id, domain=domain, key_path=key_path
    )
    offer_id = cast(str, offer.get("offer_id"))
    assert resp.status_code == httpx.codes.OK, (
        f"ExecuteTransaction should succeed for offer {offer_id!r}; "
        f"got {resp.status_code}: {resp.text[:512]}"
    )
    payload = cast(dict[str, Any], resp.json())
    return AcceptResult(response=resp, payload=payload, transaction_id=tx_request_id)
