"""Two-phase Broker-relay execute producer for the E2E suites (re-package).

Why this exists
---------------
On the modern protocol line the AGENT originates ExecuteTransaction, and under the
re-package model it is topology-decoupled from the Exchange. Phase 2 of
the relay flow is: the agent reflects the discovered, signed Offer onto
``TransactionRequest.offer``, detached-signs an ``AgentAcceptance`` over that offer
(R4 made acceptance REQUIRED at execute), serializes the request ONCE,
RFC 9421-signs those exact bytes (sig1) against the **Broker relay route** it POSTs
to (NOT the Exchange URL — the agent never knows or signs over an Exchange
endpoint), then POSTs the identical bytes to ``POST /broker/v1/exchange/execute``.
The Broker verifies sig1 as received, reads the signed ``offer.exchange`` from the
body, resolves the Exchange endpoint via that exchange's own ``/.well-known/ramp.json``,
RE-PACKAGES a fresh broker-signed ExecuteTransaction, and the Exchange verifies the
offer signature + the acceptance and binds the signed retrieval URL to the agent's
proven key. Routing flows entirely from the first-class signed ``Offer.exchange``.

The body is serialized exactly once and the SAME bytes are both signed and posted —
re-marshaling would change the bytes and break the agent's Content-Digest binding
(and sig1), which the Broker reconstructs and verifies.

Public surface
--------------
:func:`relay_execute` — phase 2: build + sign + relay one discovered Offer,
returning the raw ``httpx.Response`` so callers own their status/body assertions.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import httpx

from ramp_sdk.core import sign_offer_acceptance_jcs
from .httpsig_signer import load_keypair
from .signing import (
    AGENT_E2E_KEY_PATH,
    build_signed_headers,
)

_RELAY_ROUTE = "/broker/v1/exchange/execute"


def relay_execute(
    broker_url: str,
    offer: dict[str, Any],
    *,
    agent_id: str,
    domain: str,
    key_path: Path = AGENT_E2E_KEY_PATH,
    idempotency_key: str | None = None,
    timeout: float = 30.0,
) -> httpx.Response:
    """Phase 2: relay-execute one discovered ``offer`` (re-package).

    Reflects the FULL discovered ``offer`` verbatim onto ``TransactionRequest.offer``
    (the tightened proto verifies ``offer.signature`` over the exact
    presented bytes — XOR ``items``), detached-signs an ``AgentAcceptance`` over
    ``offer.signature`` + ``requester`` + ``idempotency_key``, then
    sig1-signs the serialized body against the **Broker relay route** and POSTs the
    SAME bytes there. ``key_path`` MUST match ``agent_id`` — both sig1's keyID and
    the acceptance key are this agent (the Exchange binds the response to the agent
    that signed the acceptance). The broker derives the Exchange target from the
    signed ``offer.exchange`` in the body, so no Exchange URL is supplied.

    Returns the raw ``httpx.Response`` (a successful relay carries the Exchange's
    ``TransactionResponse`` with the agent-bound ``retrievalEndpoint`` in
    ``items[0]``); callers own the status/body verdict and read ``items[0]``.

    A single offer is the degenerate 1-element batch — this folds
    onto :func:`relay_execute_batch` so the wire body is a 1-item ``items[]`` (never
    the deprecated top-level ``offer``/``agentAcceptance``). The agent-facing
    signature is unchanged; only the wire shape collapses onto the batch envelope.
    """
    resp, _ = relay_execute_batch(
        broker_url,
        [offer],
        agent_id=agent_id,
        domain=domain,
        key_path=key_path,
        idempotency_key=idempotency_key,
        timeout=timeout,
    )
    return resp


def relay_execute_batch(
    broker_url: str,
    offers: list[dict[str, Any]],
    *,
    agent_id: str,
    domain: str,
    key_path: Path = AGENT_E2E_KEY_PATH,
    idempotency_key: str | None = None,
    timeout: float = 30.0,
) -> tuple[httpx.Response, bytes]:
    """Batch relay: relay-execute a BATCH of discovered ``offers``.

    Builds ONE ``TransactionRequest`` carrying ``items[]`` (offer absent), one
    item per ``offer`` — each item reflects the FULL discovered offer and carries
    its own detached ``AgentAcceptance`` signed over THAT offer's signature + the
    SHARED requester + the SHARED ``idempotency_key`` (Core Invariant: the broker
    forwards each item byte-identical, so every item's acceptance still verifies at
    the exchange it routes to). The agent sig1-signs the serialized body against
    the Broker relay route and POSTs the SAME bytes; the broker groups the items by
    each item's signed ``offer.exchange``, fans out one broker-signed sub-request
    per exchange, and merges the per-exchange ``items[]`` back in original order.

    Returns ``(response, payload)`` — the raw ``httpx.Response`` (a successful
    batch carries a 200 ``TransactionResponse`` with one ``items[]`` entry per
    offer, in original order; per-item denials stay in-body) AND the exact body
    bytes posted, so callers can assert the inbound batch body stays under the
    broker's 64 KiB pre-auth bound. ``key_path`` MUST match ``agent_id``.
    """
    idem = idempotency_key or f"tx-{uuid.uuid4().hex}"
    _, priv = load_keypair(key_path)
    requester = {"id": agent_id, "domain": domain, "type": "REQUESTER_TYPE_AGENT"}

    items: list[dict[str, Any]] = []
    for offer in offers:
        offer_signature = offer.get("signature")
        assert offer_signature, f"discovered offer carries no signature: {offer!r}"
        acceptance_sig, acceptance_alg = sign_offer_acceptance_jcs(
            seed=priv.private_bytes_raw(),
            offer_sig=str(offer_signature),
            requester_id=agent_id,
            requester_domain=domain,
            idempotency_key=idem,
        )
        items.append(
            {
                "offer": offer,
                "agent_acceptance": {
                    "signature": acceptance_sig,
                    "signature_algorithm": acceptance_alg,
                },
            }
        )

    body: dict[str, Any] = {
        "ver": "1.0",
        "idempotency_key": idem,
        "requester": requester,
        "items": items,
    }
    payload = json.dumps(body, separators=(",", ":")).encode()
    relay_url = f"{broker_url}{_RELAY_ROUTE}"
    headers = build_signed_headers(
        method="POST",
        target_uri=relay_url,
        body=payload,
        key_path=key_path,
    )
    return httpx.post(relay_url, content=payload, headers=headers, timeout=timeout), payload


__all__ = ["relay_execute", "relay_execute_batch"]
