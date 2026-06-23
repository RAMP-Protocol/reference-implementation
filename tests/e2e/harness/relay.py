"""Shared producers for the RAMP-56 two-phase Broker-relay flow.

Why this exists
---------------
Five e2e tests independently rebuilt the discovery RAMPRequest body and the
"sign a TransactionRequest with the Exchange ``@target-uri``, then POST it to
the Broker relay" block. The copies had drifted on real contract fields —
``requester.domain`` present in some and absent in others, ``offerSignature``
conditional in some and unconditional in others — exactly the silent
divergence the repo's "shared fixtures, not copy-pasted" rule exists to
prevent. This module is the single producer of both request shapes.

Public surface
--------------
:func:`build_resolve_body` — build a canonical RAMPRequest body for discovery.
:func:`resolve` — POST a signed RAMPRequest to ``/broker/v1/resolve``.
:func:`relay_execute` — phase 2: sign a TransactionRequest with the Exchange
``@target-uri`` and POST it to the Broker relay endpoint.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import httpx

from .signing import (
    AGENT_E2E_KEY_PATH,
    EXCHANGE_ENDPOINT_HEADER,
    build_signed_headers,
    sign_post,
)


def build_resolve_body(
    agent_id: str, *, uri: str | None = None, query: str | None = None
) -> dict[str, Any]:
    """Build a canonical RAMPRequest body for ``/broker/v1/resolve`` (discovery).

    The per-call unique ``id`` keeps the signed bytes — hence the Content-Digest
    and the signature — distinct, so the Broker's (keyID, signature) replay store
    never treats two resolves of the same {agent, uri} as a duplicate. The Broker
    decodes the body with a DiscardUnknown protojson decoder, so forward-
    compatible extras are ignored.
    """
    requester: dict[str, Any] = {"id": agent_id}
    if uri:
        requester["uris"] = [uri]
    body: dict[str, Any] = {
        "ver": "1.0",
        "id": f"rampreq-{uuid.uuid4().hex}",
        "requester": requester,
    }
    if query:
        body["query"] = query
    return body


def resolve(
    broker_url: str, body: dict[str, Any], *, key_path: Path = AGENT_E2E_KEY_PATH
) -> httpx.Response:
    """POST a signed canonical RAMPRequest to ``/broker/v1/resolve`` as the agent.

    The Broker requires every ``/broker/v1/*`` call to carry a valid RFC 9421
    signature whose keyID equals the request's ``requester.id`` (self-act); the
    default ``AGENT_E2E_KEY_PATH`` signs as ``agent-e2e`` (kid == requester.id),
    the identity the seed both credits and registers.
    """
    return sign_post(f"{broker_url}/broker/v1/resolve", body=body, key_path=key_path)


def build_transaction_body(
    *,
    agent_id: str,
    offer_id: str,
    offer_signature: str | None = None,
    domain: str | None = None,
    tx_request_id: str | None = None,
) -> dict[str, Any]:
    """Build a RAMP TransactionRequest body for the relay execute phase.

    ``offer_signature`` and ``domain`` are included only when truthy, so one
    shape serves both the always-set obligation callers and the conditional
    full-stack/multisig callers without re-diverging. ``tx_request_id`` defaults
    to a fresh ``tx-<uuid>`` when not supplied.
    """
    requester: dict[str, Any] = {"id": agent_id, "type": "REQUESTER_TYPE_AGENT"}
    if domain:
        requester["domain"] = domain
    body: dict[str, Any] = {
        "ver": "1.0",
        "id": tx_request_id or f"tx-{uuid.uuid4().hex}",
        "offerId": offer_id,
        "requester": requester,
    }
    if offer_signature:
        body["offerSignature"] = offer_signature
    return body


def relay_execute(
    *,
    broker_url: str,
    exchange_endpoint: str,
    agent_id: str,
    offer_id: str,
    offer_signature: str | None = None,
    domain: str | None = None,
    tx_request_id: str | None = None,
    key_path: Path = AGENT_E2E_KEY_PATH,
    timeout: float = 30.0,
) -> httpx.Response:
    """RAMP-56 phase 2: sign a TransactionRequest with the Exchange ``@target-uri``
    (the final destination, per the RFC 9421 relay pattern — the signature must
    cover where it is verified, the Exchange, not the intermediate Broker hop)
    and POST it to the Broker relay endpoint. The Broker preserves the agent's
    sig1 and appends its own sig2 (multisig). Returns the raw ``httpx.Response``
    so callers own their own status/body assertions.
    """
    body = build_transaction_body(
        agent_id=agent_id,
        offer_id=offer_id,
        offer_signature=offer_signature,
        domain=domain,
        tx_request_id=tx_request_id,
    )
    payload = json.dumps(body, separators=(",", ":")).encode()
    exchange_url = f"{exchange_endpoint}/ramp.v1.ExchangeService/ExecuteTransaction"
    headers = build_signed_headers(
        method="POST", target_uri=exchange_url, body=payload, key_path=key_path
    )
    headers[EXCHANGE_ENDPOINT_HEADER] = exchange_endpoint
    return httpx.post(
        f"{broker_url}/broker/v1/exchange/execute",
        content=payload,
        headers=headers,
        timeout=timeout,
    )


__all__ = [
    "build_resolve_body",
    "build_transaction_body",
    "relay_execute",
    "resolve",
]
