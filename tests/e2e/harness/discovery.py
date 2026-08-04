"""The one DiscoverResources request body the harness sends.

Every signed ``ResourceQuery`` the E2E suite issues is built here. Two
properties make a single builder worth having rather than a shape each caller
retypes:

**A fresh query id per call is load-bearing, not cosmetic.** The RFC 9421
signature base covers ``@method``, ``@target-uri``, ``content-digest``,
``authorization`` and ``signature-agent``, plus the parameters ``keyid``,
``alg``, ``created`` and ``expires``. It carries no nonce, ``created`` has
one-second granularity, and Ed25519 is deterministic. So two calls that send the
same body to the same URL inside one wall-clock second produce a byte-identical
``Signature`` header, and the server's replay store — keyed on the keyid and the
signature bytes — rejects the second one with 401 "request replayed within
window". A unique ``id`` changes the Content-Digest, which changes the signature,
which makes that collision impossible. The revocation E2E was passing on exactly
that collision before this builder existed; it read the replay 401 as proof of
revocation.

**Requester.type must never be UNSPECIFIED.** The pinned proto sets enum
``not_in:[0]`` on every message carrying a Requester, ``ResourceQuery``
included — not just ``ExecuteTransaction``.

The requester's self-declared facets (``domain`` / ``user_type`` /
``geography``) are legitimate on the Exchange path: per ADR-014 the Exchange does
scope-only projection and does not filter terms by them, but they are still
carried on the wire. They are optional here because only the offer-buying flows
have anything to declare — a probe that just asks whether a URI is licensable
sends the identity and nothing else.
"""

from __future__ import annotations

import uuid
from typing import Any

DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"


def discover_body(
    *,
    uris: list[str],
    agent_id: str,
    domain: str | None = None,
    user_type: str | None = None,
    geography: str | None = None,
) -> dict[str, Any]:
    """Build a ``ResourceQuery`` body for ``uris``, asking as ``agent_id``.

    The ``id`` is fresh on every call — see the module docstring for why that is
    a correctness property and not a convenience. Facet arguments left at
    ``None`` are omitted from the requester entirely rather than sent empty.
    """
    requester: dict[str, Any] = {"id": agent_id, "type": "REQUESTER_TYPE_AGENT"}
    if domain is not None:
        requester["domain"] = domain
    if user_type is not None:
        requester["user_type"] = user_type
    if geography is not None:
        requester["geography"] = geography
    return {"id": f"q-{uuid.uuid4().hex}", "requester": requester, "uris": list(uris)}


__all__ = ["DISCOVER_PATH", "discover_body"]
