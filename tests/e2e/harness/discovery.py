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
from pathlib import Path
from typing import Any, cast

import httpx
from ramp_sdk import ProtocolVersion

from .constants import requester
from .exchanges import recipient_of
from .signing import sign_post

DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"


def discover_body(
    *,
    uris: list[str],
    agent_id: str,
    exchange: str,
    domain: str | None = None,
    user_type: str | None = None,
    geography: str | None = None,
) -> dict[str, Any]:
    """Build a ``ResourceQuery`` body for ``uris``, asking as ``agent_id``.

    ``exchange`` is the bare identity domain of the exchange this query is
    addressed to. It is required, and it is NOT the URL the query is posted to:
    from the host those URLs are ephemeral ``127.0.0.1`` ports naming no
    exchange, and an exchange refuses a query addressed to anything other than
    its own domain. Use ``exchanges.recipient_of`` to get it from the URL being posted to.

    The ``id`` is fresh on every call — see the module docstring for why that is
    a correctness property and not a convenience. Facet arguments left at
    ``None`` are omitted from the requester entirely rather than sent empty.
    """
    return {
        "ver": ProtocolVersion,
        "id": f"q-{uuid.uuid4().hex}",
        "exchange": exchange,
        "requester": requester(agent_id, domain, user_type=user_type, geography=geography),
        "uris": list(uris),
    }


def offer_uris(payload: dict[str, Any]) -> set[str]:
    """The resource URIs a Discover response carries an OFFER for.

    ``ResourceResponse.offer_groups[]`` gives one group per requested URI, each
    with a ``uri`` and an ``offers`` list; the wire is proto-JSON under proto
    field names, so those are the keys. A URI counts as discoverable only when
    its group has a NON-EMPTY ``offers`` — an empty group carries an
    ``absence_reason`` and means the resource is not licensable, which is the
    absence-of-side-effect signal every negative path reads.
    """
    groups = cast(list[dict[str, Any]], payload.get("offer_groups") or [])
    found: set[str] = set()
    for group in groups:
        uri = group.get("uri")
        if isinstance(uri, str) and uri and (group.get("offers") or []):
            found.add(uri)
    return found


def discoverable(exchange_url: str, uri: str, *, agent_id: str, key_path: Path) -> bool:
    """Whether ``uri`` resolves to an offer at ``exchange_url``.

    This is the read leg every catalog negative path needs: it goes through the
    production DiscoverResources RPC — signed httpsig, caller resolution,
    catalog lookup — which is the same surface a real agent uses, and never
    past it into the database. A push that was refused must leave its URI
    undiscoverable, and asserting the refusal without asserting that leaves the
    all-or-nothing claim untested: a server that answered the right status and
    stored the entry anyway would pass.

    ``exchange_url`` selects the owning exchange and also supplies the identity
    the query is addressed to, because an exchange refuses a query naming
    anyone else.
    """
    resp = sign_post(
        f"{exchange_url}{DISCOVER_PATH}",
        body=discover_body(uris=[uri], agent_id=agent_id, exchange=recipient_of(exchange_url)),
        key_path=key_path,
    )
    if resp.status_code != httpx.codes.OK:
        msg = f"DiscoverResources for {uri} failed: {resp.status_code} {resp.text}"
        raise AssertionError(msg)
    return uri in offer_uris(cast(dict[str, Any], resp.json()))


__all__ = ["DISCOVER_PATH", "discover_body", "discoverable", "offer_uris"]
