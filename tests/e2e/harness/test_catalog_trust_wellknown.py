"""E2E: catalog-write trust learned ONLY via the publisher well-known.

Core Invariant under test
-------------------------
The Exchange must learn every catalog-writer's Ed25519 signing key by fetching
that writer's domain Web Bot Auth directory (Gate-1
self-signup, ``agentreg.RegisterFromDirectory``) — never from a ``ramp.agents``
DB pre-seed. The seed deliberately registers NO catalog-writer key
(``seed._register_setup_state`` no longer upserts one), so a push that the
Exchange accepts proves the key was fetched: if it had not been, Gate-1 would
refuse the signature as an unknown caller.

Both Gate-2 trust branches are exercised through the SAME well-known fetch gate:

* **Shape A — self-publish** (``caller_id == publisher domain``): philosophy and
  sfx publishers sign their own pushes with a key whose ``kid`` equals their
  domain. Gate-1 fetches the publisher's edge well-known; Gate-2 passes on the
  ``caller == m.GetDomain()`` branch.
* **Shape B — 3rd-party contributor** (``caller_id`` in the publisher's
  ``catalog_contributors[]``): the ``catalog-contributor-e2e`` identity pushes to
  the music publisher. Gate-1 fetches the contributor's OWN well-known host
  (the ``catalog-contributor`` compose service); Gate-2 passes on the
  ``contributors`` branch because the music edge lists that contributor.

Assertion hierarchy (well-known trust lock)
--------------------------------
PRIMARY = OUTCOME: the push is accepted AND ``DiscoverResources`` returns the
pushed resource for a domain+path that had NO pre-seeded ``ramp.agents`` row —
only a fetched key could have admitted it. SECONDARY = the assertable Exchange
slog line ``"catalog: caller self-signup from well-known manifest"``, which
fires only on a cache MISS, so it is corroboration on the cold stack
(``make test-e2e`` uses fresh volumes) rather than the load-bearing signal.

Negative paths (Doctrine 10 — drive the failure through the same surface):

* **Gate-2 reject — non-contributor caller**: a writer whose key IS fetchable
  (so Gate-1 passes) but is neither the publisher's domain nor in its
  contributors. All-or-nothing: the push is rejected wholesale (HTTP 400
  invalid_argument) and the resource is ABSENT from a follow-up Discover.
* **Gate-1 reject — domain serves no key**: a writer whose ``kid`` is a host that
  serves no fetchable well-known. The self-signup fetch fails and the RPC is
  refused with Connect ``Unauthenticated`` (HTTP non-200) — never reaching
  Gate-2.

Every key here is a REAL Ed25519 keypair (the generated self-publish / contributor
fixtures, or a freshly-generated keypair for the unfetchable-domain negative) —
no fabricated key material, no DB short-circuit.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from .catalog_push import (
    PRICING_MODEL_FREE,
    CatalogEntry,
    license_term,
    push_catalog,
)
from .conftest import StackURLs
from .discovery import DISCOVER_PATH, discover_body
from .httpsig_signer import generate_random_keypair, sign_request
from .seed import (
    CONTRIBUTOR_KEY_PATH,
    DEMO_MUSIC_DOMAIN,
    DEMO_PHILOSOPHY_DOMAIN,
    DEMO_SFX_DOMAIN,
    SELFPUB_PHILOSOPHY_KEY_PATH,
    SELFPUB_SFX_KEY_PATH,
    USD_AGENT_ID,
    USD_AGENT_KEY_PATH,
    SeededFixture,
)
from .signing import sign_post

pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_PUSH_PROCEDURE = "/ramp.v1.CatalogService/PushResources"

# Tenant ids (server derives the owning tenant from the entry domain, but the
# binary/RPC still carries it; it must match the domain's tenant).
_TENANT_PHILOSOPHY = "tenant-demo-philosophy"
_TENANT_MUSIC = "tenant-demo-music"


def _free_term() -> dict[str, Any]:
    # FREE EUR so the discovered offer needs no billing arrangement to surface.
    return license_term(model=PRICING_MODEL_FREE, rate=0.0, currency="EUR")


def _discover(exchange_url: str, uri: str) -> httpx.Response:
    """DiscoverResources for a single URI, signed AS the USD buyer agent.

    The read leg traverses the production ExchangeService RPC (signed httpsig →
    resolveCaller → catalog trie lookup) — the same surface a real agent uses.
    ``exchange_url`` selects the owning exchange (philosophy→exchange-a,
    music→exchange-b, sfx→exchange-c).
    """
    return sign_post(
        f"{exchange_url}{DISCOVER_PATH}",
        body=discover_body(uris=[uri], agent_id=USD_AGENT_ID),
        key_path=USD_AGENT_KEY_PATH,
    )


def _offer_uris(payload: dict[str, Any]) -> set[str]:
    """Collect the resource URIs the Discover response carries an OFFER for.

    DiscoverResources returns ``ResourceResponse.offer_groups[]`` (proto3-JSON
    ``offerGroups``); each group carries a ``uri`` and an ``offers`` list. A URI
    counts as discoverable only when its group has a non-empty ``offers`` — an
    empty group (carrying ``absenceReason``) means the resource is NOT licensable
    and is the absence-of-side-effect signal the negative paths assert on.
    """
    groups = cast(list[dict[str, Any]], payload.get("offer_groups") or [])
    uris: set[str] = set()
    for g in groups:
        uri = g.get("uri")
        offers = g.get("offers") or []
        if isinstance(uri, str) and uri and offers:
            uris.add(uri)
    return uris


def _assert_push_accepted_and_discoverable(
    exchange_url: str,
    *,
    tenant_id: str,
    domain: str,
    key_path: Path,
) -> str:
    """Push one FREE entry signed by ``key_path`` and assert it becomes discoverable.

    Returns the pushed URI. The push caller_id is the keyfile's kid; the Exchange
    can only admit it by fetching that kid's well-known (no ramp.agents pre-seed),
    so an accepted push + a Discover that returns the resource is the OUTCOME
    proof the key was fetched. ``exchange_url`` is the owning exchange.
    """
    path = f"/articles/trust/{uuid.uuid4().hex}.txt"
    uri = f"http://{domain}{path}"
    payload = push_catalog(
        exchange_url=exchange_url,
        tenant_id=tenant_id,
        entries=[
            CatalogEntry(
                domain=domain,
                path=path,
                content_id=f"trust-{uuid.uuid4().hex}",
                terms=(_free_term(),),
            )
        ],
        key_path=key_path,
        strict=True,
    )
    assert payload.get("accepted") == 1, payload
    assert payload.get("rejected") == 0, payload

    # PRIMARY: the resource is discoverable — only a fetched key could have
    # admitted the push, since nothing pre-seeded this writer's key.
    resp = _discover(exchange_url, uri)
    assert resp.status_code == httpx.codes.OK, resp.text
    discovered = _offer_uris(cast(dict[str, Any], resp.json()))
    assert uri in discovered, (
        f"pushed resource {uri!r} not discoverable — the well-known key fetch "
        f"did not admit the push; discovered={sorted(discovered)} "
        f"body={resp.text[:512]}"
    )
    return uri


# ── Shape A: self-publish (caller_id == publisher domain) ──────────────────


def test_self_publish_push_accepted_via_wellknown(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed registers tenants + edges
) -> None:
    """A publisher pushes its OWN catalog signed with kid==domain (Gate-2 caller==domain).

    The philosophy publisher signs with the self-publish key whose kid equals
    ``demo.ramp-protocol.org``. Gate-1 fetches the philosophy edge's Web Bot
    Auth directory; Gate-2 passes the caller==domain branch. The pushed resource
    becomes discoverable — proving the key was learned via the fetch.
    """
    _assert_push_accepted_and_discoverable(
        compose_stack.exchange,  # philosophy → exchange-a
        tenant_id=_TENANT_PHILOSOPHY,
        domain=DEMO_PHILOSOPHY_DOMAIN,
        key_path=SELFPUB_PHILOSOPHY_KEY_PATH,
    )


def test_self_publish_push_accepted_via_wellknown_aws_edge(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed registers tenants + edges
) -> None:
    """Self-publish trust holds on the AWS-shim edge too (sfx publisher).

    sfx is an AWS_CLOUDFRONT_RSA tenant, but the catalog-push signature is ALWAYS
    Ed25519/RFC-9421 (tenant scheme only governs URL minting). Gate-1 fetches the
    sfx edge's Web Bot Auth directory served by the raw-Node shim; Gate-2 passes
    caller==domain.
    """
    _assert_push_accepted_and_discoverable(
        compose_stack.exchange_c,  # sfx → exchange-c
        tenant_id="tenant-demo-sfx",
        domain=DEMO_SFX_DOMAIN,
        key_path=SELFPUB_SFX_KEY_PATH,
    )


# ── Shape B: 3rd-party contributor (caller_id in catalog_contributors[]) ────


def test_third_party_contributor_push_accepted_via_wellknown(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed registers tenants + edges
) -> None:
    """A 3rd-party contributor pushes to the music publisher (Gate-2 contributors branch).

    ``catalog-contributor-e2e`` signs a push to ``music.demo.ramp-protocol.org``.
    Gate-1 fetches the contributor's OWN well-known host (the catalog-contributor
    compose service) to learn its key; Gate-2 passes because the music edge lists
    that contributor in CATALOG_CONTRIBUTORS_JSON. Neither leg uses a DB pre-seed.
    """
    _assert_push_accepted_and_discoverable(
        compose_stack.exchange_b,  # music → exchange-b
        tenant_id=_TENANT_MUSIC,
        domain=DEMO_MUSIC_DOMAIN,
        key_path=CONTRIBUTOR_KEY_PATH,
    )


# ── NEGATIVE: Gate-2 reject — fetchable key, but not authorized for target ──


def test_non_contributor_caller_rejected_at_gate2(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed registers tenants + edges
) -> None:
    """A writer with a FETCHABLE key but no authorization for the target is Gate-2 rejected.

    The sfx self-publish key (kid==sfx.demo.ramp-protocol.org) signs a push to the
    MUSIC publisher. Gate-1 PASSES (sfx serves that key in its well-known), so the
    request reaches Gate-2 — where the caller is neither the music domain nor in
    music's catalog_contributors. All-or-nothing: the unauthorized entry rejects
    the WHOLE push (HTTP 400 invalid_argument naming caller_not_in_catalog_contributors);
    nothing persists and the resource is ABSENT from a follow-up Discover
    (Doctrine 10 absence-of-side-effect).
    """
    path = f"/lyrics/trust-neg/{uuid.uuid4().hex}.txt"
    uri = f"http://{DEMO_MUSIC_DOMAIN}{path}"
    try:
        push_catalog(
            exchange_url=compose_stack.exchange_b,  # music → exchange-b
            tenant_id=_TENANT_MUSIC,
            entries=[
                CatalogEntry(
                    domain=DEMO_MUSIC_DOMAIN,
                    path=path,
                    content_id=f"trust-neg-{uuid.uuid4().hex}",
                    terms=(_free_term(),),
                )
            ],
            # sfx self key: Gate-1 resolvable, Gate-2 unauthorized for music.
            key_path=SELFPUB_SFX_KEY_PATH,
            strict=False,
        )
    except RuntimeError as exc:
        assert "caller_not_in_catalog_contributors" in str(exc) or "invalid_argument" in str(exc), (
            exc
        )
    else:
        raise AssertionError("expected Gate-2 whole-request rejection (400), push succeeded")

    # No side effect: the rejected resource must not be discoverable.
    resp = _discover(compose_stack.exchange_b, uri)
    assert resp.status_code == httpx.codes.OK, resp.text
    discovered = _offer_uris(cast(dict[str, Any], resp.json()))
    assert uri not in discovered, (
        f"Gate-2-rejected resource {uri!r} leaked into the catalog: discovered={sorted(discovered)}"
    )


# ── NEGATIVE: Gate-1 reject — caller domain serves no fetchable key ─────────


def test_unfetchable_domain_caller_rejected_at_gate1(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed registers tenants + edges
) -> None:
    """A caller whose kid resolves to no served key is refused at Gate-1 (Unauthenticated).

    The caller_id is a host with no compose alias and no well-known — the Exchange
    self-signup fetch cannot resolve a key. Gate-1 (verifyCallerSignature) refuses
    the signature with Connect ``Unauthenticated`` (HTTP non-200) BEFORE Gate-2 is
    consulted, and nothing is written. The push is signed with a REAL freshly
    generated keypair whose kid is the unfetchable host.
    """
    unfetchable = f"no-wellknown-{uuid.uuid4().hex}.invalid"
    path = f"/articles/trust-neg/{uuid.uuid4().hex}.txt"
    url = f"{compose_stack.exchange}{_PUSH_PROCEDURE}"

    # Build a PushResources body whose caller_id == the unfetchable host, signed
    # with a real keypair whose kid is that same host.
    kid, priv = generate_random_keypair(unfetchable)
    body = _build_push_body(
        tenant_id=_TENANT_PHILOSOPHY,
        caller_id=unfetchable,
        domain=DEMO_PHILOSOPHY_DOMAIN,
        path=path,
    )
    signed = sign_request(method="POST", target_uri=url, body=body, kid=kid, priv=priv)
    headers = {**signed.headers, "Content-Type": "application/json"}
    resp = httpx.post(url, content=body, headers=headers, timeout=30.0)

    # Gate-1 refusal: HTTP non-200 (Connect Unauthenticated). The body names the
    # self-signup failure path.
    assert resp.status_code != httpx.codes.OK, (
        f"a caller whose domain serves no key must be refused at Gate-1; "
        f"got {resp.status_code}: {resp.text[:512]}"
    )
    haystack = resp.text.lower()
    assert "unauthenticated" in haystack or "self-signup" in haystack or "caller" in haystack, (
        f"Gate-1 refusal must name the unauthenticated/self-signup cause; got {resp.text[:512]}"
    )

    # No side effect: the resource must not be discoverable (philosophy → exchange-a).
    discover_uri = f"http://{DEMO_PHILOSOPHY_DOMAIN}{path}"
    discover_resp = _discover(compose_stack.exchange, discover_uri)
    assert discover_resp.status_code == httpx.codes.OK, discover_resp.text
    discovered = _offer_uris(cast(dict[str, Any], discover_resp.json()))
    assert discover_uri not in discovered, (
        f"Gate-1-rejected resource {discover_uri!r} leaked into the catalog: "
        f"discovered={sorted(discovered)}"
    )


def _build_push_body(*, tenant_id: str, caller_id: str, domain: str, path: str) -> bytes:
    """Build a minimal proto3-JSON PushResourcesRequest body (one FREE entry).

    Built inline (rather than via push_catalog) so the Gate-1 negative can set a
    caller_id that differs from any generated fixture kid while signing with a
    matching real keypair.
    """
    import json

    payload = {
        "tenant_id": tenant_id,
        "caller_id": caller_id,
        "entries": [
            {
                "domain": domain,
                "path": path,
                "content_id": f"trust-neg-{uuid.uuid4().hex}",
                "terms": [_free_term()],
            }
        ],
    }
    return json.dumps(payload, separators=(",", ":")).encode()
