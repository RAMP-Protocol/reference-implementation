"""The RAMP SDK's own client, wired for this stack.

Everywhere else in this harness a RAMP call is a body dict built by hand, signed
by ``signing.sign_post`` and posted to a path constant. That is the
re-derivation the SDK exists to remove, and until this revision Python had no
choice: the SDK could build, sign, verify and validate every message and could
not send one. It can now, over a Connect-unary JSON client.

This module is the wiring such a client needs and does not supply itself. Three
pieces are load-bearing, and each is a thing the client refuses to guess:

* **the signer** — an RFC 9421 signing transport over the agent's own key. The
  SDK holds one agent key: the one the request is signed with.
* **the verifier** — fail-closed by default over a resolver that resolves
  nothing, so a client given no keys rejects EVERY offer, with a reason. That is
  the correct default and it looks exactly like a broken stack on first run.
  Real keys come out of each Exchange's Web Bot Auth directory, which is the only
  place an exchange's offer-signing key is published.
* **the endpoint resolver** — turns the exchange domain inside a signed offer
  into the origin that Exchange advertises for itself. A usage report goes where
  the signed offer says, never where configuration says, so this is not an
  optional convenience.

The blocking face (``ramp_sdk.sync``) is used rather than the async core,
because everything around it here is synchronous. Prefetching the offer keys is
the one async step, and it runs once during setup rather than inside a call.

Scheme note: this stack speaks http on a private network. The resolvers are told
so; the client's own scheme gate reads ``ALLOW_INSECURE``, which the runner
service sets for the same reason the five Go RAMP services that dial out do.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence
from pathlib import Path

import httpx
from ramp_sdk.client import ClientConfig
from ramp_sdk.core import Mode, StaticOfferKeyResolver, Verifier
from pydantic import ValidationError
from ramp_sdk.resolvers import (
    CachedOfferKeyResolver,
    SsrfError,
    WellKnownEndpointResolver,
    guarded_async_client,
    guarded_client,
    wba_directory_url,
)
from ramp_sdk.sync import BrokerClient, Client
from ramp_sdk.window import monotonic_window
from wire.models import WBAFile

from .constants import AGENT_DOMAIN, requester
from .exchanges import exchange_url
from .httpsig_signer import load_keypair, signing_transport
from .signing import AGENT_E2E_KEY_PATH
from .stack_urls import StackURLs

#: The scheme every service in the compose network answers on.
STACK_SCHEME = "http"

_FETCH_TIMEOUT_SEC = 10.0

#: Signature validity, matching the SDK transport's own default rather than
#: choosing a second number for the same thing.
_SIGNING_TTL_SEC = 600

#: One signing window for every client this module builds, and it has to be shared.
#:
#: The services keep a replay store and refuse a signature they have already seen
#: inside its window. Two suites resolving the same URI as the same agent in the
#: same wall-clock second produce a byte-identical signature base, so the second
#: one is answered "request replayed within window" — which reads like an auth
#: failure and is not one.
#:
#: ``monotonic_window`` is the SDK's answer: it bumps ``expires`` by a second per
#: call when a burst lands in one second, so no two signatures share a
#: (keyid, expires) pair. Its running maximum lives in the closure, so a window
#: built per transport would reset for every client and collide exactly as
#: before. This one is built once for the process.
_SIGNING_WINDOW = monotonic_window(time.time, _SIGNING_TTL_SEC)

#: One endpoint resolver for every client this module builds, for the same reason
#: the window above is shared: it is built once for the process, not once per
#: client.
#:
#: ``Client.close()`` closes only the two RPC transports, so one resolver per
#: client left a keep-alive pool per client to object finalization. It also
#: caches each Exchange's manifest behind its own locks, which is what makes
#: sharing correct rather than merely cheaper: five clients asking the same
#: Exchange for its endpoint now ask it once.
#:
#: It IS handed an ``http`` client of ours, and passing one re-decides nothing.
#: Left to itself the resolver builds ``default_client``, which the SDK documents
#: as unguarded and which trusts the ambient proxy environment.
#: ``guarded_client`` sets the same ``follow_redirects``, the same
#: ``max_redirects`` and the same ``timeout`` by ``setdefault`` — the three
#: values ``default_client`` chooses — and adds ``trust_env=False`` on top, so a
#: set ``HTTP(S)_PROXY`` cannot tunnel this leg somewhere else.
#:
#: Be clear about how much that buys HERE: the runner sets ``SKIP_SSRF`` and
#: ``ALLOW_INSECURE``, so the dial-time address guard and the https-only check
#: are both off in this stack and ``trust_env=False`` is the whole gain. The
#: point is that the leg dials through the factory the SDK marks for a
#: third-party-influenceable fetch, so it inherits whatever that factory decides
#: rather than the unguarded default.
#:
#: We own this client and the resolver still exposes no way to close it, so the
#: pool closes at interpreter exit exactly as before. That is an upstream gap,
#: not something to reach past the seam for.
_ENDPOINTS = WellKnownEndpointResolver(
    scheme=STACK_SCHEME, http=guarded_client(timeout=_FETCH_TIMEOUT_SEC)
)


async def _fetch_wba_directory(domain: str) -> WBAFile | None:
    """Read one exchange's Web Bot Auth directory.

    The offer-signing key lives ONLY here — not in ``ramp.json`` — so this is
    what makes an offer verifiable at all.

    **Returns None for every failure, and raises for none of them.** That is the
    seam's contract, not a preference: ``CachedOfferKeyResolver.prefetch`` gathers
    these calls without ``return_exceptions``, so one raised error abandons the
    whole prefetch instead of leaving a single exchange unresolved. Its own
    docstring states the intent — an unresolvable exchange is simply absent from
    the map, and the Verifier then rejects that exchange's offers fail-closed.
    A dropped connection would otherwise take down the verifier setup for every
    exchange, which surfaces as a crash in module setup rather than as the one
    exchange whose offers could not be checked.

    Dials through the SDK's guarded client rather than a bare httpx one. That is
    what reads ``SKIP_SSRF`` and ``ALLOW_INSECURE`` — the two flags the runner
    sets — and what keeps this leg off the ambient proxy environment.

    Three outbound legs run under a client built here, and they are not guarded
    alike:

    1. This fetch. Its host comes from the domain list the caller hands
       :func:`offer_verifier`, and today every call site fills that from the
       stack's own exchange constants — so it is addressed by configuration, not
       by anything read off the wire. Guarded, as above.
    2. The SDK's ``WellKnownEndpointResolver``, reading an Exchange's manifest
       before a usage report or a dispute. Its host is the report's ``exchange``
       field — data, and the leg a signed offer actually steers. The shared
       ``_ENDPOINTS`` resolver is handed ``guarded_client``, so this leg dials
       through the same factory as leg 1 rather than the unguarded default.

       ``vet_exchange_endpoint`` runs in front of it, and it is worth being exact
       about what that does and does not do. It calls ``is_bare_host``, which
       answers whether the value is EXACTLY a host — it refuses a scheme,
       userinfo, a path, a query or a fragment, so a URL smuggled into the
       ``exchange`` field cannot choose what gets fetched. That is a real check
       and it is a check about SHAPE. It is not an address check: ``localhost``,
       ``127.0.0.1``, ``169.254.169.254`` and ``10.0.0.5:8080`` are all bare
       hosts and all pass it. The address class an SSRF guard exists for is the
       dial-time guard's job, which is why this leg dials guarded rather than
       relying on the vet alone.
    3. The RPC send that follows the resolve. The SDK marks that one guarded,
       and keeps the plain transport for discover and execute, whose address is
       the operator's own configuration rather than an offer's.
    """
    try:
        async with guarded_async_client(timeout=_FETCH_TIMEOUT_SEC) as http:
            resp = await http.get(wba_directory_url(STACK_SCHEME, domain))
        if resp.status_code != httpx.codes.OK:
            return None
        return WBAFile.model_validate(resp.json())
    except (httpx.HTTPError, SsrfError, ValidationError, ValueError):
        # ValueError covers a body that is not JSON; ValidationError, a body that
        # is JSON and not a directory.
        return None


def offer_verifier(exchange_domains: Sequence[str]) -> Verifier:
    """A fail-closed verifier holding the offer-signing key of each named exchange.

    The Python SDK's cached resolver is a batch prefetch rather than a lookup
    per offer, so the caller names the exchanges it expects to hear from and the
    keys are read once. An exchange left out of that list is not an error here —
    its offers simply arrive rejected, which is what the caller asserts on.
    """
    keys = asyncio.run(
        CachedOfferKeyResolver(fetch=_fetch_wba_directory).prefetch(exchange_domains)
    )
    return Verifier(
        mode=Mode.STRICT,
        resolver=StaticOfferKeyResolver(keys),
        now=lambda: int(time.time()),
    )


def _config(base_url: str, agent_id: str, key_path: Path, verifier: Verifier) -> ClientConfig:
    """One client's configuration. Both faces below are built from this."""
    directory, priv = load_keypair(key_path)
    return ClientConfig(
        base_url=base_url,
        # The keyfile's kid is the signer's DIRECTORY, not its keyid; the
        # helper applies that split (its docstring says why). The window is
        # the one shared instance above, for the reason given there.
        signer=signing_transport(directory, priv, window=_SIGNING_WINDOW),
        requester=requester(agent_id, AGENT_DOMAIN),
        verifier=verifier,
        endpoint_resolver=_ENDPOINTS,
    )


def sdk_exchange_client(
    stack: StackURLs,
    exchange_domain: str,
    verifier: Verifier,
    *,
    agent_id: str = "agent-e2e",
    key_path: Path = AGENT_E2E_KEY_PATH,
) -> Client:
    """The SDK client for one Exchange, addressed at the URL this stack reaches it on."""
    return Client(_config(exchange_url(stack, exchange_domain), agent_id, key_path, verifier))


def sdk_broker_client(
    stack: StackURLs,
    verifier: Verifier,
    *,
    agent_id: str = "agent-e2e",
    key_path: Path = AGENT_E2E_KEY_PATH,
) -> BrokerClient:
    """The SDK client for the Broker's discovery RPC."""
    return BrokerClient(_config(stack.broker, agent_id, key_path, verifier))


__all__ = [
    "STACK_SCHEME",
    "offer_verifier",
    "sdk_broker_client",
    "sdk_exchange_client",
]
