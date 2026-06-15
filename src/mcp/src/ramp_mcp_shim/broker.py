"""Broker client used by the MCP ramp_fetch tool.

Thin async HTTP wrapper around POST /broker/v1/resolve. All Broker-facing
error classification happens here so the server module is a one-layer
orchestration: call Broker, follow the signed URL, return content.

Every outbound POST is signed with the agent's RFC 9421 key material via
:func:`signing_client.make_signing_async_client` — obligation 04:
agent-as-own-principal.
"""

from __future__ import annotations

import logging
import uuid
from urllib.parse import parse_qs, urlsplit

import httpx

from .httpsig import Signer
from .models import (
    RampRequest,
    RampResponse,
)
from .signing_client import AgentKeyConfigError, load_agent_key, make_signing_async_client

logger = logging.getLogger(__name__)

_HTTP_SERVER_ERROR = 500
_HTTP_CLIENT_ERROR = 400


class BrokerError(RuntimeError):
    """Raised when a resolve cannot be completed.

    Covers the whole resolve path: the Broker rejecting the request, the Broker
    being unreachable, or the outbound signing client failing to construct (a
    misconfigured explicit ``RAMP_AGENT_KEY_FILE``). ``ramp_fetch_impl`` catches
    this and returns a structured ``RampFetchResult`` error rather than letting it
    escape the ``@mcp.tool`` as a stack trace.
    """


class BrokerClient:
    """Async client for the RAMP Broker's resolve endpoint."""

    def __init__(self, base_url: str, *, timeout_seconds: float = 30.0) -> None:
        """Store the Broker's base URL and per-request timeout."""
        self._base_url = base_url.rstrip("/")
        self._timeout = httpx.Timeout(timeout_seconds)

    async def resolve(self, req: RampRequest) -> RampResponse:
        """POST canonical ``RAMPRequest`` to ``/broker/v1/resolve``; parse ``RAMPResponse``.

        Threads a freshly-minted ``X-Request-ID`` so the Broker logs this tool
        call under the same correlation id the shim originates (CLAUDE.md rule
        #8). The header is outside the RFC 9421 covered-component set, so adding
        it does not affect the outbound request signature; the Broker echoes the
        id back into ``response.request_id``.
        """
        request_id = str(uuid.uuid4())
        # make_signing_async_client is inside the try: it fails closed
        # (AgentKeyConfigError) on a malformed explicit RAMP_AGENT_KEY_FILE, and
        # that local-config failure must be classified here — broker.py is the
        # sole error-classification layer — not escape ramp_fetch as a stack trace.
        try:
            async with make_signing_async_client(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._base_url}/broker/v1/resolve",
                    json=req.model_dump(by_alias=True, exclude_none=True, mode="json"),
                    headers={"X-Request-ID": request_id},
                )
        except AgentKeyConfigError as exc:
            raise BrokerError(f"agent signing key misconfigured: {exc}") from exc
        except httpx.HTTPError as exc:
            raise BrokerError(f"broker unreachable: {exc}") from exc
        return _parse_resolve(resp)

    async def fetch_content(self, url: str) -> str:
        """GET ``url`` (signed or bare) and return the body as text.

        Unbound content fetches stay unsigned (no service-to-service RFC 9421
        signature) so a third-party origin never sees the agent's key. A *bound*
        retrieval_endpoint — one carrying an ``agent_id`` query param — is
        different: the binding requires the agent to prove possession of the
        bound key to the delivery edge, so the proof-of-possession headers are
        assembled here (:func:`_binding_proof`) and attached, keeping the fetch
        signing inside the client layer like :meth:`resolve` (ADR-013).
        """
        pop_headers = _binding_proof(url)
        async with httpx.AsyncClient(timeout=self._timeout, follow_redirects=True) as client:
            try:
                resp = await client.get(url, headers=pop_headers)
            except httpx.HTTPError as exc:
                raise BrokerError(f"content fetch failed: {exc}") from exc
        if resp.status_code >= _HTTP_CLIENT_ERROR:
            raise BrokerError(f"content fetch {resp.status_code}: {resp.text[:256]}")
        return resp.text


def _parse_resolve(resp: httpx.Response) -> RampResponse:
    if resp.status_code >= _HTTP_SERVER_ERROR:
        raise BrokerError(f"broker {resp.status_code}: {resp.text[:256]}")
    try:
        payload = resp.json()
    except ValueError as exc:
        raise BrokerError(f"broker returned non-JSON ({resp.status_code}): {exc}") from exc
    return RampResponse.model_validate(payload)


def _binding_proof(target: str) -> dict[str, str] | None:
    """Build proof-of-possession headers for a bound retrieval_endpoint, else None.

    "Bound" is read from the URL's own ``agent_id`` query param — the same source
    the delivery edge keys off — so the shim and the edge agree on one binding
    signal rather than the shim consulting the response ``agent_identity_hash``
    and the edge the URL param. When present, the agent presents its raw key plus
    an RFC 9421 GET signature (:meth:`Signer.sign_get`).

    ADR-013 D6.1: on the v1 ``MCP -> Broker -> Exchange`` relay path the Exchange
    binds the URL to the *broker's* proven key, so an agent-key proof is
    structurally unsatisfiable there; this is inert because edge enforcement
    defaults OFF (bearer). It becomes load-bearing only on a direct-agent
    deployment whose fetcher holds the bound key. No agent key configured -> the
    fetch proceeds unsigned and an enforcing edge refuses it (surfaced as a
    content-fetch error).
    """
    agent_id = parse_qs(urlsplit(target).query).get("agent_id", [""])[0]
    if not agent_id:
        return None
    key = load_agent_key()
    if key is None:
        logger.warning("bound retrieval_endpoint but no agent key; fetching without proof")
        return None
    return Signer(key).sign_get(target)
