"""FastMCP server exposing the agent-facing ``ramp_fetch`` tool.

Flow:
    agent → ramp_fetch(query | uri)
         → BrokerClient.resolve(...)  (canonical RAMPRequest → RAMPResponse)
            - licensed: GET retrieval_endpoint, return content + tx metadata
            - refused:  no URL; return licensed=false + the refusal reason

The shim signs every outbound request with the agent's RFC 9421 key
material (obligation 04: agent-as-own-principal) and follows the
resolved URL on the agent's behalf so the agent never sees the
underlying delivery URL.
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import TYPE_CHECKING

import anyio
from fastmcp import FastMCP
from starlette.responses import JSONResponse, Response

from .broker import BrokerClient, BrokerError
from .models import (
    RampFetchResult,
    RampRequest,
    RampResponse,
    Requester,
)
from .wellknown import load_agent_manifest

if TYPE_CHECKING:
    from starlette.requests import Request

__all__ = [
    "WELL_KNOWN_PATH",
    "main",
    "mcp",
    "ramp_fetch_impl",
    "well_known_ramp",
]

logger = logging.getLogger(__name__)

# Fixed path every RAMP participant serves its discovery manifest at.
WELL_KNOWN_PATH = "/.well-known/ramp.json"


mcp: FastMCP = FastMCP("ramp-shim")


def _broker() -> BrokerClient:
    """Construct a BrokerClient from env (``BROKER_URL`` defaults to localhost)."""
    return BrokerClient(os.environ.get("BROKER_URL", "http://localhost:8082"))


def _agent_id() -> str:
    """Pick the caller's agent_id from env or generate an ephemeral one."""
    return os.environ.get("RAMP_AGENT_ID", f"mcp-agent-{uuid.uuid4().hex[:8]}")


def _license_id() -> str | None:
    """Optional license id from env; absent in the demo path."""
    return os.environ.get("RAMP_LICENSE_ID") or None


def _licensed_result(resp: RampResponse, content: str | None) -> RampFetchResult:
    return RampFetchResult(
        licensed=True,
        content=content,
        transaction_id=resp.transaction_id or None,
        offer_id=resp.offer_id,
        exchange_id=resp.exchange or None,
        request_id=resp.request_id or None,
    )


def _refused_result(resp: RampResponse, content: str | None) -> RampFetchResult:
    return RampFetchResult(
        licensed=False,
        content=content,
        request_id=resp.request_id or None,
        error=resp.error,
    )


async def ramp_fetch_impl(
    query: str | None = None,
    uri: str | None = None,
) -> RampFetchResult:
    """Implementation of ``ramp_fetch`` — kept unwrapped so tests can call it directly.

    Resolves the request via POST /broker/v1/resolve (canonical RAMPRequest →
    RAMPResponse) and follows the signed ``retrieval_endpoint`` to return the
    content.

    See :func:`ramp_fetch` for the agent-facing docstring.
    """
    if not query and not uri:
        return RampFetchResult(licensed=False, error="query or uri is required")

    req = RampRequest(
        id=f"rampreq-{uuid.uuid4().hex}",
        requester=Requester(
            id=_agent_id(),
            uris=[uri] if uri else [],
            license_id=_license_id(),
        ),
        query=query,
    )
    client = _broker()
    try:
        resp = await client.resolve(req)
    except BrokerError as exc:
        logger.warning("broker resolve failed", exc_info=exc)
        return RampFetchResult(licensed=False, error=str(exc))

    target = resp.retrieval_endpoint
    content: str | None = None
    if target:
        try:
            content = await client.fetch_content(target)
        except BrokerError as exc:
            logger.warning("content fetch failed", exc_info=exc)
            err_result = (
                _licensed_result(resp, None) if resp.licensed else _refused_result(resp, None)
            )
            err_result.error = str(exc)
            return err_result
    return _licensed_result(resp, content) if resp.licensed else _refused_result(resp, content)


@mcp.tool
async def ramp_fetch(query: str | None = None, uri: str | None = None) -> RampFetchResult:
    """Fetch a resource via the RAMP Broker and return its content.

    Either ``query`` (free-form natural-language) or ``uri`` (direct URL) must
    be provided. When both are provided, ``uri`` takes precedence.

    If an exchange represents the publisher, content is delivered under an
    Exchange-signed URL and the agent receives ``transaction_id`` + ``offer_id``
    for audit. Otherwise the resolve is refused and the agent receives
    ``licensed=false`` with the refusal reason.
    """
    return await ramp_fetch_impl(query=query, uri=uri)


@mcp.custom_route(WELL_KNOWN_PATH, methods=["GET"])
async def well_known_ramp(request: Request) -> Response:
    """Serve the agent's ``/.well-known/ramp.json`` (role=ROLE_AGENT).

    The manifest is built lazily per request from ``RAMP_AGENT_ID`` and the
    on-disk agent key. When discovery cannot be published — ``RAMP_AGENT_ID``
    unset, or no/corrupt agent key (e.g. a keyless stdio dev run) — we answer a
    bare, body-less 404 rather than crashing the server, mirroring the keyless
    tolerance of the outbound signing path. The status code is the contract,
    matching the body-less responses of the other RAMP producers.
    """
    # Echo (or mint) X-Request-ID so this discovery route carries the same
    # correlation id as the other RAMP producers, whose middleware stamps it.
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    # load_agent_manifest does blocking disk I/O (key file stat + read); offload
    # it so the async event loop is never blocked on this low-frequency route.
    manifest = await anyio.to_thread.run_sync(load_agent_manifest, os.environ.get("RAMP_AGENT_ID"))
    response: Response = (
        Response(status_code=404)
        if manifest is None
        else JSONResponse(manifest.model_dump(mode="json"))
    )
    response.headers["X-Request-ID"] = request_id
    return response


def main() -> None:
    """Entrypoint for the ``ramp-mcp`` console script.

    Transport is selected by ``RAMP_MCP_TRANSPORT``:

    * ``stdio`` (default) — local MCP clients (Claude Desktop, Cursor).
    * ``http`` — remote MCP clients (FastMCP streamable-HTTP); binds to
      ``RAMP_MCP_HOST`` (default 0.0.0.0) and ``RAMP_MCP_PORT`` (default 8000).
    """
    logging.basicConfig(level=logging.INFO)
    transport = os.environ.get("RAMP_MCP_TRANSPORT", "stdio").lower()
    if transport == "stdio":
        mcp.run()
        return
    if transport == "http":
        host = os.environ.get("RAMP_MCP_HOST", "0.0.0.0")  # noqa: S104 — intentional bind for container
        port = int(os.environ.get("RAMP_MCP_PORT", "8000"))
        mcp.run(transport="http", host=host, port=port)
        return
    msg = f"unknown RAMP_MCP_TRANSPORT {transport!r} (expected 'stdio' or 'http')"
    raise SystemExit(msg)


if __name__ == "__main__":
    main()
