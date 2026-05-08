"""FastMCP server exposing the agent-facing ``ramp_fetch`` tool.

Flow:
    agent → ramp_fetch(query | uri)
         → BrokerClient.resolve(...)
            - licensed: GET signed_url, return content + tx metadata
            - unlicensed: GET bare_url, return content + bare_url marker

The shim performs the signed-URL fetch on the agent's behalf so the agent
never sees the underlying delivery URL.
"""

from __future__ import annotations

import logging
import os
import uuid

from fastmcp import FastMCP

from .broker import BrokerClient, BrokerError
from .models import RampFetchResult, ResolveRequest, ResolveResponse

logger = logging.getLogger(__name__)

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


def _licensed_result(resp: ResolveResponse, content: str | None) -> RampFetchResult:
    # Surface the winning candidate's price so the agent can quote it back to
    # the human ("I spent $0.01 on Socrates"). Currency is not on the Broker's
    # CandidateInfo wire; the demo runs USD-only and the Exchange already
    # writes a currency column on the transaction_log row, so default to USD
    # here and read the canonical value via /admin/ledger if precision matters.
    winner = resp.candidates[0] if resp.candidates else None
    return RampFetchResult(
        licensed=True,
        content=content,
        transaction_id=resp.transaction_id,
        offer_id=resp.offer_id,
        marketplace_id=resp.marketplace_id,
        request_id=resp.request_id,
        cost=winner.unit_cost if winner else None,
        currency="USD" if winner else None,
    )


def _unlicensed_result(resp: ResolveResponse, content: str | None) -> RampFetchResult:
    return RampFetchResult(
        licensed=False,
        content=content,
        bare_url=resp.bare_url,
        request_id=resp.request_id,
        error=resp.error,
    )


async def ramp_fetch_impl(
    query: str | None = None,
    uri: str | None = None,
    intended_use: str | None = None,
    max_price_cents: int | None = None,
) -> RampFetchResult:
    """Implementation of ``ramp_fetch`` — kept unwrapped so tests can call it directly.

    See :func:`ramp_fetch` for the agent-facing docstring.
    """
    if not query and not uri:
        return RampFetchResult(licensed=False, error="query or uri is required")

    req = ResolveRequest(
        agent_id=_agent_id(),
        license_id=_license_id(),
        query=query,
        uri=uri,
        intended_use=intended_use,
        budget_minor=max_price_cents,
    )
    client = _broker()
    try:
        resp = await client.resolve(req)
    except BrokerError as exc:
        logger.warning("broker resolve failed", exc_info=exc)
        return RampFetchResult(licensed=False, error=str(exc))

    target = resp.signed_url or resp.bare_url
    content: str | None = None
    if target:
        try:
            content = await client.fetch_content(target)
        except BrokerError as exc:
            logger.warning("content fetch failed", exc_info=exc)
            err_result = (
                _licensed_result(resp, None) if resp.licensed else _unlicensed_result(resp, None)
            )
            err_result.error = str(exc)
            return err_result

    return _licensed_result(resp, content) if resp.licensed else _unlicensed_result(resp, content)


@mcp.tool
async def ramp_fetch(
    query: str | None = None,
    uri: str | None = None,
    intended_use: str | None = None,
    max_price_cents: int | None = None,
) -> RampFetchResult:
    """Fetch a resource via the RAMP Broker and return its content.

    Either ``query`` (free-form natural-language) or ``uri`` (direct URL) must
    be provided. When both are provided, ``uri`` takes precedence.

    ``intended_use`` declares what the agent will do with the content — common
    values: "ai_input", "ai_train", "ai_index", "search", "display". Marketplaces
    use it to filter offers whose licensing rules permit the stated use; if
    omitted the Broker treats it as unrestricted browse.

    ``max_price_cents`` caps the per-fetch unit cost. Offers that exceed it
    are dropped from selection; if no offer fits the budget the call returns
    ``licensed=false`` with ``error="budget exhausted"``. Omit for no cap.

    If a marketplace represents the publisher, content is delivered under an
    Exchange-signed URL and the agent receives ``transaction_id``, ``offer_id``,
    ``cost``, and ``currency`` for audit. Otherwise the shim fetches the bare
    URL and returns ``licensed=false``.
    """
    return await ramp_fetch_impl(
        query=query,
        uri=uri,
        intended_use=intended_use,
        max_price_cents=max_price_cents,
    )


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
