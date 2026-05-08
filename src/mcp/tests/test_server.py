"""Integration tests for the MCP ramp_fetch tool.

Per CLAUDE.md testing doctrine: mock ONLY the external Broker boundary
(via respx), exercise the rest of the shim through its real surface. No
internal logic is stubbed.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from ramp_mcp_shim.models import RampFetchResult
from ramp_mcp_shim.server import mcp, ramp_fetch_impl

BROKER_URL = "http://broker.test"


@pytest.fixture(autouse=True)
def _broker_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the shim at the mocked Broker base URL for every test."""
    monkeypatch.setenv("BROKER_URL", BROKER_URL)
    monkeypatch.setenv("RAMP_AGENT_ID", "agent-test")
    monkeypatch.delenv("RAMP_LICENSE_ID", raising=False)


@pytest.mark.asyncio
async def test_tool_registered_on_server() -> None:
    """The ramp_fetch tool must be exposed to MCP clients."""
    tool = await mcp.get_tool("ramp_fetch")
    assert tool is not None
    assert tool.name == "ramp_fetch"


@pytest.mark.asyncio
async def test_licensed_flow_returns_content_and_tx_metadata() -> None:
    """Licensed resolve → signed-URL fetch → agent-facing result with audit ids."""
    signed_url = "https://edge.test/premium/article?sig=abc&exp=1800000000"
    broker_body: dict[str, Any] = {
        "licensed": True,
        "signed_url": signed_url,
        "transaction_id": "tx-123",
        "offer_id": "offer-456",
        "marketplace_id": "marketplace.test",
        "request_id": "req-1",
    }
    article = "Premium article body."

    with respx.mock(base_url=BROKER_URL) as broker_mock:
        broker_mock.post("/broker/v1/resolve").mock(
            return_value=httpx.Response(200, json=broker_body),
        )
        with respx.mock() as edge_mock:
            edge_mock.get(signed_url).mock(return_value=httpx.Response(200, text=article))
            result = await ramp_fetch_impl(query="premium article")

    assert isinstance(result, RampFetchResult)
    assert result.licensed is True
    assert result.content == article
    assert result.transaction_id == "tx-123"
    assert result.offer_id == "offer-456"
    assert result.marketplace_id == "marketplace.test"
    assert result.request_id == "req-1"
    assert result.error is None


@pytest.mark.asyncio
async def test_unlicensed_flow_returns_bare_url_content() -> None:
    """When no marketplace represents the publisher, the shim still fetches."""
    bare_url = "https://example.test/public.html"
    broker_body: dict[str, Any] = {
        "licensed": False,
        "bare_url": bare_url,
        "request_id": "req-2",
    }
    public_content = "<html>public content</html>"

    with respx.mock(base_url=BROKER_URL) as broker_mock:
        broker_mock.post("/broker/v1/resolve").mock(
            return_value=httpx.Response(200, json=broker_body),
        )
        with respx.mock() as edge_mock:
            edge_mock.get(bare_url).mock(return_value=httpx.Response(200, text=public_content))
            result = await ramp_fetch_impl(uri=bare_url)

    assert result.licensed is False
    assert result.content == public_content
    assert result.bare_url == bare_url
    assert result.transaction_id is None


@pytest.mark.asyncio
async def test_broker_upstream_error_propagates_safely() -> None:
    """A 5xx from the Broker becomes a structured error, not an exception."""
    with respx.mock(base_url=BROKER_URL) as broker_mock:
        broker_mock.post("/broker/v1/resolve").mock(
            return_value=httpx.Response(503, text="upstream failure"),
        )
        result = await ramp_fetch_impl(query="anything")

    assert result.licensed is False
    assert result.error is not None
    assert "503" in result.error
    assert result.content is None


@pytest.mark.asyncio
async def test_missing_inputs_rejected_without_broker_call() -> None:
    """No query and no uri is a client-side error — do not hit the Broker."""
    with respx.mock(base_url=BROKER_URL, assert_all_called=False) as broker_mock:
        resolve_route = broker_mock.post("/broker/v1/resolve")
        result = await ramp_fetch_impl()
        assert not resolve_route.called

    assert result.licensed is False
    assert result.error == "query or uri is required"


@pytest.mark.asyncio
async def test_agent_id_forwarded_to_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    """The shim must forward RAMP_AGENT_ID in the resolve request body."""
    monkeypatch.setenv("RAMP_AGENT_ID", "agent-explicit")

    with respx.mock(base_url=BROKER_URL) as broker_mock:
        route = broker_mock.post("/broker/v1/resolve").mock(
            return_value=httpx.Response(200, json={"licensed": False, "request_id": "req-4"}),
        )
        await ramp_fetch_impl(query="anything")
        assert route.called
        body = route.calls.last.request.content.decode()
        assert '"agent_id":"agent-explicit"' in body
