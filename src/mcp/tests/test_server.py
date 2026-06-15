"""Integration tests for the MCP ramp_fetch tool.

Per CLAUDE.md testing doctrine: mock ONLY the external Broker boundary
(via respx), exercise the rest of the shim through its real surface. No
internal logic is stubbed.
"""

from __future__ import annotations

import base64
import json
import uuid
from typing import TYPE_CHECKING, Any

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ramp_mcp_shim.httpsig import AGENT_KEY_HEADER, AgentKey
from ramp_mcp_shim.models import RampFetchResult
from ramp_mcp_shim.server import mcp, ramp_fetch_impl
from ramp_mcp_shim.thumbprint import ed25519_thumbprint

if TYPE_CHECKING:
    from pathlib import Path

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
        "retrievalEndpoint": signed_url,
        "transactionId": "tx-123",
        "exchange": "exchange.test",
        "requestId": "req-1",
        "ext": {
            "ramp.broker.licensed": True,
            "ramp.broker.offer_id": "offer-456",
        },
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
    assert result.exchange_id == "exchange.test"
    assert result.request_id == "req-1"
    assert result.error is None


@pytest.mark.asyncio
async def test_bound_retrieval_presents_proof_of_possession(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A response carrying agent_identity_hash → the fetch proves key possession."""
    priv = Ed25519PrivateKey.generate()
    seed_b64 = base64.urlsafe_b64encode(priv.private_bytes_raw()).rstrip(b"=").decode()
    key_file = tmp_path / "agent-key.json"
    key_file.write_text(json.dumps({"kid": "agent.v1", "private_key": seed_b64}))
    monkeypatch.setenv("RAMP_AGENT_KEY_FILE", str(key_file))

    agent_thumb = AgentKey(kid="agent.v1", private_seed_b64=seed_b64).thumbprint()
    signed_url = f"https://edge.test/premium?sig=abc&exp=1800000000&agent_id={agent_thumb}"
    broker_body: dict[str, Any] = {
        "retrievalEndpoint": signed_url,
        "agentIdentityHash": agent_thumb,
        "transactionId": "tx-bound",
        "ext": {"ramp.broker.licensed": True},
    }

    with respx.mock(base_url=BROKER_URL) as broker_mock:
        broker_mock.post("/broker/v1/resolve").mock(
            return_value=httpx.Response(200, json=broker_body),
        )
        with respx.mock() as edge_mock:
            route = edge_mock.get(signed_url).mock(return_value=httpx.Response(200, text="ok"))
            result = await ramp_fetch_impl(query="premium")

    assert result.content == "ok"
    sent = route.calls.last.request.headers
    presented = base64.urlsafe_b64decode(
        sent[AGENT_KEY_HEADER] + "=" * (-len(sent[AGENT_KEY_HEADER]) % 4)
    )
    # The presented key's thumbprint is the bound agent_id, and the signer
    # carries it as keyid — the 3-way identity the edge enforces.
    assert ed25519_thumbprint(presented) == agent_thumb
    assert f'keyid="{agent_thumb}"' in sent["Signature-Input"]
    assert sent["Signature"].startswith("sig1=:")


@pytest.mark.asyncio
async def test_unbound_retrieval_omits_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    """A response with no agent_identity_hash fetches without any proof headers."""
    monkeypatch.delenv("RAMP_AGENT_KEY_FILE", raising=False)
    signed_url = "https://edge.test/premium?sig=abc&exp=1800000000"
    broker_body: dict[str, Any] = {
        "retrievalEndpoint": signed_url,
        "ext": {"ramp.broker.licensed": True},
    }
    with respx.mock(base_url=BROKER_URL) as broker_mock:
        broker_mock.post("/broker/v1/resolve").mock(
            return_value=httpx.Response(200, json=broker_body),
        )
        with respx.mock() as edge_mock:
            route = edge_mock.get(signed_url).mock(return_value=httpx.Response(200, text="ok"))
            await ramp_fetch_impl(query="premium")

    assert AGENT_KEY_HEADER not in route.calls.last.request.headers
    assert "Signature" not in route.calls.last.request.headers


@pytest.mark.asyncio
async def test_refused_flow_returns_no_content() -> None:
    """A refused resolve (no canonical retrieval_endpoint) yields no content.

    v1 publishers MUST host ramp.json, so the Broker either licenses a
    transaction or refuses — there is no bare-URL fallback. The shim surfaces
    licensed=false with the refusal reason and never fetches.
    """
    broker_body: dict[str, Any] = {
        "requestId": "req-2",
        "ext": {
            "ramp.broker.licensed": False,
            "ramp.broker.error": "no offers returned by exchanges",
        },
    }

    with respx.mock(base_url=BROKER_URL) as broker_mock:
        broker_mock.post("/broker/v1/resolve").mock(
            return_value=httpx.Response(200, json=broker_body),
        )
        result = await ramp_fetch_impl(uri="https://example.test/public.html")

    assert result.licensed is False
    assert result.content is None
    assert result.request_id == "req-2"
    assert result.error == "no offers returned by exchanges"
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
async def test_malformed_agent_key_returns_structured_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed explicit RAMP_AGENT_KEY_FILE must surface as a structured
    RampFetchResult error, not an unhandled AgentKeyConfigError escaping the tool.

    The outbound-signing client fails closed on a present-but-unusable explicit
    key (signing_client.make_signing_async_client). That construction happens
    inside BrokerClient.resolve, so the failure must be classified as a
    BrokerError there and returned as a clean result — never propagated out of
    ramp_fetch as a stack trace. No Broker call is made (construction fails first).
    """
    short_seed = base64.urlsafe_b64encode(b"too-short").rstrip(b"=").decode()
    key_file = tmp_path / "bad.json"
    key_file.write_text(
        json.dumps({"kid": "agent.v1", "private_key": short_seed, "public_key": "x"}),
    )
    monkeypatch.setenv("RAMP_AGENT_KEY_FILE", str(key_file))
    monkeypatch.chdir(tmp_path)  # no ./deploy/mcp/agent-key.json fallback here

    result = await ramp_fetch_impl(query="anything")

    assert isinstance(result, RampFetchResult)
    assert result.licensed is False
    assert result.error is not None
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
    """The shim must forward RAMP_AGENT_ID as requester.id of the RAMPRequest."""
    monkeypatch.setenv("RAMP_AGENT_ID", "agent-explicit")

    with respx.mock(base_url=BROKER_URL) as broker_mock:
        route = broker_mock.post("/broker/v1/resolve").mock(
            return_value=httpx.Response(
                200, json={"requestId": "req-4", "ext": {"ramp.broker.licensed": False}}
            ),
        )
        await ramp_fetch_impl(query="anything")
        assert route.called
        body = json.loads(route.calls.last.request.content.decode())
        assert body["requester"]["id"] == "agent-explicit"


@pytest.mark.asyncio
async def test_request_id_threaded_to_broker() -> None:
    """The shim sends a dashed-UUID X-Request-ID so the Broker logs the tool call
    under the same correlation id (CLAUDE.md rule #8).
    """
    with respx.mock(base_url=BROKER_URL) as broker_mock:
        route = broker_mock.post("/broker/v1/resolve").mock(
            return_value=httpx.Response(
                200, json={"requestId": "req-5", "ext": {"ramp.broker.licensed": False}}
            ),
        )
        await ramp_fetch_impl(query="anything")
        assert route.called
        sent = route.calls.last.request.headers.get("X-Request-ID")
        assert sent
        # Canonical dashed UUIDv4, not the 32-char undashed hex form.
        assert str(uuid.UUID(sent)) == sent
