"""Broker client used by the MCP ramp_fetch tool.

Thin async HTTP wrapper around POST /broker/v1/resolve. All Broker-facing
error classification happens here so the server module is a one-layer
orchestration: call Broker, follow the signed URL, return content.
"""

from __future__ import annotations

import httpx

from .models import ResolveRequest, ResolveResponse

_HTTP_SERVER_ERROR = 500
_HTTP_CLIENT_ERROR = 400


class BrokerError(RuntimeError):
    """Raised when the Broker rejects the resolve request."""


class BrokerClient:
    """Async client for the RAMP Broker's resolve endpoint."""

    def __init__(self, base_url: str, *, timeout_seconds: float = 30.0) -> None:
        """Store the Broker's base URL and per-request timeout."""
        self._base_url = base_url.rstrip("/")
        self._timeout = httpx.Timeout(timeout_seconds)

    async def resolve(self, req: ResolveRequest) -> ResolveResponse:
        """POST ``req`` to ``/broker/v1/resolve`` and return the parsed response."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            try:
                resp = await client.post(
                    f"{self._base_url}/broker/v1/resolve",
                    json=req.model_dump(exclude_none=True),
                )
            except httpx.HTTPError as exc:
                raise BrokerError(f"broker unreachable: {exc}") from exc
        if resp.status_code >= _HTTP_SERVER_ERROR:
            raise BrokerError(f"broker {resp.status_code}: {resp.text[:256]}")
        try:
            payload = resp.json()
        except ValueError as exc:
            raise BrokerError(f"broker returned non-JSON ({resp.status_code}): {exc}") from exc
        return ResolveResponse.model_validate(payload)

    async def fetch_content(self, url: str) -> str:
        """GET ``url`` (signed or bare) and return the body as text."""
        async with httpx.AsyncClient(timeout=self._timeout, follow_redirects=True) as client:
            try:
                resp = await client.get(url)
            except httpx.HTTPError as exc:
                raise BrokerError(f"content fetch failed: {exc}") from exc
        if resp.status_code >= _HTTP_CLIENT_ERROR:
            raise BrokerError(f"content fetch {resp.status_code}: {resp.text[:256]}")
        return resp.text
