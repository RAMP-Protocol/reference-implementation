"""Real-AWS acceptance tests for the demo deployment.

Gated by ``RAMP_E2E_AWS=1`` so the suite stays no-op by default. Drives the
deployed stack via its public HTTPS surface — Broker resolve → CloudFront
RSA-signed URL → native CloudFront verification → origin bytes.

Prereqs:
    RAMP_E2E_AWS=1
    RAMP_E2E_BROKER_URL      e.g. https://broker.demo.ramp-protocol.org
    RAMP_E2E_CLOUDFRONT_URL  e.g. https://demo.ramp-protocol.org
    RAMP_E2E_AGENT_ID        agent_id the Broker expects
    RAMP_E2E_RESOURCE_URI    catalog URI seeded on the Exchange for an
                             AWS_CLOUDFRONT_RSA tenant, reachable via
                             RAMP_E2E_CLOUDFRONT_URL
"""

from __future__ import annotations

import os
import re

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RAMP_E2E_AWS") != "1",
    reason="set RAMP_E2E_AWS=1 to hit deployed AWS infra",
)


def _env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        pytest.skip(f"missing env {name}")
    return value


@pytest.fixture(scope="session")
def broker_url() -> str:
    return _env("RAMP_E2E_BROKER_URL")


@pytest.fixture(scope="session")
def resource_uri() -> str:
    return _env("RAMP_E2E_RESOURCE_URI")


@pytest.fixture(scope="session")
def agent_id() -> str:
    return _env("RAMP_E2E_AGENT_ID")


def test_resolve_returns_cloudfront_signed_url(
    broker_url: str, resource_uri: str, agent_id: str
) -> None:
    """Broker should return a CloudFront canned-policy signed URL."""
    resp = httpx.post(
        f"{broker_url}/broker/v1/resolve",
        json={"agent_id": agent_id, "uri": resource_uri},
        timeout=30.0,
    )
    assert resp.status_code == httpx.codes.OK, resp.text
    payload = resp.json()
    assert payload.get("licensed") is True, payload
    signed = payload["signed_url"]
    for name in ("Expires", "Signature", "Key-Pair-Id"):
        assert name in signed, f"{name} missing in {signed}"


def test_signed_url_delivers_content_via_cloudfront(
    broker_url: str, resource_uri: str, agent_id: str
) -> None:
    """Real CloudFront natively verifies the signed URL and serves the origin."""
    resp = httpx.post(
        f"{broker_url}/broker/v1/resolve",
        json={"agent_id": agent_id, "uri": resource_uri},
        timeout=30.0,
    )
    signed = resp.json()["signed_url"]
    content_resp = httpx.get(signed, timeout=30.0)
    assert content_resp.status_code == httpx.codes.OK, content_resp.text
    assert len(content_resp.content) > 0


def test_tampered_signature_is_rejected_by_cloudfront(
    broker_url: str, resource_uri: str, agent_id: str
) -> None:
    """CloudFront native verify returns 403 on a mutated Signature param."""
    resp = httpx.post(
        f"{broker_url}/broker/v1/resolve",
        json={"agent_id": agent_id, "uri": resource_uri},
        timeout=30.0,
    )
    signed = resp.json()["signed_url"]
    match = re.search(r"Signature=([^&]+)", signed)
    assert match, signed
    sig = match.group(1)
    mid = len(sig) // 2
    tampered_sig = sig[:mid] + ("B" if sig[mid] != "B" else "C") + sig[mid + 1 :]
    tampered = signed.replace(f"Signature={sig}", f"Signature={tampered_sig}")
    bad = httpx.get(tampered, timeout=30.0)
    assert bad.status_code == httpx.codes.FORBIDDEN, bad.text


def test_bot_redirect_without_signature(broker_url: str) -> None:
    """Lambda@Edge should 403 + X-Content-Rules when a bot UA hits unsigned URL."""
    cloudfront_url = _env("RAMP_E2E_CLOUDFRONT_URL")
    resp = httpx.get(
        f"{cloudfront_url}/any-path",
        headers={"User-Agent": "GPTBot/1.0 (+https://openai.com/gptbot)"},
        timeout=30.0,
    )
    # Acceptable outcomes: CloudFront's own missing-key-pair 403 (native)
    # OR Lambda@Edge's bot-redirect 403. Either way, not 200.
    assert resp.status_code == httpx.codes.FORBIDDEN, resp.text
    # X-Content-Rules is our Lambda@Edge signal; allow either path.
    if "x-content-rules" in {k.lower() for k in resp.headers}:
        assert "ramp.json" in resp.headers.get("x-content-rules", "").lower()
