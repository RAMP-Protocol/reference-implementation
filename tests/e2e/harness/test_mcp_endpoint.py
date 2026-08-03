"""E2E: drive the Go MCP endpoint over the MCP protocol, as an agent.

The replacement for the retired Python shim's e2e: a real MCP client speaks
Streamable HTTP to the identity service's /mcp endpoint and makes genuine
tools/call requests. The agent is provisioned through a REAL Zitadel sign-up
(identity_signup.provision_agent), so its signing key is custodied in identity's
Vault and its WBA directory is hosted on its subdomain — which the Broker and
Exchange resolve (via the compose wildcard-DNS) to verify the signatures identity
makes on the agent's behalf.

Flow: ramp_discover a FREE demo resource → the agent picks the offer →
ramp_execute → the real bytes come back INSIDE the tool result, as an MCP
embedded resource. A free offer is used deliberately: a freshly-signed-up
registry agent has no billing account (ramp_register/ramp_status mint one, covered
by the Go integration suite), and free access needs none.

The edges run with delivery-URL binding ENFORCED. A custodied agent holds no key
and never fetches: the identity service fetches on its behalf, presenting the key
it signed the offer acceptance with, which is the key the Exchange bound the URL
to (ADR-023). That the bytes arrive at all is therefore the proof that the whole
custody chain lines up — and the companion negative below shows the same URL is
worthless to anyone who cannot present that key.
"""

from __future__ import annotations

import base64
import os

import httpx
import pytest
from fastmcp import Client

from .conftest import StackURLs, _wait_healthy
from .edge_fetch import edge_fetch_target
from .identity_signup import mint_bearer, provision_agent
from .seed import SeededFixture

pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")


# The token signing seed and issuer come from the environment, which the compose
# file's `x-identity-auth` anchor sets on BOTH the identity service and this
# runner — one spelling, shared. They are read without a fallback on purpose: a
# default here would be a second copy of a credential, and the failure mode of a
# stale copy is an unexplained 401 rather than anything that names the mismatch.
# Absent env means the stack was not brought up as the compose file defines it,
# which is worth failing on rather than papering over.
#
# Read inside the test, not at import: a module-level failure would be a
# COLLECTION error, and `make test-e2e-collect` enumerates this suite deliberately
# without a stack. Failing in the test body keeps collection honest and still
# refuses to run against a guessed credential.
def _required_env(name: str) -> str:
    """Read ``name`` or fail naming what is supposed to set it."""
    value = os.environ.get(name)
    if not value:
        pytest.fail(
            f"{name} is not set. docker-compose.e2e.yml sets it on the runner via the "
            f"x-identity-auth anchor, shared with the identity service; run this test "
            f"through `make test-e2e` (or `docker compose --profile test run --rm "
            f"runner`), not a bare pytest."
        )
    return value


# socrates lyric/article marker — the real delivered body, not a non-empty stub.
_CONTENT_MARKER = "Socrates"


def _require_in_network(compose_stack: StackURLs) -> None:
    """The MCP-endpoint test is in-network only: identity publishes no host port."""
    if os.environ.get("RAMP_E2E_IN_NETWORK") != "1" or not compose_stack.identity:
        pytest.skip("identity MCP endpoint is reachable only in-network (RAMP_E2E_IN_NETWORK=1)")


def _await_identity(compose_stack: StackURLs) -> None:
    """Wait for identity to answer /healthz (distroless carries no healthcheck).

    Uses the harness's one readiness poller rather than a third copy: that one
    also treats a refused connection (OSError) as "not up yet", which is exactly
    the condition here while the container is starting, and it reports the last
    error it saw instead of discarding every diagnostic across the whole wait.
    """
    _wait_healthy(f"{compose_stack.identity}/healthz", timeout_seconds=60.0)


def _embedded_content(executed: object) -> list[tuple[str, bytes]]:
    """Return (mime_type, bytes) for every embedded resource on a tool result.

    The bytes ride as a blob rather than text whatever the media type: the Go
    side will not put arbitrary origin bytes through a UTF-8 string, where
    invalid input is silently replaced rather than reported.
    """
    found: list[tuple[str, bytes]] = []
    for block in getattr(executed, "content", []):
        resource = getattr(block, "resource", None)
        if resource is None:
            continue
        blob = getattr(resource, "blob", None)
        if blob is None:
            continue
        raw = blob if isinstance(blob, bytes) else base64.b64decode(blob)
        found.append((str(getattr(resource, "mimeType", "")), raw))
    return found


def _mcp_session_bearer(compose_stack: StackURLs) -> str:
    """Provision a real agent through Zitadel sign-up and mint its bearer.

    The issuer and seed the identity service verifies bearers with are read from
    the shared compose env, never defaulted here — a default would let this suite
    pass against a service configured differently from the one deployed.
    """
    issuer = _required_env("IDENTITY_AUTH_ISSUER")
    seed_b64 = _required_env("IDENTITY_TOKEN_SIGNING_KEY")
    subdomain = provision_agent(compose_stack.identity, compose_stack.zitadel)
    return mint_bearer(subdomain, issuer=issuer, audience=issuer, seed_b64=seed_b64)


def _refusal_reason(resp: httpx.Response) -> str:
    """The edge's refusal token, or a description of why there wasn't one.

    ``resp.json()`` raises on a non-JSON body, and a 403 arriving as HTML or empty
    is exactly the case worth diagnosing — the raw parse would blow up before the
    assertion could report what it actually saw.
    """
    if not resp.headers.get("content-type", "").startswith("application/json"):
        return f"<non-JSON body: {resp.text[:120]!r}>"
    try:
        payload = resp.json()
    except ValueError:
        return f"<unparseable JSON: {resp.text[:120]!r}>"
    if not isinstance(payload, dict):
        return f"<JSON is {type(payload).__name__}, not an object>"
    return str(payload.get("reason", "<no reason field>"))


async def test_agent_discovers_executes_and_receives_content_over_mcp(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Two-call MCP flow against the Go endpoint: discover → execute → real bytes.

    Nothing is fetched from outside the MCP session: that is the point of the
    change this test covers. The content arrives on the execute result.
    """
    _require_in_network(compose_stack)
    _await_identity(compose_stack)

    bearer = _mcp_session_bearer(compose_stack)
    res = seeded.free  # socrates: FREE EUR, no billing account required

    async with Client(f"{compose_stack.identity}/mcp", auth=bearer) as client:
        # Phase 1 — discovery. The agent asks for offers; nothing is charged and no
        # delivery URL is minted yet.
        discovered = await client.call_tool("ramp_discover", {"uris": [res.uri]})
        # .structured_content is the raw JSON object the tool returned; .data is a
        # reconstructed model that is not subscriptable.
        disc = discovered.structured_content
        groups = disc["offer_groups"]
        assert groups and groups[0]["offers"], f"no offers discovered for {res.uri!r}: {disc}"
        offer = groups[0]["offers"][0]
        assert offer["offer_id"], offer
        assert offer["signature"], offer

        # Phase 2 — execute the chosen offer. The endpoint signs the acceptance
        # with the agent's custodied key, relays through the Broker, then fetches
        # the content itself at the edge with that SAME key and returns both the
        # bytes and the signed delivery URL.
        executed = await client.call_tool("ramp_execute", {"offers": [offer]})
        result = executed.structured_content
        delivered = _embedded_content(executed)

    items = result["items"]
    assert len(items) == 1, result
    item = items[0]
    assert not item.get("denial_reason"), f"execute denied: {item}"
    # The item must answer for the offer the agent CHOSE, not a substitute. Without
    # this the adapter could relay a different offer from the group — or mismatch
    # results to submissions in a >1 batch — and every other assertion would pass.
    assert item.get("offer_id") == offer["offer_id"], (
        f"execute answered for offer {item.get('offer_id')!r}, "
        f"but the agent chose {offer['offer_id']!r}"
    )
    signed_url = item.get("retrieval_endpoint")
    assert signed_url, f"execute returned no retrieval_endpoint: {item}"
    assert not result.get("delivery_failures"), (
        f"the service could not fetch the content it licensed: {result['delivery_failures']}"
    )

    # The bytes came back through MCP, having crossed a binding-enforcing edge.
    assert len(delivered) == 1, f"want one embedded resource, got {len(delivered)}: {delivered}"
    mime_type, body = delivered[0]
    assert _CONTENT_MARKER in body.decode("utf-8", errors="replace"), (
        f"delivered body does not carry {_CONTENT_MARKER!r}: {body[:200]!r}"
    )
    # The media type the publisher actually served, with parameters stripped —
    # socrates is a .txt, so text/plain. Asserted concretely for the same reason
    # the body marker above is: application/octet-stream is what the service falls
    # back to when the edge sends no usable Content-Type, so a truthiness check
    # would pass on precisely the outcome worth catching.
    assert mime_type == "text/plain", (
        f"embedded resource media type is {mime_type!r}, want the served text/plain"
    )


async def test_a_leaked_delivery_url_is_useless_without_the_key(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """The security property, driven end to end: holding the URL is not enough.

    Everything above would still pass if the edges quietly served bound URLs to
    anyone, so this is what shows the check is live rather than that the MCP path
    got lucky. The URL is a real one the service just used successfully; the only
    difference here is that the caller cannot prove possession of the key it names.
    """
    _require_in_network(compose_stack)
    _await_identity(compose_stack)

    bearer = _mcp_session_bearer(compose_stack)
    res = seeded.free

    async with Client(f"{compose_stack.identity}/mcp", auth=bearer) as client:
        discovered = await client.call_tool("ramp_discover", {"uris": [res.uri]})
        offer = discovered.structured_content["offer_groups"][0]["offers"][0]
        executed = await client.call_tool("ramp_execute", {"offers": [offer]})

    signed_url = str(executed.structured_content["items"][0]["retrieval_endpoint"])
    assert "agent_id=" in signed_url, f"the URL carries no binding to defeat: {signed_url}"
    # The service's OWN fetch of this URL succeeded. Without this the 403 below
    # would be just as consistent with an edge that refuses everyone, which would
    # make this test pass at the exact moment registry-side delivery broke.
    assert not executed.structured_content.get("delivery_failures"), (
        f"the service could not fetch the URL it is about to prove is bound: "
        f"{executed.structured_content['delivery_failures']}"
    )

    # A bespoke GET rather than fetch_signed: that helper asserts 200, and the
    # whole point here is the refusal.
    url, headers = edge_fetch_target(signed_url, compose_stack)
    async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
        leaked = await client.get(url, headers=headers)
    assert leaked.status_code == httpx.codes.FORBIDDEN, (
        f"a bound URL was served to a caller with no key: {leaked.status_code} {leaked.text[:200]}"
    )
    assert _refusal_reason(leaked) == "missing_agent_key", (
        f"refused for the wrong reason: {_refusal_reason(leaked)}"
    )


async def test_mcp_rejects_a_missing_or_invalid_bearer(compose_stack: StackURLs) -> None:
    """The endpoint must refuse an unauthenticated caller before doing any work.

    The ticket's acceptance criteria ask for a missing/invalid-bearer negative,
    and this module introduces the bearer, so the negative belongs beside the
    happy path rather than only in the Go suite. It needs no seeded fixture and
    no sign-up, so it is also the cheapest test here.
    """
    _require_in_network(compose_stack)
    _await_identity(compose_stack)

    # No credential at all: the endpoint answers 401 with the RFC 9728 challenge
    # that tells a client where to go and get one.
    resp = httpx.post(
        f"{compose_stack.identity}/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream"},
        timeout=10.0,
    )
    assert resp.status_code == httpx.codes.UNAUTHORIZED, (
        f"unauthenticated tools/list got {resp.status_code}, want 401: {resp.text[:200]}"
    )
    assert "resource_metadata" in resp.headers.get("WWW-Authenticate", ""), (
        "401 carries no resource_metadata pointer, so a client cannot discover where to sign in: "
        f"{resp.headers.get('WWW-Authenticate')!r}"
    )

    # A syntactically valid but unsigned-by-us token must fare no better.
    forged = httpx.post(
        f"{compose_stack.identity}/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={
            "Accept": "application/json, text/event-stream",
            "Authorization": "Bearer not-a-token-this-service-minted",
        },
        timeout=10.0,
    )
    assert forged.status_code == httpx.codes.UNAUTHORIZED, (
        f"garbage bearer got {forged.status_code}, want 401: {forged.text[:200]}"
    )
