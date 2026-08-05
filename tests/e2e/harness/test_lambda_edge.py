"""E2E: the edge worker on the AWS Lambda@Edge runtime.

What runs here is the production artifact. The container is built by
``src/edge/scripts/build-lambda-edge.mjs`` — the same script a deployment runs,
with the per-deployment config baked into the bundle because Lambda@Edge has no
environment variables — and it executes inside the AWS Lambda runtime image, so
the invocations below go through the real Lambda runtime rather than a Node
process pretending to be one. The other two runtimes (Cloudflare via Miniflare,
Fastly Compute via Viceroy) already have that; this closes the third.

Two shapes are asserted throughout, and telling them apart is what the
Lambda@Edge entry exists for: a denial or a well-known document comes back as a
GENERATED RESPONSE (status/headers/body) that CloudFront returns without
touching the origin, while an authorized read comes back as the REQUEST OBJECT,
which is how the function tells CloudFront to go and fetch the origin itself.
This deployment bakes no ORIGIN_URL, the CloudFront-native posture where the CDN
owns that fetch.

Why the delivery URLs here are signed by the test rather than minted through
Broker and Exchange, as the other runtimes' suites do:

* CloudFront terminates TLS, so a Lambda@Edge function always sees an https
  request, and the adapter rebuilds the URL that way. The compose network is
  http-only, and the Exchange mints its delivery URLs on http demo domains. The
  signature covers the scheme, so a URL minted in this stack can never verify
  through this runtime — it would only ever prove a mismatch.
* The signing key is not a test key. It is exchange-a's own Ed25519
  delivery-URL key, and the fixture below refuses to run unless the Exchange is
  publishing that exact key in its Web Bot Auth directory.
* Verification stays entirely on the production path: the worker resolves the
  key by thumbprint by fetching the Exchange's directory over the network, with
  no pre-provisioned key list baked in.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
)
from ramp_sdk.b64 import b64url_decode
from ramp_sdk.signedurl import sign_ed25519_signed_url
from ramp_sdk.thumbprint import thumbprint as ed25519_thumbprint

from .conftest import StackURLs
from .constants import AI_BOT_UA, BROWSER_UA, WBA_DIRECTORY_PATH
from .edge_fetch import tamper_query_param
from .httpsig_signer import key_thumbprint
from .lambda_edge import invoke, is_pass_through, response_header, viewer_request_event
from .signing import AGENT_E2E_KEY_PATH, build_pop_headers

# The publisher this deployment fronts, and the exchange it points agents at.
# Both are baked into the bundle at build time (tests/e2e/lambda-edge/
# write-configs.mjs), so asserting on them is how a test notices that the built
# artifact no longer carries the configuration it was built for.
PUBLISHER = "lambda.demo.ramp-protocol.org"
EXCHANGE_ENDPOINT = "http://exchange:8081"

# An ordinary content path. Nothing is fetched from an origin on this
# deployment — CloudFront would own that — so the path only has to look like a
# real article read.
ARTICLE_PATH = "/articles/on-the-examined-life"

# Query the publisher's own site puts on its URLs. It must survive a
# pass-through untouched, unlike the signature parameters.
SITE_QUERY = "page=2&utm_source=e2e"

# The reserved query parameters the Exchange's signer appends. The function
# strips exactly these before handing the request back to CloudFront, so the
# origin never sees the spoofable attribution namespace and the cache key stays
# clean.
SIGNATURE_PARAMS = ("exp", "sig", "kid", "agent_id")


@dataclass(frozen=True)
class ExchangeKey:
    """exchange-a's Ed25519 delivery-URL signing key.

    ``kid`` is the RFC 7638 thumbprint of the public half, which is both the
    keyid the Exchange stamps on a delivery URL and the name the key is
    published under in the Exchange's Web Bot Auth directory.
    """

    seed: bytes
    kid: str


@pytest.fixture(scope="session")
def exchange_key(compose_stack: StackURLs) -> ExchangeKey:
    """Load the Exchange's signing key and confirm the Exchange publishes it.

    The confirmation is the point of the fixture. Without it, a key that had
    drifted from the one the Exchange serves would surface as an ordinary
    "invalid signature" denial in every positive test below — a failure that
    looks like the edge rejecting a bad URL rather than the harness signing with
    the wrong key.
    """
    pem_path = os.environ.get("RAMP_EXCHANGE_ED25519_PEM_FILE")
    if not pem_path or not Path(pem_path).is_file():
        pytest.fail(
            "RAMP_EXCHANGE_ED25519_PEM_FILE must name the Exchange's Ed25519 key file. "
            "docker-compose.e2e.yml sets it on the runner and mounts the key volume "
            "read-only, so run this through `make test-e2e` (or `docker compose "
            "--profile test run --rm runner`), not a bare pytest."
        )
    private = load_pem_private_key(Path(pem_path).read_bytes(), password=None)
    assert isinstance(private, Ed25519PrivateKey), (
        f"{pem_path} holds a {type(private).__name__}, want an Ed25519 private key"
    )
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    kid = ed25519_thumbprint(public)

    directory = httpx.get(f"{compose_stack.exchange}{WBA_DIRECTORY_PATH}", timeout=30.0)
    assert directory.status_code == httpx.codes.OK, directory.text
    published = [ed25519_thumbprint(b64url_decode(k["x"])) for k in directory.json()["keys"]]
    assert kid in published, (
        f"the Exchange publishes {published} in its Web Bot Auth directory, not {kid}: "
        "the key this suite signs with is no longer the key the edge will resolve"
    )
    return ExchangeKey(seed=private.private_bytes_raw(), kid=kid)


def signed_url(
    key: ExchangeKey,
    *,
    path: str = ARTICLE_PATH,
    query: str = "",
    agent_id: str = "",
    ttl_seconds: int = 300,
) -> str:
    """Mint a delivery URL for this publisher, signed with the Exchange's key.

    https, because that is what CloudFront hands a Lambda@Edge function. An
    empty ``agent_id`` yields a bearer URL; a non-empty one binds the URL to
    that agent's key and turns on the proof-of-possession check at the edge. A
    negative ``ttl_seconds`` produces an already-expired URL.
    """
    base = f"https://{PUBLISHER}{path}"
    if query:
        base = f"{base}?{query}"
    return sign_ed25519_signed_url(
        base,
        seed=key.seed,
        kid=key.kid,
        agent_id=agent_id,
        exp=int(time.time()) + ttl_seconds,
    )


def _json_body(result: dict[str, Any]) -> dict[str, Any]:
    """Parse a generated response's JSON body, saying clearly when there isn't one.

    Every answer this worker generates — the well-known documents and each
    denial — is JSON. A 403 that arrives as HTML or empty is exactly the failure
    worth naming, and a bare json.loads would raise before an assertion could
    say what it saw.

    The media type is checked by its "+json" family rather than by an exact
    string: denials and the manifest are application/json, while the Web Bot
    Auth directory is application/jwk-set+json so an off-the-shelf verifier
    recognises it. The route that cares about the exact value asserts it itself.
    """
    content_type = response_header(result, "content-type") or ""
    assert content_type.split(";")[0].strip().endswith("json"), (
        f"expected a JSON body; content-type was {content_type!r}, "
        f"body {str(result.get('body'))[:160]!r}"
    )
    body = json.loads(result["body"])
    assert isinstance(body, dict), f"body is not a JSON object: {body!r}"
    return body


def _querystring(result: dict[str, Any]) -> str:
    return str(result["querystring"])


def test_manifest_route_is_served_as_a_generated_response(compose_stack: StackURLs) -> None:
    """GET /.well-known/ramp.json answers the publisher manifest, origin untouched.

    This is the document the whole discovery chain starts from: an agent that
    was turned away reads it to learn which exchange sells access. It must come
    back as a generated response — CloudFront must not forward this to an origin
    that knows nothing about RAMP.
    """
    result = invoke(
        compose_stack.lambda_edge,
        viewer_request_event(f"https://{PUBLISHER}/.well-known/ramp.json"),
    )
    assert result["status"] == "200", result
    manifest = _json_body(result)
    assert manifest["domain"] == PUBLISHER, manifest
    exchanges = manifest["exchanges"]
    assert [e["endpoint"] for e in exchanges] == [EXCHANGE_ENDPOINT], manifest


@pytest.mark.parametrize(
    ("service", "expected_status"),
    [("publishing", "200"), ("not-publishing", "404")],
)
def test_wba_directory_matches_the_deployment_key_posture(
    compose_stack: StackURLs,
    service: str,
    expected_status: str,
) -> None:
    """The Web Bot Auth directory is served only where the publisher has a key.

    Two containers, because a Lambda function serves exactly one baked bundle
    and the two answers come from two build-time configurations of the same
    worker. The publishing one serves its signing key as a JWK Set, which is how
    the Exchange learns a catalog writer's key without a database pre-seed; the
    other answers 404, which is what a publisher that issues no key must do
    rather than serve an empty directory a verifier would treat as a key set.
    """
    base_url = (
        compose_stack.lambda_edge if service == "publishing" else compose_stack.lambda_edge_no_wba
    )
    result = invoke(base_url, viewer_request_event(f"https://{PUBLISHER}{WBA_DIRECTORY_PATH}"))
    assert result["status"] == expected_status, result
    if expected_status != "200":
        return
    assert response_header(result, "content-type") == "application/jwk-set+json", result
    keys = _json_body(result)["keys"]
    assert len(keys) >= 1, keys
    assert all(k["kty"] == "OKP" and k["crv"] == "Ed25519" for k in keys), keys


def test_valid_delivery_url_passes_through_with_signature_params_stripped(
    compose_stack: StackURLs,
    exchange_key: ExchangeKey,
) -> None:
    """An authorized read is handed back to CloudFront, carrying only the site's query.

    Two properties in one invocation, because they are one decision. The result
    is the request object, so CloudFront fetches the origin — the function never
    serves the bytes itself, which at viewer-request it could not do anyway (a
    generated response is capped at about 40 KB). And the signature parameters
    are gone from the query, so the origin cannot be handed spoofable
    attribution data that looks like it survived verification, while the site's
    own parameters arrive untouched.
    """
    url = signed_url(exchange_key, query=SITE_QUERY)
    result = invoke(compose_stack.lambda_edge, viewer_request_event(url))
    assert is_pass_through(result), result
    assert result["uri"] == ARTICLE_PATH, result
    querystring = _querystring(result)
    for param in SIGNATURE_PARAMS:
        assert f"{param}=" not in querystring, (
            f"{param} survived into the origin request: {querystring}"
        )
    assert "page=2" in querystring and "utm_source=e2e" in querystring, querystring


def test_tampered_signature_is_refused(
    compose_stack: StackURLs,
    exchange_key: ExchangeKey,
) -> None:
    """One flipped character in the signature turns the read into a 403.

    The key still resolves — this invocation fetches the Exchange's directory
    like the successful one above — so what is being proved is that the
    signature is actually checked against the URL, not merely that some key was
    found.
    """
    url = tamper_query_param(signed_url(exchange_key))
    result = invoke(compose_stack.lambda_edge, viewer_request_event(url))
    assert result["status"] == "403", result
    body = _json_body(result)
    assert body == {"error": "Invalid signature", "reason": "signature_mismatch"}, body


def test_expired_delivery_url_is_refused(
    compose_stack: StackURLs,
    exchange_key: ExchangeKey,
) -> None:
    """A correctly signed URL whose expiry has passed is refused as expired.

    The distinct reason matters operationally: an agent that comes back with a
    stale URL should buy a new one, while an invalid signature means something
    is wrong with the URL it was given.
    """
    url = signed_url(exchange_key, ttl_seconds=-60)
    result = invoke(compose_stack.lambda_edge, viewer_request_event(url))
    assert result["status"] == "403", result
    body = _json_body(result)
    assert body == {"error": "Signed URL has expired", "reason": "expired"}, body


def test_unsigned_ai_bot_is_sent_to_negotiate(compose_stack: StackURLs) -> None:
    """An unsigned AI bot gets a 403 that tells it where to buy access.

    The headers are the machine-readable half of that answer: X-Content-Rules
    points at this publisher's manifest and X-RAMP-Exchange at the exchange that
    sells the license. A 403 without them is a dead end for the bot.
    """
    result = invoke(
        compose_stack.lambda_edge,
        viewer_request_event(
            f"https://{PUBLISHER}{ARTICLE_PATH}", headers={"User-Agent": AI_BOT_UA}
        ),
    )
    assert result["status"] == "403", result
    assert response_header(result, "X-Content-Rules") == (
        f"https://{PUBLISHER}/.well-known/ramp.json"
    ), result
    assert response_header(result, "X-RAMP-Exchange") == EXCHANGE_ENDPOINT, result
    body = _json_body(result)
    assert body["reason"] == "ai_bot", body
    assert body["error"], body


def test_unsigned_human_read_passes_through(compose_stack: StackURLs) -> None:
    """A browser reads the site normally: no signature, no license, no denial.

    The bot gate must not turn the publisher's site off for its ordinary
    readers, so this is the case that keeps the gate from being a blanket block.
    """
    result = invoke(
        compose_stack.lambda_edge,
        viewer_request_event(
            f"https://{PUBLISHER}{ARTICLE_PATH}", headers={"User-Agent": BROWSER_UA}
        ),
    )
    assert is_pass_through(result), result
    assert result["uri"] == ARTICLE_PATH, result


def test_unsigned_browser_at_site_root_passes_through(compose_stack: StackURLs) -> None:
    """The site root passes through to the origin like any other page.

    The origin serves the human-facing landing page at /, so the function must
    hand the root request back to CloudFront untouched. A stakeholder demo
    starts by opening the demo hostname in a browser; if this pass-through
    breaks, that first impression is an error page.
    """
    result = invoke(
        compose_stack.lambda_edge,
        viewer_request_event(f"https://{PUBLISHER}/", headers={"User-Agent": BROWSER_UA}),
    )
    assert is_pass_through(result), result
    assert result["uri"] == "/", result


def test_unsigned_ai_bot_at_site_root_is_sent_to_negotiate(compose_stack: StackURLs) -> None:
    """The landing page is for people: an AI bot at / still gets the 403 payload.

    The root must not become a hole in the bot gate — the same negotiation
    pointers apply there as on any content path.
    """
    result = invoke(
        compose_stack.lambda_edge,
        viewer_request_event(f"https://{PUBLISHER}/", headers={"User-Agent": AI_BOT_UA}),
    )
    assert result["status"] == "403", result
    body = _json_body(result)
    assert body["reason"] == "ai_bot", body


def test_agent_bound_url_needs_the_key_it_names(
    compose_stack: StackURLs,
    exchange_key: ExchangeKey,
) -> None:
    """A bound delivery URL is worthless to anyone who cannot present its key.

    The same URL is driven twice and only the proof of possession changes, so
    the difference between the two answers is the check itself and not something
    about the URL. Without the proof the read is refused; with an RFC 9421
    signature made by the agent key the URL is bound to, it passes through. This
    is what stops a leaked URL from being a bearer token.
    """
    agent_id = key_thumbprint(AGENT_E2E_KEY_PATH)
    url = signed_url(exchange_key, agent_id=agent_id)

    refused = invoke(compose_stack.lambda_edge, viewer_request_event(url))
    assert refused["status"] == "403", refused
    body = _json_body(refused)
    assert body == {"error": "Agent binding check failed", "reason": "missing_agent_key"}, body

    proven = invoke(
        compose_stack.lambda_edge,
        viewer_request_event(url, headers=build_pop_headers(url=url, key_path=AGENT_E2E_KEY_PATH)),
    )
    assert is_pass_through(proven), proven
    assert proven["uri"] == ARTICLE_PATH, proven


def test_signed_read_url_replayed_as_a_write_is_refused(
    compose_stack: StackURLs,
    exchange_key: ExchangeKey,
) -> None:
    """A valid signed URL does not authorize a POST to the origin.

    The URL signature covers the URL and nothing else — not the method, not the
    body. Only the proof-of-possession check binds the method, and this URL is
    unbound, so nothing would check it. Without this refusal one leaked read URL
    could be replayed as a write with an arbitrary body against the origin.
    """
    url = signed_url(exchange_key)
    result = invoke(compose_stack.lambda_edge, viewer_request_event(url, method="POST"))
    assert result["status"] == "405", result
    assert response_header(result, "Allow") == "GET, HEAD", result
    body = _json_body(result)
    assert body == {
        "error": "Signed URLs authorize content reads only",
        "reason": "method_not_bound",
    }, body


def test_rsl_document_is_served_as_a_generated_response(compose_stack: StackURLs) -> None:
    """GET /rsl.txt answers the baked RSL body, origin untouched.

    This route matters twice on this runtime. It is one of the four documents
    the deployment generates at the edge. And with no body configured it would
    produce exactly the empty 200 that made "empty body" unusable as the
    pass-through signal — so it must come back as a generated response with the
    baked body, never as a pass-through.
    """
    result = invoke(
        compose_stack.lambda_edge,
        viewer_request_event(f"https://{PUBLISHER}/rsl.txt"),
    )
    assert result["status"] == "200", result
    content_type = response_header(result, "content-type")
    assert content_type is not None and content_type.startswith("text/plain"), result
    assert result["body"] == "# e2e rsl lambda", result


def test_unknown_ramp_verify_token_is_refused(compose_stack: StackURLs) -> None:
    """GET /.well-known/ramp-verify/<unknown token> answers a generated 404.

    This deployment bakes no ACME tokens: the CloudFront certificate is
    DNS-validated, so the route's whole surface here is the refusal. An unknown
    token must get a generated 404 — not a pass-through that would hand the
    challenge probe to an origin that knows nothing about it.
    """
    result = invoke(
        compose_stack.lambda_edge,
        viewer_request_event(f"https://{PUBLISHER}/.well-known/ramp-verify/never-issued"),
    )
    assert result["status"] == "404", result
