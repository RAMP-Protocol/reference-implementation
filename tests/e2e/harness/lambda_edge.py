"""Drive the Lambda@Edge worker through the AWS Lambda runtime emulator.

The emulator speaks the Lambda invoke protocol and nothing else: one POST route
that takes an event as JSON and returns whatever the function returned. So a
test does not "request a URL" from this runtime — it builds the CloudFront
viewer-request event CloudFront itself would deliver, invokes the function with
it, and reads the JSON that comes back.

That returned JSON has two shapes, and telling them apart is the whole point of
the Lambda@Edge entry:

* a **generated response** — a denial, or a well-known document — carries
  ``status``, ``headers`` and ``body``, and CloudFront returns it to the viewer
  without ever contacting the origin;
* a **pass-through** — the answer for an authorized read — is the incoming
  REQUEST object (``uri``, ``querystring``, ``headers``), which tells CloudFront
  to go and fetch the origin.

The translation between a URL and a CloudFront event stays here, in the test
harness, rather than in an HTTP front-end inside the container. A front-end
would have to decide which of the two shapes to turn back into an HTTP response,
and that decision is exactly the behavior these tests exist to prove.

Header note: the CloudFront header map is keyed by LOWERCASED header name, each
entry a list of ``{"key", "value"}`` pairs. :func:`response_header` reads it so
tests do not repeat the shape.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

import httpx

# The emulator's one route. The path is fixed by the Lambda runtime API and is
# the same for every function it hosts.
INVOKE_PATH = "/2015-03-31/functions/function/invocations"

# The header AWS sets on an invocation the function ended by throwing. Its
# presence turns an otherwise-ordinary 200 into a failed invocation.
_FUNCTION_ERROR_HEADER = "X-Amz-Function-Error"


def viewer_request_event(
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build the CloudFront viewer-request event for ``url``.

    ``url`` is split the way CloudFront delivers a request: the authority
    becomes the Host header (which is how the function reconstructs the URL it
    verifies signatures against), the path becomes ``uri`` and the query becomes
    ``querystring`` — without the leading "?".
    """
    parts = urlsplit(url)
    cf_headers: dict[str, list[dict[str, str]]] = {
        "host": [{"key": "Host", "value": parts.netloc}],
    }
    for name, value in (headers or {}).items():
        cf_headers[name.lower()] = [{"key": name, "value": value}]
    return {
        "Records": [
            {
                "cf": {
                    "config": {
                        "distributionDomainName": "e2e.cloudfront.example",
                        "distributionId": "E2ELAMBDAEDGE",
                        "eventType": "viewer-request",
                        "requestId": "e2e-lambda-edge",
                    },
                    "request": {
                        "clientIp": "203.0.113.7",
                        "method": method,
                        "uri": parts.path,
                        "querystring": parts.query,
                        "headers": cf_headers,
                    },
                }
            }
        ]
    }


def invoke(base_url: str, event: Mapping[str, Any], *, timeout: float = 30.0) -> dict[str, Any]:
    """Invoke the function with ``event`` and return what it returned.

    Raises ``AssertionError`` when the invocation itself failed — the function
    threw, or the emulator answered something other than 200. Those are never
    the outcome under test, and the error message carries the function's own
    message so the failure names its cause instead of a shape mismatch three
    assertions later.
    """
    resp = httpx.post(f"{base_url}{INVOKE_PATH}", json=dict(event), timeout=timeout)
    assert resp.status_code == httpx.codes.OK, (
        f"lambda runtime emulator answered {resp.status_code}: {resp.text[:256]}"
    )
    result = resp.json()
    assert isinstance(result, dict), f"function returned {type(result).__name__}, want an object"
    if _FUNCTION_ERROR_HEADER in resp.headers or "errorMessage" in result:
        raise AssertionError(f"the function invocation failed: {result}")
    return result


def is_pass_through(result: Mapping[str, Any]) -> bool:
    """True when the function handed the REQUEST back for CloudFront to fetch.

    A generated response always carries ``status``; a request object never does,
    and carries ``uri`` instead.
    """
    return "status" not in result and "uri" in result


def response_header(result: Mapping[str, Any], name: str) -> str | None:
    """Read one header out of a generated response, or None when absent."""
    entries = result.get("headers", {}).get(name.lower())
    if not entries:
        return None
    value = entries[0].get("value")
    return str(value) if value is not None else None


def wait_ready(base_url: str, timeout_seconds: float = 90.0) -> None:
    """Poll the invoke endpoint until the function answers its /healthz route.

    The compose healthcheck already gates the runner on this, so in a normal run
    the first invocation succeeds. It matters for a host-side run against a
    stack that is still coming up.
    """
    event = viewer_request_event("http://lambda-edge.invalid/healthz")
    deadline = time.monotonic() + timeout_seconds
    last_err: str | None = None
    while time.monotonic() < deadline:
        try:
            result = invoke(base_url, event, timeout=5.0)
            if result.get("status") == "200":
                return
            last_err = str(result)[:128]
        except (httpx.HTTPError, OSError, AssertionError) as exc:
            last_err = str(exc)[:128]
        time.sleep(1.0)
    msg = f"{base_url} did not answer /healthz after {timeout_seconds}s (last: {last_err})"
    raise TimeoutError(msg)
