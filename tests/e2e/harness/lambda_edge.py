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

# Emulators this process gave up waiting on, base URL -> what happened.
#
# The emulator serves ONE invocation at a time and holds it reserved until the
# function returns. A client-side timeout abandons that reservation without
# ending it, so the next POST is a second concurrent invocation — and the
# emulator answers that by aborting the in-flight request unanswered and
# exiting its own process. The container dies, and every later test fails on a
# name that no longer resolves instead of on the timeout that actually
# happened.
#
# So a timeout retires that emulator for the rest of the session. Module state
# rather than a fixture because the reservation is a property of the emulator
# process, not of any one test; keyed by base URL because the stack runs two
# emulator containers and only the one that timed out is in doubt. Nothing
# clears it: once the slot state is unknown it stays unknown.
_ABANDONED: dict[str, str] = {}


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

    Also refuses to POST at all once an earlier call to this emulator timed out
    client-side, and records a timeout so later calls can refuse. See
    ``_ABANDONED`` for why posting into that state destroys the container.
    """
    abandoned = _ABANDONED.get(base_url)
    if abandoned is not None:
        msg = (
            f"not invoking {base_url}: an earlier invocation was abandoned "
            f"client-side ({abandoned}) and the emulator may still hold it "
            "reserved. Posting again makes the emulator exit and takes the "
            "container down, which turns one timeout into every later test "
            "failing on an unresolvable name."
        )
        raise AssertionError(msg)
    try:
        resp = httpx.post(f"{base_url}{INVOKE_PATH}", json=dict(event), timeout=timeout)
    except httpx.TimeoutException as exc:
        _ABANDONED[base_url] = f"{type(exc).__name__} after {timeout}s"
        raise
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

    This is the ONLY readiness invocation, and it is why the container probe
    must not invoke: two invocations at once destroy the emulator. The compose
    healthcheck proves the emulator is accepting connections and nothing more,
    so a stack that is still bringing the function up is caught here.

    Never more than one invocation in flight. The client deadline is whatever
    is left of the budget rather than a fixed slice, so a timeout means the
    budget is spent — it can never mean "retry now" while the emulator still
    holds the previous invocation reserved.
    """
    event = viewer_request_event("http://lambda-edge.invalid/healthz")
    deadline = time.monotonic() + timeout_seconds
    last_err: str | None = None
    while True:
        remaining = deadline - time.monotonic()
        # Under a second is not a real attempt, and a sub-second client
        # deadline would report a connect timeout as the reason the function
        # never answered.
        if remaining < 1.0:
            break
        try:
            result = invoke(base_url, event, timeout=remaining)
            if result.get("status") == "200":
                return
            last_err = str(result)[:128]
        except httpx.TimeoutException:
            # The emulator may still hold this invocation. `invoke` has already
            # retired it for the session; spend the budget rather than retry.
            last_err = "timed out with the invocation still in flight"
            break
        # A refused connection reserved nothing, and a completed invocation
        # that answered badly has already released the slot. Both are safe to
        # retry. TimeoutException is a subclass of HTTPError, which is why it
        # is caught above this line rather than swept in here.
        except (httpx.HTTPError, OSError, AssertionError) as exc:
            last_err = str(exc)[:128]
        time.sleep(1.0)
    msg = f"{base_url} did not answer /healthz after {timeout_seconds}s (last: {last_err})"
    raise TimeoutError(msg)
