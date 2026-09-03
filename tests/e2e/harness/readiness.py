"""Waiting for a compose service to answer.

Lives beside stack_urls.py rather than in conftest.py, for the same reason and
with the same consequence. conftest.py is the pytest plugin file that every
module in this package already imports, so anything defined there cannot be
imported BACK by a module conftest itself uses — and the poller is used by both.
That is what forced mcp_session.py's two imports inside fixture bodies, with a
comment naming the cycle as the reason. Defined here, both become ordinary
top-level imports.
"""

from __future__ import annotations

import time

import httpx


def wait_healthy(url: str, timeout_seconds: float = 90.0) -> None:
    """Poll ``url`` until it returns 2xx or timeout."""
    deadline = time.monotonic() + timeout_seconds
    last_err: str | None = None
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(url, timeout=2.0)
            if 200 <= resp.status_code < 300:
                return
            last_err = f"{resp.status_code} {resp.text[:128]}"
        except (httpx.HTTPError, OSError) as exc:
            last_err = str(exc)
        time.sleep(1.0)
    msg = f"{url} not healthy after {timeout_seconds}s (last: {last_err})"
    raise TimeoutError(msg)
