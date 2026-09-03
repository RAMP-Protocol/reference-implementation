"""Reading a Connect-Go error body the way a client does.

A refusal assertion that only checks the status code cannot say WHICH refusal
happened. That matters most where a request has several ways to be refused: a
report for a transaction nobody holds is refused by the service layer, and the
same request with a field missing is refused by wire validation long before —
both non-2xx, and a status-only assertion reads them as the same result. The
test then keeps passing while proving something else entirely.

So the code is pinned. A refusal that moves to another layer, or is
reclassified, fails here instead of being absorbed.
"""

from __future__ import annotations

from collections.abc import Collection
from typing import Any

import httpx


def assert_refused(resp: httpx.Response, codes: Collection[str], what: str) -> dict[str, Any]:
    """Assert resp is a Connect-Go refusal carrying one of codes, and return it.

    ``what`` names the request, so a failure says which one was not refused as
    expected rather than only what arrived.
    """
    assert resp.status_code >= httpx.codes.BAD_REQUEST, (
        f"{what} was NOT refused: status={resp.status_code} body={resp.text[:256]}"
    )
    try:
        payload: dict[str, Any] = resp.json()
    except ValueError as exc:
        msg = f"expected a Connect-Go JSON error body for {what}, got: {resp.text[:256]}"
        raise AssertionError(msg) from exc
    code = payload.get("code")
    message = payload.get("message")
    assert isinstance(code, str) and code in codes, (
        f"refusal code {code!r} not in {sorted(codes)} for {what}: {payload}"
    )
    assert isinstance(message, str) and message, f"refusal carries no message for {what}: {payload}"
    return payload


__all__ = ["assert_refused"]
