"""The usage report a suite sends, built once.

A report body is five required fields plus two that depend on the obligation,
and it was written out at every call site. The pattern is the one the discovery
body already has a builder for: when the protocol adds a required field, a
builder is one edit and four hand-written bodies are four.

The recipient is the exchange that ISSUED the offer, which is not always the
exchange a suite is otherwise talking to. It is required, and an exchange
refuses a report naming anybody else — before the obligation is read, so a
misaddressed report leaves no record to inspect afterwards. Use
``exchanges.recipient_of`` on the URL the report is posted to.
"""

from __future__ import annotations

import uuid
from typing import Any

from ramp_sdk import ProtocolVersion

from .constants import requester

REPORT_USAGE_PATH = "/ramp.v1.ExchangeService/ReportUsage"


def report_body(
    *,
    exchange: str,
    transaction_id: str,
    agent_id: str | None = None,
    consumed_quantity: int = 0,
    function: list[str] | None = None,
    billing_id: str | None = None,
    domain: str | None = None,
    idempotency_key: str | None = None,
) -> dict[str, Any]:
    """A ``UsageReport`` body addressed to ``exchange``.

    ``consumed_quantity`` defaults to 0 because an obligation with a zero
    estimate strict-rejects a positive quantity, and most suites report against
    one. ``billing_id`` is omitted when absent rather than sent empty, which is
    what an obligation that carries none expects.
    """
    body: dict[str, Any] = {
        "ver": ProtocolVersion,
        "exchange": exchange,
        "idempotency_key": idempotency_key or f"report-{uuid.uuid4().hex}",
        "transaction_id": transaction_id,
        "usage": {
            "consumed_quantity": consumed_quantity,
            "function": list(function or ["ai_input"]),
        },
    }
    # Omitted rather than sent empty when the caller names no agent: a report
    # carries the agent's identity in its signature, and the suites that leave
    # this out are testing what the Exchange does with a report it holds no
    # obligation for.
    if agent_id:
        body["requester"] = requester(agent_id, domain)
    if billing_id:
        body["billing_id"] = billing_id
    return body


__all__ = ["REPORT_USAGE_PATH", "report_body"]
