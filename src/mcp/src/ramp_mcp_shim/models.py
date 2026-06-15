"""Pydantic models for the MCP ramp_fetch tool and Broker interaction.

These mirror the canonical RAMP proto shapes the Broker now speaks on
``POST /broker/v1/resolve`` (``RAMPRequest`` → ``RAMPResponse``, proto-JSON).
Field names are the proto's snake_case; a camelCase alias generator lets the
models (de)serialize the canonical camelCase wire while the Python attributes
stay snake_case. Broker-specific signals that ``RAMPResponse`` has no canonical
field for ride under ``ext`` with ``ramp.broker.*`` keys; the typed accessors on
``RampResponse`` keep those literals in one place.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class _Canonical(BaseModel):
    """Base for canonical wire models: camelCase on the wire, snake in Python."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class Cost(_Canonical):
    """Canonical Cost message."""

    amount: float
    currency: str = "USD"
    unit_cost: float | None = None


class Requester(_Canonical):
    """Canonical Requester sub-message of RAMPRequest."""

    id: str
    domain: str | None = None
    type: str = "REQUESTER_TYPE_AGENT"
    uris: list[str] = Field(default_factory=list)
    intended_use: list[str] = Field(default_factory=list)
    license_id: str | None = None


class RequestConstraints(_Canonical):
    """Canonical RequestConstraints sub-message of RAMPRequest."""

    period_budget: Cost | None = None
    max_hops: int | None = None


class RampRequest(_Canonical):
    """Body of POST /broker/v1/resolve — canonical proto RAMPRequest."""

    ver: str = "1.0"
    id: str
    requester: Requester
    query: str | None = None
    constraints: RequestConstraints | None = None


class RampResponse(_Canonical):
    """Body returned by POST /broker/v1/resolve — canonical proto RAMPResponse.

    Only the fields the shim consumes are modelled; the Broker also sends
    ``cost``/``delivery_method``/``reporting_obligation``/``expires_at`` which
    Pydantic ignores on parse (extra fields are dropped by default). The
    Broker-specific signals (licensed flag, winning offer, refusal cause) ride
    under ``ext`` with ``ramp.broker.*`` keys; the properties below expose them.
    """

    ver: str = ""
    id: str = ""
    request_id: str = ""
    transaction_id: str = ""
    billing_id: str = ""
    exchange: str = ""
    resource_title: str | None = None
    retrieval_endpoint: str | None = None
    agent_identity_hash: str | None = None
    ext: dict[str, Any] = Field(default_factory=dict)

    @property
    def licensed(self) -> bool:
        """True when the Broker delivered a licensed transaction."""
        return bool(self.ext.get("ramp.broker.licensed", False))

    @property
    def offer_id(self) -> str | None:
        """Winning offer id, surfaced under ext (no canonical RAMPResponse field)."""
        value = self.ext.get("ramp.broker.offer_id")
        return value if isinstance(value, str) else None

    @property
    def error(self) -> str | None:
        """Refusal / upstream error string, surfaced under ext."""
        value = self.ext.get("ramp.broker.error")
        return value if isinstance(value, str) else None


class RampFetchResult(BaseModel):
    """Agent-facing result of ``ramp_fetch``.

    The MCP shim performs the signed-URL fetch on the agent's behalf, so the
    agent only sees the resolved content plus audit metadata. This is the tool's
    own output contract, independent of the canonical wire shape.
    """

    licensed: bool
    content: str | None = None
    transaction_id: str | None = None
    offer_id: str | None = None
    exchange_id: str | None = None
    request_id: str | None = None
    error: str | None = None
