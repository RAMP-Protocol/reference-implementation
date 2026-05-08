"""Pydantic models for the MCP ramp_fetch tool and Broker interaction.

Boundary types — kept separate from transport + tool logic so shape changes
in the Broker JSON surface stay isolated here.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ResolveRequest(BaseModel):
    """Body of POST /broker/v1/resolve as the Broker expects it."""

    agent_id: str
    license_id: str | None = None
    query: str | None = None
    uri: str | None = None
    budget_minor: int | None = None
    requester_domain: str | None = None
    intended_use: str | None = None


class BudgetState(BaseModel):
    """Budget audit snippet returned by the Broker."""

    limit_minor: int
    consumed_minor: int
    remaining_minor: int


class CandidateInfo(BaseModel):
    """One offer candidate evaluated by the Broker's ranker."""

    offer_id: str
    marketplace_id: str
    unit_cost: float
    trust_level: str


class ResolveResponse(BaseModel):
    """Body returned by POST /broker/v1/resolve.

    Either ``signed_url`` or ``bare_url`` is populated depending on whether
    a marketplace represented the publisher.
    """

    licensed: bool
    signed_url: str | None = None
    bare_url: str | None = None
    transaction_id: str | None = None
    offer_id: str | None = None
    marketplace_id: str | None = None
    request_id: str
    budget: BudgetState | None = None
    error: str | None = None
    candidates: list[CandidateInfo] = Field(default_factory=list)


class RampFetchResult(BaseModel):
    """Agent-facing result of ``ramp_fetch``.

    The MCP shim performs the signed-URL fetch on the agent's behalf, so
    the agent only sees the resolved content plus audit metadata.

    Cost fields come from the winning candidate the Broker selected — useful
    for the agent to surface to the human ("I just spent $0.01 on ..."). For
    the unlicensed path they remain None.
    """

    licensed: bool
    content: str | None = None
    bare_url: str | None = None
    transaction_id: str | None = None
    offer_id: str | None = None
    marketplace_id: str | None = None
    request_id: str | None = None
    cost: float | None = None
    currency: str | None = None
    error: str | None = None
