"""Shared constants for the E2E harness: well-known routes, User-Agents, and the
default agent domain.

Single source of truth for each, so a spec change (e.g. a WBA directory route
rename) touches one line, not four.
"""

from __future__ import annotations

# One representative on each side of the edge's bot gate: a mainstream
# browser signature (allowed through to the origin) and an AI crawler from
# the worker's built-in deny list (sent to negotiate).
BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
    " (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)
AI_BOT_UA = "GPTBot/1.0 (+https://openai.com/gptbot)"

# Web Bot Auth directory: after the WBA split, identity/revocation keys moved
# off ramp.json and are served here as a JWK set (keys named by RFC 7638
# thumbprint, no kid).
WBA_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"

# Broker-published key-revocation channel (KeyRevocationList wire shape).
REVOCATION_PATH = "/.well-known/ramp-key-revocations.json"

# The requester domain the harness sends when a suite does not care which one it
# is. Every addressed request carries requester.domain as a bare host — it names
# where a verifier would fetch the agent's key — and an empty value is refused
# for its shape. The Exchange authorizes on requester.id against the signing key,
# not on this, so one value serves every suite that is not testing the field.
AGENT_DOMAIN = "agent.example"


def requester(
    agent_id: str,
    domain: str | None = None,
    **facets: object,
) -> dict[str, object]:
    """The requester object every addressed request carries.

    One builder rather than a dict written out per call site: the three keys and
    the domain default were copied five times, and the two copies that left the
    default out are the ones that sent an empty ``domain`` — a value the wire
    refuses for its shape.

    ``domain`` names where a verifier would fetch the agent's key. Nothing in
    these suites resolves it (the Exchange authorizes on ``id`` against the
    signing key), so a caller that does not care gets the harness's own agent
    domain rather than an absent field. Facets left out are omitted entirely
    rather than sent empty.
    """
    out: dict[str, object] = {
        "id": agent_id,
        "domain": domain or AGENT_DOMAIN,
        "type": "REQUESTER_TYPE_AGENT",
    }
    for key, value in facets.items():
        if value is not None:
            out[key] = value
    return out
