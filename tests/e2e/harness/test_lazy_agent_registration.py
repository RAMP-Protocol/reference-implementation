"""Lazy agent registration (ADR-009 D2) through the real Agent -> Broker -> Exchange chain.

A fresh agent — absent from ramp.agents, serving its own Web Bot Auth key
directory on the ``lazy-agent-e2e`` network alias (== its keyID/domain),
billing-seeded in docker-compose.e2e.yml — discovers an offer and
relay-executes it. Both the Broker (sig1 boundary verify) and the Exchange resolve
its transport key from that directory at
/.well-known/http-message-signatures-directory; the Exchange then LAZILY persists
the ramp.agents row. The host also serves a ROLE_AGENT ramp.json, but nothing on
either path reads it — the overlay carries no keys.

This is the only test that exercises the lazy-registration SUCCESS path through the
genuine two-phase relay chain: seed.py pre-registers every other signing agent, so
the existing suite never fires the well-known fetch on the relay path.

Both paths drive the modern model: discover via the Broker
``Resolve`` then relay-execute the winning Offer (agent sig1 + Broker sig2 +
offer-acceptance) through ``POST /broker/v1/exchange/execute``. ``broker_client``'s
combined :func:`execute_first_offer` runs both phases with the fresh agent's own key,
so the Exchange binds + lazily registers THAT agent. The per-result fields ride on
``items[0]``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import httpx
import psycopg
import pytest

from .broker_client import execute_first_offer, resolve
from .conftest import COMPOSE_FILE, StackURLs
from .resolve_carriers import first_item_of, retrieval_endpoint_of
from .seed import DEMO_PHILOSOPHY_DOMAIN, SeededFixture, _resolve_pg_dsn

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Fresh agent: published manifest on the `lazy-agent-e2e` alias, USD billing-seeded
# in docker-compose.e2e.yml, but NOT seeded into ramp.agents.
LAZY_AGENT_ID = "lazy-agent-e2e"
LAZY_KEY_PATH = _FIXTURES / "agent_lazy_e2e_key.json"

# Ghost agent: a valid signing key but NO well-known host, so its key can be
# resolved nowhere — the negative control for the per-agent resolver.
GHOST_AGENT_ID = "ghost-agent-e2e"
GHOST_KEY_PATH = _FIXTURES / "agent_ghost_e2e_key.json"

# epicurus: PER_UNIT 0.0001/characters USD — a PAID resource. A lazily registered
# agent has an identity row but NO billing account (D1 / ADR-021), so the
# paid execute is denied ACCOUNT_NOT_REGISTERED while the lazy-registration side
# effect still fires. Buying paid content requires an explicit Register first.
_RESOURCE_URI = f"http://{DEMO_PHILOSOPHY_DOMAIN}/articles/philosophers/epicurus.txt"


def _agent_row_exists(agent_id: str) -> bool:
    """BLACK-BOX e2e DB read: observe the lazily-persisted ramp.agents row.

    Lazy registration is an internal Exchange side effect with no protocol read
    surface by design — there is no RPC that reports whether an agent row exists.
    Reading the deployment datastore directly is the only way to assert the side
    effect end-to-end (consistent with the transaction_log read in
    obligations/test_00_happy_03_usage_record_paid_access.py); it is a full-stack
    e2e observation, not an in-process layer bypass.
    """
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM ramp.agents WHERE agent_id = %s", (agent_id,))
        return cur.fetchone() is not None


def test_lazy_registration_fires_but_paid_needs_register(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests the demo catalog
) -> None:
    """A never-seen agent is lazily registered (identity), but a PAID buy needs Register.

    Round-trip: discover (Broker Resolve, sig1 over the agent's own key resolved
    from http://lazy-agent-e2e/.well-known/http-message-signatures-directory) ->
    relay-execute the winning
    Offer (agent sig1 + Broker sig2 + offer-acceptance). Lazy registration
    (ADR-009 D2) persists the ramp.agents IDENTITY row from the verified well-known
    — enough for free crawling, but NOT a billing account. Per ADR-021 D1 /
    ADR-021, an agent with no billing_ref cannot buy paid content, so the PAID
    epicurus item is denied in-body with DENIAL_REASON_ACCOUNT_NOT_REGISTERED (the
    agent must call Register first). The test asserts BOTH: the in-body paid denial
    AND the lazy-registration side effect — the agents row flips False -> True even
    on the denied paid request, because resolveAgentID persists the row before the
    billing check.
    """
    assert not _agent_row_exists(LAZY_AGENT_ID), (
        "precondition violated: lazy-agent-e2e is already in ramp.agents"
    )

    resp = execute_first_offer(
        compose_stack,
        {"agent_id": LAZY_AGENT_ID, "uri": _RESOURCE_URI, "domain": DEMO_PHILOSOPHY_DOMAIN},
        agent_id=LAZY_AGENT_ID,
        domain=DEMO_PHILOSOPHY_DOMAIN,
        key_path=LAZY_KEY_PATH,
    )
    # The paid item is denied IN-BODY (per-item denial, HTTP 200), not a transport error.
    assert resp.status_code == httpx.codes.OK, (
        f"relay execute should return an in-body denial, not a transport error; "
        f"got {resp.status_code}: {resp.text[:512]}"
    )

    # C2 (the items-only collapse): read the per-item result from items[0]. A lazily registered
    # identity is not a registered billing account, so the paid buy is refused.
    accept_payload = cast(dict[str, Any], resp.json())
    item = first_item_of(accept_payload)
    assert item is not None, f"relay response carried no items[0]: {accept_payload}"
    assert item.get("denial_reason") == "DENIAL_REASON_ACCOUNT_NOT_REGISTERED", (
        f"a paid buy by an identity-only lazy agent must be denied ACCOUNT_NOT_REGISTERED "
        f"(Register mints the account first): {accept_payload}"
    )
    assert not retrieval_endpoint_of(item), (
        f"a denied paid item must carry no signed URL: {accept_payload}"
    )

    # The side effect that proves lazy registration still fired on the real relay
    # path — the identity row is persisted even though the paid charge was refused.
    assert _agent_row_exists(LAZY_AGENT_ID), (
        "agent was not lazily registered after the relayed execute"
    )


def test_unresolvable_agent_refused_before_execute(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests the demo catalog
) -> None:
    """Negative control: a fresh agent with NO well-known host is refused; not registered.

    The ghost agent holds a valid signing key but no well-known host serves its
    key directory — and directories are the ONLY path a verifier learns a key
    by — so its key resolves NOWHERE. The
    Broker's httpsig middleware verifies the self-act keyID on EVERY signed
    ``/ramp.*`` call against the agent's resolvable key (resolve.go
    authorizeAgentSelfAct sits behind that middleware); with no key to resolve, the
    rejection surfaces as a TRANSPORT error (HTTP 401 Unauthenticated), not a
    per-item in-body denial.

    The refusal lands on the FIRST signed leg — Broker ``Resolve`` (discovery) —
    so the relay-execute is never reached: an unresolvable agent cannot even
    discover, let alone execute. We therefore drive and assert the rejection
    directly on the ``Resolve`` leg (the combined ``execute_first_offer`` asserts a
    200 discover internally, which would mask the 401 as an AssertionError).
    Lazy registration never fires.
    """
    resp = resolve(
        compose_stack,
        {"agent_id": GHOST_AGENT_ID, "uri": _RESOURCE_URI, "domain": DEMO_PHILOSOPHY_DOMAIN},
        key_path=GHOST_KEY_PATH,
    )
    assert resp.status_code == httpx.codes.UNAUTHORIZED, (
        f"ghost agent (no well-known) must be refused at the Broker sig1 boundary; "
        f"got {resp.status_code}: {resp.text[:512]}"
    )
    assert not _agent_row_exists(GHOST_AGENT_ID), (
        "ghost agent must not be lazily registered after a refused signed call"
    )
